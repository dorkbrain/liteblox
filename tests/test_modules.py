"""Modules (4.0): the switches, what keeps one on, hiding everywhere, 404s, the first-run card and the CLI."""

import sqlite3

import pytest

from liteblox import cli, db, modules
from liteblox.api import tokens
from liteblox.ipam.model import add_network

from conftest import csrf_from


@pytest.fixture
def admin(client, make_user, login):
    make_user()
    login('alice', 'correct-horse')
    return client


def switch(conn, **wanted):
    on = modules.enabled(conn)
    on.update(wanted)
    assert modules.save(conn, on) == {}


def post(client, **on):
    token = csrf_from(client.get('/settings/modules').text)
    data = {'csrf_token': token, **{n: 'on' for n, v in on.items() if v}}
    return client.post('/settings/modules', data=data, follow_redirects=False)


def add_node(conn, name='ns1', **kw):
    cols = {'name': name, 'host': '192.0.2.1', 'host_key': 'k', 'host_key_fp': 'f', **kw}
    with conn:
        conn.execute(f"INSERT INTO nodes ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))


def test_a_fresh_install_has_everything_on_but_not_chosen(conn):
    assert modules.enabled(conn) == {'dns': True, 'dhcp': True, 'ntp': True, 'ipam': True}
    assert not modules.chosen(conn)


def test_an_upgraded_install_counts_as_chosen(tmp_path):
    path = tmp_path / 'old.db'
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    for version, step in enumerate(db.MIGRATIONS[:31], start=1):
        c.executescript(step)
        c.execute(f'PRAGMA user_version = {version}')
    c.execute("INSERT INTO users (username, password_hash, role) VALUES ('old', 'x', 'admin')")
    c.commit()
    c.close()
    db.migrate(path)
    c = db.connect(path)
    assert modules.chosen(c) and all(modules.enabled(c).values())
    c.close()


def test_a_module_in_use_cannot_go_off(conn):
    add_node(conn, dhcp=1, ntp=1)
    with conn:
        conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES ('example.com', 'managed', 'example.com.zone')")
    errors = modules.save(conn, {'dns': False, 'dhcp': False, 'ntp': False, 'ipam': True})
    assert errors == {'dns': 'in use: remove 1 zone and 1 BIND node first',
                      'dhcp': 'in use: remove 1 node with Kea first', 'ntp': 'in use: remove 1 node with chrony first'}
    assert all(modules.enabled(conn).values()) and not modules.chosen(conn)


def test_one_module_stays_on_and_ipam_can_always_go(conn):
    assert modules.save(conn, dict.fromkeys(modules.NAMES, False)) == {'all': 'keep at least one module on'}
    switch(conn, ipam=False)
    assert modules.enabled(conn)['ipam'] is False and modules.chosen(conn)


def test_settings_page_saves_and_refuses(admin, conn):
    page = admin.get('/settings/modules').text
    assert 'name="dns" value="on" checked' in page and '>Modules</a>' in page
    r = post(admin, ipam=True)
    assert r.status_code == 303 and r.headers['location'] == '/settings/modules?done=Saved.'
    assert modules.enabled(conn) == {'dns': False, 'dhcp': False, 'ntp': False, 'ipam': True}
    assert conn.execute("SELECT detail FROM audit WHERE action = 'modules'").fetchone()[0] == 'IPAM'
    add_node(conn, ntp=1)
    switch(conn, ntp=True)
    r = post(admin, ipam=True)
    assert r.status_code == 422 and 'in use: remove 1 node with chrony first' in r.text
    r = post(admin)
    assert r.status_code == 422 and 'Keep at least one module on' in r.text


def test_readers_cannot_switch(client, make_user, login):
    make_user('bob', 'correct-horse', 'readonly')
    login('bob', 'correct-horse')
    assert client.get('/settings/modules').status_code == 403


def test_the_menu_and_settings_tabs_follow_the_switches(admin, conn):
    page = admin.get('/ipam').text
    assert 'href="/zones"' in page and 'href="/dhcp"' in page
    switch(conn, dns=False, dhcp=False, ntp=False)
    page = admin.get('/ipam').text
    assert 'href="/zones"' not in page and 'href="/dhcp"' not in page and 'href="/ipam"' in page
    tabs = admin.get('/settings/ipam').text
    assert 'href="/settings/acls"' not in tabs and 'href="/settings/time"' not in tabs and 'href="/settings/modules"' in tabs
    assert admin.get('/settings', follow_redirects=False).headers['location'] == '/settings/ipam'


def test_off_modules_answer_404_in_the_ui_and_the_api(admin, conn):
    switch(conn, dns=False, dhcp=False, ntp=False)
    for path in ('/zones', '/zones/new', '/dhcp', '/settings/time', '/settings/acls', '/settings/keys', '/nodes/1/dhcp'):
        r = admin.get(path)
        assert r.status_code == 404, path
    assert 'is switched off' in admin.get('/dhcp').text and 'href="/settings/modules"' in admin.get('/dhcp').text
    token = tokens.create(conn, 'alice', 'ci', 'read', 'alice')[1]
    auth = {'Authorization': f'Bearer {token}'}
    r = admin.get('/api/v1/zones', headers=auth)
    assert r.status_code == 404 and 'DNS module is off' in r.json()['detail']
    assert admin.get('/api/v1/status', headers=auth).json()['modules'] == ['ipam']
    assert admin.get('/api/v1/ipam/networks', headers=auth).status_code == 200
    assert admin.get('/nodes').status_code == 200 and admin.get('/search?q=x').status_code == 200


def test_the_path_map():
    assert modules.module_of('/zones/example.com/records') == 'dns'
    assert modules.module_of('/nodes/3/takeover') == 'dns' and modules.module_of('/nodes/3') is None
    assert modules.module_of('/nodes/3/dhcp/setup') == 'dhcp' and modules.module_of('/api/v1/dhcp/subnets') == 'dhcp'
    assert modules.module_of('/nodes/3/time') == 'ntp' and modules.module_of('/settings/ipam') == 'ipam'
    assert modules.module_of('/zonesx') is None and modules.module_of('/settings/modules') is None


def test_the_first_run_card_until_chosen(admin, conn):
    page = admin.get('/').text
    assert 'What will this LiteBlox run?' in page and 'name="next" value="dashboard"' in page
    token = csrf_from(page)
    r = admin.post('/settings/modules', data={'csrf_token': token, 'ipam': 'on', 'next': 'dashboard'},
                   follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/'
    page = admin.get('/').text
    assert 'What will this LiteBlox run?' not in page
    assert 'Add a network to IPAM' in page and 'BIND node' not in page


def test_an_ipam_only_dashboard(admin, conn):
    switch(conn, dns=False, dhcp=False, ntp=False)
    add_network(conn, '192.0.2.0/24', 'Lab')
    page = admin.get('/').text
    assert 'data-tile="ipam"' in page and 'data-tile="dns"' not in page and 'data-tile="dhcp"' not in page
    assert 'Getting started' not in page and 'href="/zones/new"' not in page


def test_problems_of_off_modules_are_dropped(conn, settings, monkeypatch):
    from liteblox import status
    monkeypatch.setattr(status, '_dhcp_problems', lambda c: [{'severity': 'error', 'area': 'dhcp', 'node': None,
                                                             'link': '/dhcp', 'what': 'x'}])
    monkeypatch.setattr(status, '_ipam_problems', lambda c, now: [{'severity': 'warn', 'area': 'ipam', 'node': None,
                                                                  'link': '/ipam', 'what': 'y'}])
    assert {p['area'] for p in status.problems(conn, settings)} == {'dhcp', 'ipam'}
    switch(conn, dhcp=False)
    assert {p['area'] for p in status.problems(conn, settings)} == {'ipam'}


def test_help_lists_off_module_pages_apart(admin, conn):
    page = admin.get('/help').text
    assert 'Not in use here' not in page
    switch(conn, dns=False, ntp=False)
    page = admin.get('/help').text
    assert 'Not in use here' in page
    used, other = page.split('Not in use here', 1)
    assert 'href="/help/zones"' in other and 'href="/help/ntp"' in other and 'href="/help/zones"' not in used.split('</ul>')[0]
    assert admin.get('/help/zones').status_code == 200 and 'href="/help/ipam"' in used


def test_search_skips_ipam_when_it_is_off(admin, conn, monkeypatch):
    from liteblox.ipam import devices
    called = []
    monkeypatch.setattr(devices, 'matching', lambda *a, **k: called.append(1) or [])
    admin.get('/search?q=printer')
    assert called
    called.clear()
    switch(conn, ipam=False)
    admin.get('/search?q=printer')
    assert not called


def test_the_cli(settings, conn, monkeypatch, capsys):
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    assert cli.main(['modules']) == 0
    out = capsys.readouterr().out
    assert 'DNS   on' in out and 'not chosen yet' in out
    assert cli.main(['modules', '--off', 'dns', 'ntp']) == 0
    assert '✓ modules: DHCP, IPAM' in capsys.readouterr().out
    add_node(conn, dhcp=1)
    assert cli.main(['modules', '--off', 'dhcp']) == 1
    assert 'DHCP: in use: remove 1 node with Kea first' in capsys.readouterr().err
    assert modules.chosen(conn)


def test_in_use_counts_read_well(conn):
    add_node(conn, 'ns1', dhcp=1)
    add_node(conn, 'ns2', dhcp=1)
    assert modules.in_use(conn, 'dhcp') == '2 nodes with Kea' and modules.in_use(conn, 'dns') == '2 BIND nodes'
