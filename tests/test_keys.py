"""TSIG keys: one-time reveal, grants into the dynamic zone's update-policy, rotate, delete, CLI."""

import re

import pytest

from liteblox import jobs, keys
from liteblox.bindconf import apply
from liteblox.dns import declare

from conftest import csrf_from
from test_dynamic import FORWARD, dyn, server, zone_row  # noqa: F401 (fixtures)
from test_managed import lab, ok_verify  # noqa: F401 (fixtures)


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    monkeypatch.setattr(apply, '_served', lambda host, zone: True)
    monkeypatch.setattr(apply, 'recursive_ok', lambda host: True)


@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def post(client, url, **data):
    t = csrf_from(client.get('/settings/keys').text)
    return client.post(url, data={'csrf_token': t, **data}, follow_redirects=False)


def job_ok(conn, r):
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    return job


def secret_of(conn, name):
    return conn.execute('SELECT secret FROM tsig_keys WHERE name = ?', (name,)).fetchone()[0]


def test_a_new_key_is_shown_once(admin, conn, settings, dyn):
    fakes, _ = dyn
    r = post(admin, '/settings/keys', name='dhcp', algorithm='hmac-sha256')
    reveal = r.headers['location']
    assert reveal.startswith('/settings/keys/reveal/')
    secret = secret_of(conn, 'dhcp')
    assert 'key "dhcp"' in fakes[1].config_files['keys.conf'] and secret in fakes[2].config_files['keys.conf']
    assert secret in admin.get(reveal).text
    download = admin.get(reveal + '/download')
    assert download.headers['content-disposition'] == 'attachment; filename="dhcp.key"' and secret in download.text
    assert secret not in admin.get('/settings/keys').text                 # the list never shows it
    admin.post(reveal + '/done', data={'csrf_token': csrf_from(admin.get('/settings/keys').text)})
    assert admin.get(reveal).status_code == 404 and admin.get(reveal + '/download').status_code == 404


def test_names_and_internal_keys(admin, conn, settings, dyn):
    for name, error in (('liteblox', "LiteBlox&#39;s own key"), ('bad name', 'letters, digits'),
                        ('', 'letters, digits')):
        r = post(admin, '/settings/keys', name=name)
        assert r.status_code == 422 and error in r.text
    post(admin, '/settings/keys', name='dhcp')
    assert 'already a key named dhcp' in post(admin, '/settings/keys', name='dhcp').text
    assert post(admin, '/settings/keys/liteblox/rotate').status_code == 404
    with pytest.raises(keys.KeyProblem, match='own key'):
        keys.delete(settings, 'liteblox-xfr', 'admin', print)


def test_only_the_creator_sees_the_reveal(admin, client, conn, make_user, login, dyn):
    reveal = post(admin, '/settings/keys', name='dhcp').headers['location']
    login(*make_user('other', 'other-password-1', 'admin'))
    assert client.get(reveal).status_code == 404


def test_grants_go_into_the_policy_while_the_zone_is_dynamic(admin, conn, settings, dyn):
    fakes, _ = dyn
    declare.create_zone(settings, 'static.lab', ['1', '2'], FORWARD.replace('dyn.lab', 'static.lab'), 'admin',
                        print, verify=ok_verify)
    post(admin, '/settings/keys', name='dhcp')
    post(admin, '/settings/keys', name='acme')
    job_ok(conn, post(admin, '/settings/keys/dhcp/grants', zone='dyn.lab', scope='zonesub', types='a aaaa,DHCID'))
    job_ok(conn, post(admin, '/settings/keys/acme/grants', zone='dyn.lab', scope='name',
                      owner='_acme-challenge.dyn.lab.', types='TXT'))
    job_ok(conn, post(admin, '/settings/keys/acme/grants', zone='static.lab', scope='zonesub', types=''))
    zones = fakes[1].zones_conf
    policy = re.search(r'zone "dyn.lab" \{.*?update-policy \{(.*?)\};', zones, re.S).group(1)
    assert [g.strip() for g in policy.split(';') if g.strip()] == [
        'grant liteblox zonesub ANY', 'grant acme name _acme-challenge.dyn.lab. TXT', 'grant dhcp zonesub A AAAA DHCID']
    assert 'update-policy' not in re.search(r'zone "static.lab" \{.*?\};\n', zones, re.S).group(0)
    assert 'update-policy' not in fakes[2].zones_conf                    # the secondary takes no updates
    page = admin.get('/settings/keys').text
    assert 'only _acme-challenge.dyn.lab' in page and 'inactive' in page

    for zone, scope, owner, types, error in (
            ('nope.lab', 'zonesub', '', 'A', 'no zone nope.lab'),
            ('dyn.lab', 'name', 'x.other.lab', 'A', 'must be inside dyn.lab'),
            ('dyn.lab', 'subdomain', '', 'A', 'must be inside'),
            ('dyn.lab', 'zonesub', '', 'A BOGUS', 'BOGUS is not a record type'),
            ('dyn.lab', 'everything', '', 'A', 'the scope is')):
        r = post(admin, '/settings/keys/dhcp/grants', zone=zone, scope=scope, owner=owner, types=types)
        assert error in admin.get(r.headers['location']).text

    g = conn.execute("SELECT g.id FROM key_grants g JOIN tsig_keys k ON k.id = g.key_id WHERE k.name = 'dhcp'").fetchone()
    job_ok(conn, post(admin, f"/settings/keys/grants/{g['id']}/revoke"))
    assert 'grant dhcp' not in fakes[1].zones_conf


def test_rotate_and_delete(admin, conn, settings, dyn):
    fakes, _ = dyn
    post(admin, '/settings/keys', name='dhcp')
    job_ok(conn, post(admin, '/settings/keys/dhcp/grants', zone='dyn.lab', scope='zonesub', types='A'))
    old = secret_of(conn, 'dhcp')
    reveal = post(admin, '/settings/keys/dhcp/rotate').headers['location']
    new = secret_of(conn, 'dhcp')
    assert new != old and new in admin.get(reveal).text
    assert new in fakes[1].config_files['keys.conf'] and old not in fakes[1].config_files['keys.conf']

    with conn:
        conn.execute("UPDATE zones SET allow_transfer = 'key dhcp' WHERE name = 'dyn.lab'")
    r = post(admin, '/settings/keys/dhcp/delete')
    assert 'still used by zone dyn.lab' in admin.get(r.headers['location']).text
    with conn:
        conn.execute("UPDATE zones SET allow_transfer = '' WHERE name = 'dyn.lab'")
    job_ok(conn, post(admin, '/settings/keys/dhcp/delete'))
    assert conn.execute('SELECT COUNT(*) FROM key_grants').fetchone()[0] == 0
    assert 'dhcp' not in fakes[1].config_files['keys.conf'] and 'grant dhcp' not in fakes[1].zones_conf


def test_a_failed_apply_leaves_the_key_out(admin, conn, settings, dyn):
    fakes, _ = dyn
    fakes[1].fail_commit = True                 # the primary goes last: ns2 is rolled back
    post(admin, '/settings/keys', name='dhcp')
    assert conn.execute("SELECT 1 FROM tsig_keys WHERE name = 'dhcp'").fetchone() is None
    assert all('dhcp' not in f.config_files['keys.conf'] for f in fakes.values())


def test_readonly_users_see_no_keys(client, make_user, login, dyn):
    login(*make_user('viewer', 'viewer-password-1', 'readonly'))
    assert client.get('/settings/keys').status_code == 403


def test_cli(app, conn, settings, dyn, monkeypatch, capsys):
    from liteblox import cli
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    assert cli.main(['key', 'add', 'dhcp']) == 0
    out = capsys.readouterr().out
    assert 'shown only now' in out and secret_of(conn, 'dhcp') in out
    assert cli.main(['key', 'grant', 'dhcp', 'dyn.lab', 'zonesub', 'A', 'AAAA']) == 0
    assert cli.main(['key', 'list']) == 0
    out = capsys.readouterr().out
    assert 'dyn.lab: zonesub  A AAAA' in out and secret_of(conn, 'dhcp') not in out
    assert cli.main(['key', 'grant', 'dhcp', 'nope.lab', 'zonesub', 'A']) == 1
    grant_id = conn.execute('SELECT id FROM key_grants').fetchone()[0]
    assert cli.main(['key', 'revoke', str(grant_id)]) == 0
    assert cli.main(['key', 'delete', 'dhcp']) == 0
    assert conn.execute("SELECT 1 FROM tsig_keys WHERE name = 'dhcp'").fetchone() is None
