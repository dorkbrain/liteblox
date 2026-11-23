"""DHCPv4 subnets, pools, options and served interfaces: validation, rendering, apply, the DHCP tab."""

import json

import pytest

from liteblox import jobs
from liteblox.dhcp import apply as dhcp_apply, store, validate
from liteblox.dhcp.model import Dhcp4Settings, KeaConfig, Subnet, settings as load_settings, subnets as load_subnets
from liteblox.dhcp.render import render
from liteblox.nodes import service as nodes

from conftest import csrf_from
from test_managed import Client, FakeNode, lab  # noqa: F401 (fixtures)

ENS19 = {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24']}
NET = '198.51.100.0/24'


def subnet(**kw):
    return Subnet(**{'id': 1, 'prefix': NET, 'interface': '', 'pools': ['198.51.100.100 - 198.51.100.199'], **kw})


def with_dhcp(conn, *node_ids, serve=()):
    with conn:
        for i in node_ids:
            conn.execute("UPDATE nodes SET dhcp = 1, kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks', "
                         'dhcp_interfaces = ? WHERE id = ?', (json.dumps(list(serve)), i))


# ── validation ─────────────────────────────────────────────────────────────────

def test_a_good_subnet_is_placed_on_its_interface():
    s = subnet(options={'dns': ['198.51.100.53'], 'domain': 'ddns.lab'})
    assert validate.check_subnet(s, [], [ENS19]) == {} and s.interface == 'ens19'


@pytest.mark.parametrize('changes, field, message', [
    ({'prefix': '198.51.100.7/24'}, 'prefix', 'not an IPv4 network'),
    ({'prefix': '2001:db8::/64'}, 'prefix', 'not an IPv4 network'),
    ({'prefix': '203.0.113.0/24', 'pools': ['203.0.113.10 - 203.0.113.20']}, 'prefix', 'no DHCP node has an address'),
    ({'pools': ['198.51.100.200 - 198.51.100.100']}, 'pools', 'first not after last'),
    ({'pools': ['203.0.113.1 - 203.0.113.9']}, 'pools', 'not inside'),
    ({'pools': ['198.51.100.0 - 198.51.100.9']}, 'pools', 'network or broadcast'),
    ({'pools': ['198.51.100.10 - 198.51.100.60']}, 'pools', '198.51.100.53, which is a router or this server'),
    ({'pools': ['198.51.100.10 - 198.51.100.20', '198.51.100.15 - 198.51.100.30']}, 'pools', 'overlap'),
    ({'pools': []}, 'pools', 'at least one pool'),
    ({'options': {'routers': ['198.51.100.150']}}, 'pools', 'router'),
    ({'options': {'dns': ['not-an-ip']}}, 'dns', 'not an IPv4 address'),
    ({'options': {'domain': 'bad domain'}}, 'domain', 'not a domain name'),
    ({'valid_lifetime': 100, 'renew_timer': 200}, 'rebind_timer', 'before the lease ends'),
    ({'renew_timer': 300, 'rebind_timer': 200}, 'renew_timer', 'renew must come before rebind'),
    ({'extra': {'subnet': '10.0.0.0/8'}}, 'extra', "LiteBlox's"),
    ({'extra_options': {'name': 'x'}}, 'extra_options', 'JSON list'),
])
def test_subnet_errors(changes, field, message):
    errors = validate.check_subnet(subnet(**changes), [], [ENS19])
    assert message in errors.get(field, ''), errors


def test_subnets_may_not_overlap():
    other = subnet(id=1, interface='ens19')
    errors = validate.check_subnet(subnet(id=2, prefix='198.51.100.128/25', pools=['198.51.100.130 - 198.51.100.140']),
                                   [other], [ENS19])
    assert 'overlaps subnet 198.51.100.0/24' in errors['prefix']


def test_one_serving_node_and_unknown_interfaces():
    node = {'name': 'ns2'}
    errors = validate.check_interfaces(node, ['ens19'], [ENS19], [{'name': 'ns1'}])
    assert 'ns1 already serves DHCP' in errors['interfaces']
    assert 'eth9: not an interface on ns2' in validate.check_interfaces(node, ['eth9'], [ENS19], [])['interfaces']
    assert validate.check_interfaces(node, [], [ENS19], [{'name': 'ns1'}]) == {}       # serving nothing is fine


def test_the_dev_guard(monkeypatch):
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '198.51.100.0/24, garbage')
    assert 'never serves' in validate.check_interfaces({'name': 'ns1'}, ['ens19'], [ENS19], [])['interfaces']
    assert 'never serves' in validate.check_subnet(subnet(), [], [ENS19])['prefix']
    files = render(KeaConfig(['ens19'], subnets=[subnet(interface='ens19')]))
    with pytest.raises(validate.Invalid, match='refusing to write 198.51.100.0/24'):
        validate.guard_rendered(files)
    monkeypatch.delenv(validate.DEV_NEVER_SERVE)
    validate.guard_rendered(files)


# ── rendering ──────────────────────────────────────────────────────────────────

def test_render_subnets_options_and_lifetimes():
    s = subnet(interface='ens19', options={'dns': ['198.51.100.53', '198.51.100.54'], 'domain': 'ddns.lab'},
               extra_options=[{'name': 'time-offset', 'data': '3600'}], extra={'match-client-id': False},
               valid_lifetime=3600)
    g = Dhcp4Settings(options={'ntp': ['198.51.100.1'], 'search': ['ddns.lab', 'example.com']}, authoritative=True,
                      renew_timer=900, rebind_timer=1800)
    body = json.loads(render(KeaConfig(['ens19'], g, [s]))['kea-dhcp4.conf'])['Dhcp4']
    assert body['interfaces-config']['interfaces'] == ['ens19']
    assert body['authoritative'] is True and body['renew-timer'] == 900 and 'valid-lifetime' not in body
    assert body['option-data'] == [{'name': 'domain-search', 'data': 'ddns.lab, example.com'},
                                   {'name': 'ntp-servers', 'data': '198.51.100.1'}]
    (sub,) = body['subnet4']
    assert sub == {'id': 1, 'subnet': NET, 'interface': 'ens19', 'pools': [{'pool': '198.51.100.100 - 198.51.100.199'}],
                   'option-data': [{'name': 'domain-name-servers', 'data': '198.51.100.53, 198.51.100.54'},
                                   {'name': 'domain-name', 'data': 'ddns.lab'}, {'name': 'time-offset', 'data': '3600'}],
                   'user-context': {'liteblox-subnet': 1}, 'valid-lifetime': 3600, 'match-client-id': False}


def test_only_subnets_on_served_interfaces_render(conn):
    store.save_subnet(conn, subnet(interface='ens19'))
    from liteblox.dhcp.model import for_node
    assert for_node(conn, {'dhcp_interfaces': '["ens19"]'}).subnets[0].prefix == NET
    assert for_node(conn, {'dhcp_interfaces': '[]'}).subnets == []


# ── apply with the DB change ───────────────────────────────────────────────────

def test_apply_saves_the_rows_and_a_failure_restores_them(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1, serve=['ens19'])
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    s = subnet(interface='ens19')
    snap = store.snapshot(conn)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'add', 'admin', print, change=lambda c: store.save_subnet(c, s),
                          undo=lambda c: store.restore(c, snap))
    assert [x.prefix for x in load_subnets(conn)] == [NET]
    assert json.loads(fakes[1].kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]['subnet'] == NET

    # sockets that don't open (an interface gone, say): rolled back, and the row change undone
    fakes[1].kea_sockets = 'failed'
    snap = store.snapshot(conn)
    before = fakes[1].kea_files['kea-dhcp4.conf']
    with pytest.raises(dhcp_apply.DhcpError, match='Kea stopped working'):
        dhcp_apply.apply_dhcp(settings, conn, [1], 'delete', 'admin', print, change=lambda c: store.delete_subnet(c, 1),
                              undo=lambda c: store.restore(c, snap))
    assert [x.prefix for x in load_subnets(conn)] == [NET] and fakes[1].kea_files['kea-dhcp4.conf'] == before


def test_apply_refuses_what_the_dev_guard_forbids(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '192.0.2.0/24')          # ns1's ens18 (its management network)
    snap = store.snapshot(conn)
    with pytest.raises(dhcp_apply.DhcpError, match='never serves'):
        dhcp_apply.apply_dhcp(settings, conn, [1], 'serve', 'admin', print,
                              change=lambda c: store.set_interfaces(c, 1, ['ens18']), undo=lambda c: store.restore(c, snap))
    assert 'stage dhcp' not in fakes[1].calls and nodes.get_node(conn, 1)['dhcp_interfaces'] == '[]'


# ── the DHCP tab ───────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def job_of(conn, r):
    return jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))


def test_overview_and_serving_an_interface(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    page = admin.get('/dhcp').text
    assert '>DHCP</a>' in page and 'value="ens19"' in page and '198.51.100.53/24' in page
    assert page.count('management: LiteBlox reaches the node here') == 1
    t = csrf_from(page)
    review = admin.post('/dhcp/nodes/1/interfaces/preview', data={'csrf_token': t, 'interfaces': 'ens19'},
                        headers={'X-CSRF-Token': t}).text
    assert '&#34;ens19&#34;' in review and 'Serve on ens19' in review and 'check dhcp' in fakes[1].calls
    r = admin.post('/dhcp/nodes/1/interfaces', data={'csrf_token': t, 'interfaces': 'ens19'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    assert nodes.get_node(conn, 1)['dhcp_interfaces'] == '["ens19"]'


def test_subnet_form_review_save_and_delete(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1, serve=['ens19'])
    page = admin.get('/dhcp/subnets/new').text
    t = csrf_from(page)
    form = {'csrf_token': t, 'prefix': NET, 'pools': '198.51.100.100 - 198.51.100.199', 'dns': '198.51.100.53',
            'domain': 'ddns.lab'}
    review = admin.post('/dhcp/subnets/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert '198.51.100.0/24' in review and 'accepts it' in review
    bad = admin.post('/dhcp/subnets/preview', data={**form, 'pools': '10.0.0.1 - 10.0.0.9'}, headers={'X-CSRF-Token': t})
    assert 'not inside' in bad.text
    r = admin.post('/dhcp/subnets', data=form, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    (s,) = load_subnets(conn)
    assert s.interface == 'ens19' and s.options == {'dns': ['198.51.100.53'], 'domain': 'ddns.lab'}
    assert 'Served on <code>ens19</code>' in admin.get(f'/dhcp/subnets/{s.id}/settings').text
    assert f'/dhcp/subnets/{s.id}' in admin.get('/nodes/1/dhcp').text           # the node card lists it

    # changing the subnet keeps its reservations, and so does the review of the change (3.3.4)
    from liteblox.dhcp.model import Reservation
    store.save_reservation(conn, Reservation(None, s.id, 'aa:bb:cc:dd:ee:09', '198.51.100.9', 'printer'))
    assert job_of(conn, admin.post('/dhcp/subnets', data={**form, 'id': str(s.id)}, follow_redirects=False))['status'] == 'ok'
    review = admin.post('/dhcp/subnets/preview', data={**form, 'id': str(s.id), 'valid_lifetime': '7200'},
                        headers={'X-CSRF-Token': t}).text
    assert '7200' in review and 'aa:bb:cc:dd:ee:09' not in review and 'accepts it' in review   # not shown as removed
    r = admin.post('/dhcp/subnets', data={**form, 'id': str(s.id), 'valid_lifetime': '7200'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok'
    (written,) = json.loads(fakes[1].kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4']
    assert [x['ip-address'] for x in written['reservations']] == ['198.51.100.9']

    # a bad form comes back with the fields marked, nothing saved
    r = admin.post('/dhcp/subnets', data={**form, 'id': str(s.id), 'valid_lifetime': 'soon'})
    assert r.status_code == 422 and 'a number of seconds' in r.text
    # delete needs the subnet typed in
    r = admin.post(f'/dhcp/subnets/{s.id}/delete', data={'csrf_token': t, 'confirm': 'nope'}, follow_redirects=False)
    assert 'error=' in r.headers['location'] and load_subnets(conn)
    r = admin.post(f'/dhcp/subnets/{s.id}/delete', data={'csrf_token': t, 'confirm': NET}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok' and load_subnets(conn) == []
    assert json.loads(fakes[1].kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4'] == []


def test_settings_page(admin, conn, settings, lab):  # noqa: F811
    with_dhcp(conn, 1)
    t = csrf_from(admin.get('/dhcp/settings').text)
    r = admin.post('/dhcp/settings', data={'csrf_token': t, 'domain': 'ddns.lab', 'valid_lifetime': '3600',
                                           'authoritative': '1'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok'
    s = load_settings(conn)
    assert s.options == {'domain': 'ddns.lab'} and s.valid_lifetime == 3600 and s.authoritative
    r = admin.post('/dhcp/settings', data={'csrf_token': t, 'renew_timer': '900', 'rebind_timer': '600'})
    assert r.status_code == 422 and 'renew must come before rebind' in r.text


def test_viewers_read_only(client, conn, lab, make_user, login):  # noqa: F811
    with_dhcp(conn, 1)
    login(*make_user('viewer', 'viewer-password', 'readonly'))
    page = client.get('/dhcp').text
    assert 'Add subnet' not in page and '/interfaces/preview' not in page and 'Change interfaces' not in page
    assert 'serves nothing yet' in page
    t = csrf_from(page)
    assert client.post('/dhcp/settings', data={'csrf_token': t}).status_code == 403


# ── a subnet prepared before its interface is served ───────────────────────────

def test_a_subnet_may_wait_on_an_interface_not_served_yet():
    s = subnet()
    assert validate.check_subnet(s, [], [], [ENS19]) == {} and s.interface == 'ens19'
    other = {'name': 'ens20', 'up': True, 'addresses': ['198.51.100.54/24']}
    errors = validate.check_subnet(subnet(), [], [], [ENS19, other])
    assert 'ens19, ens20' in errors['prefix'] and 'tick the one' in errors['prefix']
    # a served interface wins over one that isn't
    s = subnet()
    assert validate.check_subnet(s, [], [other], [ENS19]) == {} and s.interface == 'ens20'
    # the node's own address on the waiting interface still keeps out of the pools
    assert 'this server' in validate.check_subnet(subnet(pools=['198.51.100.50 - 198.51.100.60']), [], [],
                                                  [ENS19])['pools']


def test_prepare_a_subnet_then_serve_it(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    dhcp_apply.record_commit(conn, 1, dhcp_apply.files_for(conn, nodes.get_node(conn, 1)))   # as set up left it
    assert '/dhcp/subnets/new' in admin.get('/dhcp').text                  # offered before anything is served
    page = admin.get('/dhcp/subnets/new').text
    t = csrf_from(page)
    form = {'csrf_token': t, 'prefix': NET, 'pools': '198.51.100.100 - 198.51.100.199'}
    review = admin.post('/dhcp/subnets/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert "isn&#39;t served yet" in review and 'tick ens19' in review and 'Save (not served yet)' in review
    r = admin.post('/dhcp/subnets', data=form, follow_redirects=False)
    job = job_of(conn, r)
    assert job['status'] == 'ok' and 'unchanged: nothing written' in job['log'], job['log']
    assert "Saved; no node's Kea config changed" in job['log'] and 'stage dhcp' not in fakes[1].calls
    (s,) = load_subnets(conn)
    assert s.interface == 'ens19'
    assert 'not served' in admin.get('/dhcp').text

    # a reservation in it is saved the same way, without touching Kea
    form = {'csrf_token': t, 'hw_address': 'aa:bb:cc:00:00:01', 'ip_address': '198.51.100.60', 'hostname': 'printer'}
    review = admin.post(f'/dhcp/subnets/{s.id}/reservations/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'Save (not served yet)' in review
    r = admin.post(f'/dhcp/subnets/{s.id}/reservations', data=form, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok' and 'stage dhcp' not in fakes[1].calls

    # ticking the interface says what starts, and Kea gets the subnet and its reservation
    review = admin.post('/dhcp/nodes/1/interfaces/preview', data={'csrf_token': t, 'interfaces': 'ens19'},
                        headers={'X-CSRF-Token': t}).text
    assert 'Kea starts answering for 198.51.100.0/24 on ens19' in review and '1 reservation)' in review
    r = admin.post('/dhcp/nodes/1/interfaces', data={'csrf_token': t, 'interfaces': 'ens19'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok'
    (rendered,) = json.loads(fakes[1].kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4']
    assert rendered['subnet'] == NET and rendered['reservations'][0]['hw-address'] == 'aa:bb:cc:00:00:01'


def test_unchanged_nodes_are_skipped_but_a_rewrite_writes(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1, serve=['ens19'])
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    assert dhcp_apply.apply_dhcp(settings, conn, [1], 'first', 'admin', print, skip_unchanged=True) == ['ns1']
    fakes[1].calls.clear()
    lines = []
    assert dhcp_apply.apply_dhcp(settings, conn, [1], 'again', 'admin', lines.append, skip_unchanged=True) == []
    assert fakes[1].calls == [] and '  unchanged: nothing written' in lines
    # drift on the node: written even though LiteBlox's own config is the same
    with conn:
        conn.execute("UPDATE nodes SET dhcp_drift = '[\"kea-dhcp4.conf\"]' WHERE id = 1")
    assert dhcp_apply.apply_dhcp(settings, conn, [1], 'drift', 'admin', print, skip_unchanged=True) == ['ns1']
    fakes[1].calls.clear()
    job = dhcp_apply.start_rewrite(settings, 1, 'admin', background=False)
    assert 'stage dhcp' in fakes[1].calls and jobs.get(conn, job)['status'] == 'ok'
