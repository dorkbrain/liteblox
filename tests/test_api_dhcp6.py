"""IPv6 through the API, lbcli and CSV (6.0 M6): DHCPv6 subnets, leases, reservations (jobs) and lease deletes;
IPAM's IPv6 networks; Search's DHCPv6 fields."""

import json

import pytest

from liteblox import jobs
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation6, Subnet6
from liteblox.ipam import model as ipam_model

from test_api_zones import api  # noqa: F401 (fixture)
from test_ipam_free import lbcli
from test_managed import FakeNode, lab  # noqa: F401 (fixtures)

LAB = 'fd00:1:2:100::/64'
IFACES = [{'name': 'ens18', 'up': True, 'addresses': ['192.0.2.53/24', 'fe80::1/64']},
          {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24', 'fe80::2/64', 'fd00:1:2:100::213/64']}]


def lease6(ip, duid='00:01:00:01:aa:01', kind='IA_NA', length=128, **kw):
    return {'ip-address': ip, 'duid': duid, 'iaid': 1, 'type': kind, 'prefix-len': length, 'subnet-id': 1,
            'state': 0, 'cltt': 1_000_000_000, 'valid-lft': 3600, 'hostname': kw.pop('hostname', ''),
            'fqdn-fwd': kw.pop('fwd', False), **kw}


@pytest.fixture
def v6(api, conn, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    real_status = FakeNode.status
    monkeypatch.setattr(FakeNode, 'status', lambda self: dict(real_status(self), interfaces=IFACES))
    for f in fakes.values():
        f.kea_running['dhcp6'] = True
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp6 = 1, kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks', "
                     "dhcp_interfaces = '[\"ens19\"]' WHERE id = 1")
    store.save_subnet6(conn, Subnet6(1, LAB, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'],
                                     pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}],
                                     comment='lab'))
    store.save_reservation6(conn, Reservation6(None, 1, duid='00:01:00:01:aa:50', ip_address='fd00:1:2:100::50',
                                               hostname='printer'))
    return fakes


def job(api, r):
    assert r.status_code == 202, r.text
    return api.get(f"/api/v1/jobs/{r.json()['job']}").json()


def test_servers_settings_and_subnets(api, v6):
    d = api.get('/api/v1/dhcp6').json()
    assert d['servers'] == [{'node': 'ns1', 'runs_dhcp6': True, 'ha_state': None}] and d['port6'] is None
    assert set(d['settings']) >= {'preferred_lifetime', 'valid_lifetime', 'options'}
    (s,) = api.get('/api/v1/dhcp6/subnets').json()
    assert (s['prefix'], s['interface'], s['comment'], s['ra']) == (LAB, 'ens19', 'lab', False)
    assert s['pd_pools'] == [{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}]
    assert s['reservations'][0]['duid'] == '00:01:00:01:aa:50' and s['reservations'][0]['hostname'] == 'printer'
    assert api.get('/api/v1/dhcp6/subnets/1').json()['pools'] == ['fd00:1:2:100::1000 - fd00:1:2:100::1fff']
    assert api.get('/api/v1/dhcp6/subnets/9').status_code == 404


def test_leases(api, v6):
    v6[1].kea_leases6 = [lease6('fd00:1:2:100::1003', hostname='pc1.ddns.lab.', fwd=True),
                         lease6('fd00:1:2:100::50', duid='00:01:00:01:aa:50'),
                         lease6('fd00:1:2:f010::', duid='00:01:00:01:aa:60', kind='IA_PD', length=60)]
    got = api.get('/api/v1/dhcp6/leases').json()
    assert got['read_from'] == 'ns1' and got['errors'] == []
    assert [(x['ip'], x['type'], x['prefix'], x['reserved']) for x in got['leases']] == [
        ('fd00:1:2:100::50', 'address', '', True), ('fd00:1:2:100::1003', 'address', '', False),
        ('fd00:1:2:f010::', 'prefix', 'fd00:1:2:f010::/60', False)]
    pc = got['leases'][1]
    assert pc['hostname'] == 'pc1.ddns.lab' and pc['registered'] and pc['expires'].endswith('+00:00')
    assert api.get('/api/v1/dhcp6/leases?subnet=2').json()['leases'] == []


def test_reservations_are_jobs(api, conn, v6):
    r = api.post('/api/v1/dhcp6/subnets/1/reservations',
                 json={'duid': '00-01-00-01-BB-01', 'ip_address': 'fd00:1:2:100::51', 'prefix': 'fd00:1:2:f020::/60',
                       'hostname': 'Router2'})
    done = job(api, r)
    assert done['status'] == 'ok', done['log']
    sub = json.loads(v6[1].kea_files['kea-dhcp6.conf'])['Dhcp6']['subnet6'][0]
    assert {'duid': '00:01:00:01:bb:01', 'ip-addresses': ['fd00:1:2:100::51'], 'prefixes': ['fd00:1:2:f020::/60'],
            'hostname': 'router2'} in sub['reservations']
    added = next(x for x in api.get('/api/v1/dhcp6/subnets/1').json()['reservations'] if x['duid'] == '00:01:00:01:bb:01')
    assert '(token ci)' in conn.execute("SELECT detail FROM audit WHERE action = 'dhcp_apply' ORDER BY id DESC").fetchone()[0]

    assert job(api, api.patch(f"/api/v1/dhcp6/subnets/1/reservations/{added['id']}",
                              json={'hostname': 'router3', 'prefix': ''}))['status'] == 'ok'
    changed = next(x for x in api.get('/api/v1/dhcp6/subnets/1').json()['reservations'] if x['id'] == added['id'])
    assert (changed['hostname'], changed['prefix'], changed['ip_address']) == ('router3', '', 'fd00:1:2:100::51')
    assert job(api, api.delete(f"/api/v1/dhcp6/subnets/1/reservations/{added['id']}"))['status'] == 'ok'
    assert 'bb:01' not in str(api.get('/api/v1/dhcp6/subnets/1').json()['reservations'])
    assert api.delete('/api/v1/dhcp6/subnets/1/reservations/999').status_code == 404


def test_reservation_errors(api, v6):
    r = api.post('/api/v1/dhcp6/subnets/1/reservations', json={'duid': 'nope', 'ip_address': '192.0.2.9'})
    assert r.status_code == 422
    errors = r.json()['errors']
    assert errors['duid'] and 'not an IPv6 address' in errors['ip_address']
    r = api.post('/api/v1/dhcp6/subnets/1/reservations', json={'duid': '00:01:00:01:cc:01',
                                                                 'ip_address': 'fd00:1:2:100::50'})
    assert r.status_code == 422 and 'already reserved' in r.json()['errors']['ip_address']


def test_lease_deletes(api, conn, v6):
    v6[1].kea_leases6 = [lease6('fd00:1:2:100::1003'),
                         lease6('fd00:1:2:f010::', kind='IA_PD', length=60)]
    r = api.delete('/api/v1/dhcp6/leases/fd00:1:2:f010::/60')
    assert r.json() == {'ip': 'fd00:1:2:f010::/60', 'type': 'prefix', 'node': 'ns1', 'partner': None}
    assert ('lease6-del', {'ip-address': 'fd00:1:2:f010::', 'type': 'IA_PD', 'update-ddns': True}) in v6[1].kea_commands
    assert api.delete('/api/v1/dhcp6/leases/fd00:1:2:100::1003').json()['type'] == 'address'
    assert v6[1].kea_leases6 == []
    assert api.delete('/api/v1/dhcp6/leases/fd00:1:2:100::1003').status_code == 404
    assert conn.execute("SELECT detail FROM audit WHERE action = 'dhcp_lease_delete'").fetchone()[0].endswith('(token ci)')


def test_writes_need_a_full_admin_token(api, v6):
    v6[1].kea_leases6 = [lease6('fd00:1:2:100::1003')]
    calls = [('post', '/api/v1/dhcp6/subnets/1/reservations', {'duid': '00:01:00:01:cc:02'}),
             ('patch', '/api/v1/dhcp6/subnets/1/reservations/1', {'hostname': 'x'}),
             ('delete', '/api/v1/dhcp6/subnets/1/reservations/1', None),
             ('delete', '/api/v1/dhcp6/leases/fd00:1:2:100::1003', None)]
    for headers in (api.read, api.viewer):
        for method, url, body in calls:
            kw = {'json': body} if body is not None else {}
            assert api.request(method, url, headers=headers, **kw).status_code == 403, (method, url)
    assert v6[1].kea_leases6 and api.get('/api/v1/dhcp6/leases', headers=api.read).status_code == 200


def test_search_tells_the_families_apart(api, v6):
    v6[1].kea_leases6 = [lease6('fd00:1:2:100::50', duid='00:01:00:01:aa:50')]
    d = api.get('/api/v1/search', params={'q': '00:01:00:01:aa:50'}).json()
    (r,) = d['reservations']['items']
    assert (r['family'], r['duid'], r['ip'], r['subnet_id']) == (6, '00:01:00:01:aa:50', 'fd00:1:2:100::50', 1)
    a = api.get('/api/v1/search', params={'q': 'fd00:1:2:100::50'}).json()['address']
    assert a['subnet'] == LAB and a['reservation']['duid'] == '00:01:00:01:aa:50'
    assert a['lease']['family'] == 6 and a['lease']['type'] == 'address'
    assert api.get('/api/v1/search', params={'q': LAB}).json()['subnets']['items'][0]['family'] == 6


def test_ipam_api_takes_ipv6(api, conn, v6):
    r = api.post('/api/v1/ipam/networks', json={'prefix': 'fd00:1:2::/48', 'name': 'lab v6'})
    assert r.status_code == 201, r.text
    leaf = api.post('/api/v1/ipam/networks', json={'prefix': LAB}).json()
    found = {n['prefix']: n for n in api.get('/api/v1/ipam/networks').json()}
    assert found[LAB]['used'] == 1 and found[LAB]['parent'] == r.json()['id']          # the reservation's address
    assert found['fd00:1:2::/48']['container'] and found['fd00:1:2::/48']['used'] is None
    page = api.get(f"/api/v1/ipam/networks/{leaf['id']}/addresses").json()
    assert page['pages'] == 1 and [(x['ip'], x['state']) for x in page['items']] == [('fd00:1:2:100::50', 'reserved')]
    assert api.get(f"/api/v1/ipam/networks/{leaf['id']}/addresses?page=1").status_code == 404
    detail = api.get(f"/api/v1/ipam/networks/{leaf['id']}").json()
    assert [x['kind'] for x in detail['ranges']] == ['dhcp']
    r = api.post('/api/v1/ipam/next-free', json={'network': LAB})
    assert r.status_code == 422 and 'IPv6 has no next free' in r.json()['detail']
    r = api.post('/api/v1/ipam/assign', json={'ip': 'fd00:1:2:100::60', 'name': 'x', 'zone': 'lab.example'})
    assert r.status_code == 422 and 'assign takes IPv4 addresses' in r.json()['detail']
    assert api.put('/api/v1/ipam/names/fd00:1:2:100::60', json={'name': 'nas'}).status_code == 200
    assert api.put('/api/v1/ipam/names/192.0.2.60', json={'name': 'nas4'}).status_code == 200
    assert [n['ip'] for n in api.get('/api/v1/ipam/names').json()] == ['192.0.2.60', 'fd00:1:2:100::60']
    assert [n['ip'] for n in api.get('/api/v1/ipam/names', params={'network': LAB}).json()] == ['fd00:1:2:100::60']
    with conn:
        conn.execute("INSERT INTO ipam_seen (ip, mac, first_seen, last_seen, node_id, source) "
                     "VALUES ('fd00:1:2:100::77', 'aa:bb:cc:00:00:77', 1, 2, 1, 'neigh')")
    assert [s['ip'] for s in api.get('/api/v1/ipam/seen', params={'network': LAB}).json()] == ['fd00:1:2:100::77']
    assert api.delete('/api/v1/ipam/seen/fd00:1:2:100::77').status_code == 204
    assert ipam_model.networks(conn)


def test_csv_and_the_dhcp_page(api, client, make_user, login, v6):
    v6[1].kea_leases6 = [lease6('fd00:1:2:100::1003', hostname='pc1'),
                         lease6('fd00:1:2:f010::', kind='IA_PD', length=60)]
    del client.headers['Authorization']
    login(*make_user('carol', 'correct-horse', 'readonly'))
    text = client.get('/dhcp/v6/leases.csv').text
    lines = text.strip().splitlines()
    assert lines[0].startswith('subnet,address_or_prefix,kind')
    assert any('fd00:1:2:100::1003' in x and 'pc1' in x for x in lines)
    assert any('fd00:1:2:f010::/60,prefix' in x for x in lines) and any('fd00:1:2:100::50' in x for x in lines)
    page = client.get('/dhcp').text
    assert '<title>DHCP · LiteBlox</title>' in page and page.count('id="v6"') == 1 and '/dhcp/v6/leases.csv' in page


def test_lbcli_show_an_ipv6_address(api, conn, v6, monkeypatch, capsys):
    from liteblox.api import tokens as tok
    monkeypatch.setenv('LITEBLOX_URL', 'http://lb')
    monkeypatch.setenv('LITEBLOX_TOKEN', tok.create(conn, 'alice', 'cli', 'read', 'test')[1])
    auth = api.headers.pop('Authorization')
    try:
        cli = lbcli(api, monkeypatch)
        assert cli.main(['show', 'fd00:1:2:100::50']) == 0
        out = capsys.readouterr().out
        assert 'fd00:1:2:100::50' in out and 'duid 00:01:00:01:aa:50 printer' in out and LAB in out
    finally:
        api.headers['Authorization'] = auth
