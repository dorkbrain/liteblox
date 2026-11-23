"""Reservations and the leases view."""

import json
import re

import pytest

from liteblox import jobs
from liteblox.dhcp import leases as lease_mod, store, validate
from liteblox.dhcp.model import KeaConfig, Reservation, Subnet, subnets as load_subnets
from liteblox.dhcp.render import render

from conftest import csrf_from
from test_managed import Client, FakeNode, lab  # noqa: F401 (fixtures)

ENS19 = {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24']}
NET = '198.51.100.0/24'
MAC = 'bc:24:11:6c:51:d8'


def subnet(**kw):
    return Subnet(**{'id': 1, 'prefix': NET, 'interface': 'ens19', 'pools': ['198.51.100.100 - 198.51.100.199'], **kw})


def lease(ip, mac=MAC, hostname='lab-client.dyn.lab.', subnet_id=1, **kw):
    return {'ip-address': ip, 'hw-address': mac, 'hostname': hostname, 'subnet-id': subnet_id, 'cltt': 1000,
            'valid-lft': 3600, 'state': 0, 'fqdn-fwd': True, **kw}


@pytest.mark.parametrize('text, want', [('AA-BB-CC-DD-EE-FF', 'aa:bb:cc:dd:ee:ff'), ('aabb.ccdd.eeff', 'aa:bb:cc:dd:ee:ff'),
                                        ('aabbccddeeff', 'aa:bb:cc:dd:ee:ff'), ('aa:bb:cc', None), ('zz:bb:cc:dd:ee:ff', None)])
def test_mac_formats(text, want):
    assert validate.normalize_mac(text) == want


@pytest.mark.parametrize('changes, field, message', [
    ({'hw_address': 'nope'}, 'hw_address', 'not a MAC address'),
    ({'ip_address': '203.0.113.5'}, 'ip_address', 'not in 198.51.100.0/24'),
    ({'ip_address': '198.51.100.255'}, 'ip_address', 'broadcast'),
    ({'ip_address': '198.51.100.53'}, 'ip_address', "DHCP server's own address"),
    ({'ip_address': 'x'}, 'ip_address', 'not an IPv4 address'),
    ({'hostname': 'two.labels'}, 'hostname', 'one name'),
])
def test_reservation_errors(changes, field, message):
    r = Reservation(None, 1, **{'hw_address': MAC, 'ip_address': '198.51.100.50', **changes})
    errors, _ = validate.check_reservation(r, subnet(), [ENS19])
    assert message in errors.get(field, ''), errors


def test_duplicates_and_the_pool_warning():
    s = subnet(reservations=[Reservation(7, 1, MAC, '198.51.100.40')])
    errors, _ = validate.check_reservation(Reservation(None, 1, MAC.upper(), '198.51.100.41'), s, [ENS19])
    assert 'already has a reservation here' in errors['hw_address']
    errors, _ = validate.check_reservation(Reservation(None, 1, 'aa:bb:cc:dd:ee:ff', '198.51.100.40'), s, [ENS19])
    assert 'already reserved' in errors['ip_address']
    # Kea serves a reservation inside a pool: no warning, unless the subnet turned that off
    errors, warnings = validate.check_reservation(Reservation(7, 1, MAC, '198.51.100.150', 'Printer'), s, [ENS19])
    assert errors == {} and warnings == []
    s.extra = {'reservations-out-of-pool': True}
    errors, warnings = validate.check_reservation(Reservation(7, 1, MAC, '198.51.100.150', 'Printer'), s, [ENS19])
    assert errors == {} and 'reservations-out-of-pool' in warnings[0]


def test_render_reservations_sorted():
    s = subnet(reservations=[Reservation(1, 1, MAC, '198.51.100.60', 'printer', {'dns': ['198.51.100.53']}),
                             Reservation(2, 1, 'aa:bb:cc:dd:ee:ff', '198.51.100.9')])
    sub = json.loads(render(KeaConfig(['ens19'], subnets=[s]))['kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]
    assert sub['reservations'] == [
        {'hw-address': 'aa:bb:cc:dd:ee:ff', 'ip-address': '198.51.100.9'},
        {'hw-address': MAC, 'ip-address': '198.51.100.60', 'hostname': 'printer',
         'option-data': [{'name': 'domain-name-servers', 'data': '198.51.100.53'}]}]


def test_store_and_undo(conn):
    store.save_subnet(conn, subnet())
    snap = store.snapshot(conn)
    store.save_reservation(conn, Reservation(None, 1, MAC, '198.51.100.50', 'printer'))
    assert [r.ip_address for r in load_subnets(conn)[0].reservations] == ['198.51.100.50']
    store.restore(conn, snap)
    assert load_subnets(conn)[0].reservations == []


def serve(conn):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp_interfaces = '[\"ens19\"]', "
                     "kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks' WHERE id = 1")
    store.save_subnet(conn, subnet())


def test_leases_paging_and_delete(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    serve(conn)
    monkeypatch.setattr(lease_mod, 'PAGE', 2)
    fakes[1].kea_leases = [lease(f'198.51.100.{i}', mac=f'aa:bb:cc:dd:ee:{i:02x}') for i in (120, 101, 105, 110, 130)]
    from liteblox.nodes import service as nodes
    rows = lease_mod.leases(settings, nodes.get_node(conn, 1), now=1000)
    assert [r['ip'] for r in rows] == ['198.51.100.101', '198.51.100.105', '198.51.100.110', '198.51.100.120',
                                       '198.51.100.130']
    assert rows[0]['hostname'] == 'lab-client.dyn.lab' and rows[0]['expires_in'] == 3600 and rows[0]['state'] == 'active'
    lease_mod.delete(settings, nodes.get_node(conn, 1), '198.51.100.105')
    assert ('lease4-del', {'ip-address': '198.51.100.105', 'update-ddns': True}) in fakes[1].kea_commands
    with pytest.raises(lease_mod.LeaseError, match='not found'):
        lease_mod.delete(settings, nodes.get_node(conn, 1), '198.51.100.105')


# ── leases and reservations merged ─────────────────────────────────────────────

def test_addresses_merge_every_state():
    s = subnet(reservations=[Reservation(1, 1, MAC, '198.51.100.20', 'printer'),            # online
                             Reservation(2, 1, 'aa:bb:cc:00:00:02', '198.51.100.21'),        # offline
                             Reservation(3, 1, 'aa:bb:cc:00:00:03', '198.51.100.150')])     # in a pool, taken
    rows = [lease_mod._lease(x, 2000) for x in (
        lease('198.51.100.20'),
        lease('198.51.100.150', mac='aa:bb:cc:00:00:09'),
        lease('198.51.100.120', mac='aa:bb:cc:00:00:04'),                                     # leased
        lease('198.51.100.30', mac='aa:bb:cc:00:00:05'),                                      # outside the pools
        lease('198.51.100.121', mac='aa:bb:cc:00:00:06', state=2),                            # expired
        lease('198.51.100.21', mac='aa:bb:cc:00:00:02', state=2),                             # the reservation's, ended
        lease('203.0.113.5', subnet_id=2))]                                                   # another subnet
    got = {a['ip']: (a['state'], a['label']) for a in lease_mod.addresses(s, rows)}
    assert got == {'198.51.100.20': ('online', 'reserved, online'),
                   '198.51.100.21': ('offline', 'reserved, offline'),
                   '198.51.100.30': ('outside', 'leased outside the pools'),
                   '198.51.100.120': ('leased', 'leased'),
                   '198.51.100.121': ('expired-reclaimed', 'expired-reclaimed'),
                   '198.51.100.150': ('taken', 'reserved, held by another client')}
    assert list(got) == sorted(got, key=lambda ip: int(ip.rsplit('.', 1)[1]))           # by address
    first = lease_mod.addresses(s, rows)[0]
    assert first['hostname'] == 'printer' and first['lease']['mac'] == MAC              # the reservation's name wins


def test_an_active_lease_wins_over_an_old_one_on_the_same_address():
    rows = [lease_mod._lease(x, 2000) for x in (lease('198.51.100.120', state=2),
                                                lease('198.51.100.120', mac='aa:bb:cc:00:00:04'))]
    (a,) = lease_mod.addresses(subnet(), rows)
    assert a['state'] == 'leased' and a['mac'] == 'aa:bb:cc:00:00:04'


def test_declined_addresses_are_counted_apart_and_taken_in_the_pools(conn):
    s = subnet(reservations=[Reservation(1, 1, MAC, '198.51.100.20', 'printer')])
    found = [lease_mod._lease(x, 2000) for x in (
        lease('198.51.100.20'),                                                               # outside the pools
        lease('198.51.100.120', mac='aa:bb:cc:00:00:04'),
        lease('198.51.100.121', mac='', hostname='', state=1),                               # declined: no MAC
        lease('198.51.100.122', mac='aa:bb:cc:00:00:06', state=2))]
    rows = lease_mod.addresses(s, found)
    declined = next(a for a in rows if a['ip'] == '198.51.100.121')
    assert (declined['state'], declined['label'], declined['pill']) == ('declined', 'declined', 'warn')
    assert lease_mod.tally(rows) == [(2, 'active'), (1, 'declined'), (1, 'expired-reclaimed'), (1, 'reservation')]
    assert lease_mod.tally([]) == [(0, 'active'), (0, 'reservations')]
    store.save_subnet(conn, s)
    use = lease_mod.pool_use(conn, [(None, x) for x in found])[s.id]
    assert use == {'active': 2, 'in_pool': 2, 'outside': 1, 'size': use['size']}       # .120 and the declined .121


# ── pages ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def test_leases_page_reserve_and_delete(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    serve(conn)
    fakes[1].kea_leases = [lease('198.51.100.101'), lease('198.51.100.102', mac='aa:bb:cc:dd:ee:ff', hostname='')]
    page = admin.get('/dhcp/leases').text
    assert 'data-search="198.51.100.101 bc:24:11:6c:51:d8 lab-client.dyn.lab leased' in page and 'id="address-filter"' in page
    assert '/dhcp/subnets/1/reservations/new?mac=bc%3A24%3A11%3A6c%3A51%3Ad8&ip=198.51.100.101' in page
    assert '2 active · 0 reservations' in page and '>2</a>' in admin.get('/dhcp').text   # the overview's count
    form = admin.get('/dhcp/subnets/1/reservations/new?mac=bc:24:11:6c:51:d8&ip=198.51.100.101&hostname=lab-client.dyn.lab').text
    assert 'value="bc:24:11:6c:51:d8"' in form and 'value="lab-client"' in form
    t = csrf_from(page)
    r = admin.post('/dhcp/leases/delete', data={'csrf_token': t, 'ip': '198.51.100.102', 'node_id': '1'},
                   follow_redirects=False)
    assert 'Deleted+the+lease' in r.headers['location'] or 'Deleted%20the%20lease' in r.headers['location']
    assert [x['ip-address'] for x in fakes[1].kea_leases] == ['198.51.100.101']


def test_the_addresses_table_counts_marks_and_sorts(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    serve(conn)
    fakes[1].kea_leases = [lease('198.51.100.110'), lease('198.51.100.109', mac='', hostname='', state=1),
                           lease('198.51.100.9', mac='aa:bb:cc:00:00:07', hostname='')]
    for page in (admin.get('/dhcp/subnets/1/addresses').text, admin.get('/dhcp/leases').text):
        assert '2 active · 1 declined · 0 reservations' in page
        assert '<span class="pill warn">declined</span>' in page and 'Kea holds it back for a while">none</span>' in page
        assert '<button type="button" class="sort" data-sort="lease"' in page and "liteblox-sort-addresses" in page
        orders = re.findall(r'data-order="(\d+)" data-mac="[^"]*" data-name="[^"]*" data-state="[^"]*"', page)
        ips = re.findall(r'<td><code>([\d.]+)</code></td>', page)
        assert ips == ['198.51.100.9', '198.51.100.109', '198.51.100.110'] and orders == ['0', '1', '2']   # numeric
        assert 'data-lease=""' in page                                       # the declined one sorts last by lease


def test_reservation_review_apply_and_delete(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    serve(conn)
    fakes[1].kea_leases = [lease('198.51.100.50', mac='aa:bb:cc:dd:ee:ff')]
    t = csrf_from(admin.get('/dhcp/subnets/1/reservations/new').text)
    form = {'csrf_token': t, 'hw_address': 'BC-24-11-6C-51-D8', 'ip_address': '198.51.100.50', 'hostname': 'printer'}
    review = admin.post('/dhcp/subnets/1/reservations/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'aa:bb:cc:dd:ee:ff (lab-client.dyn.lab.) has a lease on 198.51.100.50' in review and 'accepts it' in review
    r = admin.post('/dhcp/subnets/1/reservations', data=form, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    (res,) = load_subnets(conn)[0].reservations
    assert (res.hw_address, res.ip_address, res.hostname) == (MAC, '198.51.100.50', 'printer')
    sub = json.loads(fakes[1].kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]
    assert sub['reservations'] == [{'hw-address': MAC, 'ip-address': '198.51.100.50', 'hostname': 'printer'}]
    addresses = admin.get('/dhcp/subnets/1/addresses').text
    assert f'/dhcp/subnets/1/reservations/{res.id}"' in addresses and 'reserved, held by another client' in addresses
    bad = admin.post('/dhcp/subnets/1/reservations', data={**form, 'ip_address': '198.51.100.51'})
    assert bad.status_code == 422 and 'already has a reservation here' in bad.text
    r = admin.post(f'/dhcp/subnets/1/reservations/{res.id}/delete', data={'csrf_token': t}, follow_redirects=False)
    assert jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))['status'] == 'ok'
    assert load_subnets(conn)[0].reservations == []


def test_viewers_see_leases_read_only(client, conn, lab, make_user, login):  # noqa: F811
    fakes, _ = lab
    serve(conn)
    fakes[1].kea_leases = [lease('198.51.100.101')]
    login(*make_user('viewer', 'viewer-password', 'readonly'))
    page = client.get('/dhcp/leases').text
    assert '198.51.100.101' in page and '/dhcp/leases/delete' not in page and 'Reserve' not in page
    t = csrf_from(page)
    assert client.post('/dhcp/leases/delete', data={'csrf_token': t, 'ip': '198.51.100.101', 'node_id': '1'}).status_code == 403


def test_the_subnet_tabs(admin, conn, settings, lab):  # noqa: F811
    from liteblox import stats
    fakes, _ = lab
    serve(conn)
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:00:00:02', '198.51.100.21', 'nas'))
    fakes[1].kea_leases = [lease('198.51.100.101')]
    stats.sample_leases(conn, {1: {'active': 1, 'in_pool': 1, 'outside': 0, 'size': 100}})
    asked = len(fakes[1].kea_commands)
    overview = admin.get('/dhcp/subnets/1').text
    assert 'aria-current="page">Overview' in overview and '1 / 100' in overview
    assert len(fakes[1].kea_commands) == asked                     # from the samples: Kea isn't asked
    assert 'href="/dhcp/subnets/1/addresses"' in overview and 'href="/dhcp/subnets/1/settings"' in overview
    addresses = admin.get('/dhcp/subnets/1/addresses').text
    assert 'reserved, offline' in addresses and '>leased</span>' in addresses
    assert 'name="back" value="/dhcp/subnets/1/addresses"' in addresses
    assert 'id="subnet-form"' in admin.get('/dhcp/subnets/1/settings').text
    assert admin.get('/dhcp/subnets/9/addresses').status_code == 404
    # deleting a lease from the tab comes back to it
    t = csrf_from(addresses)
    r = admin.post('/dhcp/leases/delete', data={'csrf_token': t, 'ip': '198.51.100.101', 'node_id': '1',
                                                'back': '/dhcp/subnets/1/addresses'}, follow_redirects=False)
    assert r.headers['location'].startswith('/dhcp/subnets/1/addresses?done=')
    r = admin.post('/dhcp/leases/delete', data={'csrf_token': t, 'ip': '198.51.100.9', 'node_id': '1',
                                                'back': '//evil.example/dhcp/'}, follow_redirects=False)
    assert r.headers['location'].startswith('/dhcp/leases?')                      # only a DHCP page of this site
    # the all-subnets page lists the reservation with no lease too
    assert 'reserved, offline' in admin.get('/dhcp/leases').text
