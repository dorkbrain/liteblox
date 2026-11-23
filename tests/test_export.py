"""CSV exports from the web UI (4.3): every zone at once, DHCP addresses and leases, IPAM networks and devices seen."""

import csv
import io
import time

import pytest

from conftest import csrf_from
from liteblox import csvout
from liteblox.dhcp import routes as dhcp_routes
from liteblox.ipam import model, seen
from test_ipam_free import net  # noqa: F401 (fixture)
from test_many import outcomes
from test_search import MAC, kea_lease, world  # noqa: F401 (fixtures)


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('alice', 'correct-horse', 'admin'))
    return client


@pytest.fixture
def viewer(client, make_user, login):
    login(*make_user('bob', 'correct-horse', 'readonly'))
    return client


def parsed(r):
    """(# notes, header, rows as dicts) of a CSV download."""
    assert r.status_code == 200, r.text[:300]
    assert r.headers['content-type'].startswith('text/csv')
    assert r.headers['content-disposition'].startswith('attachment; filename="')
    lines = r.text.splitlines()
    notes = [line[2:] for line in lines if line.startswith('# ')]
    reader = csv.DictReader(io.StringIO('\n'.join(line for line in lines if not line.startswith('# '))))
    return notes, reader.fieldnames, list(reader)


# ── the helper ─────────────────────────────────────────────────────────────────

def test_cells():
    assert [csvout.cell(v) for v in (None, True, False, 3600, ['a', 'b'], '=1+2', '+x', '-y', '@z', 'ok')] == [
        '', 'yes', '', '3600', 'a; b', "'=1+2", "'+x", "'-y", "'@z", 'ok']
    assert csvout.filename('ipam', '192.0.2.0/24') == 'ipam-192.0.2.0_24.csv'
    assert csvout.filename('dhcp-leases', dated=True).startswith('dhcp-leases-20')
    assert csvout.when(None) == '' and csvout.when(0) != '' and len(csvout.when(1_800_000_000)) == 19


# ── DNS: every zone ────────────────────────────────────────────────────────────

def test_every_zone_in_one_file(admin, world):
    notes, header, rows = parsed(admin.get('/zones/records.csv'))
    assert header == ['zone', 'name', 'ttl', 'type', 'value', 'comment'] and notes == []
    assert {r['zone'] for r in rows} == {'lab.example', '2.0.192.in-addr.arpa', 'dyn.lab.example'}
    assert {'zone': 'lab.example', 'name': 'pc1', 'ttl': '', 'type': 'A', 'value': '192.0.2.51',
            'comment': "Dan's desk"} in rows
    assert any(r['zone'] == 'dyn.lab.example' and r['name'] == 'laptop' for r in rows)    # read from its primary
    assert not any(r['type'] == 'SOA' or (r['type'] == 'NS' and r['name'] == '@') for r in rows)
    reverse = parsed(admin.get('/zones/records.csv?kind=reverse'))[2]
    assert {r['zone'] for r in reverse} == {'2.0.192.in-addr.arpa'}
    assert 'Export CSV' in admin.get('/zones').text


def test_a_zone_that_cant_be_read_is_noted(admin, world):
    world.text = None
    notes, _, rows = parsed(admin.get('/zones/records.csv'))
    assert len(notes) == 1 and notes[0].startswith('dyn.lab.example: left out')
    assert 'dyn.lab.example' not in {r['zone'] for r in rows} and rows


def test_one_zones_rows_import_back_unchanged(admin, world):
    _, _, rows = parsed(admin.get('/zones/records.csv'))
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(['name', 'ttl', 'type', 'value', 'comment'])
    for row in rows:
        if row['zone'] == 'lab.example':
            w.writerow([row['name'], row['ttl'], row['type'], row['value'], row['comment']])
    token = csrf_from(admin.get('/zones/lab.example/records/many').text)
    r = admin.post('/zones/lab.example/records/many/preview', data={'text': '', 'ptr_field': '1', 'csrf_token': token},
                   files={'csv': ('z.csv', buf.getvalue().encode(), 'text/csv')})
    got = outcomes(r.text)
    assert got and {o for o, _, _ in got} == {'same'}, (got, r.status_code, r.text[:1500])


# ── DHCP ───────────────────────────────────────────────────────────────────────

def test_a_subnets_addresses(admin, world):
    notes, header, rows = parsed(admin.get('/dhcp/subnets/1/addresses.csv'))
    assert header == list(dhcp_routes.CSV_COLUMNS)
    by_ip = {r['ip']: r for r in rows}
    assert by_ip['192.0.2.60'] == {'subnet': '192.0.2.0/24', 'ip': '192.0.2.60', 'state': 'reserved, offline',
                                   'mac': 'aa:bb:cc:00:00:01', 'hostname': 'printer', 'reserved': 'address',
                                   'lease_state': '', 'expires': '', 'node': '', 'in_pool': '', 'dns_zone': ''}
    leased = by_ip['192.0.2.120']
    lease = world.leases[0]
    assert (leased['state'], leased['mac'], leased['lease_state'], leased['node'], leased['in_pool'],
            leased['dns_zone']) == ('leased', MAC, 'active', 'ns1', 'yes', 'dyn.lab.example')
    assert leased['expires'] == csvout.when(lease['expires'])
    assert by_ip['192.0.2.130']['state'] == 'expired-reclaimed'
    assert 'Export CSV' in admin.get('/dhcp/subnets/1/addresses').text
    r = admin.get('/dhcp/subnets/1/addresses.csv')
    assert 'filename="dhcp-192.0.2.0_24-' in r.headers['content-disposition']
    assert admin.get('/dhcp/subnets/9/addresses.csv').status_code == 404


def test_every_lease_with_strays_errors_and_formulas(admin, world):
    world.leases.append(kea_lease('192.0.2.140', mac='aa:bb:cc:dd:ee:01', hostname='=cmd|calc'))
    world.leases.append(kea_lease('198.51.100.7', mac='aa:bb:cc:dd:ee:02', hostname='lost', subnet_id=7))
    world.errors.append('ns2: no answer')
    notes, _, rows = parsed(admin.get('/dhcp/leases.csv'))
    assert notes == ['ns2: no answer']
    by_ip = {r['ip']: r for r in rows}
    assert by_ip['192.0.2.140']['hostname'] == "'=cmd|calc"
    assert by_ip['198.51.100.7']['subnet'] == 'subnet 7' and by_ip['198.51.100.7']['state'] == 'active'
    assert rows[-1]['ip'] == '198.51.100.7'                  # the strays come last
    assert 'href="/dhcp/leases.csv"' in admin.get('/dhcp/leases').text


# ── IPAM ───────────────────────────────────────────────────────────────────────

def test_a_networks_addresses_every_page(admin, conn, net):
    big = model.get(conn, model.add_network(conn, '198.51.100.0/23', 'Two pages'))
    notes, header, rows = parsed(admin.get(f'/ipam/networks/{big.id}/addresses.csv'))
    assert header[:3] == ['ip', 'state', 'names'] and header[-1] == 'checks'
    assert len(rows) == 512 and rows[0]['ip'] == '198.51.100.0' and rows[-1]['ip'] == '198.51.101.255'
    assert {r['state'] for r in rows} == {'free'}


def test_used_only_and_what_a_row_holds(admin, conn, net):
    seen.record(conn, 1, [{'ip': '192.0.2.77', 'mac': 'aa:bb:cc:00:00:77', 'state': 'REACHABLE',
                           'confirmed': 3 * 86400}], now=int(time.time()))
    _, _, every = parsed(admin.get(f'/ipam/networks/{net.id}/addresses.csv'))
    assert len(every) == 256
    by_ip = {r['ip']: r for r in every}
    assert by_ip['192.0.2.51']['names'] == 'pc1.lab.example' and by_ip['192.0.2.51']['comment'] == "Dan's desk"
    assert by_ip['192.0.2.60']['state'] == 'reserved'
    old = by_ip['192.0.2.77']          # seen three days ago: free now, its MAC and when kept
    assert old['state'] == 'free' and old['mac'] == 'aa:bb:cc:00:00:77' and old['last_seen']
    r = admin.get(f'/ipam/networks/{net.id}/addresses.csv?used=1')
    _, _, used = parsed(r)
    assert used and 'free' not in {u['state'] for u in used} and len(used) < 256
    assert '192.0.2.77' not in {u['ip'] for u in used} and 'used.csv' in r.headers['content-disposition']
    page = admin.get(f'/ipam/networks/{net.id}?used=1').text
    assert f'/ipam/networks/{net.id}/addresses.csv?used=1' in page


def test_a_container_has_no_table(admin, conn, net):
    outer = model.add_network(conn, '10.0.0.0/16', 'Site')
    model.add_network(conn, '10.0.1.0/24', 'Inside')
    assert model.get(conn, outer).container
    assert admin.get(f'/ipam/networks/{outer}/addresses.csv').status_code == 404
    assert admin.get('/ipam/networks/999/addresses.csv').status_code == 404


def test_devices_seen(admin, conn, net):
    now = int(time.time())
    seen.record(conn, 1, [{'ip': '192.0.2.70', 'mac': 'aa:bb:cc:00:00:70', 'state': 'REACHABLE', 'confirmed': 0},
                          {'ip': '192.0.2.71', 'mac': 'aa:bb:cc:00:00:71', 'state': 'REACHABLE', 'confirmed': 0}],
                now=now)
    _, header, rows = parsed(admin.get('/ipam/seen.csv'))
    assert header[:2] == ['ip', 'mac'] and {r['ip'] for r in rows} == {'192.0.2.70', '192.0.2.71'}
    row = rows[0]
    assert row['network'] == '192.0.2.0/24' and row['node'] == 'ns1' and row['last_seen'] == csvout.when(now)
    _, _, one = parsed(admin.get('/ipam/seen.csv?q=00:71'))
    assert [r['ip'] for r in one] == ['192.0.2.71']
    assert 'id="seen-csv"' in admin.get('/ipam/seen').text


# ── who may ────────────────────────────────────────────────────────────────────

PATHS = ['/zones/records.csv', '/dhcp/subnets/1/addresses.csv', '/dhcp/leases.csv', '/ipam/seen.csv']


def test_read_only_users_may_export(viewer, conn, net):
    for path in PATHS + [f'/ipam/networks/{net.id}/addresses.csv']:
        assert viewer.get(path).status_code == 200, path


def test_a_login_is_needed(client, conn, net):
    for path in PATHS + [f'/ipam/networks/{net.id}/addresses.csv']:
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (302, 303, 401) and 'text/csv' not in r.headers.get('content-type', ''), path
