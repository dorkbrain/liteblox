"""IPAM (3.4 M4): devices (labels), name-only reservations and the steps up and down, and expected MACs."""

import sqlite3
import time

import pytest

from liteblox import search
from liteblox.dhcp import leases as lease_mod
from liteblox.dhcp import render, store, validate
from liteblox.dhcp.model import Reservation, Subnet
from liteblox.ipam import devices, seen, view
from test_ipam_seen import admin, entry, flap, post, viewer  # noqa: F401 (fixtures)
from test_search import MAC, kea_lease, world  # noqa: F401 (fixture)

NOW = 1_800_000_000
A, B, C = 'aa:bb:cc:00:00:0a', 'aa:bb:cc:00:00:0b', 'aa:bb:cc:00:00:0c'


def ddns_subnet(**kw):
    return Subnet(1, '192.0.2.0/24', 'ens19', pools=['192.0.2.100 - 192.0.2.199'], ddns=True,
                  ddns_zone='dyn.lab.example', **kw)


# ── name-only reservations ─────────────────────────────────────────────────────

def test_a_name_only_reservation_needs_a_name_and_ddns():
    s = ddns_subnet(reservations=[Reservation(7, 1, A, '', 'tablet')])
    assert validate.check_reservation(Reservation(None, 1, B, '', 'Phone'), s, []) == ({}, [])
    errors, _ = validate.check_reservation(Reservation(None, 1, B, ' ', ''), s, [])
    assert errors == {'hostname': 'a name, for a reservation without an address'}
    errors, _ = validate.check_reservation(Reservation(None, 1, A, '', 'other'), s, [])
    assert errors == {'hw_address': f'{A} already has a reservation here (name tablet)'}
    plain = Subnet(1, '192.0.2.0/24', 'ens19', pools=['192.0.2.100 - 192.0.2.199'])
    errors, _ = validate.check_reservation(Reservation(None, 1, B, '', 'phone'), plain, [])
    assert 'needs that' in errors['ip_address']
    # an address still works as before, and still has to be free
    s.reservations.append(Reservation(8, 1, C, '192.0.2.20', 'nas'))
    errors, _ = validate.check_reservation(Reservation(None, 1, B, '192.0.2.20', ''), s, [])
    assert errors == {'ip_address': f'192.0.2.20 is already reserved for {C}'}


def test_render_leaves_the_address_out():
    s = ddns_subnet(reservations=[Reservation(1, 1, B, '', 'phone'), Reservation(2, 1, A, '192.0.2.30', 'nas'),
                                  Reservation(3, 1, C, '192.0.2.9', '')])
    out = render.subnet4(s)['reservations']
    assert out == [{'hw-address': C, 'ip-address': '192.0.2.9'},
                   {'hw-address': A, 'ip-address': '192.0.2.30', 'hostname': 'nas'},
                   {'hw-address': B, 'hostname': 'phone'}]


def test_several_name_only_reservations_in_one_subnet(conn):
    store.save_subnet(conn, ddns_subnet())
    store.save_reservation(conn, Reservation(None, 1, A, '', 'tablet'))
    store.save_reservation(conn, Reservation(None, 1, B, '', 'phone'))
    store.save_reservation(conn, Reservation(None, 1, C, '192.0.2.20', ''))
    with pytest.raises(sqlite3.IntegrityError):
        store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:00:00:0d', '192.0.2.20', ''))


def test_the_addresses_table_joins_a_name_only_reservation_to_its_lease():
    s = ddns_subnet(reservations=[Reservation(1, 1, A, '', 'tablet'), Reservation(2, 1, B, '', 'phone')])
    rows = lease_mod.addresses(s, [kea_lease('192.0.2.120', mac=A, hostname='tablet.dyn.lab.example.')])
    assert [(r['ip'], r['state'], r['label'], r['hostname'], r['reservation'].id) for r in rows] == [
        ('192.0.2.120', 'named', 'named, online', 'tablet', 1), ('', 'named-offline', 'named, offline', 'phone', 2)]
    assert lease_mod.tally(rows)[-1] == (2, 'reservations')


def test_search_finds_a_name_only_reservation_through_its_lease(conn, settings, world):  # noqa: F811
    store.save_reservation(conn, Reservation(None, 1, MAC, '', 'laptop'))
    res = search.search(conn, settings, '192.0.2.120')
    assert [h['r'].hostname for h in res.reservations.hits] == ['laptop']
    assert res.address['reservations'][0].hw_address == MAC
    assert [h['r'].hostname for h in search.search(conn, settings, 'laptop').reservations.hits] == ['laptop']
    # the network view still counts it as leased, by its lease
    facts = view.gather(conn, settings)
    assert facts.state(search._v4('192.0.2.120')) == 'leased'


# ── devices ────────────────────────────────────────────────────────────────────

def test_labels(conn):
    assert devices.save(conn, 'AA-BB-CC-00-00-0A', ' Kitchen tablet ', 'on the fridge', now=NOW)['label'] == \
        'Kitchen tablet'
    assert devices.labels(conn) == {A: 'Kitchen tablet'}
    assert [d['mac'] for d in devices.matching(conn, 'fridge')] == [A]
    assert devices.matching(conn, 'garage') == []
    assert devices.hostname_for('Kitchen tablet #2') == 'kitchen-tablet-2'
    assert devices.line('Kitchen tablet', 'private address') == 'Kitchen tablet · private address'
    assert devices.save(conn, A, '', '') is None and devices.get(conn, A) is None
    with pytest.raises(ValueError):
        devices.save(conn, 'nope', 'x', '')


def test_search_finds_labels(conn, settings, world):  # noqa: F811
    devices.save(conn, B, 'Garage door', '')
    res = search.search(conn, settings, 'garage')
    assert [d['mac'] for d in res.devices.hits] == [B] and not res.empty
    assert search.to_dict(res)['devices'] == {'count': 1, 'items': [{'mac': B, 'label': 'Garage door',
                                                                     'comment': ''}]}


# ── expected MACs ──────────────────────────────────────────────────────────────

def test_expected_macs(conn):
    ip = '192.0.2.40'
    flap(conn, ip, 3, start=NOW)
    assert [f['macs'] for f in seen.flapping(conn, now=NOW + 300)] == [[A, B]]
    assert seen.expect(conn, ip, [A, B], ' bond0 ', 'alice', now=NOW + 300) == [A, B]
    assert seen.expected(conn)[ip] == {'macs': [A, B], 'reason': 'bond0', 'username': 'alice', 'at': NOW + 300}
    # A and B keep swapping: never flapping again
    flap(conn, ip, 5, start=NOW + 360)
    assert seen.flapping(conn, now=NOW + 700) == []
    # a third MAC does count, but only its own changes
    for i, mac in enumerate((C, A, C, B)):
        seen.record(conn, None, [entry(ip, mac)], now=NOW + 720 + 60 * i)
    assert [(f['changes'], f['macs']) for f in seen.flapping(conn, now=NOW + 960)] == [(4, [A, B, C])]
    # Forget and prune leave it; unmute counts every change from then on
    seen.forget(conn, ip)
    seen.prune(conn, now=NOW + 30 * 86400)
    assert seen.expected(conn)[ip]['macs'] == [A, B]
    seen.unmute(conn, ip, now=NOW + 30 * 86400)
    assert seen.expected(conn) == {}
    flap(conn, ip, 3, start=NOW + 30 * 86400 + 60)
    assert len(seen.flapping(conn, now=NOW + 30 * 86400 + 300)) == 1


# ── the pages ──────────────────────────────────────────────────────────────────

def ddns_world(conn):
    zone = conn.execute("SELECT id FROM zones WHERE name = 'dyn.lab.example'").fetchone()[0]
    with conn:
        conn.execute('UPDATE dhcp4_subnets SET ddns_zone_id = ? WHERE id = 1', (zone,))
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'liteblox'")


def test_the_device_page_and_its_steps(admin, conn, settings, world):  # noqa: F811
    ddns_world(conn)
    devices.save(conn, MAC, 'Dan laptop', '')
    page = admin.get(f'/ipam/devices/{MAC}').text
    assert 'Dan laptop' in page and 'Register a name' in page and 'Reserve 192.0.2.120' in page
    assert f'reservations/new?mac={MAC.replace(":", "%3A")}&hostname=dan-laptop' in page
    # up a step: a name-only reservation
    store.save_reservation(conn, Reservation(None, 1, MAC, '', 'dan-laptop'))
    rid = conn.execute("SELECT id FROM dhcp4_reservations WHERE hostname = 'dan-laptop'").fetchone()[0]
    page = admin.get(f'/ipam/devices/{MAC}').text
    assert 'name only' in page and 'Fix its address' in page and f'reservations/{rid}?ip=192.0.2.120' in page
    assert 'Back down' in page and 'Register a name' not in page
    form = admin.get(f'/dhcp/subnets/1/reservations/{rid}?ip=192.0.2.120').text
    assert 'value="192.0.2.120"' in form
    # with an address: back down to the name
    with conn:
        conn.execute("UPDATE dhcp4_reservations SET ip_address = '192.0.2.120' WHERE id = ?", (rid,))
    page = admin.get(f'/ipam/devices/{MAC}').text
    assert 'Back down to a name' in page and f'reservations/{rid}?ip=' in page
    assert 'Dan laptop' in admin.get('/dhcp/subnets/1/addresses').text
    assert admin.get('/ipam/devices/nope').status_code == 404


def test_labelling_from_devices_seen(admin, conn, world):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.77', B)], now=int(time.time()))
    assert '>Label<' in admin.get('/ipam/seen').text
    r = post(admin, f'/ipam/devices/{B}', label='Garage door', comment='', back='/ipam/seen')
    assert r.status_code == 303 and r.headers['location'].startswith('/ipam/seen?done=')
    assert 'Garage door' in admin.get('/ipam/seen').text
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ipam_device'").fetchone()[0] == f'{B} Garage door'


def test_expect_and_unmute_on_the_card(admin, conn, world):  # noqa: F811
    now = int(time.time())
    flap(conn, '192.0.2.200', 3, start=now - 300)
    assert 'These MACs are expected here' in admin.get('/search?q=192.0.2.200').text
    r = post(admin, '/ipam/flapping/192.0.2.200/expect', reason='two NICs')
    assert r.status_code == 303 and seen.flapping(conn) == []
    card = admin.get('/search?q=192.0.2.200').text
    assert 'two NICs' in card and 'Unmute' in card and 'These MACs are expected here' not in card
    assert 'expected' in admin.get('/ipam/seen').text
    r = post(admin, '/ipam/flapping/192.0.2.200/unmute')
    assert r.status_code == 303 and seen.expected(conn) == {}


def test_read_only(viewer, conn, world):  # noqa: F811
    page = viewer.get(f'/ipam/devices/{MAC}').text
    assert 'Register a name' not in page and 'name="label"' not in page
    for path in (f'/ipam/devices/{MAC}', '/ipam/flapping/192.0.2.200/expect', '/ipam/flapping/192.0.2.200/unmute'):
        assert post(viewer, path, label='x').status_code == 403
