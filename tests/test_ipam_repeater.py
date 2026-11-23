"""IPAM (4.4): a Wi-Fi repeater's MAC, which stands in on the LAN for the devices connected through it."""

import csv
import io
import time

from conftest import csrf_from
from liteblox import db
from liteblox.dhcp.model import Reservation, Subnet
from liteblox.ipam import checks, devices, seen
from test_api import bearer, make, people  # noqa: F401 (fixture)
from test_ipam import hit, ip
from test_ipam_free import net  # noqa: F401 (fixture)
from test_ipam_seen import admin, entry, post, viewer  # noqa: F401 (fixtures)
from test_search import world  # noqa: F401 (fixture)

NOW = 1_800_000_000
A, B, R = 'aa:bb:cc:00:00:0a', 'aa:bb:cc:00:00:0b', '5a:d8:12:04:2c:32'
PRINTER = 'aa:bb:cc:00:00:01'          # world's reservation at 192.0.2.60


def mark(conn, mac=R):
    return devices.save(conn, mac, '', '', repeater=True)


# ── the flag ───────────────────────────────────────────────────────────────────

def test_v38_adds_the_column(conn):
    assert len(db.MIGRATIONS) >= 38
    assert 'repeater' in {r['name'] for r in conn.execute('PRAGMA table_info(devices)')}


def test_a_repeater_without_a_label_is_kept(conn):
    assert mark(conn)['repeater'] is True and devices.repeaters(conn) == {R}
    # a label saved without saying (Devices seen's label form) leaves the flag alone
    assert devices.save(conn, R, 'Upstairs repeater', '')['repeater'] is True
    assert devices.save(conn, R, '', '')['repeater'] is True
    assert devices.save(conn, R, '', '', repeater=False) is None and devices.repeaters(conn) == set()
    assert devices.save(conn, A, 'Tablet', '')['repeater'] is False


def test_the_line_under_a_mac():
    assert devices.line('Upstairs', 'private address', True) == 'Upstairs · Wi-Fi repeater · private address'
    assert devices.line('', '', True) == 'Wi-Fi repeater' and devices.line('Tablet', 'Maker') == 'Tablet · Maker'


# ── what it silences ───────────────────────────────────────────────────────────

def test_flapping_skips_changes_to_and_from_a_repeater(conn):
    ip_ = '192.0.2.40'
    for i, mac in enumerate((A, R, A, R, A)):                # a phone moving between the AP and the repeater
        seen.record(conn, None, [entry(ip_, mac)], now=NOW + 60 * i)
    assert [f['ip'] for f in seen.flapping(conn, now=NOW + 300)] == [ip_]
    mark(conn)
    assert seen.flapping(conn, now=NOW + 300) == []
    for i, mac in enumerate((A, B, A, B)):                   # two other devices: still flapping
        seen.record(conn, None, [entry(ip_, mac)], now=NOW + 360 + 60 * i)
    assert [f['macs'] for f in seen.flapping(conn, now=NOW + 600)] == [[A, B]]


def subnet():
    return Subnet(1, '192.0.2.0/24', 'ens19', pools=['192.0.2.100 - 192.0.2.199'])


def test_the_mismatch_checks_skip_a_repeater():
    a = ip('192.0.2.7')
    r = Reservation(1, 1, '58:d8:12:f4:2c:32', '192.0.2.7', 'wakefield')
    names = [hit('wakefield.lab.example', '192.0.2.7')]

    def texts(seen_mac, repeaters, reservation=r, ipam=None):
        return [t for _, t, _ in checks.address_checks(a, names, [], None, reservation, None, subnet(), False,
                                                       seen={'mac': seen_mac}, ipam=ipam, repeaters=repeaters)]
    assert any('but the nodes last saw 5a:d8:12:04:2c:32' in t for t in texts(R, frozenset()))
    assert not any('nodes last saw' in t for t in texts(R, frozenset({R})))
    assert any(f'but the nodes last saw {B}' in t for t in texts(B, frozenset({R})))     # another MAC still warns
    record = {'name': 'cam.lab.example', 'mac': A}
    assert any('IPAM has it for' in t for t in texts(R, frozenset(), None, record))
    assert not any('IPAM has it for' in t for t in texts(R, frozenset({R}), None, record))


def test_saving_a_reservation_leaves_the_repeater_out(conn, settings):
    now = int(time.time())
    seen.record(conn, None, [entry('192.0.2.7', R)], now=now)
    r = Reservation(None, 1, '58:d8:12:f4:2c:32', '192.0.2.7', '')
    assert checks.reservation_warnings(conn, settings, r, now=now) == [
        f'The nodes saw {R} on 192.0.2.7 in the last day: another device may be using it.']
    mark(conn)
    assert checks.reservation_warnings(conn, settings, r, now=now) == []


# ── the pages ──────────────────────────────────────────────────────────────────

def test_mark_it_on_the_device_page(admin, conn, world):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.60', R)], now=int(time.time()))
    card = admin.get('/search?q=192.0.2.60').text
    assert f'but the nodes last saw {R} on it' in card
    page = admin.get(f'/ipam/devices/{R}').text
    assert 'name="repeater"' in page and 'repeater_shown' in page
    r = post(admin, f'/ipam/devices/{R}', label='Upstairs', comment='', repeater_shown='1', repeater='1')
    assert r.status_code == 303 and devices.get(conn, R)['repeater'] is True
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ipam_device'").fetchone()[0] == (
        f'{R} Upstairs (Wi-Fi repeater)')
    card = admin.get('/search?q=192.0.2.60').text
    assert 'nodes last saw' not in card and 'Wi-Fi repeater' in card
    assert '>repeater</span>' in admin.get(f'/ipam/devices/{R}').text
    # Devices seen's label form has no checkbox: the flag stays
    post(admin, f'/ipam/devices/{R}', label='Repeater', comment='', back='/ipam/seen')
    assert devices.get(conn, R)['repeater'] is True
    rows = admin.get('/ipam/seen').text
    assert '>repeater</span>' in rows and 'wi-fi repeater' in rows
    # unticked on the device page
    post(admin, f'/ipam/devices/{R}', label='Repeater', comment='', repeater_shown='1')
    assert devices.get(conn, R)['repeater'] is False


def test_the_network_table(admin, conn, net):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.60', R)], now=int(time.time()))
    page = admin.get(f'/ipam/networks/{net.id}').text
    assert 'but the nodes last saw' in page
    mark(conn)
    page = admin.get(f'/ipam/networks/{net.id}').text
    assert 'but the nodes last saw' not in page


def test_read_only_users_cant_mark_it(viewer, conn, world):  # noqa: F811
    assert 'name="repeater"' not in viewer.get(f'/ipam/devices/{R}').text
    assert post(viewer, f'/ipam/devices/{R}', repeater_shown='1', repeater='1').status_code == 403
    assert devices.repeaters(conn) == set()


def test_the_seen_csv(admin, conn, net):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.70', R), entry('192.0.2.71', A)], now=int(time.time()))
    mark(conn)
    r = admin.get('/ipam/seen.csv')
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {x['mac']: x['repeater'] for x in rows} == {R: 'yes', A: ''}
    assert [x['mac'] for x in csv.DictReader(io.StringIO(admin.get('/ipam/seen.csv?q=repeater').text))] == [R]


# ── the API ────────────────────────────────────────────────────────────────────

def test_the_api(client, people, conn, net):  # noqa: F811
    full = bearer(make(people, 'alice', 'full'))
    seen.record(conn, None, [entry('192.0.2.70', R)], now=int(time.time()))
    got = client.put(f'/api/v1/ipam/devices/{R}', headers=full, json={'repeater': True}).json()
    assert got['repeater'] is True and got['seen'][0]['repeater'] is True
    # a PUT that leaves it out keeps it
    assert client.put(f'/api/v1/ipam/devices/{R}', headers=full, json={'label': 'Upstairs'}).json()['repeater']
    assert client.get('/api/v1/ipam/seen', headers=full).json()[0]['repeater'] is True
    assert [d['mac'] for d in client.get('/api/v1/ipam/devices', headers=full).json()] == [R]
    assert client.delete(f'/api/v1/ipam/devices/{R}', headers=full).status_code == 204
    assert devices.get(conn, R) is None
    read = bearer(make(people, 'bob', 'read'))
    assert client.put(f'/api/v1/ipam/devices/{R}', headers=read, json={'repeater': True}).status_code == 403


def test_csrf_is_needed(admin, conn):
    token = csrf_from(admin.get('/ipam').text)
    assert token
    r = admin.post(f'/ipam/devices/{R}', data={'repeater_shown': '1', 'repeater': '1'}, follow_redirects=False)
    assert r.status_code in (400, 403) and devices.repeaters(conn) == set()
