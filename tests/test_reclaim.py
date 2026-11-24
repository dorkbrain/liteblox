"""Stale DHCP names and reclaiming them (4.1 M5)."""

import re
import time

import pytest

from liteblox import db, status
from liteblox.dhcp import leases as lease_mod
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation, Reservation6, Subnet, Subnet6
from liteblox.dns import reclaim

from test_dynamic import dyn, ok_verify, ptr_zones, server, zone_row  # noqa: F401 (fixtures)
from test_ptr import admin  # noqa: F401 (fixture)
from test_managed import lab  # noqa: F401 (fixture)

DHCID = 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA='
REV = '0.168.192.in-addr.arpa'
NOW = 1_800_000_000


def kea(name, address):
    return f'{name}\t300\tIN\tA\t{address}\n{name}\t300\tIN\tDHCID\t{DHCID}\n'


def kea_ptr(last, target):
    return f'{last}\t300\tIN\tPTR\t{target}.\n{last}\t300\tIN\tDHCID\t{DHCID}\n'


def lease(ip, hostname, expires, state='active'):
    return {'ip': ip, 'mac': 'aa:bb:cc:00:00:01', 'hostname': hostname, 'subnet_id': 1, 'state': state,
            'expires': expires, 'expires_in': expires - NOW, 'registered': True}


@pytest.fixture
def names(conn, settings, ptr_zones, monkeypatch):  # noqa: F811
    """dyn.lab with Kea's kea1..kea4 (.61-.64), a hand-made name (no DHCID) and pc1; the reverse zone with Kea's
    PTRs for .61 and .62 and someone else's for .63. Leases come from live.leases (no errors)."""
    _, server = ptr_zones
    server.load('dyn.lab', server.text('dyn.lab') + kea('kea1', '192.168.0.61') + kea('kea2', '192.168.0.62')
                + kea('kea3', '192.168.0.63') + kea('kea4', '192.168.0.64') + 'hand\t300\tIN\tA\t192.168.0.65\n')
    server.load(REV, server.text(REV) + kea_ptr(61, 'kea1.dyn.lab') + kea_ptr(62, 'kea2.dyn.lab')
                + kea_ptr(63, 'printer.elsewhere.lab'))

    class Live:
        leases, errors = [], []
    live = Live()
    node = {'id': 1, 'name': 'ns1', 'dhcp6': 1}
    monkeypatch.setattr(lease_mod, 'serving_leases', lambda s, c, family=4: ([(node, x) for x in live.leases if (':' in x['ip']) == (family == 6)], live.errors))
    monkeypatch.setattr(lease_mod, 'serving', lambda c: [node])
    live.server = server
    return live


def items(conn, settings, now=NOW, notice=True):
    from liteblox.dns import editing
    edit = editing.ZoneEdit(settings, conn, 'dyn.lab')
    found, _ = reclaim.all_leases(settings, conn)
    return {i['fqdn']: i for i in reclaim.review(conn, settings, zone_row(conn, 'dyn.lab'), edit.zone, found,
                                                 now=now, notice=notice)}


def test_only_kea_names_and_the_clock_starts_when_first_seen(conn, settings, names):
    got = items(conn, settings)
    assert sorted(got) == ['kea1.dyn.lab', 'kea2.dyn.lab', 'kea3.dyn.lab', 'kea4.dyn.lab']      # no hand, no pc1
    assert not any(i['stale'] for i in got.values()) and 'stale in 2h' in got['kea1.dyn.lab']['why']
    got = items(conn, settings, now=NOW + 7200 + 1)
    assert all(i['stale'] for i in got.values()) and 'no lease for at least 2h' in got['kea1.dyn.lab']['why']
    # the zone page only looks: a name it sees first doesn't start a clock
    with conn:
        conn.execute('DELETE FROM ddns_names')
    items(conn, settings, notice=False)
    assert conn.execute('SELECT COUNT(*) FROM ddns_names').fetchone()[0] == 0


def test_the_last_lease_expiry_and_what_keeps_a_name(conn, settings, names):
    names.leases = [lease('192.168.0.61', 'kea1.dyn.lab.', NOW - 9000, state='expired-reclaimed'),
                    lease('192.168.0.62', 'kea2.dyn.lab', NOW + 600),
                    lease('192.168.0.70', 'kea3.dyn.lab', NOW - 100, state='expired-reclaimed')]
    reclaim.remember(conn, [(None, x) for x in names.leases])
    store.save_subnet(conn, Subnet(1, '192.168.0.0/24', 'ens19', pools=['192.168.0.100 - 192.168.0.199']))
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:00:00:04', '192.168.0.64', ''))
    got = items(conn, settings)
    assert got['kea1.dyn.lab']['stale'] and 'its lease ended 2h30m ago' in got['kea1.dyn.lab']['why']
    assert got['kea2.dyn.lab']['why'] == 'a live lease'
    assert not got['kea3.dyn.lab']['stale'] and 'its lease ended 1m40s ago' in got['kea3.dyn.lab']['why']
    assert got['kea4.dyn.lab']['why'] == 'reserved'
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:00:00:05', '', 'kea1'))       # by name
    assert items(conn, settings)['kea1.dyn.lab']['why'] == 'reserved'


def test_grace_default_and_setting(conn, settings, names):
    row = zone_row(conn, 'dyn.lab')
    assert reclaim.grace(conn, row) == reclaim.KEA_VALID
    store.save_subnet(conn, Subnet(1, '192.168.0.0/24', 'ens19', valid_lifetime=14400, ddns=True))
    with conn:
        conn.execute("UPDATE dhcp4_subnets SET ddns_zone_id = ?", (row['id'],))
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'liteblox'")
    assert reclaim.grace_default(conn, row) == 14400
    with conn:
        conn.execute("UPDATE zones SET reclaim_after = 600 WHERE name = 'dyn.lab'")
    assert reclaim.grace(conn, zone_row(conn, 'dyn.lab')) == 600


def test_still_on_the_network(conn, settings, names):
    items(conn, settings)
    with conn:
        conn.execute("INSERT INTO ipam_seen (ip, mac, first_seen, last_seen) VALUES ('192.168.0.62', 'aa:bb:cc:00:00:02', ?, ?)",
                     (NOW, NOW + 7000))
    got = items(conn, settings, now=NOW + 7300)
    assert not got['kea2.dyn.lab']['stale'] and 'still on the network' in got['kea2.dyn.lab']['why']
    assert got['kea1.dyn.lab']['stale']
    with conn:
        conn.execute('UPDATE ipam_settings SET keep_seen_names = 0')
    assert items(conn, settings, now=NOW + 7300)['kea2.dyn.lab']['stale']
    with conn:
        conn.execute('UPDATE ipam_settings SET keep_seen_names = 1')
        conn.execute('UPDATE modules SET ipam = 0')
    assert items(conn, settings, now=NOW + 7300)['kea2.dyn.lab']['stale']                  # IPAM off: no say


def test_a_pass_reclaims_names_and_their_ptrs(conn, settings, names):
    names.leases = [lease('192.168.0.63', 'kea3.dyn.lab', NOW + 600), lease('192.168.0.64', 'kea4.dyn.lab', NOW + 600)]
    items(conn, settings, now=NOW - 7300)                       # first seen two hours ago
    log = []
    gone = reclaim.run_pass(settings, conn, zone_row(conn, 'dyn.lab'), log.append, now=NOW)
    assert gone == ['kea1.dyn.lab', 'kea2.dyn.lab']
    fwd, rev = names.server.text('dyn.lab'), names.server.text(REV)
    assert 'kea1' not in fwd and 'kea2' not in fwd and 'kea3' in fwd and 'hand' in fwd
    assert not re.search(r'^6[12]\s', rev, re.M) and re.search(r'^63\s.*PTR', rev, re.M)
    assert any('removed the PTR for 192.168.0.61' in line for line in log)
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ddns_reclaim'").fetchone()[0] == (
        'dyn.lab: kea1.dyn.lab 192.168.0.61, kea2.dyn.lab 192.168.0.62')
    row = zone_row(conn, 'dyn.lab')
    assert row['reclaim_checked_at'] == NOW and row['reclaim_note'] is None


def test_a_ptr_to_another_name_stays(conn, settings, names):
    names.server.load(REV, names.server.text(REV).replace('kea2.dyn.lab.', 'other.dyn.lab.'))
    items(conn, settings, now=NOW - 7300)
    reclaim.run_pass(settings, conn, zone_row(conn, 'dyn.lab'), print, now=NOW)
    rev = names.server.text(REV)
    assert re.search(r'^62\s.*PTR\s+other\.dyn\.lab\.', rev, re.M) and re.search(r'^62\s.*DHCID', rev, re.M)


def test_guards(conn, settings, names):
    items(conn, settings, now=NOW - 7300)
    row = zone_row(conn, 'dyn.lab')
    names.errors = ['ns1: no answer']
    assert reclaim.run_pass(settings, conn, row, print, now=NOW) == []
    assert zone_row(conn, 'dyn.lab')['reclaim_note'].startswith("skip: the leases couldn't be read")
    names.errors = []
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp_sockets = ? WHERE name = 'ns1'", ('{"status": "failed"}',))
    assert reclaim.run_pass(settings, conn, row, print, now=NOW) == []
    assert 'DHCP is not healthy' in zone_row(conn, 'dyn.lab')['reclaim_note']
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 0, dhcp_sockets = NULL")
        conn.execute("UPDATE zones SET reclaim = 1 WHERE name = 'dyn.lab'")
    # all four would go: more than a quarter, and at least 4
    assert reclaim.run_pass(settings, conn, row, print, now=NOW) == []
    note = zone_row(conn, 'dyn.lab')['reclaim_note']
    assert note.startswith('hold: 4 of its 4 DHCP names would go at once')
    problems = status._zone_problems(conn, settings)
    assert any('stale DHCP names held back' in p['what'] and p['link'].endswith('?stale=1#stale') for p in problems)
    assert 'kea1' in names.server.text('dyn.lab')


def test_pass_due_runs_hourly_and_only_with_reclaim_on(conn, settings, names, monkeypatch):
    from liteblox import jobs
    started = []
    monkeypatch.setattr(jobs, 'start', lambda *a, **kw: started.append(kw['zone_id']) or 1)
    items(conn, settings, now=NOW - 7300)
    names.leases = [lease('192.168.0.63', 'kea3.dyn.lab', NOW + 600), lease('192.168.0.64', 'kea4.dyn.lab', NOW + 600)]
    assert reclaim.pass_due(settings, conn, now=NOW) == []                 # off
    with conn:
        conn.execute("UPDATE zones SET reclaim = 1 WHERE name = 'dyn.lab'")
    assert reclaim.pass_due(settings, conn, now=NOW) == [1] and len(started) == 1
    with conn:
        conn.execute("UPDATE zones SET reclaim_checked_at = ? WHERE name = 'dyn.lab'", (NOW,))
    assert reclaim.pass_due(settings, conn, now=NOW + 600) == []            # checked 10 minutes ago
    names.leases = []
    assert reclaim.pass_due(settings, conn, now=NOW + 3600) == []           # due, but now too many: held back
    assert zone_row(conn, 'dyn.lab')['reclaim_note'].startswith('hold:')


def test_remember_keeps_the_newest_expiry(conn, settings):
    reclaim.remember(conn, [(None, lease('192.168.0.9', 'a.lab.', NOW + 100))])
    reclaim.remember(conn, [(None, lease('192.168.0.9', 'A.lab', NOW - 100))])
    assert conn.execute('SELECT last_expiry FROM ddns_names').fetchall()[0][0] == NOW + 100


# ── IPv6 and stale PTRs ────────────────────────────────────────────────────────

REV6 = '0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa'
NIB = '0.0.0.0.0.0.0.0.0.0.0.0.0.0'        # the host part of fd00:1:2:100::XY before its last two nibbles


def lease6(ip, hostname, expires, state='active', kind='address'):
    return {'ip': ip, 'type': kind, 'duid': '00:01:aa:bb', 'mac': '', 'hostname': hostname, 'subnet_id': 1,
            'state': state, 'expires': expires, 'expires_in': expires - NOW, 'registered': True}


@pytest.fixture
def names6(conn, settings, names):
    """names, plus a DHCPv6 subnet and the /64's dynamic reverse zone. dual.dyn.lab is Kea's with .66 and ::66
    (both PTRs Kea's). Stale-PTR material: ::77 -> kea1 and .69 -> kea2 (neither has that address any more)."""
    from liteblox.dns import declare
    server = names.server
    store.save_subnet6(conn, Subnet6(1, 'fd00:1:2:100::/64', 'ens19'))
    rev6 = f'$TTL 3600\n@\tIN\tSOA\tns1.dyn.lab. hostmaster.dyn.lab. 1 3600 900 1209600 300\n@\tIN\tNS\tns1.dyn.lab.\n'
    declare.create_zone(settings, REV6, ['1', '2'], rev6, 'admin', print, verify=ok_verify)
    server.load(REV6, rev6)
    declare.set_dynamic(settings, REV6, True, 'admin', print, verify=ok_verify)
    server.load('dyn.lab', server.text('dyn.lab') + kea('dual', '192.168.0.66')
                + 'dual\t300\tIN\tAAAA\tfd00:1:2:100::66\n')
    server.load(REV, server.text(REV) + kea_ptr(66, 'dual.dyn.lab') + kea_ptr(69, 'kea2.dyn.lab'))
    server.load(REV6, server.text(REV6) + kea_ptr(f'6.6.{NIB}', 'dual.dyn.lab') + kea_ptr(f'7.7.{NIB}', 'kea1.dyn.lab'))
    # kea1..kea4 have live leases, so only what a test changes goes stale
    names.leases = [lease(f'192.168.0.6{n}', f'kea{n}.dyn.lab', NOW + 99999) for n in (1, 2, 3, 4)]
    return names


def ptrs(conn, settings, now=NOW, notice=True):
    from liteblox.dns import editing
    edit = editing.ZoneEdit(settings, conn, 'dyn.lab')
    found, _ = reclaim.all_leases(settings, conn)
    got, total = reclaim.review_ptrs(settings, conn, zone_row(conn, 'dyn.lab'), edit.zone, found, now=now, notice=notice)
    return {i['address']: i for i in got}, total


def test_a_dual_stack_name_and_its_ipv6_lease(conn, settings, names6):
    names6.leases.append(lease6('fd00:1:2:100::66', 'dual.dyn.lab', NOW + 600))
    got = items(conn, settings)
    assert got['dual.dyn.lab']['addresses'] == ['192.168.0.66', 'fd00:1:2:100::66']
    assert got['dual.dyn.lab']['why'] == 'a live lease'
    names6.leases.pop()
    store.save_reservation6(conn, Reservation6(None, 1, duid='00:01:aa:bb', ip_address='fd00:1:2:100::66'))
    assert items(conn, settings)['dual.dyn.lab']['why'] == 'reserved'
    with conn:
        conn.execute('DELETE FROM dhcp6_reservations')
    items(conn, settings)                                                           # its clock starts
    assert items(conn, settings, now=NOW + 7201)['dual.dyn.lab']['stale']
    lines = reclaim.delete(settings, conn, 'dyn.lab', ['dual.dyn.lab'], 'admin')
    assert 'dual' not in names6.server.text('dyn.lab')
    assert not re.search(r'^66\s', names6.server.text(REV), re.M)
    assert not re.search(r'^6\.6\.0', names6.server.text(REV6), re.M)
    assert 'removed the PTR for fd00:1:2:100::66 from ' + REV6 in lines


def test_remember_takes_ipv6_leases(conn, settings):
    reclaim.remember(conn, [(None, lease6('fd00:1:2:100::66', 'dual.lab', NOW + 100))])
    reclaim.remember(conn, [(None, lease('192.168.0.66', 'dual.lab', NOW + 50))])
    assert tuple(conn.execute('SELECT address, last_expiry FROM ddns_names').fetchone()) == ('fd00:1:2:100::66', NOW + 100)


def test_stale_ptrs_are_found_and_reclaimed(conn, settings, names6):
    names6.leases.append(lease('192.168.0.66', 'dual.dyn.lab', NOW + 99999))
    got, total = ptrs(conn, settings)
    # Kea's PTRs into dyn.lab: .61 .62 .66 .69 and ::66 ::77 (.63 points elsewhere)
    assert total == 6 and sorted(got) == ['192.168.0.69', 'fd00:1:2:100::77']
    assert not got['fd00:1:2:100::77']['stale'] and 'kea1.dyn.lab has no record for it' in got['fd00:1:2:100::77']['why']
    got, _ = ptrs(conn, settings, now=NOW + 7201)
    assert all(i['stale'] for i in got.values())
    names6.leases.append(lease('192.168.0.69', 'someone.dyn.lab', NOW + 99999))
    assert ptrs(conn, settings, now=NOW + 7201)[0]['192.168.0.69']['why'] == 'a live lease has its address'
    names6.leases.pop()
    log = []
    gone = reclaim.run_pass(settings, conn, zone_row(conn, 'dyn.lab'), log.append, now=NOW + 7201)
    assert gone == ['69.0.168.192.in-addr.arpa', f'7.7.{NIB}.{REV6}']
    rev, rev6 = names6.server.text(REV), names6.server.text(REV6)
    assert not re.search(r'^69\s', rev, re.M) and re.search(r'^6[126]\s.*PTR', rev, re.M)
    assert not re.search(r'^7\.7\.0', rev6, re.M) and re.search(r'^6\.6\.0.*PTR', rev6, re.M)
    assert 'kea1' in names6.server.text('dyn.lab')                                    # the names stay
    assert any('removed the stale PTR for fd00:1:2:100::77' in line for line in log)
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ddns_reclaim'").fetchone()[0] == (
        'dyn.lab: the PTR for 192.168.0.69 (kea2.dyn.lab), the PTR for fd00:1:2:100::77 (kea1.dyn.lab)')
    assert conn.execute("SELECT COUNT(*) FROM ddns_names WHERE name LIKE '%.arpa'").fetchone()[0] == 0


def test_a_ptr_that_matches_again_restarts_its_clock(conn, settings, names6):
    ptrs(conn, settings)
    names6.server.load('dyn.lab', names6.server.text('dyn.lab') + 'kea2\t300\tIN\tA\t192.168.0.69\n')
    assert '192.168.0.69' not in ptrs(conn, settings, now=NOW + 100)[0]
    names6.server.load('dyn.lab', re.sub(r'^kea2\s.*192\.168\.0\.69\n', '', names6.server.text('dyn.lab'), flags=re.M))
    got, _ = ptrs(conn, settings, now=NOW + 7201)
    assert not got['192.168.0.69']['stale'] and got['fd00:1:2:100::77']['stale']


def test_too_many_stale_ptrs_hold_the_pass(conn, settings, names6):
    names6.leases.append(lease('192.168.0.66', 'dual.dyn.lab', NOW + 99999))
    names6.server.load(REV, names6.server.text(REV) + kea_ptr(70, 'kea3.dyn.lab') + kea_ptr(71, 'kea4.dyn.lab'))
    ptrs(conn, settings)
    assert reclaim.run_pass(settings, conn, zone_row(conn, 'dyn.lab'), print, now=NOW + 7201) == []
    assert zone_row(conn, 'dyn.lab')['reclaim_note'].startswith('hold: 4 of the 8 PTR records DHCP made')


def test_dhcpv6_trouble_holds_the_pass(conn, settings, names6):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp6 = 1, dhcp6_sockets = ? WHERE name = 'ns1'", ('{"status": "failed"}',))
    assert reclaim.dhcp_trouble(conn) == "ns1: Kea isn't serving DHCPv6"
    with conn:
        conn.execute("UPDATE nodes SET dhcp6_sockets = NULL, dhcp6_ha_state = 'partner-down'")
    assert reclaim.dhcp_trouble(conn) is None                                   # no pair
    with conn:
        conn.execute('DELETE FROM dhcp6_subnets')
        conn.execute("UPDATE nodes SET dhcp6_sockets = '{}'")
    assert reclaim.dhcp_trouble(conn) is None                                   # no v6 served: not asked


def test_the_zone_page_shows_and_deletes_stale_ptrs(admin, conn, settings, names6):  # noqa: F811
    ptrs(conn, settings, now=int(time.time()) - 8000)
    page = admin.get('/zones/dyn.lab?stale=1').text
    assert 'PTR records without a name' in page and f'value="7.7.{NIB}.{REV6}"' in page
    r = admin.post('/zones/dyn.lab/stale', data={'ptrs': [f'7.7.{NIB}.{REV6}']}, follow_redirects=False)
    assert r.status_code == 303 and 'done=1%20stale%20PTR%20record%20removed' in r.headers['location']
    assert not re.search(r'^7\.7\.0', names6.server.text(REV6), re.M)
    assert re.search(r'^69\s', names6.server.text(REV), re.M)
    # a PTR whose name got its address back isn't deleted
    names6.server.load('dyn.lab', names6.server.text('dyn.lab') + 'kea2\t300\tIN\tA\t192.168.0.69\n')
    r = admin.post('/zones/dyn.lab/stale', data={'ptrs': ['69.0.168.192.in-addr.arpa']}, follow_redirects=False)
    assert re.search(r'^69\s', names6.server.text(REV), re.M) and 'no%20PTR%20record%20removed' in r.headers['location']
    assert [r[0] for r in conn.execute("SELECT detail FROM audit WHERE action = 'ddns_delete'")] == [
        f'dyn.lab: the stale PTR for fd00:1:2:100::77 from {REV6}']


# ── the pages ──────────────────────────────────────────────────────────────────

def test_the_zone_page_and_settings(admin, conn, settings, names):  # noqa: F811
    items(conn, settings, now=int(time.time()) - 8000)
    page = admin.get('/zones/dyn.lab?stale=1').text
    assert 'DHCP names' in page and page.count('<span class="pill warn">stale</span>') == 4
    assert 'Stale names' in admin.get('/zones/dyn.lab').text
    r = admin.post('/zones/dyn.lab/stale', data={'names': ['kea1.dyn.lab', 'kea2.dyn.lab']}, follow_redirects=False)
    assert r.status_code == 303 and 'done=2%20names%20removed%2C%20with%202%20PTR%20records' in r.headers['location']
    assert 'kea1' not in names.server.text('dyn.lab') and 'kea3' in names.server.text('dyn.lab')
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ddns_delete'").fetchone()[0] == (
        'dyn.lab: kea1.dyn.lab, kea2.dyn.lab')
    r = admin.post('/zones/dyn.lab/reclaim', data={'reclaim': '1', 'reclaim_after': '1d'}, follow_redirects=False)
    assert r.headers['location'] == '/zones/dyn.lab?stale=1#stale'
    row = zone_row(conn, 'dyn.lab')
    assert row['reclaim'] == 1 and row['reclaim_after'] == 86400
    assert 'error=' in admin.post('/zones/dyn.lab/reclaim', data={'reclaim_after': 'soon'},
                                  follow_redirects=False).headers['location']
    settings_page = admin.get('/zones/dyn.lab/settings').text
    assert 'Reclaim stale DHCP names' in settings_page and 'value="1d"' in settings_page
    assert 'Reclaim stale DHCP names' not in admin.get('/zones/static.lab/settings').text


def test_ipam_setting(admin, conn):  # noqa: F811
    page = admin.get('/settings/ipam').text
    assert 'name="keep_seen_names" value="1" checked' in page
    admin.post('/settings/ipam', data={'keep_days': '7', 'flap_changes': '3', 'flap_minutes': '10', 'resolver': '',
                                       'ptr_hours': '24'})
    assert db.connect(conn.execute('PRAGMA database_list').fetchone()[2]).execute(
        'SELECT keep_seen_names FROM ipam_settings').fetchone()[0] == 0
