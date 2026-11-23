"""IPAM (3.4 M3): what the nodes see (learned entries), MAC changes and flapping, vendors, and their pages."""

import ipaddress
import time
from pathlib import Path

import pytest

from conftest import csrf_from
from liteblox import status
from liteblox.dhcp.model import Reservation
from liteblox.ipam import checks, model, oui, seen, view
from liteblox.nodes import health
from liteblox.nodes.client import AgentError
from test_search import world  # noqa: F401 (fixture)

NOW = 1_800_000_000
ROOT = Path(__file__).resolve().parent.parent
A, B = 'aa:bb:cc:00:00:0a', 'aa:bb:cc:00:00:0b'


def entry(ip, mac, confirmed=0, state='REACHABLE'):
    return {'ip': ip, 'mac': mac, 'dev': 'ens19', 'state': state, 'confirmed': confirmed, 'updated': confirmed}


def rows(conn):
    return [tuple(r) for r in conn.execute('SELECT ip, mac, first_seen, last_seen, node_id, source FROM ipam_seen '
                                           'ORDER BY ip, mac')]


@pytest.fixture
def two_nodes(conn):
    with conn:
        for name in ('ns1', 'ns2'):
            conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp, status) VALUES (?, ?, 'k', 'fp', 'ready')",
                         (name, name))


# ── recording ──────────────────────────────────────────────────────────────────

def test_last_seen_is_when_the_node_confirmed_it_and_never_moves_back(conn, two_nodes):
    seen.record(conn, 1, [entry('192.0.2.10', 'AA-BB-CC-00-00-0A', confirmed=30)], now=NOW)
    assert rows(conn) == [('192.0.2.10', A, NOW - 30, NOW - 30, 1, 'neigh')]
    # a minute later the entry is STALE: it was confirmed 90 s ago, the same moment
    seen.record(conn, 1, [entry('192.0.2.10', A, confirmed=90, state='STALE')], now=NOW + 60)
    assert rows(conn)[0][3] == NOW - 30
    # ns2 has an older copy: last_seen stays, and so does the node that saw it last
    seen.record(conn, 2, [entry('192.0.2.10', A, confirmed=600)], now=NOW + 60)
    assert rows(conn)[0][2:5] == (NOW + 60 - 600, NOW - 30, 1)
    seen.record(conn, 2, [entry('192.0.2.10', A, confirmed=0)], now=NOW + 120)
    assert rows(conn)[0][3:5] == (NOW + 120, 2)


def test_what_isnt_recorded(conn, two_nodes):
    seen.record(conn, 1, [
        {'ip': '192.0.2.1', 'mac': A, 'state': 'PERMANENT', 'confirmed': None},      # typed in, not seen
        entry('192.0.2.2', '00:00:00:00:00:00'), entry('192.0.2.3', 'ff:ff:ff:ff:ff:ff'),
        entry('192.0.2.4', '01:00:5e:00:00:fb'),                                         # multicast
        entry('224.0.0.251', A), entry('127.0.0.1', A), entry('fe80::1', A), entry('nope', A),
        entry('192.0.2.9', 'bc:24:11:6c:51:d8')], now=NOW)
    assert [r[0] for r in rows(conn)] == ['192.0.2.9']


def test_a_mac_change_across_two_nodes(conn, two_nodes):
    seen.record(conn, 1, [entry('192.0.2.10', A, confirmed=100)], now=NOW)
    # ns2 still remembers the old device from before: not a change
    assert seen.record(conn, 2, [entry('192.0.2.10', B, confirmed=500)], now=NOW) == []
    # now ns2 sees B after A was last seen: a change
    assert seen.record(conn, 2, [entry('192.0.2.10', B, confirmed=5)], now=NOW + 60) == [
        ('192.0.2.10', A, B, NOW + 55)]
    # ns1's copy of A is older than that: still B
    assert seen.record(conn, 1, [entry('192.0.2.10', A, confirmed=160)], now=NOW + 60) == []
    assert seen.changes_at(conn, '192.0.2.10') == [{'at': NOW + 55, 'old_mac': A, 'new_mac': B}]
    assert seen.latest(conn)[ipaddress.IPv4Address('192.0.2.10')] == {'mac': B, 'last_seen': NOW + 55, 'macs': 2}


def flap(conn, ip, times, start=NOW, every=60):
    for i in range(times + 1):
        seen.record(conn, None, [entry(ip, A if i % 2 == 0 else B)], now=start + i * every)


def test_flapping_ack_and_flapping_again(conn, two_nodes):
    flap(conn, '192.0.2.20', 2)
    assert seen.flapping(conn, NOW + 180) == []                      # 2 changes: not yet
    flap(conn, '192.0.2.30', 3)
    assert seen.flapping(conn, NOW + 180) == [{'ip': '192.0.2.30', 'changes': 3, 'macs': [A, B],
                                               'last_at': NOW + 180}]
    assert seen.flapping(conn, NOW + 180 + 10 * 60) == []           # the changes fall out of the window
    seen.ack(conn, '192.0.2.30', 'alice', now=NOW + 200)
    assert seen.flapping(conn, NOW + 200) == []
    flap(conn, '192.0.2.30', 1, start=NOW + 300)                     # B → A → B: 2 changes since the ACK
    assert seen.flapping(conn, NOW + 360) == []
    flap(conn, '192.0.2.30', 3, start=NOW + 480)
    assert [f['ip'] for f in seen.flapping(conn, NOW + 700)] == ['192.0.2.30']


def test_the_flapping_thresholds_are_settings(conn, two_nodes):
    flap(conn, '192.0.2.30', 2)
    seen.save_settings(conn, 7, 2, 10)
    assert [f['ip'] for f in seen.flapping(conn, NOW + 120)] == ['192.0.2.30']
    seen.save_settings(conn, 7, 2, 1)
    assert seen.flapping(conn, NOW + 180) == []                     # only the last change is within a minute


def test_flapping_needs_attention(conn, settings, two_nodes):
    flap(conn, '192.0.2.30', 3, start=int(time.time()) - 300)
    found = [p for p in status.problems(conn, settings) if p['area'] == 'ipam']
    assert found == [{'severity': 'warn', 'area': 'ipam', 'node': None, 'link': '/search?q=192.0.2.30#address',
                      'what': '192.0.2.30: 2 different MACs in 10 minutes (an address conflict?)'}]
    seen.ack(conn, '192.0.2.30', 'alice')
    assert not [p for p in status.problems(conn, settings) if p['area'] == 'ipam']


def test_prune_and_forget(conn, two_nodes):
    seen.record(conn, 1, [entry('192.0.2.1', A), entry('192.0.2.2', A, confirmed=8 * 86400)], now=NOW)
    flap(conn, '192.0.2.3', 3)
    seen.ack(conn, '192.0.2.3', 'alice', now=NOW)
    seen.prune(conn, NOW + 1)
    assert sorted({r[0] for r in rows(conn)}) == ['192.0.2.1', '192.0.2.3']
    seen.forget(conn, '192.0.2.3', B)
    assert {r[1] for r in rows(conn) if r[0] == '192.0.2.3'} == {A}
    assert seen.changes_at(conn, '192.0.2.3')                       # A is still there: its history stays
    seen.forget(conn, '192.0.2.3')
    assert seen.changes_at(conn, '192.0.2.3') == [] and not conn.execute('SELECT * FROM ipam_acks').fetchall()
    seen.prune(conn, NOW + 8 * 86400)
    assert rows(conn) == []


def test_devices_are_one_row_per_mac(conn, two_nodes):
    seen.record(conn, 1, [entry('192.0.2.5', A, confirmed=3600), entry('192.0.2.6', A, confirmed=10),
                          entry('192.0.2.7', B, confirmed=20)], now=NOW)
    got = {d['mac']: d for d in seen.devices(conn)}
    assert (got[A]['ip'], got[A]['earlier'], got[A]['first_seen'], got[A]['last_seen'], got[A]['node']) == (
        '192.0.2.6', ['192.0.2.5'], NOW - 3600, NOW - 10, 'ns1')
    assert [d['mac'] for d in seen.devices(conn)] == [A, B]           # the most recent first
    assert seen.recent_mac(conn, '192.0.2.5', within=600, now=NOW) == {}
    assert seen.recent_mac(conn, '192.0.2.6', within=600, now=NOW) == {A: NOW - 10}


# ── the health check ───────────────────────────────────────────────────────────

class Agent:
    def __init__(self, entries=None, error=None):
        self.entries, self.error = entries or [], error

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def neigh(self):
        if self.error:
            raise self.error
        return self.entries


def test_the_health_check_feeds_it(conn, settings, two_nodes, monkeypatch):
    node = conn.execute('SELECT * FROM nodes WHERE id = 1').fetchone()
    monkeypatch.setattr(health.nodes, 'agent_client', lambda s, n, timeout=10.0: Agent([entry('192.0.2.10', A)]))
    health._neighbours(settings, conn, node)
    assert [r[:2] for r in rows(conn)] == [('192.0.2.10', A)]
    # an agent older than 3.4 has no /neigh
    monkeypatch.setattr(health.nodes, 'agent_client',
                        lambda s, n, timeout=10.0: Agent(error=AgentError(404, 'not found')))
    health._neighbours(settings, conn, node)
    assert len(rows(conn)) == 1


# ── vendors ────────────────────────────────────────────────────────────────────

OUI = """OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

BC-24-11   (hex)\t\tProxmox Server Solutions GmbH
BC2411     (base 16)\t\tProxmox Server Solutions GmbH
\t\t\t\tMandelbachtal

00-0C-29   (hex)\t\tVMware, Inc.
000C29     (base 16)\t\tVMware, Inc.
"""


def test_parse_and_vendor(settings):
    assert oui.parse(OUI) == {'bc2411': 'Proxmox Server Solutions GmbH', '000c29': 'VMware, Inc.'}
    assert oui.vendor(settings, 'bc:24:11:6c:51:d8') == ''            # no list yet
    assert oui.info(settings) == {'date': None, 'count': 0}
    oui.path(settings).write_text(OUI)
    assert oui.vendor(settings, 'BC-24-11-6C-51-D8') == 'Proxmox Server Solutions GmbH'
    assert oui.vendor(settings, '00:0c:29:00:00:01') == 'VMware, Inc.'
    assert oui.vendor(settings, '02:00:5e:10:00:01') == 'private address'     # locally administered
    assert oui.vendor(settings, 'aa:bb:cc:00:00:01') == 'private address'
    assert oui.vendor(settings, '00:11:22:33:44:55') == '' and oui.vendor(settings, '') == ''
    assert oui.info(settings)['count'] == 2


def big_list(n=1200):
    return OUI + ''.join(f'00-{i // 256:02X}-{i % 256:02X}   (hex)\t\tMaker {i}\n' for i in range(n))


def test_refresh(conn, settings):
    calls = []

    def fetch(since):
        calls.append(since)
        return 200, big_list().encode()
    assert oui.due(settings)
    assert oui.refresh(settings, conn, fetch=fetch, now=NOW) == 'fetched 1202 prefixes from the MAC vendor list'
    assert calls == [None] and oui.info(settings)['count'] == 1202
    # a week later it asks with If-Modified-Since, and 304 keeps the list
    mtime = int(oui.path(settings).stat().st_mtime)
    assert oui.refresh(settings, conn, fetch=fetch, now=mtime + 60) == 'the MAC vendor list is current'
    assert oui.refresh(settings, conn, fetch=lambda since: (304, None), now=mtime + 8 * 86400) == \
        "the MAC vendor list hasn't changed"
    assert not oui.due(settings, mtime + 8 * 86400)
    # failures leave the old list and are shown on Settings → IPAM
    assert 'only 2 entries' in oui.refresh(settings, conn, force=True, fetch=lambda since: (200, OUI.encode()))
    assert oui.info(settings)['count'] == 1202

    def down(since):
        raise OSError('network is unreachable')
    oui.refresh(settings, conn, force=True, fetch=down, now=NOW)
    assert seen.settings(conn).oui_error == "couldn't fetch the MAC vendor list: network is unreachable"
    assert seen.settings(conn).oui_checked_at == NOW
    oui.refresh(settings, conn, force=True, fetch=fetch)
    assert seen.settings(conn).oui_error is None


# ── in the network view and the checks ─────────────────────────────────────────

def test_the_view_with_what_was_seen(conn, settings, world):  # noqa: F811
    now = int(time.time())
    seen.record(conn, None, [entry('192.0.2.7', A), entry('192.0.2.60', 'aa:bb:cc:00:00:99'),
                             entry('192.0.2.25', B)], now=now)
    n = model.get(conn, model.add_network(conn, '192.0.2.0/24'))
    model.save_range(conn, n, '192.0.2.20', '192.0.2.29', 'static', 'Servers')
    facts = view.gather(conn, settings)
    ranges = model.all_ranges(conn, n, facts.subnets)
    got = {str(r['ip']): r for r in view.rows(facts, n, ranges, {}, used_only=True)}
    assert (got['192.0.2.7']['state'], got['192.0.2.7']['mac'], got['192.0.2.7']['vendor']) == ('seen', A,
                                                                                                'private address')
    assert view.counts(facts, n)['seen'] == 2
    assert [t for _, t, _ in got['192.0.2.25']['checks']] == [
        'Something is here (aa:bb:cc:00:00:0b), in a static range, with no name in DNS: an unknown device?']
    # the printer's reservation is for ...:01, the nodes saw ...:99 there
    assert "It's reserved for aa:bb:cc:00:00:01, but the nodes last saw aa:bb:cc:00:00:99 on it." in [
        t for _, t, _ in got['192.0.2.60']['checks']]
    assert got['192.0.2.7']['checks'] == []                       # seen, not in a static range: nothing to say


def test_a_reservation_where_another_mac_was_seen(conn, settings, world):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.70', B, confirmed=600)], now=NOW)
    r = Reservation(None, 1, A, '192.0.2.70', '')
    assert checks.reservation_warnings(conn, settings, r, now=NOW) == [
        f'The nodes saw {B} on 192.0.2.70 in the last day: another device may be using it.']
    assert checks.reservation_warnings(conn, settings, r, now=NOW + 2 * 86400) == []
    assert checks.reservation_warnings(conn, settings, Reservation(None, 1, B, '192.0.2.70', ''), now=NOW) == []


# ── the pages ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('alice', 'correct-horse', 'admin'))
    return client


@pytest.fixture
def viewer(client, make_user, login):
    login(*make_user('bob', 'correct-horse', 'readonly'))
    return client


def post(client, path, **data):
    token = csrf_from(client.get('/ipam').text)
    return client.post(path, data={'csrf_token': token, **data}, follow_redirects=False)


def test_devices_seen_page(admin, conn, settings, world):  # noqa: F811
    oui.path(settings).write_text(OUI)
    now = int(time.time())
    seen.record(conn, None, [entry('192.0.2.51', 'bc:24:11:6c:51:d8')], now=now)
    flap(conn, '192.0.2.200', 3, start=now - 300)
    page = admin.get('/ipam/seen?q=proxmox').text
    assert 'Proxmox Server Solutions GmbH' in page and 'pc1.lab.example' in page and 'value="proxmox"' in page
    assert 'flapping' in page and '>Forget<' in page
    r = post(admin, '/ipam/seen/forget', ip='192.0.2.51', mac='bc:24:11:6c:51:d8')
    assert r.status_code == 303 and seen.at_address(conn, '192.0.2.51') == []
    assert 'Nothing seen yet' not in admin.get('/ipam/seen').text


def test_the_address_card_and_acknowledge(admin, conn, settings, world):  # noqa: F811
    now = int(time.time())
    flap(conn, '192.0.2.200', 3, start=now - 300)
    card = admin.get('/search?q=192.0.2.200').text
    assert '2 different MACs on 192.0.2.200' in card and 'Acknowledge' in card and 'MAC changes (3)' in card
    assert 'Only the nodes know something is here' in card
    r = post(admin, '/ipam/flapping/192.0.2.200/ack')
    assert r.status_code == 303 and seen.flapping(conn) == []
    assert 'Acknowledge' not in admin.get('/search?q=192.0.2.200').text
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ipam_ack'").fetchone()[0] == '192.0.2.200'


def test_ipam_settings(admin, conn, settings, monkeypatch):
    page = admin.get('/settings/ipam').text
    assert 'value="7"' in page and 'not fetched yet' in page
    r = post(admin, '/settings/ipam', keep_days='14', flap_changes='4', flap_minutes='15')
    assert r.status_code == 303 and (seen.settings(conn).keep_days, seen.settings(conn).flap_changes) == (14, 4)
    r = post(admin, '/settings/ipam', keep_days='0', flap_changes='x', flap_minutes='15')
    assert r.status_code == 422 and 'from 1 to 90' in r.text and 'from 2 to 20' in r.text
    monkeypatch.setattr(oui, '_fetch', lambda since: (200, big_list().encode()))
    r = post(admin, '/settings/ipam/vendors')
    assert 'Fetched%201202%20prefixes' in r.headers['location'] and oui.info(settings)['count'] == 1202
    assert conn.execute("SELECT detail FROM audit WHERE action = 'ipam_vendors'").fetchone()[0] == '1202 prefixes'


def test_read_only(viewer, conn, world):  # noqa: F811
    seen.record(conn, None, [entry('192.0.2.200', A)], now=int(time.time()))
    page = viewer.get('/ipam/seen').text
    assert '192.0.2.200' in page and '/ipam/seen/forget' not in page
    assert viewer.get('/settings/ipam').status_code == 403
    for path in ('/ipam/seen/forget', '/ipam/flapping/192.0.2.200/ack', '/settings/ipam', '/settings/ipam/vendors'):
        assert post(viewer, path, ip='192.0.2.200').status_code == 403


# ── 4.2: how long a seen address counts as in use, apart from how long it's kept ───────

def test_a_seen_address_counts_as_in_use_only_within_seen_hours(conn, settings, world):  # noqa: F811
    now = int(time.time())
    seen.record(conn, None, [entry('192.0.2.7', A)], now=now - 2 * 3600)
    seen.record(conn, None, [entry('192.0.2.8', B)], now=now - 30 * 3600)
    n = model.get(conn, model.add_network(conn, '192.0.2.0/24'))
    assert seen.settings(conn).seen_hours == 24                        # the v37 default

    facts = view.gather(conn, settings)
    got = {str(r['ip']): r for r in view.rows(facts, n, model.all_ranges(conn, n, facts.subnets), {})}
    assert got['192.0.2.7']['state'] == 'seen'
    # older than the window: free on the map, but still kept, with its MAC and when it was seen
    assert (got['192.0.2.8']['state'], got['192.0.2.8']['mac']) == ('free', B)
    assert got['192.0.2.8']['seen']['last_seen'] == now - 30 * 3600
    assert view.counts(facts, n)['seen'] == 1
    assert int(ipaddress.IPv4Address('192.0.2.8')) not in facts.used

    seen.save_settings(conn, 7, 3, 10, seen_hours=48)
    facts = view.gather(conn, settings)
    assert view.counts(facts, n)['seen'] == 2


def test_the_in_use_setting(admin, conn):
    base = {'keep_days': '7', 'flap_changes': '3', 'flap_minutes': '10'}
    assert 'name="seen_hours" value="24"' in admin.get('/settings/ipam').text
    r = post(admin, '/settings/ipam', **base, seen_hours='6')
    assert r.status_code == 303 and seen.settings(conn).seen_hours == 6
    assert 'in use for 6 h' in conn.execute(
        "SELECT detail FROM audit WHERE action = 'ipam_settings' ORDER BY id DESC").fetchone()[0]
    # left out (an older form), it stays as it is
    assert post(admin, '/settings/ipam', **base).status_code == 303 and seen.settings(conn).seen_hours == 6
    for bad, text in (('0', 'from 1 to 2160'), ('x', 'from 1 to 2160'), ('169', 'at most 168 hours (Keep for)')):
        r = post(admin, '/settings/ipam', **base, seen_hours=bad)
        assert r.status_code == 422 and text in r.text, bad
    assert seen.settings(conn).seen_hours == 6


def test_the_network_list_folds_to_squares(admin, conn):
    nid = model.add_network(conn, '192.0.2.0/24', 'Lab')
    model.add_network(conn, '192.0.0.0/16', 'Site')
    page = admin.get(f'/ipam/networks/{nid}').text
    assert 'data-ipam-tree-toggle' in page and 'aria-controls="tree-full"' in page
    assert 'title="192.0.2.0/24 · Lab · 0 of 254 in use"' in page
    assert 'class="sq box" title="192.0.0.0/16 · Site · 1 network"' in page
    assert 'aria-current="page" title="192.0.2.0/24 · Lab' in page
    script = (ROOT / 'liteblox' / 'static' / 'topbar.js').read_text()
    assert "'liteblox-ipam-tree'" in script and 'dataset.ipamTree' in script
