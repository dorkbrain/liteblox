"""Re-adopting nodes without BIND (4.0): DHCP-only and Time-only nodes, DNS registration at another DNS server."""

import json

import pytest

from liteblox import db, modules
from liteblox.bindconf import readopt
from liteblox.config import load_settings
from liteblox.dhcp import apply as dhcp_apply
from liteblox.dhcp import store
from liteblox.dhcp.model import Dhcp4Settings, Reservation, Subnet, settings as load_dhcp, subnets as load_subnets
from liteblox.nodes import service as nodes
from liteblox.ntp import apply as ntp_apply

from test_managed import Client, FakeNode
from test_nodes import FP, HOST_KEY
from test_readopt import HOOKS, NTP_SOURCES, OldNode, build_old, render_old, transfer

KEY = {'name': 'kea-home', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0LWZvci10aGUtb3RoZXItc2VydmVy'}
HOSTS = {'dhcp1': ['192.0.2.53/24', '198.51.100.53/24', '10.1.4.53/22'], 'time1': ['192.0.2.60/24'],
         'dhcp3': ['192.0.2.55/24', '203.0.113.55/24']}


class NoBindNode(OldNode):
    """A node an earlier LiteBlox set up without BIND: the agent has no BIND config to give."""

    def status(self):
        out = FakeNode.status(self)         # (OldNode's knows only ns1/ns2's addresses)
        d4 = json.loads(self.kea_files.get('kea-dhcp4.conf') or '{}').get('Dhcp4') or {}
        out['kea'].update(installed=bool(self.kea_files), subnets=len(d4.get('subnet4') or []),
                          liteblox=(d4.get('user-context') or {}).get('generated-by') == 'LiteBlox')
        out.update(taken_over=False, config_files={}, named_version=None)
        out['interfaces'] = [{'name': f'ens{18 + n}', 'up': True, 'addresses': [a]}
                             for n, a in enumerate(HOSTS[self.name])]
        return out

    def config(self, secrets=False, files=False):
        raise AssertionError('a node without BIND has no /config')


def build_dhcp_only(tmp_path):
    """A LiteBlox without the DNS module: dhcp1 (Kea, registering at another DNS server; chrony serving) and
    time1 (chrony only)."""
    settings = load_settings(tmp_path / 'old' / 'data', tmp_path / 'old' / 'backups')
    db.migrate(settings.db_path)
    conn = db.connect(settings.db_path)
    dhcp1 = nodes.add_node(conn, 'dhcp1', '192.0.2.53', 22, 8530, HOST_KEY, FP, bind=False)
    time1 = nodes.add_node(conn, 'time1', '192.0.2.60', 22, 8530, HOST_KEY, FP, bind=False)
    with conn:
        conn.execute('UPDATE modules SET dns = 0')
        conn.execute("UPDATE nodes SET status = 'ready', agent_version = '4.0.0', ntp = 1")
        conn.execute("UPDATE nodes SET dhcp = 1, kea_hooks_dir = ?, dhcp_interfaces = '[\"ens19\", \"ens20\"]', "
                     "ntp_serve = 1, ntp_allow = '[\"198.51.100.0/24\"]' WHERE id = ?", (HOOKS, dhcp1))
        conn.execute('UPDATE ntp_settings SET sources = ? WHERE id = 1', (NTP_SOURCES,))
    store.save_settings(conn, Dhcp4Settings(valid_lifetime=3600, options={'dns': ['192.0.2.99'], 'domain': 'home.lan'},
                                            ddns_mode='external', ddns_server='192.0.2.99', ddns_port=5353,
                                            ddns_external_key=KEY))
    store.save_subnet(conn, Subnet(2, '198.51.100.0/24', 'ens19', ['198.51.100.100 - 198.51.100.199'],
                                   {'routers': ['198.51.100.1']}, ddns=True, ddns_suffix='dhcp.home.lan'))
    store.save_subnet(conn, Subnet(3, '10.1.4.0/22', 'ens20', ['10.1.5.0 - 10.1.5.255'], ddns=True,
                                   ddns_suffix='lab.home.lan', ddns_reverse='4.1.10.in-addr.arpa'))
    store.save_reservation(conn, Reservation(None, 2, 'aa:bb:cc:dd:ee:01', '198.51.100.50', 'printer'))
    return settings, conn, (dhcp1, time1)


def render_nodes(conn, cls=NoBindNode):
    calls, fakes = [], {}
    for node in nodes.list_nodes(conn):
        fake = cls(node['name'], calls)
        fake.config_files = {}
        if node['dhcp']:
            fake.kea_files = dhcp_apply.files_for(conn, node)
        if node['ntp']:
            fake.chrony_files = ntp_apply.files_for(conn, node)
        fakes[node['name']] = fake
    return fakes


@pytest.fixture
def lost(tmp_path, conn, settings, monkeypatch):
    """The lost LiteBlox's two nodes, added again to a fresh one chosen as IPAM only, and repaired (nothing ticked)."""
    old_settings, old_conn, _ = build_dhcp_only(tmp_path)
    fakes = render_nodes(old_conn)
    with conn:
        conn.execute("UPDATE modules SET dns = 0, dhcp = 0, ntp = 0, ipam = 1, chosen_at = datetime('now')")
    for name, host in (('time1', '192.0.2.60'), ('dhcp1', '192.0.2.53')):
        node_id = nodes.add_node(conn, name, host, 22, 8530, HOST_KEY, FP, bind=False)
        nodes.record_status(conn, node_id, fakes[name].status())
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['name']]))
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    yield old_conn, fakes
    old_conn.close()


def ids(conn):
    return [r['id'] for r in readopt.candidates(conn)]


def test_nodes_without_bind_are_offered(conn, lost):
    assert [r['name'] for r in readopt.candidates(conn)] == ['dhcp1', 'time1']


def test_a_fresh_kea_config_is_not_offered(conn, settings, monkeypatch):
    fake = NoBindNode('dhcp1', [])
    fake.kea_files = dhcp_apply.files_for(None, {'id': 9, 'name': 'dhcp1', 'dhcp': 1})
    node_id = nodes.add_node(conn, 'dhcp1', '192.0.2.53', 22, 8530, HOST_KEY, FP, bind=False)
    status = fake.status()
    assert status['kea']['liteblox'] and status['kea']['subnets'] == 0
    nodes.record_status(conn, node_id, status)
    assert readopt.candidates(conn) == []


def test_preview_and_readopt(conn, settings, lost):
    old_conn, fakes = lost
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.blockers == [] and pv.diffs == {'dhcp1': '', 'time1': ''} and pv.ready
    text = '\n'.join(line for _, lines in readopt.summary(pv.plan) for line in lines)
    assert 'dhcp1: no BIND; DHCP on ens19, ens20' in text and 'time1: no BIND' in text
    assert 'registers clients at another DNS server, 192.0.2.99 port 5353, with key kea-home' in text
    assert KEY['secret'] not in text and KEY['secret'] not in ''.join(pv.diffs.values())
    before = {name: dict(f.kea_files) for name, f in fakes.items()}
    lines = []
    readopt.readopt(conn, settings, ids(conn), 'admin', lines.append)
    assert '✓ LiteBlox manages dhcp1, time1 again' in '\n'.join(lines) or \
        '✓ LiteBlox manages time1, dhcp1 again' in '\n'.join(lines)
    for name, f in fakes.items():         # nothing written to the nodes
        assert f.kea_files == before[name] and 'commit dhcp' not in [w for _, w in f.all_calls]

    s = load_dhcp(conn)
    assert (s.ddns_mode, s.ddns_server, s.ddns_port, s.ddns_external_key, s.ddns_key_id) == (
        'external', '192.0.2.99', 5353, KEY, None)
    assert (s.valid_lifetime, s.options) == (3600, {'dns': ['192.0.2.99'], 'domain': 'home.lan'})
    subs = {x.id: x for x in load_subnets(conn)}
    assert (subs[2].ddns, subs[2].ddns_suffix, subs[2].ddns_reverse, subs[2].ddns_zone_id) == (True, 'dhcp.home.lan', '', None)
    assert (subs[3].ddns_suffix, subs[3].ddns_reverse) == ('lab.home.lan', '4.1.10.in-addr.arpa')
    assert [r.hostname for r in subs[2].reservations] == ['printer']
    by_name = {r['name']: r for r in nodes.list_nodes(conn)}
    for name in ('dhcp1', 'time1'):
        o, n = nodes.get_node(old_conn, name), by_name[name]
        for col in ('bind', 'managed', 'dhcp', 'kea_hooks_dir', 'dhcp_interfaces', 'ntp', 'ntp_serve', 'ntp_allow'):
            assert n[col] == o[col], (name, col)
        assert n['other_liteblox'] == 0
        if n['dhcp']:
            assert dhcp_apply.files_for(conn, n) == fakes[name].kea_files
        assert ntp_apply.files_for(conn, n) == fakes[name].chrony_files
    assert modules.enabled(conn) == {'dns': False, 'dhcp': True, 'ntp': True, 'ipam': True}
    assert conn.execute('SELECT COUNT(*) FROM tsig_keys').fetchone()[0] == 0
    assert readopt.candidates(conn) == []


def test_a_scanner_has_nothing_to_readopt(conn, settings, lost, monkeypatch):
    old_conn, fakes = lost
    fakes['scan1'] = NoBindNode('scan1', [])
    HOSTS['scan1'] = ['192.0.2.61/24']
    scan = nodes.add_node(conn, 'scan1', '192.0.2.61', 22, 8530, HOST_KEY, FP, bind=False)
    pv = readopt.preview(conn, settings, [scan])
    assert pv.blockers == ['scan1: nothing on it was written by a LiteBlox (a scanner has nothing to re-adopt: it '
                           'works as it is)']


def test_a_dhcp_only_node_next_to_bind_nodes(tmp_path, conn, settings, monkeypatch):
    """A full install with a third node running only Kea, registering through LiteBlox's own DNS primary."""
    old_settings, old_conn = build_old(tmp_path)
    dhcp3 = nodes.add_node(old_conn, 'dhcp3', '192.0.2.55', 22, 8530, HOST_KEY, FP, bind=False)
    with old_conn:
        old_conn.execute("UPDATE nodes SET status = 'ready', dhcp = 1, kea_hooks_dir = ?, "
                         "dhcp_interfaces = '[\"ens19\"]' WHERE id = ?", (HOOKS, dhcp3))
        old_conn.execute("UPDATE dhcp4_subnets SET interface = 'ens20' WHERE id = 5")
    zone = old_conn.execute("SELECT id FROM zones WHERE name = 'ddns.lab'").fetchone()[0]
    store.save_subnet(old_conn, Subnet(7, '203.0.113.128/25', 'ens19', ['203.0.113.200 - 203.0.113.250'], ddns=True,
                                       ddns_zone_id=zone))
    with old_conn:      # only dhcp3 serves its subnet: the pair serves ens19's other subnet
        old_conn.execute("UPDATE nodes SET dhcp_interfaces = '[\"ens19\"]' WHERE name IN ('ns1', 'ns2')")
    fakes = render_old(old_conn)
    third = NoBindNode('dhcp3', [])
    third.config_files = {}
    third.kea_files = dhcp_apply.files_for(old_conn, nodes.get_node(old_conn, 'dhcp3'))
    fakes['dhcp3'] = third
    for name, host, bind in (('ns2', '192.0.2.54', True), ('ns1', '192.0.2.53', True), ('dhcp3', '192.0.2.55', False)):
        node_id = nodes.add_node(conn, name, host, 22, 8530, HOST_KEY, FP, bind=bind)
        nodes.record_status(conn, node_id, fakes[name].status())
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['name']]))
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    from liteblox.backups import service as backups
    monkeypatch.setattr(backups, 'snapshot_before_change', lambda *a, **kw: None)
    assert sorted(r['name'] for r in readopt.candidates(conn)) == ['dhcp3', 'ns1', 'ns2']
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.blockers == [] and set(pv.diffs.values()) == {''}, pv.diffs
    assert pv.plan.dhcp['settings']['ddns_mode'] == 'liteblox'
    readopt.readopt(conn, settings, ids(conn), 'admin', lambda line: None, transfer=transfer)
    s = load_dhcp(conn)
    assert (s.ddns_mode, s.ddns_key['name']) == ('liteblox', 'dhcp')
    n = nodes.get_node(conn, 'dhcp3')
    assert (n['bind'], n['managed'], n['dhcp'], n['other_liteblox']) == (0, 0, 1, 0)
    assert dhcp_apply.files_for(conn, n) == third.kea_files
    zone = conn.execute("SELECT id FROM zones WHERE name = 'ddns.lab'").fetchone()[0]
    assert {x.id: x.ddns_zone_id for x in load_subnets(conn)}[7] == zone
    old_conn.close()
