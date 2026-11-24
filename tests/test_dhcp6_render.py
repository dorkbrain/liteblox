"""DHCPv6's foundations (6.0): address helpers, schema v43, kea-dhcp6.conf from the DB, the dev guard, the apply path
with three Kea files, and bootstrap / Repair setting kea-dhcp6 up."""

import ipaddress
import json
import sqlite3

import pytest

from liteblox import addrs, db
from liteblox.dhcp import apply as dhcp_apply, validate
from liteblox.dhcp.model import (KeaConfig, Reservation6, Subnet6, for_node, ha_pair, settings6, subnets6)
from liteblox.dhcp.render import render
from liteblox.nodes import bootstrap as bootstrap_mod, service as nodes
from liteblox.pki import PKI

from test_managed import FakeNode, lab  # noqa: F401 (fixtures)
from test_nodes import FP, HOST_KEY, FakeAgent, FakeRemote

LAB = 'fd00:1:2:100::/64'
ENS19 = [{'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24', 'fe80::1/64', 'fd00:1:2:100::213/64']}]


# ── addresses ──────────────────────────────────────────────────────────────────

def test_addrs_read_and_sort_both_families():
    assert addrs.ip(' [fd00::1] ') == ipaddress.IPv6Address('fd00::1')
    assert addrs.ip_or_none('nope') is None and addrs.family('10.0.0.0/8') == 4 and addrs.family('fd00::5') == 6
    assert addrs.family('x') is None
    assert sorted(['fd00::2', '10.0.0.10', 'junk', '10.0.0.9', 'fd00::1'], key=addrs.sort_key) == \
        ['10.0.0.9', '10.0.0.10', 'fd00::1', 'fd00::2', 'junk']
    assert sorted(['fd00::/48', '10.0.0.0/8', 'fd00::/64'], key=addrs.net_sort_key) == \
        ['10.0.0.0/8', 'fd00::/48', 'fd00::/64']
    assert addrs.net('fd00:1:2:100::7/64') == ipaddress.IPv6Network(LAB)
    assert addrs.is_host_scope('fd00::1') and not addrs.is_host_scope('fe80::1') and not addrs.is_host_scope('ff02::1')


# ── schema ─────────────────────────────────────────────────────────────────────

def save_subnet6(conn, prefix=LAB, interface='ens19', **cols):
    values = {'prefix': prefix, 'interface': interface, 'pools': 'fd00:1:2:100::1000 - fd00:1:2:100::1fff', **cols}
    with conn:
        return conn.execute(f"INSERT INTO dhcp6_subnets ({', '.join(values)}) VALUES ({', '.join('?' * len(values))})",
                            tuple(values.values())).lastrowid


def test_schema_v43(conn):
    assert db.schema_version(conn) == len(db.MIGRATIONS) >= 43
    assert settings6(conn).preferred_lifetime is None and ha_pair(conn).port6 == 8002
    sid = save_subnet6(conn, pd_pools=json.dumps([{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}]))
    with conn:
        conn.execute("INSERT INTO dhcp6_reservations (subnet_id, duid, ip_address) VALUES (?, '00:01:aa', 'fd00:1:2:100::50')",
                     (sid,))
    with pytest.raises(sqlite3.IntegrityError):            # by DUID or by MAC: one of them
        with conn:
            conn.execute("INSERT INTO dhcp6_reservations (subnet_id, hostname) VALUES (?, 'x')", (sid,))
    with pytest.raises(sqlite3.IntegrityError):            # one reservation per address
        with conn:
            conn.execute("INSERT INTO dhcp6_reservations (subnet_id, hw_address, ip_address) "
                         "VALUES (?, 'aa:bb:cc:00:00:01', 'fd00:1:2:100::50')", (sid,))
    with conn:          # two name-only reservations are fine
        for mac in ('aa:bb:cc:00:00:01', 'aa:bb:cc:00:00:02'):
            conn.execute("INSERT INTO dhcp6_reservations (subnet_id, hw_address, hostname) VALUES (?, ?, 'n')", (sid, mac))
    (s,) = subnets6(conn)
    assert s.pd_pools == [{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}] and len(s.reservations) == 3
    assert s.reservations[0].identifier == ('duid', '00:01:aa') and s.reservations[1].identifier[0] == 'hw-address'


# ── rendering ──────────────────────────────────────────────────────────────────

def test_kea_dhcp6_conf_only_for_nodes_that_have_it():
    assert set(render(KeaConfig())) == {'kea-dhcp4.conf', 'kea-dhcp-ddns.conf'}
    d6 = json.loads(render(KeaConfig(dhcp6=True))['kea-dhcp6.conf'])['Dhcp6']
    assert d6['interfaces-config']['interfaces'] == [] and d6['subnet6'] == []
    assert d6['control-socket'] == {'socket-type': 'unix', 'socket-name': '/run/kea/kea6-ctrl-socket'}
    assert d6['lease-database']['name'] == '/var/lib/kea/kea-leases6.csv'
    assert d6['user-context'] == {'generated-by': 'LiteBlox'}
    assert d6['host-reservation-identifiers'] == ['hw-address', 'duid']


def test_a_dhcp6_subnet_renders():
    subnet = Subnet6(3, LAB, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'],
                     pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}],
                     options={'dns': ['fd00:1:2:100::213', 'fd00:1:2:100::214'], 'search': ['ddns.lab'],
                              'ntp': ['fd00:1:2:100::214']},
                     preferred_lifetime=3000, valid_lifetime=4000, extra={'rapid-commit': True, 'id': 99},
                     reservations=[Reservation6(1, 3, hw_address='aa:bb:cc:00:00:01', hostname='byname'),
                                   Reservation6(2, 3, duid='00:01:00:01:aa', prefix='fd00:1:2:f100::/60'),
                                   Reservation6(3, 3, duid='00:01:00:01:bb', ip_address='fd00:1:2:100::50',
                                                hostname='client')])
    d6 = json.loads(render(KeaConfig(dhcp6=True, subnets6=[subnet], interfaces6=['ens19']))['kea-dhcp6.conf'])['Dhcp6']
    assert d6['interfaces-config']['interfaces'] == ['ens19']
    (s,) = d6['subnet6']
    assert s['id'] == 3 and s['subnet'] == LAB and s['interface'] == 'ens19' and s['rapid-commit'] is True
    assert s['pools'] == [{'pool': 'fd00:1:2:100::1000 - fd00:1:2:100::1fff'}]
    assert s['pd-pools'] == [{'prefix': 'fd00:1:2:f000::', 'prefix-len': 52, 'delegated-len': 60}]
    assert s['option-data'] == [{'name': 'dns-servers', 'data': 'fd00:1:2:100::213, fd00:1:2:100::214'},
                                {'name': 'domain-search', 'data': 'ddns.lab'},
                                {'name': 'sntp-servers', 'data': 'fd00:1:2:100::214'}]
    assert s['preferred-lifetime'] == 3000 and s['valid-lifetime'] == 4000
    assert s['reservations'] == [      # by address, then prefix, then name only
        {'duid': '00:01:00:01:bb', 'ip-addresses': ['fd00:1:2:100::50'], 'hostname': 'client'},
        {'duid': '00:01:00:01:aa', 'prefixes': ['fd00:1:2:f100::/60']},
        {'hw-address': 'aa:bb:cc:00:00:01', 'hostname': 'byname'}]


def dhcp_lab(conn, dhcp6=1):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp6 = ?, dhcp_interfaces = '[\"ens19\"]', "
                     "kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks'", (dhcp6,))


def test_for_node_reads_the_db(conn, lab):  # noqa: F811
    dhcp_lab(conn)
    save_subnet6(conn)
    save_subnet6(conn, 'fd00:1:2:200::/64', 'ens20')        # not an interface ns1 serves
    cfg = for_node(conn, nodes.get_node(conn, 1))
    assert cfg.dhcp6 and [s.prefix for s in cfg.subnets6] == [LAB] and cfg.interfaces6 == ['ens19']
    d6 = json.loads(render(cfg)['kea-dhcp6.conf'])['Dhcp6']
    assert [s['subnet'] for s in d6['subnet6']] == [LAB]
    # a node from before 6.0's Repair: no kea-dhcp6.conf
    with conn:
        conn.execute('UPDATE nodes SET dhcp6 = 0 WHERE id = 1')
    assert 'kea-dhcp6.conf' not in render(for_node(conn, nodes.get_node(conn, 1)))


def test_the_standby_serves_dhcp6_under_its_own_names(conn, settings, lab):  # noqa: F811
    from liteblox.dhcp import store
    dhcp_lab(conn)
    save_subnet6(conn)
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001, {'ens19': 'eth0.100'})
    theirs = json.loads(render(for_node(conn, nodes.get_node(conn, 2)))['kea-dhcp6.conf'])['Dhcp6']
    assert theirs['interfaces-config']['interfaces'] == ['eth0.100'] and theirs['subnet6'][0]['interface'] == 'eth0.100'


def test_the_dev_guard_covers_dhcp6(monkeypatch):
    sub = Subnet6(1, 'fd00:bad::/64', 'ens18', pools=['fd00:bad::10 - fd00:bad::ff'])
    files = render(KeaConfig(dhcp6=True, subnets6=[sub], interfaces6=['ens18']))
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '192.0.2.0/24')
    validate.guard_rendered(files)      # a v4 entry alone says nothing about a v6 prefix ...
    # ... but the interface that carries it is refused (the agent's interfaces, as apply reads them)
    lan = [{'name': 'ens18', 'up': True, 'addresses': ['192.0.2.53/24', 'fd00:bad::53/64']}]
    with pytest.raises(validate.Invalid, match='never serves'):
        dhcp_apply._guard({'name': 'ns1'}, files, lan)
    with pytest.raises(validate.Invalid, match='not an interface on ns1'):        # unknown: refused
        dhcp_apply._guard({'name': 'ns1'}, files, [])
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '192.0.2.0/24, fd00:bad::/48')
    with pytest.raises(validate.Invalid, match='refusing to write fd00:bad::/64'):
        validate.guard_rendered(files)
    assert dhcp_apply.served_interfaces(files) == ['ens18']


def test_apply_writes_and_checks_kea_dhcp6(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    dhcp_lab(conn)
    save_subnet6(conn)
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    real_status = FakeNode.status
    monkeypatch.setattr(FakeNode, 'status', lambda self: dict(real_status(self), interfaces=ENS19))
    fakes[1].kea_running['dhcp6'] = True
    lines = []
    assert dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', lines.append) == ['ns1']
    assert 'kea-dhcp6.conf' in fakes[1].kea_files
    assert ('status-get', None) in fakes[1].kea_commands
    assert json.loads(nodes.get_node(conn, 1)['dhcp_files']).keys() == {'kea-dhcp4.conf', 'kea-dhcp6.conf',
                                                                        'kea-dhcp-ddns.conf'}
    assert any('kea-dhcp6' in line for line in lines)
    # kea-dhcp6 down after a change: rolled back like DHCPv4
    fakes[1].kea_running['dhcp6'] = False
    with conn:
        conn.execute("UPDATE dhcp6_subnets SET comment = 'x', pools = 'fd00:1:2:100::2000 - fd00:1:2:100::2fff'")
    with pytest.raises(dhcp_apply.DhcpError, match=r'Kea stopped working after the change \(dhcp6\)'):
        dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', lines.append)


# ── bootstrap / Repair ─────────────────────────────────────────────────────────

NODE = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530, 'host_key': HOST_KEY,
        'host_key_fp': FP}


def run_bootstrap(tmp_path, monkeypatch, remote, node=None, options=None):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', lambda s: None)
    node = dict(node or NODE)
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'),
                            options or bootstrap_mod.Options(dhcp=True), PKI(tmp_path / 'pki').ensure(),
                            tmp_path / 'backups', '0.1.0', print, connect=remote)
    return node, '\n'.join(remote.last.commands)


def test_a_fresh_node_gets_kea_dhcp6(tmp_path, monkeypatch):
    node, joined = run_bootstrap(tmp_path, monkeypatch, FakeRemote)
    assert 'install -y kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server' in joined
    assert 'systemctl mask kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server kea-ctrl-agent' in joined
    assert '/usr/sbin/kea-dhcp6 -t /etc/kea/kea-dhcp6.conf' in joined
    kea_files = FakeRemote.last.uploads[0]
    assert json.loads(kea_files['kea-dhcp6.conf'])['Dhcp6']['interfaces-config']['interfaces'] == []
    assert b'/run/kea/kea6-ctrl-socket' in kea_files['liteblox-kea6-ctrl.service']
    setup = node['dhcp_setup']
    assert setup['dhcp6'] == 1 and json.loads(setup['dhcp_files']).keys() == {
        'kea-dhcp4.conf', 'kea-dhcp6.conf', 'kea-dhcp-ddns.conf'}
    assert 'systemctl restart kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server' in joined


class Before60Remote(FakeRemote):
    """A DHCP node set up by 4.x: Kea for DHCPv4 with LiteBlox's config, no kea-dhcp6 yet."""

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        if cmd == 'test -x /usr/sbin/kea-dhcp6':
            self.commands.append(cmd)
            return 1, ''
        if cmd.startswith('test '):
            self.commands.append(cmd)
            return 0, ''
        if cmd.startswith('grep -qs') and 'kea-dhcp6.conf' in cmd:
            self.commands.append(('sudo ' if sudo else '') + cmd)
            return 1, ''
        if cmd.startswith('grep -qs') and 'kea-dhcp4.conf' in cmd:
            self.commands.append(('sudo ' if sudo else '') + cmd)
            return 0, ''
        return super().run(cmd, sudo, check, label, timeout)


def test_repair_adds_kea_dhcp6_and_keeps_dhcp4(tmp_path, monkeypatch):
    old = {'kea-dhcp4.conf': 'a' * 64, 'kea-dhcp-ddns.conf': 'b' * 64}
    node, joined = run_bootstrap(tmp_path, monkeypatch, Before60Remote, dict(NODE, dhcp_files=json.dumps(old)))
    assert 'systemctl mask kea-dhcp6-server\n' in joined + '\n'          # only the new one: DHCPv4 keeps serving
    assert 'install -y kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server' in joined
    kea_files = Before60Remote.last.uploads[0]
    assert 'kea-dhcp6.conf' in kea_files and 'kea-dhcp4.conf' not in kea_files
    assert 'systemctl restart kea-dhcp6-server && systemctl start' in joined
    assert 'systemctl restart kea-dhcp4-server' not in joined
    files = json.loads(node['dhcp_setup']['dhcp_files'])
    assert files['kea-dhcp4.conf'] == 'a' * 64 and files['kea-dhcp-ddns.conf'] == 'b' * 64 and files['kea-dhcp6.conf']
    assert node['dhcp_setup']['dhcp6'] == 1


def test_install_rev_is_2():
    # 6.0 adds kea-dhcp6 and its socket proxy: every node needs one Repair, so upgrades over mTLS wait for it
    assert bootstrap_mod.INSTALL_REV == 2


def test_a_lost_liteblox_serving_only_dhcp6_is_offered_for_readopt(conn, lab):  # noqa: F811
    with conn:
        conn.execute('UPDATE nodes SET bind = 0 WHERE id = 1')
    status = {'kea': {'installed': True, 'liteblox': True, 'subnets': 0, 'subnets6': 1}}
    assert nodes.other_liteblox(conn, 1, status)
    save_subnet6(conn)
    assert not nodes.other_liteblox(conn, 1, status)
