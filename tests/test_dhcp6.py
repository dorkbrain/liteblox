"""DHCPv6 (6.0 M2): the store, the checks, DDNS (AAAA, ip6.arpa, dual-stack names), the pair on port6, leases."""

import json

import pytest

from liteblox.dhcp import leases, store, validate, validate6
from liteblox.dhcp.model import (Dhcp4Settings, Dhcp6Settings, KeaConfig, KeaLayout, Reservation6, Subnet, Subnet6,
                                 for_node, subnets6)
from liteblox.dhcp.render import derived_reverse_zones, render, reverse_network, reverse_zones_for
from liteblox.nodes import service as nodes
from liteblox.pki import PKI

from test_managed import FakeNode, lab  # noqa: F401 (fixtures)
from test_dhcp6_render import ENS19, LAB, dhcp_lab, save_subnet6

KEY = {'name': 'dhcp-ddns', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0'}


def a_subnet(**kw):
    return Subnet6(kw.pop('id', None), kw.pop('prefix', LAB), '', pools=kw.pop('pools', ['fd00:1:2:100::1000 - fd00:1:2:100::1fff']),
                   **kw)


# ── the store ──────────────────────────────────────────────────────────────────

def test_store_round_trip_and_restore(conn):
    s = a_subnet(id=store.next_subnet6_id(conn), pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}],
                 options={'dns': ['fd00:1:2:100::213']}, preferred_lifetime=3000, ra=True, ra_slaac=True,
                 ra_since='2026-11-23 10:00:00')
    s.interface = 'ens19'
    assert s.id == 1
    snap = store.snapshot(conn)
    store.save_subnet6(conn, s)
    r = Reservation6(None, 1, duid='00:01:aa:bb', ip_address='fd00:1:2:100::50', hostname='pc')
    store.save_reservation6(conn, r)
    assert r.id and store.get_reservation6(conn, r.id).duid == '00:01:aa:bb'
    got = store.get_subnet6(conn, 1)
    assert got.pd_pools == s.pd_pools and got.ra and got.ra_slaac and got.preferred_lifetime == 3000
    store.save_settings6(conn, Dhcp6Settings(3000, 4000, 1000, 2000, {'dns': ['fd00::53']}))
    store.restore(conn, snap)               # an apply that failed: all of it goes
    assert subnets6(conn) == [] and store.get_reservation6(conn, r.id) is None
    store.save_subnet6(conn, s)
    store.delete_subnet6(conn, 1)
    assert store.next_subnet6_id(conn) == 2          # ids are never reused


def test_set_pair_keeps_port6(conn, settings, lab):  # noqa: F811
    from liteblox.dhcp.model import ha_pair
    dhcp_lab(conn)
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001, port6=8012)
    assert ha_pair(conn).port6 == 8012
    save_subnet6(conn)
    store.set_pair(conn, PKI(settings.pki_dir), 2, 1, '198.51.100.54', '198.51.100.53', 8001, {})
    assert ha_pair(conn).port6 == 8012


# ── checks ─────────────────────────────────────────────────────────────────────

def test_a_good_subnet_is_placed_on_its_interface():
    s = a_subnet(pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}])
    assert validate6.check_subnet6(s, [], ENS19) == {} and s.interface == 'ens19'


@pytest.mark.parametrize('kw, field, message', [
    ({'prefix': '10.0.0.0/24'}, 'prefix', 'not an IPv6 prefix'),
    ({'prefix': 'fd00:1:2:100::1/64'}, 'prefix', 'not an IPv6 prefix'),
    ({'prefix': 'fe80::/64'}, 'prefix', 'global or unique-local'),
    ({'prefix': 'fd00:1:2:200::/64'}, 'prefix', 'no DHCP node has an address'),
    ({'pools': ['fd00:1:2:101::1 - fd00:1:2:101::9']}, 'pools', 'not inside'),
    ({'pools': ['fd00:1:2:100::100 - fd00:1:2:100::300']}, 'pools', "this server's own address"),
    ({'pools': ['fd00:1:2:100::1 - fd00:1:2:100::9', 'fd00:1:2:100::5 - fd00:1:2:100::20']}, 'pools', 'overlap'),
    ({'pools': ['fd00:1:2:100::/64']}, 'pools', 'subnet-router anycast'),
    ({'pools': []}, 'pools', 'at least one pool'),
    ({'pd_pools': [{'prefix': 'fd00:1:2:100::/56', 'delegated_len': 60}]}, 'pd_pools', 'overlaps the subnet'),
    ({'pd_pools': [{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 48}]}, 'pd_pools', 'delegated length'),
    ({'pd_pools': [{'prefix': 'fd00:1:3::/48', 'delegated_len': 60},
                   {'prefix': 'fd00:1:3:f000::/52', 'delegated_len': 64}]}, 'pd_pools', 'overlap'),
    ({'options': {'dns': ['192.0.2.53']}}, 'dns', 'not an IPv6 address'),
    ({'options': {'ntp': ['fe80::1']}}, 'ntp', 'not link-local'),
    ({'preferred_lifetime': 5000, 'valid_lifetime': 4000}, 'preferred_lifetime', 'stops being preferred'),
    ({'renew_timer': 2000, 'rebind_timer': 1000}, 'renew_timer', 'before rebind'),
    ({'preferred_lifetime': 1500, 'renew_timer': 1000, 'rebind_timer': 2000}, 'rebind_timer', 'preferred'),
    ({'extra': {'pd-pools': []}}, 'extra', "LiteBlox's"),
])
def test_subnet_errors(kw, field, message):
    errors = validate6.check_subnet6(a_subnet(**kw), [], ENS19)
    assert message in errors.get(field, ''), errors


def test_subnets_dont_overlap_and_the_dev_guard(monkeypatch):
    other = Subnet6(5, 'fd00:1:2::/48', 'ens20', pd_pools=[{'prefix': 'fd00:9::/48', 'delegated_len': 56}])
    assert 'overlaps subnet fd00:1:2::/48' in validate6.check_subnet6(a_subnet(), [other], ENS19)['prefix']
    other.prefix = 'fd00:7::/64'
    s = a_subnet(pd_pools=[{'prefix': 'fd00:9:0:f000::/52', 'delegated_len': 60}])
    assert 'of subnet fd00:7::/64' in validate6.check_subnet6(s, [other], ENS19)['pd_pools']
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '192.0.2.0/24,fd00:1::/32')
    assert 'never serves' in validate6.check_subnet6(a_subnet(), [], ENS19)['prefix']


@pytest.mark.parametrize('text, out', [
    ('fd00:1:2:f000::/52 60', {'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}),
    ('fd00:1:2:f000::/52 /60', {'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}),
    ('fd00:1:2:f000::/52 delegate /64', {'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 64}),
])
def test_pd_pool_lines(text, out):
    assert validate6.parse_pd_pool(text) == out
    assert validate6.parse_pd_pool(validate6.pd_text(out)) == out


@pytest.mark.parametrize('text', ['fd00:1:2:f000::/52', '10.0.0.0/8 24', 'fd00:1:2:f001::/52 60', 'x 60',
                                  'fd00::/16 64'])
def test_bad_pd_pool_lines(text):
    with pytest.raises(ValueError):
        validate6.parse_pd_pool(text)


def test_duids():
    assert validate6.normalize_duid('00-01-00-01-2C-AA BB') == '00:01:00:01:2c:aa:bb'
    assert validate6.normalize_duid('000300 01aabbccddeeff') == '00:03:00:01:aa:bb:cc:dd:ee:ff'
    for bad in ('', '00:01', '0:1:2', 'zz:yy:xx', '00:01:0'):
        assert validate6.normalize_duid(bad) is None


def subnet_with(*reservations, **kw):
    s = a_subnet(id=1, pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}], **kw)
    s.interface = 'ens19'
    s.reservations = list(reservations)
    return s


def test_good_reservations():
    s = subnet_with()
    r = Reservation6(None, 1, duid='00-01-00-01-AA-BB', ip_address='fd00:1:2:100::0050', hostname='PC')
    errors, warnings = validate6.check_reservation6(r, s, ENS19)
    assert errors == {} and warnings == []
    assert (r.duid, r.ip_address, r.hostname) == ('00:01:00:01:aa:bb', 'fd00:1:2:100::50', 'pc')
    r = Reservation6(None, 1, hw_address='AA-BB-CC-00-00-01', prefix='fd00:1:2:f010::/60')
    errors, warnings = validate6.check_reservation6(r, s, ENS19)
    assert errors == {} and 'a DUID is the surer match' in warnings[0]
    r = Reservation6(None, 1, duid='00:01:00:01:cc', prefix='fd00:9::/56')     # outside the pools: a warning
    errors, warnings = validate6.check_reservation6(r, s, ENS19)
    assert errors == {} and 'needs a route' in warnings[0]


@pytest.mark.parametrize('kw, field, message', [
    ({}, 'duid', "client's DUID"),
    ({'duid': '00:01:00:01:aa', 'hw_address': 'aa:bb:cc:00:00:01'}, 'duid', 'not both'),
    ({'duid': 'zz'}, 'duid', 'not a DUID'),
    ({'hw_address': 'aa:bb'}, 'hw_address', 'not a MAC'),
    ({'duid': '00:01:00:01:aa', 'ip_address': '192.0.2.5'}, 'ip_address', 'not an IPv6 address'),
    ({'duid': '00:01:00:01:aa', 'ip_address': 'fd00:9::5'}, 'ip_address', 'is not in'),
    ({'duid': '00:01:00:01:aa', 'ip_address': 'fd00:1:2:100::213'}, 'ip_address', "server's own"),
    ({'duid': '00:01:00:01:aa', 'ip_address': 'fd00:1:2:100::'}, 'ip_address', 'anycast'),
    ({'duid': '00:01:00:01:aa', 'prefix': 'fd00:1:2:100::/60'}, 'prefix', 'overlaps the subnet'),
    ({'duid': '00:01:00:01:aa', 'prefix': 'nope'}, 'prefix', 'not an IPv6 prefix'),
    ({'duid': '00:01:00:01:aa'}, 'ip_address', 'name-only reservation needs'),
    ({'duid': '00:01:00:01:aa', 'ip_address': 'fd00:1:2:100::7', 'hostname': 'a b'}, 'hostname', 'one name'),
    ({'duid': '00:01:00:01:aa', 'ip_address': 'fd00:1:2:100::7', 'options': {'dns': ['10.0.0.1']}}, 'opt_dns', 'IPv6'),
])
def test_reservation_errors(kw, field, message):
    errors, _ = validate6.check_reservation6(Reservation6(None, 1, **kw), subnet_with(), ENS19)
    assert message in errors.get(field, ''), errors


def test_reservation_duplicates():
    have = Reservation6(3, 1, duid='00:01:00:01:aa', ip_address='fd00:1:2:100::50', prefix='fd00:1:2:f000::/60')
    s = subnet_with(have)
    errors, _ = validate6.check_reservation6(Reservation6(None, 1, duid='00:01:00:01:aa', ip_address='fd00:1:2:100::51'),
                                             s, ENS19)
    assert 'already has a reservation' in errors['duid']
    errors, _ = validate6.check_reservation6(Reservation6(None, 1, duid='00:01:00:01:bb', ip_address='fd00:1:2:100::50',
                                                         prefix='fd00:1:2:f000::/56'), s, ENS19)
    assert 'already reserved' in errors['ip_address'] and 'overlaps fd00:1:2:f000::/60' in errors['prefix']
    # the same one, saved again: fine
    assert validate6.check_reservation6(Reservation6(3, 1, duid='00:01:00:01:aa', ip_address='fd00:1:2:100::50'),
                                        s, ENS19)[0] == {}
    # an address another subnet reserved
    elsewhere = [Reservation6(9, 2, duid='00:01:00:01:cc', prefix='fd00:1:2:f010::/60')]
    errors, _ = validate6.check_reservation6(Reservation6(None, 1, duid='00:01:00:01:dd', prefix='fd00:1:2:f010::/60'),
                                             subnet_with(), ENS19, elsewhere)
    assert 'overlaps' in errors['prefix']


def test_name_only_when_the_subnet_registers():
    s = subnet_with(ddns=True, ddns_zone='ddns.lab')
    errors, _ = validate6.check_reservation6(Reservation6(None, 1, duid='00:01:00:01:aa'), s, ENS19)
    assert 'a name' in errors['hostname']
    assert validate6.check_reservation6(Reservation6(None, 1, duid='00:01:00:01:aa', hostname='tv'), s, ENS19)[0] == {}


def test_settings6_checks():
    assert validate6.check_settings6(Dhcp6Settings(3000, 4000, 1000, 2000, {'dns': ['fd00::53'], 'search': ['lab']})) == {}
    assert 'search' in validate6.check_settings6(Dhcp6Settings(options={'search': ['a b']}))
    assert validate6.parse_options6({'dns': 'fd00::1, fd00::2', 'search': '', 'ntp': 'fd00::123'}) == \
        {'dns': ['fd00::1', 'fd00::2'], 'ntp': ['fd00::123']}


def test_ipv6_off_on_the_interface():
    s = subnet_with()
    assert validate6.check_interface_ipv6(s, ENS19) is None
    assert 'IPv6 is off on ens19' in validate6.check_interface_ipv6(
        s, [{'name': 'ens19', 'addresses': ['198.51.100.53/24']}])


# ── DDNS ───────────────────────────────────────────────────────────────────────

def test_ip6_arpa_zones():
    assert str(reverse_network('0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa')) == 'fd00:1:2:100::/64'
    assert reverse_network('d.f.ip6.arpa.') is not None and reverse_network('xy.ip6.arpa') is None
    assert reverse_network('0.168.192.in-addr.arpa') is not None
    assert derived_reverse_zones(LAB) == ['0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa']
    assert len(derived_reverse_zones('fd00:1:2:100::/62')) == 4
    assert derived_reverse_zones('fd00:1:2:100::/58') == [f'{n}.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa' for n in '0123']
    assert derived_reverse_zones('fd00:1:2::/48') == ['2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa']
    assert reverse_zones_for(LAB, ['2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa', '0.168.192.in-addr.arpa']) == \
        ['2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa']


def ddns_config(**kw):
    v6 = Subnet6(7, LAB, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'], ddns=True, ddns_zone='ddns.lab')
    v4 = Subnet(1, '198.51.100.0/24', 'ens19', pools=['198.51.100.100 - 198.51.100.199'], ddns=True,
                ddns_zone='ddns.lab')
    cfg = KeaConfig(interfaces=['ens19'], settings=Dhcp4Settings(ddns_key=KEY), subnets=[v4], primary='192.0.2.53',
                    reverse_zones=['100.51.198.in-addr.arpa', '2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa'], dhcp6=True,
                    subnets6=[v6], interfaces6=['ens19'], **kw)
    return cfg


def test_dhcpv6_registers_aaaa_and_ip6_arpa():
    files = render(ddns_config())
    d6 = json.loads(files['kea-dhcp6.conf'])['Dhcp6']
    assert d6['dhcp-ddns'] == {'enable-updates': True, 'server-ip': '127.0.0.1', 'server-port': 53001}
    (sub,) = d6['subnet6']
    assert sub['ddns-send-updates'] and sub['ddns-qualifying-suffix'] == 'ddns.lab.'
    assert 'ddns-conflict-resolution-mode' not in sub      # no name shared with DHCPv4
    d2 = json.loads(files['kea-dhcp-ddns.conf'])['DhcpDdns']
    assert [d['name'] for d in d2['forward-ddns']['ddns-domains']] == ['ddns.lab.']
    assert [d['name'] for d in d2['reverse-ddns']['ddns-domains']] == ['100.51.198.in-addr.arpa.',
                                                                        '2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa.']
    assert d2['tsig-keys'][0]['name'] == 'dhcp-ddns'


def test_dual_stack_names_need_the_newer_conflict_mode():
    cfg = ddns_config(shared_domains=['ddns.lab'])
    files = render(cfg)
    sub6 = json.loads(files['kea-dhcp6.conf'])['Dhcp6']['subnet6'][0]
    sub4 = json.loads(files['kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]
    assert sub6['ddns-conflict-resolution-mode'] == sub4['ddns-conflict-resolution-mode'] == 'check-exists-with-dhcid'
    # Kea 2.4 doesn't know the setting: its default stays (the second family's name is refused, documented)
    old = render(cfg, KeaLayout(kea_version='2.4.1'))
    assert 'ddns-conflict-resolution-mode' not in old['kea-dhcp6.conf'] + old['kea-dhcp4.conf']


def test_shared_domains_from_the_db(conn, lab):  # noqa: F811
    dhcp_lab(conn)
    with conn:
        zid = conn.execute("INSERT INTO zones (name, kind, dynamic, repo_file) VALUES ('ddns.lab', 'primary', 1, 'x')").lastrowid
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'liteblox'")
        conn.execute("INSERT INTO dhcp4_subnets (id, prefix, interface, pools, ddns, ddns_zone_id) "
                     "VALUES (1, '198.51.100.0/24', 'ens19', '198.51.100.100 - 198.51.100.199', 1, ?)", (zid,))
    save_subnet6(conn, ddns=1, ddns_zone_id=zid)
    assert for_node(conn, nodes.get_node(conn, 1)).shared_domains == ['ddns.lab']
    with conn:
        conn.execute('UPDATE dhcp6_subnets SET ddns = 0')
    assert for_node(conn, nodes.get_node(conn, 1)).shared_domains == []


def test_missing_grants_want_aaaa_for_dhcpv6(conn):
    with conn:
        zid = conn.execute("INSERT INTO zones (name, kind, dynamic, repo_file) VALUES ('ddns.lab', 'primary', 1, 'x')").lastrowid
        kid = conn.execute("INSERT INTO tsig_keys (name, algorithm, secret) VALUES ('dhcp-ddns', 'hmac-sha256', 'x')"
                           ).lastrowid
        conn.execute("INSERT INTO key_grants (key_id, zone_id, scope, name, types) VALUES (?, ?, 'zonesub', '', 'A DHCID')",
                     (kid, zid))
    v6 = Subnet6(7, LAB, 'ens19', ddns=True, ddns_zone='ddns.lab')
    v4 = Subnet(1, '198.51.100.0/24', 'ens19', ddns=True, ddns_zone='ddns.lab')
    assert validate.missing_grants(conn, 'dhcp-ddns', v4, []) == []
    assert validate.missing_grants(conn, 'dhcp-ddns', v6, []) == [('ddns.lab', 'zonesub', '', 'A AAAA DHCID')]


# ── the pair ───────────────────────────────────────────────────────────────────

def test_the_pair_runs_dhcpv6_failover_on_port6(conn, settings, lab):  # noqa: F811
    dhcp_lab(conn)
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001)
    d6 = lambda: json.loads(render(for_node(conn, nodes.get_node(conn, 1)))['kea-dhcp6.conf'])['Dhcp6']
    assert len(d6()['hooks-libraries']) == 1        # no v6 subnet: kea-dhcp6 stays out of the pair (prod's case)
    save_subnet6(conn)
    (_, ha) = d6()['hooks-libraries']
    peers = ha['parameters']['high-availability'][0]['peers']
    assert [p['url'] for p in peers] == ['https://198.51.100.53:8002/', 'https://198.51.100.54:8002/']
    # a partner without kea-dhcp6 (not repaired yet): no failover for DHCPv6
    with conn:
        conn.execute('UPDATE nodes SET dhcp6 = 0 WHERE id = 2')
    assert len(d6()['hooks-libraries']) == 1


def test_apply_waits_for_both_families_in_the_pair(conn, settings, lab, monkeypatch):  # noqa: F811
    from liteblox.dhcp import apply as dhcp_apply
    fakes, _ = lab
    dhcp_lab(conn)
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001)
    save_subnet6(conn)
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    real_status = FakeNode.status
    lan = [{'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24', 'fd00:1:2:100::213/64']}]
    monkeypatch.setattr(FakeNode, 'status', lambda self: dict(real_status(self), interfaces=lan))
    asked = []
    monkeypatch.setattr(dhcp_apply, 'ha_state', lambda c, service='dhcp4': asked.append(service) or 'hot-standby')
    for f in fakes.values():
        f.kea_running['dhcp6'] = True
    lines = []
    dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'test', 'admin', lines.append)
    assert 'dhcp6' in asked and any('hot-standby' in line for line in lines)
    monkeypatch.setattr(dhcp_apply, 'ha_state', lambda c, service='dhcp4': 'hot-standby' if service == 'dhcp4'
                        else 'waiting')
    with conn:
        conn.execute("UPDATE dhcp6_subnets SET comment = 'x', pools = 'fd00:1:2:100::2000 - fd00:1:2:100::2fff'")
    with pytest.raises(dhcp_apply.DhcpError, match=r'ns1 \(DHCPv6\): waiting'):
        dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'test', 'admin', lines.append, ha_wait=3)


# ── leases ─────────────────────────────────────────────────────────────────────

def lease(ip, duid='00:01:00:01:aa', kind='IA_NA', state=0, length=128, subnet=1, **kw):
    return leases._lease6({'ip-address': ip, 'duid': duid, 'type': kind, 'state': state, 'prefix-len': length,
                           'subnet-id': subnet, 'cltt': 1000, 'valid-lft': 3600, **kw}, 1500)


def test_addresses6_merges_leases_and_reservations():
    s = subnet_with(Reservation6(1, 1, duid='00:01:00:01:aa', ip_address='fd00:1:2:100::50'),
                    Reservation6(2, 1, duid='00:01:00:01:bb', ip_address='fd00:1:2:100::51'),
                    Reservation6(3, 1, hw_address='aa:bb:cc:00:00:03', hostname='tv'),
                    Reservation6(4, 1, duid='00:01:00:01:dd', prefix='fd00:1:2:f010::/60'),
                    Reservation6(5, 1, duid='00:01:00:01:ee', hostname='gone'))
    s.ddns, s.ddns_zone = True, 'ddns.lab'
    found = [lease('fd00:1:2:100::50'), lease('fd00:1:2:100::51', duid='00:01:00:01:xx'),
             lease('fd00:1:2:100::1003', duid='00:01:00:01:cc', **{'hw-address': 'aa:bb:cc:00:00:03'}),
             lease('fd00:1:2:100::9', duid='00:01:00:01:99'),
             lease('fd00:1:2:f020::', duid='00:01:00:01:pd', kind='IA_PD', length=60),
             lease('fd00:1:2:f010::', duid='00:01:00:01:dd', kind='IA_PD', length=60),
             lease('fd00:1:2:100::1004', state=2), lease('fd00:1:2:200::1', subnet=2)]
    rows = leases.addresses6(s, found)
    got = [(r['ip'], r['kind'], r['state'], r['label']) for r in rows]
    assert got == [('fd00:1:2:100::9', 'address', 'outside', 'leased outside the pools'),
                   ('fd00:1:2:100::50', 'address', 'online', 'reserved, online'),
                   ('fd00:1:2:100::51', 'address', 'taken', 'reserved, held by another client'),
                   ('fd00:1:2:100::1003', 'address', 'named', 'named, online'),
                   ('fd00:1:2:100::1004', 'address', 'expired-reclaimed', 'expired-reclaimed'),
                   ('fd00:1:2:f010::/60', 'prefix', 'online', 'reserved, online'),
                   ('fd00:1:2:f020::/60', 'prefix', 'leased', 'delegated'),
                   ('', 'address', 'named-offline', 'named, offline')]
    assert rows[3]['hostname'] == 'tv' and rows[-1]['duid'] == '00:01:00:01:ee'
    assert leases.counts6([(None, x) for x in found]) == {1: {'addresses': 4, 'prefixes': 2}, 2: {'addresses': 1,
                                                                                                    'prefixes': 0}}
    assert leases.pool_size6(s) == 4096 and leases.pd_size(s) == 256


class Kea6:
    def __init__(self, rows):
        self.rows, self.sent = rows, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def dhcp_command(self, service, command, arguments=None):
        self.sent.append((service, command, arguments))
        if command == 'lease6-get-page':
            start = arguments['from']
            rows = self.rows if start == 'start' else self.rows[[r['ip-address'] for r in self.rows].index(start) + 1:]
            page = rows[:arguments['limit']]
            return {'result': 0, 'arguments': {'leases': page}} if page else {'result': 3}
        return {'result': 0}


def test_leases6_pages_and_deletes(monkeypatch):
    rows = [{'ip-address': f'fd00:1:2:100::{i:x}', 'duid': '00:01', 'type': 'IA_NA', 'subnet-id': 1} for i in range(1, 8)]
    rows.append({'ip-address': 'fd00:1:2:f000::', 'type': 'IA_PD', 'prefix-len': 60, 'subnet-id': 1})
    kea = Kea6(rows)
    monkeypatch.setattr(leases, 'PAGE', 3)
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: kea)
    got = leases.leases6(None, {'name': 'ns1'})
    assert [x['ip'] for x in got][:2] == ['fd00:1:2:100::1', 'fd00:1:2:100::2'] and got[-1]['prefix'] == 'fd00:1:2:f000::/60'
    assert [a['from'] for _, c, a in kea.sent if c == 'lease6-get-page'] == ['start', 'fd00:1:2:100::3',
                                                                           'fd00:1:2:100::6']
    leases.delete6(None, {'name': 'ns1'}, 'fd00:1:2:f000::/60', 'prefix')
    assert kea.sent[-1] == ('dhcp6', 'lease6-del', {'ip-address': 'fd00:1:2:f000::', 'type': 'IA_PD',
                                                    'update-ddns': True})
