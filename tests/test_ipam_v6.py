"""IPv6 in IPAM and search (6.0): IPv6 networks beside IPv4 ones, the known-addresses page, NDP neighbours, probes,
Add DNS (AAAA + PTR), and search by IPv6 address, prefix and DUID."""

import ipaddress
import json
import time

import pytest

from liteblox import search
from liteblox.dhcp import leases as lease_mod
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation6, Subnet6
from liteblox.ipam import model, names, seen, view, view6

from test_ipam import admin, post  # noqa: F401 (fixtures)
from test_search import add_zone, world  # noqa: F401 (fixture)

NET = 'fd00:1:2:100::/64'
ZONE6 = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1.lab.example.
"""
LAB6 = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1
ns1\tIN\tA\t192.0.2.53
nas\tIN\tAAAA\tfd00:1:2:100::20 ; the NAS
"""
REVERSE6 = 'f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.2.0.0.0.1.0.0.0.0.0.0.d.f.ip6.arpa'.split('.', 16)[-1]


def kea_lease6(ip, duid='00:01:00:01:aa:bb:cc:dd', kind='IA_NA', length=128, hostname='laptop.lab.example.',
               state=0, subnet_id=1):
    return lease_mod._lease6({'ip-address': ip, 'duid': duid, 'type': kind, 'prefix-len': length,
                              'hostname': hostname, 'subnet-id': subnet_id, 'cltt': time.time(), 'valid-lft': 3600,
                              'state': state, 'fqdn-fwd': True}, time.time())


@pytest.fixture
def world6(conn, settings, world):  # noqa: F811
    """The search world, plus v6.lab.example with an AAAA, the /64's reverse zone, a DHCPv6 subnet with a DUID
    reservation (an address and a delegated prefix), and DHCPv6 leases."""
    add_zone(conn, settings, 'v6.lab.example', LAB6)
    add_zone(conn, settings, '0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa',
             ZONE6 + '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0\tIN\tPTR\tnas.v6.lab.example.\n')
    store.save_subnet6(conn, Subnet6(1, NET, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'],
                                     pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}],
                                     comment='lab v6'))
    store.save_reservation6(conn, Reservation6(None, 1, duid='00:01:00:01:00:00:00:30', ip_address='fd00:1:2:100::30',
                                               prefix='fd00:1:2:f010::/60', hostname='router2'))
    world.leases6 = [kea_lease6('fd00:1:2:100::1005'),
                     kea_lease6('fd00:1:2:f020::', duid='00:01:00:01:00:00:00:40', kind='IA_PD', length=60,
                                hostname='')]
    return world


# ── networks ───────────────────────────────────────────────────────────────────

def test_ipv6_networks_nest_beside_ipv4_ones(conn):
    site = model.add_network(conn, 'fd00:1:2::/48', 'Site')
    lan = model.add_network(conn, NET, 'LAN6')
    v4 = model.add_network(conn, '192.0.2.0/24', 'Lab')
    found = model.networks(conn)
    assert [n.prefix for n in found] == ['192.0.2.0/24', 'fd00:1:2::/48', NET]
    by = {n.id: n for n in found}
    assert by[lan].parent_id == site and by[v4].parent_id is None and by[site].container
    assert view.container_counts(by[site]) == {'assigned': 1, 'free': 65535, 'unit': '/64s'}
    assert view.map_prefix(by[site]) == 56
    assert model.leaf_for(found, 'fd00:1:2:100::5').id == lan and model.leaf_for(found, '192.0.2.5').id == v4
    assert model.leaf_for(found, '2001:db8::1') is None
    with pytest.raises(model.IpamError) as e:
        model.add_network(conn, 'ff02::/16')
    assert 'multicast' in e.value.errors['prefix']


def test_ipv6_ranges(conn):
    n = model.get(conn, model.add_network(conn, NET))
    rid = model.save_range(conn, n, 'fd00:1:2:100::1', 'fd00:1:2:100::ff', 'infrastructure', 'routers')
    assert [(str(r.first), str(r.last)) for r in model.ranges(conn, n.id)] == [('fd00:1:2:100::1', 'fd00:1:2:100::ff')]
    with pytest.raises(model.IpamError) as e:
        model.save_range(conn, n, '192.0.2.1', '192.0.2.5')
    assert 'not an IPv6 address' in e.value.errors['first']
    with pytest.raises(model.IpamError) as e:
        model.save_range(conn, n, 'fd00:1:2:100::80', 'fd00:1:2:100::180')
    assert 'overlaps routers' in e.value.errors['first']
    # the DHCPv6 pools show as read-only ranges
    store.save_subnet6(conn, Subnet6(1, NET, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff']))
    from liteblox.dhcp.model import subnets6
    assert [r.label for r in model.all_ranges(conn, n, subnets6(conn))] == ['routers', f'DHCP pool ({NET})']
    assert rid


def test_suggestions_include_dhcpv6_subnets_and_ip6_arpa_zones(conn, settings, world6):
    found = [s['prefix'] for s in model.suggestions(conn)]
    assert NET in found and '192.0.2.0/24' in found
    assert found.index('192.0.2.0/24') < found.index(NET)


# ── what the nodes see ─────────────────────────────────────────────────────────

def test_seen_keeps_global_ipv6_and_drops_link_local(conn):
    now = int(time.time())
    seen.record(conn, None, [{'ip': 'fd00:1:2:100::10', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5},
                             {'ip': 'fe80::be24:11ff:fe6c:51d8', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5},
                             {'ip': '192.0.2.10', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 9}], now=now)
    assert {str(ip) for ip in seen.latest(conn)} == {'fd00:1:2:100::10', '192.0.2.10'}
    (d,) = seen.devices(conn)
    assert d['ip'] == '192.0.2.10' and d['v6'] == ['fd00:1:2:100::10']


def test_health_reads_ipv6_neighbours(conn, settings, monkeypatch):
    from liteblox.nodes import health
    from liteblox.nodes import service as nodes
    calls = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def neigh(self, family=4):
            calls.append(family)
            if family == 6:     # an agent before 6.0 would send its IPv4 table again
                return [{'ip': 'fd00:1:2:100::10', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5},
                        {'ip': '192.0.2.99', 'mac': 'aa:bb:cc:00:00:99', 'confirmed': 5}]
            return [{'ip': '192.0.2.10', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5}]
    monkeypatch.setattr(nodes, 'agent_client', lambda *a, **k: Client())
    node = {'id': None, 'networks': json.dumps(['192.0.2.0/24'])}
    health._neighbours(settings, conn, node)
    assert calls == [4]
    health._neighbours(settings, conn, {**node, 'networks': json.dumps(['192.0.2.0/24', NET])})
    assert calls == [4, 4, 6]
    assert {str(ip) for ip in seen.latest(conn)} == {'192.0.2.10', 'fd00:1:2:100::10'}


# ── the network page ───────────────────────────────────────────────────────────

def test_the_known_addresses(conn, settings, world6):
    n = model.get(conn, model.add_network(conn, NET, 'LAN6'))
    names.save(conn, 'fd00:1:2:100::40', 'printer6', comment='hall')
    seen.record(conn, None, [{'ip': 'fd00:1:2:100::50', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5}])
    facts, prefixes = view6.gather(conn, settings, n)
    rows = view6.rows(facts, n, [], model.notes(conn))
    by = {str(a['ip']): a for a in rows}
    assert list(by) == ['fd00:1:2:100::20', 'fd00:1:2:100::30', 'fd00:1:2:100::40', 'fd00:1:2:100::50',
                        'fd00:1:2:100::1005']
    assert by['fd00:1:2:100::20']['state'] == 'dns' and by['fd00:1:2:100::20']['comment'] == 'the NAS'
    assert [h['rec'].target for h in by['fd00:1:2:100::20']['ptrs']] == ['nas.v6.lab.example']
    assert by['fd00:1:2:100::30']['state'] == 'reserved' and by['fd00:1:2:100::30']['reservation'].hostname == 'router2'
    assert by['fd00:1:2:100::40']['state'] == 'named'
    assert by['fd00:1:2:100::50']['state'] == 'seen' and by['fd00:1:2:100::50']['mac'] == 'bc:24:11:6c:51:d8'
    assert by['fd00:1:2:100::1005']['state'] == 'leased' and by['fd00:1:2:100::1005']['in_pool']
    assert view6.counts(rows) == {'reserved': 1, 'named': 1, 'leased': 1, 'dns': 1, 'seen': 1}
    # the delegated prefixes are outside the /64: a /48 holding both lists them
    site = model.get(conn, model.add_network(conn, 'fd00:1:2::/48', 'Site'))
    site.children = []          # looked at as a leaf here
    assert [(p['prefix'], p['kind'], bool(p['lease'])) for p in view6.gather(conn, settings, site)[1]] == [
        ('fd00:1:2:f010::/60', 'reserved', False), ('fd00:1:2:f020::/60', 'delegated', True)]


def test_the_page_and_its_csv(admin, conn, settings, world6):  # noqa: F811
    nid = model.add_network(conn, NET, 'LAN6')
    page = admin.get(f'/ipam/networks/{nid}').text
    assert 'An IPv6 network' in page and 'Known addresses' in page and 'id="ip-fd00:1:2:100::20"' in page
    assert 'nas.v6.lab.example' in page and '/dhcp/v6/subnets/1/reservations/1">reserved</a>' in page
    assert 'Move…' not in page and 'First available' not in page and 'Overview <span' not in page
    assert 'Reserve</a>' in page and 'duid=00%3A01%3A00%3A01%3Aaa%3Abb%3Acc%3Add' in page
    assert 'AAAA record in v6.lab.example' in page
    home = admin.get('/ipam').text
    assert '3 known addresses' in home       # the AAAA, the reservation and the lease
    csv = admin.get(f'/ipam/networks/{nid}/addresses.csv').text
    assert csv.splitlines()[0].startswith('ip,state,names') and 'fd00:1:2:100::30,reserved' in csv
    settings_page = admin.get(f'/ipam/networks/{nid}/settings').text
    assert "An IPv6 network isn't swept" in settings_page and 'Sweep now' not in settings_page


def test_a_comment_on_an_aaaa_record_and_a_v6_reservation(admin, conn, settings, world6):  # noqa: F811
    from liteblox.dns.drafts import Drafts
    nid = model.add_network(conn, NET)
    r = post(admin, '/ipam/comment', ip='fd00:1:2:100::20', kind='dns', zone='v6.lab.example',
             fqdn='nas.v6.lab.example', comment='the big NAS', back=f'/ipam/networks/{nid}')
    assert r.status_code == 303 and 'error' not in r.headers['location']
    text, _ = Drafts(settings).load(conn.execute("SELECT * FROM zones WHERE name = 'v6.lab.example'").fetchone())
    assert 'fd00:1:2:100::20 ; the big NAS' in text
    r = post(admin, '/ipam/comment', ip='fd00:1:2:100::30', kind='reservation', id='1', comment='upstairs',
             back=f'/ipam/networks/{nid}')
    assert 'error' not in r.headers['location']
    assert conn.execute('SELECT comment FROM dhcp6_reservations WHERE id = 1').fetchone()['comment'] == 'upstairs'


def test_check_an_ipv6_address(admin, conn, monkeypatch):  # noqa: F811
    from liteblox.nodes import service as nodes
    with conn:
        conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp, status, networks) VALUES ('ns1', '192.0.2.53', 'k', 'f', 'ready', ?)",
                     (json.dumps(['192.0.2.0/24', NET]),))
    asked = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def probe(self, addresses, wait=2.0):
            asked.append(addresses)
            return {'method': 'icmp', 'elapsed': 0.2, 'results': {addresses[0]: {
                'replied': True, 'rtt_ms': 0.4, 'state': 'REACHABLE', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 0}}}
    monkeypatch.setattr(nodes, 'agent_client', lambda *a, **k: Client())
    r = post(admin, '/ipam/check', ip='fd00:1:2:100::10')
    assert r.status_code == 200 and asked == [['fd00:1:2:100::10']] and 'bc:24:11:6c:51:d8' in r.text
    assert 'no node on this network' in post(admin, '/ipam/check', ip='2001:db8::1').text


def test_add_dns_makes_an_aaaa_and_its_ptr(admin, conn, settings, world6, monkeypatch):  # noqa: F811
    from liteblox.dns.drafts import Drafts
    from liteblox.ipam import assign
    monkeypatch.setattr(assign, '_publish', lambda *a: ([], []))
    model.add_network(conn, NET)
    page = admin.get('/ipam/dns/fd00:1:2:100::77').text
    assert 'Add the PTR record in 0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa' in page and 'AAAA' in page
    r = post(admin, '/ipam/dns/fd00:1:2:100::77', name='cam', zone='v6.lab.example', publish='draft', ptr='1')
    assert r.status_code == 303 and 'error' not in r.headers['location'], r.headers['location']
    drafts = Drafts(settings)
    text, _ = drafts.load(conn.execute("SELECT * FROM zones WHERE name = 'v6.lab.example'").fetchone())
    assert 'cam\tIN\tAAAA\tfd00:1:2:100::77' in text.replace(' ', '\t') or 'AAAA\tfd00:1:2:100::77' in text \
        or 'fd00:1:2:100::77' in text
    rev, _ = drafts.load(conn.execute("SELECT * FROM zones WHERE name LIKE '%.ip6.arpa'").fetchone())
    assert 'cam.v6.lab.example.' in rev
    assert conn.execute("SELECT detail FROM audit WHERE action = 'record_add'").fetchone()['detail'] == \
        'v6.lab.example: cam.v6.lab.example AAAA fd00:1:2:100::77 (from IPAM)'


def test_an_ipv6_ipam_record(admin, conn):  # noqa: F811
    r = post(admin, '/ipam/names/fd00:1:2:100::40', name='printer6', mac='', comment='hall')
    assert r.status_code == 303
    assert names.get(conn, 'fd00:1:2:100::40')['name'] == 'printer6'


# ── search ─────────────────────────────────────────────────────────────────────

def test_reverse_network_of_ip6_arpa():
    assert str(search.reverse_network('8.b.d.0.1.0.0.2.ip6.arpa')) == '2001:db8::/32'
    assert str(search.reverse_network('0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa')) == NET
    assert search.reverse_network('x.ip6.arpa') is None


def test_search_an_ipv6_address(conn, settings, world6):
    res = search.search(conn, settings, 'fd00:1:2:100::20')
    assert sorted(h['rec'].rtype for h in res.records.hits) == ['AAAA', 'PTR']
    a = res.address
    assert [h['rec'].fqdn for h in a['names']] == ['nas.v6.lab.example'] and a['subnet'].prefix == NET
    assert a['reverse_zone'] == '0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa'
    assert [h['zone']['name'] for h in res.zones.hits] == ['0.0.1.0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa']
    r = search.search(conn, settings, 'fd00:1:2:100::30').address
    assert r['reservations'][0].hostname == 'router2' and not r['in_pool']
    leased = search.search(conn, settings, 'fd00:1:2:100::1005').address
    assert leased['lease']['duid'] == '00:01:00:01:aa:bb:cc:dd' and leased['in_pool']


def test_search_a_prefix_a_duid_and_a_delegated_prefix(conn, settings, world6):
    res = search.search(conn, settings, NET)
    assert [h['subnet'].prefix for h in res.subnets.hits] == [NET]
    assert {h['lease']['ip'] for h in res.leases.hits} == {'fd00:1:2:100::1005'}
    res = search.search(conn, settings, '00:01:00:01:00:00:00:30')
    assert [h['r'].hostname for h in res.reservations.hits] == ['router2'] and res.query.label == 'a DUID'
    assert search.search(conn, settings, '52:54:00').query.label == 'a MAC address'
    res = search.search(conn, settings, 'fd00:1:2:f020::7')
    assert [h['lease']['prefix'] for h in res.leases.hits] == ['fd00:1:2:f020::/60']
    out = search.to_dict(search.search(conn, settings, 'router2'))
    assert out['reservations']['items'][0]['duid'] == '00:01:00:01:00:00:00:30'
    assert out['reservations']['items'][0]['prefix'] == 'fd00:1:2:f010::/60'


def test_the_search_page_for_ipv6(admin, conn, world6):  # noqa: F811
    page = admin.get('/search?q=fd00:1:2:100::30').text
    assert '/dhcp/v6/subnets/1/addresses?filter=fd00:1:2:100::30' in page and 'Move to…' not in page
    page = admin.get('/search?q=router2').text
    assert 'fd00:1:2:f010::/60' in page and '00:01:00:01:00:00:00:30' in page
    page = admin.get(f'/search?q={NET}').text
    assert 'DHCPv6 subnet' in page and 'href="/dhcp/v6/subnets/1"' in page


def test_devices_seen_lists_a_devices_ipv6_addresses(admin, conn, settings, world6):  # noqa: F811
    seen.record(conn, None, [{'ip': '192.0.2.10', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 9},
                             {'ip': 'fd00:1:2:100::20', 'mac': 'bc:24:11:6c:51:d8', 'confirmed': 5},
                             {'ip': 'fd00:1:2:100::99', 'mac': 'aa:bb:cc:00:00:99', 'confirmed': 5}])
    page = admin.get('/ipam/seen').text
    assert '<a href="/search?q=fd00:1:2:100::20#address"><code>fd00:1:2:100::20</code></a>' in page
    # an IPv6-only device has its IPv6 address as its address, and its AAAA name
    row = page.split('fd00:1:2:100::99</code>')[1].split('</tr>')[0]
    assert 'aa:bb:cc:00:00:99' in row
    assert 'nas.v6.lab.example' in page
    csv = admin.get('/ipam/seen.csv').text.splitlines()
    assert csv[0].endswith(',ipv6') and any(line.startswith('192.0.2.10,') and 'fd00:1:2:100::20' in line for line in csv)


def test_a_stale_ptr_for_an_ipv6_address_names_aaaa():
    from types import SimpleNamespace
    from liteblox.ipam.checks import address_checks
    rec = SimpleNamespace(target='old.lab.example.', name='0.5.0.0', rdata='old.lab.example.')
    hits = [{'zone': '0.0.1.0.d.f.ip6.arpa', 'rec': rec}]
    texts = [t for _, t, _ in address_checks(ipaddress.ip_address('fd00:1::50'), [], hits, '0.0.1.0.d.f.ip6.arpa',
                                             None, None, None, False)]
    assert texts == ['The PTR points to old.lab.example., but no AAAA record for old.lab.example. has this address.']
