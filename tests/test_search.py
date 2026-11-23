"""Search (3.3.2): what a query is read as, records in every zone, DHCP, the address card, the page and the API."""

import time

import pytest

from liteblox import search
from liteblox.api import tokens
from liteblox.dhcp import leases as lease_mod, store
from liteblox.dhcp.model import Reservation, Subnet
from liteblox.dns import dynamic
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file

LAB = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1
@\tIN\tTXT\t"v=spf1 ip4:192.0.2.5 -all"
ns1\tIN\tA\t192.0.2.53
pc1\tIN\tA\t192.0.2.51 ; Dan's desk
printer\tIN\tA\t192.0.2.60
www\tIN\tCNAME\tpc1
"""
REVERSE = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1.lab.example.
51\tIN\tPTR\tpc1.lab.example.
53\tIN\tPTR\tns1.lab.example.
60\tIN\tPTR\told-printer.lab.example.
"""
DYN = """$TTL 300
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 5 3600 900 1209600 300
@\tIN\tNS\tns1.lab.example.
laptop\tIN\tA\t192.0.2.120
"""
MAC = 'bc:24:11:6c:51:d8'


def add_zone(conn, settings, name, text, **kw):
    Repo(settings.repo_dir).ensure().write(zone_file(name), text, f'Import {name}', 'test')
    with conn:
        conn.execute('INSERT INTO zones (name, repo_file, dynamic, notes) VALUES (?, ?, ?, ?)',
                     (name, zone_file(name), int(kw.get('dynamic', False)), kw.get('notes', '')))
    return conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()


def kea_lease(ip, mac=MAC, hostname='laptop.dyn.lab.example.', state=0, subnet_id=1):
    return lease_mod._lease({'ip-address': ip, 'hw-address': mac, 'hostname': hostname, 'subnet-id': subnet_id,
                             'cltt': time.time(), 'valid-lft': 3600, 'state': state, 'fqdn-fwd': True}, time.time())


@pytest.fixture
def world(conn, settings, monkeypatch):
    """Two static zones, a dynamic one whose primary answers with DYN, a DHCP subnet with a reservation, and
    Kea leases (live.leases / live.errors)."""
    add_zone(conn, settings, 'lab.example', LAB, notes='Office network\nThe printer moves in March')
    add_zone(conn, settings, '2.0.192.in-addr.arpa', REVERSE)
    add_zone(conn, settings, 'dyn.lab.example', DYN, dynamic=True)
    store.save_subnet(conn, Subnet(1, '192.0.2.0/24', 'ens19', pools=['192.0.2.100 - 192.0.2.199'],
                                   comment='lab bridge', ddns=True))
    with conn:      # its clients registered by Kea in dyn.lab.example, through LiteBlox's primary
        conn.execute("UPDATE dhcp4_subnets SET ddns_zone_id = (SELECT id FROM zones WHERE name = 'dyn.lab.example')")
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'liteblox'")
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:00:00:01', '192.0.2.60', 'printer', comment='2nd floor'))

    class Live:
        leases = [kea_lease('192.0.2.120'), kea_lease('192.0.2.130', mac='aa:bb:cc:dd:ee:99', hostname='', state=2)]
        errors = []
        text = DYN
        axfr_calls = 0
    live = Live()

    def axfr(conn, zone_row, transfer=None):
        live.axfr_calls += 1
        if live.text is None:
            raise dynamic.DynamicError("can't read it")
        return live.text
    monkeypatch.setattr(search.dynamic, 'axfr', axfr)
    monkeypatch.setattr(search.dynamic, 'primary_host', lambda conn, row: '192.0.2.53')
    node = {'id': 1, 'name': 'ns1'}
    monkeypatch.setattr(search.lease_mod, 'serving_leases', lambda s, c: ([(node, x) for x in live.leases], live.errors))
    monkeypatch.setattr(search.lease_mod, 'serving', lambda c: [node])
    return live


def run(conn, settings, q, **kw):
    return search.search(conn, settings, q, **kw)


def names(group):
    return sorted(h['rec'].fqdn + ' ' + h['rec'].rtype for h in group.hits)


# ── what a query is ────────────────────────────────────────────────────────────

@pytest.mark.parametrize('q, kind, mac', [
    ('192.0.2.5', 'ip', ''), ('192.0.2.0/24', 'network', ''), ('192.0.2.7/24', 'network', ''),
    ('BC:24:11:6C:51:D8', 'mac', 'bc24116c51d8'), ('bc-24-11', 'mac', 'bc2411'), ('bc24.116c.51d8', 'mac', 'bc24116c51d8'),
    ('bc24116c51d8', 'mac', 'bc24116c51d8'), ('bc:24:1', 'mac', 'bc241'), ('0:1:2', 'mac', '00012'),
    ('cafe', 'text', ''), ('pc1.lab.example.', 'text', ''), ('192.0.2.', 'text', ''), ('2001:db8::1', 'text', ''),
])
def test_parse(q, kind, mac):
    query = search.parse(q)
    assert query.kind == kind and query.mac == mac
    assert search.parse('pc1.lab.example.').needle == 'pc1.lab.example'


def test_too_short():
    assert search.parse('') is None and search.parse(' a ') is None and search.parse('ab') is not None


def test_reverse_network():
    assert str(search.reverse_network('2.0.192.in-addr.arpa')) == '192.0.2.0/24'
    assert str(search.reverse_network('10.in-addr.arpa')) == '10.0.0.0/8'
    assert search.reverse_network('example.com') is None and search.reverse_network('x.in-addr.arpa') is None


# ── records ────────────────────────────────────────────────────────────────────

def test_text_matches_names_values_targets_and_comments(conn, settings, world):
    assert names(run(conn, settings, 'pc1').records) == [
        '51.2.0.192.in-addr.arpa PTR', 'pc1.lab.example A', 'www.lab.example CNAME']
    # a relative CNAME target matches by its full name, a trailing dot doesn't matter
    assert 'www.lab.example CNAME' in names(run(conn, settings, 'pc1.lab.example.').records)
    assert names(run(conn, settings, "dan's").records) == ['pc1.lab.example A']
    assert names(run(conn, settings, 'LAPTOP').records) == ['laptop.dyn.lab.example A']


def test_an_address_matches_a_records_ptr_owners_and_text(conn, settings, world):
    assert names(run(conn, settings, '192.0.2.51').records) == ['51.2.0.192.in-addr.arpa PTR', 'pc1.lab.example A']
    # inside text, 192.0.2.5 is a whole address: not the start of 192.0.2.51
    assert names(run(conn, settings, '192.0.2.5').records) == ['lab.example TXT']


def test_a_network_matches_what_is_inside_it(conn, settings, world):
    res = run(conn, settings, '192.0.2.48/29')
    assert names(res.records) == ['51.2.0.192.in-addr.arpa PTR', '53.2.0.192.in-addr.arpa PTR',
                                  'ns1.lab.example A', 'pc1.lab.example A']
    assert [h['zone']['name'] for h in res.zones.hits] == ['2.0.192.in-addr.arpa']
    assert [h['subnet'].prefix for h in res.subnets.hits] == ['192.0.2.0/24']


def test_a_draft_is_what_is_searched(conn, settings, world):
    row = conn.execute("SELECT * FROM zones WHERE name = 'lab.example'").fetchone()
    Drafts(settings).save(row, LAB + 'scanner\tIN\tA\t192.0.2.61\n', 'admin')
    hits = run(conn, settings, 'scanner').records.hits
    assert [h['rec'].fqdn for h in hits] == ['scanner.lab.example'] and hits[0]['draft']


def test_a_dynamic_zone_falls_back_to_its_history(conn, settings, world):
    world.text = None
    res = run(conn, settings, 'laptop')
    assert names(res.records) == ['laptop.dyn.lab.example A'] and 'dyn.lab.example' in res.stale
    assert res.records.hits[0]['rec'].fqdn == 'laptop.dyn.lab.example'


def test_a_known_down_primary_isnt_waited_for(conn, settings, world):
    with conn:
        conn.execute("INSERT INTO nodes (id, name, host, host_key, host_key_fp, status, role) "
                     "VALUES (1, 'ns1', '192.0.2.53', 'k', 'fp', 'error', 'primary')")
        conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) SELECT id, 1, 'f' FROM zones")
    res = run(conn, settings, 'laptop')
    assert world.axfr_calls == 0 and 'dyn.lab.example' in res.stale


def test_short_queries_skip_the_live_reads(conn, settings, world):
    res = run(conn, settings, 'pc')
    assert world.axfr_calls == 0 and res.skipped == ['dyn.lab.example', 'leases'] and res.leases.count == 0
    assert names(res.records) == ['51.2.0.192.in-addr.arpa PTR', 'pc1.lab.example A', 'www.lab.example CNAME']


def test_a_zone_that_doesnt_parse_is_reported(conn, settings, world):
    add_zone(conn, settings, 'broken.example', '$TTL 3600\n@ IN SOA ns1 h 1 2 3 4 5\nbad IN A ( 192.0.2.9\n')
    res = run(conn, settings, 'ns1')
    assert res.records.count and any(e.startswith("broken.example doesn't parse") for e in res.errors)


def test_the_limit(conn, settings, world):
    res = run(conn, settings, 'lab.example', limit=2)
    assert len(res.records.hits) == 2 and res.records.count > 2 and res.records.cut


# ── DHCP, zones and subnets ────────────────────────────────────────────────────

def test_reservations(conn, settings, world):
    for q in ('192.0.2.60', 'AA-BB-CC-00-00-01', 'aa:bb:cc', 'printer', '2nd floor'):
        assert [h['r'].ip_address for h in run(conn, settings, q).reservations.hits] == ['192.0.2.60'], q


def test_leases(conn, settings, world):
    assert [h['lease']['ip'] for h in run(conn, settings, 'bc24.116c').leases.hits] == ['192.0.2.120']
    assert [h['lease']['ip'] for h in run(conn, settings, 'laptop.dyn').leases.hits] == ['192.0.2.120']
    # an expired lease only shows for its exact address or MAC
    assert run(conn, settings, 'aa:bb:cc:dd').leases.count == 0
    assert [h['lease']['state'] for h in run(conn, settings, 'aa:bb:cc:dd:ee:99').leases.hits] == ['expired-reclaimed']
    assert run(conn, settings, '192.0.2.130').leases.count == 1


def test_a_lease_error_leaves_the_rest(conn, settings, world):
    world.leases, world.errors = [], ["ns1: can't reach the agent"]
    res = run(conn, settings, 'printer')
    assert res.errors == ["Leases: ns1: can't reach the agent"] and res.reservations.count == 1


def test_zones_by_name_and_notes(conn, settings, world):
    assert [h['zone']['name'] for h in run(conn, settings, 'march').zones.hits] == ['lab.example']
    assert [h['zone']['name'] for h in run(conn, settings, 'dyn.lab').zones.hits] == ['dyn.lab.example']
    assert [h['subnet'].id for h in run(conn, settings, 'lab bridge').subnets.hits] == [1]


# ── one address ────────────────────────────────────────────────────────────────

def checks(res):
    return [text for _, text, _ in res.address['checks']]


def test_a_consistent_address(conn, settings, world):
    a = run(conn, settings, '192.0.2.51').address
    assert [h['rec'].fqdn for h in a['names']] == ['pc1.lab.example'] and a['checks'] == []
    assert a['reverse_zone'] == '2.0.192.in-addr.arpa' and a['subnet'].prefix == '192.0.2.0/24' and not a['in_pool']


def test_a_ptr_pointing_elsewhere(conn, settings, world):
    assert checks(run(conn, settings, '192.0.2.60')) == [
        'The PTR points to old-printer.lab.example, but no A record for old-printer.lab.example has this address.']


def test_no_ptr_and_a_lease_not_in_dns(conn, settings, world):
    world.text = DYN.replace('192.0.2.120', '192.0.2.121')
    res = run(conn, settings, '192.0.2.120')
    assert res.address['lease']['mac'] == MAC and checks(res) == [
        "The lease's hostname laptop.dyn.lab.example isn't in DNS at this address."]
    res = run(conn, settings, '192.0.2.121')
    assert checks(res) == ['No PTR record for it in 2.0.192.in-addr.arpa.',
                           "laptop.dyn.lab.example points here, but the address is in 192.0.2.0/24's pool with no "
                           'reservation: DHCP can hand it to another client.']


def test_a_reservation_held_by_another_client(conn, settings, world):
    world.leases = [kea_lease('192.0.2.60', mac='de:ad:be:ef:00:01', hostname='')]
    assert "It's reserved for aa:bb:cc:00:00:01, but de:ad:be:ef:00:01 holds the lease." in checks(
        run(conn, settings, '192.0.2.60'))


def test_an_unused_address(conn, settings, world):
    a = run(conn, settings, '192.0.2.150').address
    assert not a['used'] and a['checks'] == [] and a['in_pool']


# ── the page and the API ───────────────────────────────────────────────────────

@pytest.fixture
def viewer(client, make_user, login):
    login(*make_user('bob', 'correct-horse', 'readonly'))
    return client


def test_the_page(viewer, conn, settings, world):
    page = viewer.get('/search?q=pc1').text
    assert 'Read as text' in page and '<mark>pc1</mark>' in page
    assert 'href="/zones/lab.example?filter=pc1"' in page and 'href="/zones/lab.example?filter=www"' in page
    page = viewer.get('/search?q=192.0.2.60').text
    assert 'id="address"' in page and 'old-printer.lab.example' in page and 'aa:bb:cc:00:00:01' in page
    assert 'Type at least 2' in viewer.get('/search?q=a').text
    assert 'How search works' in viewer.get('/search').text
    assert 'Nothing matches nothing-here' in viewer.get('/search?q=nothing-here').text


def test_the_page_escapes_what_it_shows(viewer, conn, settings, world):
    add_zone(conn, settings, 'x.example', LAB.replace('"v=spf1', '"<script>alert(1)</script> v=spf1'))
    page = viewer.get('/search?q=script').text
    assert '<script>alert' not in page and '&lt;<mark>script</mark>&gt;alert' in page


def test_the_search_box_is_on_every_page(viewer):
    assert 'id="search-box"' in viewer.get('/').text


def test_the_api(client, conn, settings, world, make_user):
    make_user('bob', 'correct-horse', 'readonly')
    token = tokens.create(conn, 'bob', 'ci', 'read', 'test')[1]
    r = client.get('/api/v1/search', params={'q': '192.0.2.60'}, headers={'Authorization': f'Bearer {token}'})
    assert r.status_code == 200
    body = r.json()
    assert body['kind'] == 'ip' and body['reservations']['items'][0]['mac'] == 'aa:bb:cc:00:00:01'
    assert body['address']['ptr'] == ['old-printer.lab.example'] and body['address']['checks'][0]['level'] == 'warn'
    r = client.get('/api/v1/search', params={'q': 'laptop', 'limit': 1}, headers={'Authorization': f'Bearer {token}'})
    assert r.json()['leases']['items'][0]['node'] == 'ns1' and r.json()['records']['count'] == 1
    assert client.get('/api/v1/search', params={'q': 'x'}, headers={'Authorization': f'Bearer {token}'}).status_code == 422
    assert client.get('/api/v1/search', params={'q': 'pc1'}).status_code == 401
