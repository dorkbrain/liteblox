from liteblox.dns import nameservers
from liteblox.dns.zonefile import Zone

ZONE = ('$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n@ NS ns1\n@ NS ns2.example.net.\n'
        'ns1 A 192.0.2.53\nsub NS ns1.elsewhere.org.\n')
NODES = [{'id': 1, 'name': 'ns1', 'host': '192.0.2.53'}, {'id': 2, 'name': 'ns2', 'host': '192.0.2.54'}]


def check(text=ZONE, nodes=NODES, known=None):
    zone = Zone.parse(text, 'example.com.')
    return nameservers.check(zone, nodes, lambda name: (known or {}).get(name.to_text()))


def test_apex_only():
    zone = Zone.parse(ZONE, 'example.com.')
    assert [r.rdata for r in nameservers.apex_ns(zone)] == ['ns1', 'ns2.example.net.']     # not the delegation


def test_unknown_address_is_a_note_not_a_problem():
    entries, problems, notes = check()
    assert [(e['target'], e['addresses'], [n['name'] for n in e['nodes']]) for e in entries] == [
        ('ns1.example.com.', ['192.0.2.53'], ['ns1']), ('ns2.example.net.', None, [])]
    assert problems == []
    assert notes == ["can't tell whether ns2 is listed: LiteBlox doesn't hold the address of ns2.example.net."]


def test_known_addresses_match_nodes():
    entries, problems, notes = check(known={'ns2.example.net.': ['192.0.2.54']})
    assert [n['name'] for n in entries[1]['nodes']] == ['ns2'] and problems == [] and notes == []


def test_unlisted_node_and_stray_nameserver():
    _, problems, notes = check(known={'ns2.example.net.': ['198.51.100.7']})
    assert problems == ["ns2 (192.0.2.54) serves this zone but isn't one of its nameservers, so resolvers never ask it"]
    assert notes == ["ns2.example.net. isn't one of the nodes serving this zone (fine for a secondary elsewhere)"]


def test_in_zone_nameserver_without_address():
    _, problems, _ = check(ZONE + '@ NS ns3\n', nodes=NODES[:1], known={'ns2.example.net.': ['192.0.2.54']})
    assert problems == ["ns3.example.com. is inside this zone but has no A or AAAA record, so the zone won't load"]


def test_node_named_by_host_name():
    nodes = [{'id': 3, 'name': 'lab', 'host': 'ns2.example.net'}]
    entries, problems, _ = check(nodes=nodes)
    assert [n['name'] for n in entries[1]['nodes']] == ['lab'] and problems == []
