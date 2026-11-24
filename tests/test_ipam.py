"""IPAM (3.4 M2): networks and their derived tree, ranges, suggestions, notes, the network view, the checks and
form warnings, and the pages."""

import ipaddress
import json

import pytest

from conftest import csrf_from
from liteblox import db
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation, Subnet, subnets
from liteblox.ipam import checks, model, view
from liteblox.nodes.service import own_networks
from test_search import add_zone, world  # noqa: F401 (fixture)


def ip(text):
    return ipaddress.IPv4Address(text)


def add(conn, prefix, name=''):
    return model.add_network(conn, prefix, name)


def by_prefix(conn):
    return {n.prefix: n for n in model.networks(conn)}


# ── the tree ───────────────────────────────────────────────────────────────────

def test_a_bigger_network_adopts_the_ones_inside_it(conn):
    add(conn, '192.168.1.0/24')
    add(conn, '192.168.10.0/24')
    add(conn, '10.0.0.0/24')
    assert all(n.parent_id is None for n in model.networks(conn))
    home = add(conn, '192.168.0.0/16', 'Home')
    nets = by_prefix(conn)
    assert nets['192.168.1.0/24'].parent_id == home and nets['192.168.10.0/24'].parent_id == home
    assert nets['10.0.0.0/24'].parent_id is None
    assert nets['192.168.0.0/16'].container and not nets['192.168.1.0/24'].container
    assert [n.prefix for n in model.networks(conn)] == ['10.0.0.0/24', '192.168.0.0/16', '192.168.1.0/24',
                                                        '192.168.10.0/24']
    assert [n.prefix for n in model.roots(model.networks(conn))] == ['10.0.0.0/24', '192.168.0.0/16']


def test_any_depth_and_deleting_moves_them_up(conn):
    top = add(conn, '10.0.0.0/8')
    site = add(conn, '10.20.0.0/16')
    leaf = add(conn, '10.20.5.0/24')
    nets = by_prefix(conn)
    assert (nets['10.20.0.0/16'].parent_id, nets['10.20.5.0/24'].parent_id) == (top, site)
    assert nets['10.20.5.0/24'].depth == 2
    assert [p.id for p in model.path(model.networks(conn), nets['10.20.5.0/24'])] == [top, site]
    model.delete_network(conn, site)
    assert model.get(conn, leaf).parent_id == top
    assert model.leaf_for(model.networks(conn), '10.20.5.9').id == leaf
    assert model.leaf_for(model.networks(conn), '10.99.0.1').id == top
    assert model.leaf_for(model.networks(conn), '192.0.2.1') is None


@pytest.mark.parametrize('prefix, message', [
    ('192.168.1.0', 'like 192.168.0.0/24'),
    ('fe80::/64', 'link-local'),
    ('fd00::/127', 'too small'),
    ('192.168.1.0/31', 'too small'),
])
def test_networks_refused(conn, prefix, message):
    with pytest.raises(model.IpamError) as e:
        add(conn, prefix)
    assert message in e.value.errors['prefix']


def test_host_bits_are_dropped_and_a_network_is_added_once(conn):
    add(conn, '192.168.1.7/24')
    assert list(by_prefix(conn)) == ['192.168.1.0/24']
    with pytest.raises(model.IpamError, match='already in IPAM'):
        add(conn, '192.168.1.0/24')


def test_a_network_with_ranges_takes_no_network_inside_it(conn):
    n = model.get(conn, add(conn, '192.168.1.0/24'))
    model.save_range(conn, n, '192.168.1.1', '192.168.1.9', 'infrastructure')
    with pytest.raises(model.IpamError, match='has ranges of its own'):
        add(conn, '192.168.1.0/26')
    add(conn, '192.168.0.0/16')            # a container above it is fine


def test_update_and_delete(conn):
    n = add(conn, '192.168.1.0/24')
    model.update_network(conn, n, ' LAN ', 'the house')
    got = model.get(conn, n)
    assert (got.name, got.comment, got.label) == ('LAN', 'the house', 'LAN')
    model.delete_network(conn, n)
    assert model.get(conn, n) is None


# ── ranges ─────────────────────────────────────────────────────────────────────

POOLED = Subnet(1, '192.168.1.0/24', 'ens19', pools=['192.168.1.100 - 192.168.1.199'])


def test_ranges(conn):
    n = model.get(conn, add(conn, '192.168.1.0/24'))
    rid = model.save_range(conn, n, '192.168.1.1', '192.168.1.20', 'infrastructure', 'Servers', subnets=[POOLED])
    model.save_range(conn, n, '192.168.1.30', '', 'reserved', subnets=[POOLED])       # one address
    got = model.all_ranges(conn, n, [POOLED])
    assert [(str(r.first), str(r.last), r.kind) for r in got] == [
        ('192.168.1.1', '192.168.1.20', 'infrastructure'), ('192.168.1.30', '192.168.1.30', 'reserved'),
        ('192.168.1.100', '192.168.1.199', 'dhcp')]
    assert got[2].dhcp and got[2].subnet_id == 1 and got[0].size == 20 and ip('192.168.1.5') in got[0]
    # a change may overlap itself
    model.save_range(conn, n, '192.168.1.1', '192.168.1.25', 'infrastructure', 'Servers', range_id=rid)
    assert str(model.ranges(conn, n.id)[0].last) == '192.168.1.25'
    model.delete_range(conn, n.id, rid)
    assert len(model.ranges(conn, n.id)) == 1


@pytest.mark.parametrize('first, last, field, message', [
    ('192.168.1.10', '192.168.1.40', 'first', 'overlaps'),
    ('192.168.1.150', '192.168.1.160', 'first', 'DHCP pool'),
    ('192.168.1.0', '192.168.1.5', 'first', 'within 192.168.1.1 – 192.168.1.254'),
    ('192.168.1.250', '192.168.1.255', 'first', 'within'),
    ('192.168.1.60', '192.168.1.50', 'last', 'comes before'),
    ('192.168.2.1', '192.168.2.2', 'first', 'within'),
    ('nope', '192.168.1.2', 'first', 'not an IPv4 address'),
])
def test_ranges_refused(conn, first, last, field, message):
    n = model.get(conn, add(conn, '192.168.1.0/24'))
    model.save_range(conn, n, '192.168.1.30', '192.168.1.39', subnets=[POOLED])
    with pytest.raises(model.IpamError) as e:
        model.save_range(conn, n, first, last, subnets=[POOLED])
    assert message in e.value.errors[field]


def test_a_container_holds_no_ranges(conn):
    add(conn, '192.168.1.0/24')
    home = model.get(conn, add(conn, '192.168.0.0/16'))
    with pytest.raises(model.IpamError, match='holds other networks'):
        model.save_range(conn, home, '192.168.200.1', '192.168.200.9')


def test_deleting_a_network_takes_its_ranges(conn):
    n = model.get(conn, add(conn, '192.168.1.0/24'))
    model.save_range(conn, n, '192.168.1.1', '192.168.1.9')
    model.delete_network(conn, n.id)
    assert conn.execute('SELECT count(*) FROM ipam_ranges').fetchone()[0] == 0


# ── suggestions and notes ──────────────────────────────────────────────────────

def test_suggestions(conn, settings, world):  # noqa: F811
    # the DHCP subnet and the reverse zone are the same network: offered once
    assert model.suggestions(conn) == [{'prefix': '192.0.2.0/24', 'source': 'dhcp', 'why': 'lab bridge'}]
    add(conn, '192.0.0.0/16')               # a /16 with nothing inside it is a leaf: it covers it
    assert model.suggestions(conn) == []
    add(conn, '192.0.1.0/24')               # now the /16 is a container, which doesn't
    assert [s['prefix'] for s in model.suggestions(conn)] == ['192.0.2.0/24']
    add(conn, '192.0.2.0/25')               # a leaf inside it covers part of it only
    assert [s['prefix'] for s in model.suggestions(conn)] == ['192.0.2.0/24']
    add(conn, '192.0.2.0/24')
    assert model.suggestions(conn) == []


def test_a_reverse_zone_alone_is_suggested(conn, settings):
    add_zone(conn, settings, '20.10.in-addr.arpa', '$TTL 300\n@ IN SOA ns1.x. h.x. 1 1 1 1 1\n@ IN NS ns1.x.\n')
    assert model.suggestions(conn) == [{'prefix': '10.20.0.0/16', 'source': 'zone', 'why': '20.10.in-addr.arpa'}]


def test_notes(conn):
    model.set_note(conn, '192.168.1.7', ' kept for the NAS ', 'alice')
    assert model.notes(conn) == {'192.168.1.7': 'kept for the NAS'}
    model.set_note(conn, '192.168.1.7', 'the NAS', 'bob')
    assert model.notes(conn) == {'192.168.1.7': 'the NAS'}
    model.set_note(conn, '192.168.1.7', '', 'bob')
    assert model.notes(conn) == {}


# ── the network view ───────────────────────────────────────────────────────────

def lab_view(conn, settings, **kw):
    n = model.get(conn, add(conn, '192.0.2.0/24'))
    facts = view.gather(conn, settings)
    ranges = model.all_ranges(conn, n, facts.subnets)
    rows = {str(r['ip']): r for r in view.rows(facts, n, ranges, model.notes(conn), **kw)}
    return n, facts, rows


def test_states_and_counts(conn, settings, world):  # noqa: F811
    n, facts, rows = lab_view(conn, settings)
    assert len(rows) == 256
    assert {k: rows[k]['state'] for k in ('192.0.2.51', '192.0.2.53', '192.0.2.60', '192.0.2.120', '192.0.2.130',
                                          '192.0.2.5')} == {
        '192.0.2.51': 'dns', '192.0.2.53': 'dns', '192.0.2.60': 'reserved', '192.0.2.120': 'leased',
        '192.0.2.130': 'free',      # an expired lease isn't a use
        '192.0.2.5': 'free'}        # only mentioned in an SPF record
    assert (rows['192.0.2.0']['kind'], rows['192.0.2.255']['kind'], rows['192.0.2.1']['kind']) == (
        'network', 'broadcast', 'host')
    assert view.counts(facts, n) == {'reserved': 1, 'named': 0, 'leased': 1, 'dns': 2, 'seen': 0, 'free': 250}
    assert view.usage(facts, n) == (4, 254)
    assert rows['192.0.2.120']['in_pool'] and rows['192.0.2.120']['range'].dhcp
    assert rows['192.0.2.60']['mac'] == 'aa:bb:cc:00:00:01' and rows['192.0.2.60']['hostname'] == 'printer'
    assert rows['192.0.2.120']['lease']['mac'] == 'bc:24:11:6c:51:d8'


def test_used_only(conn, settings, world):  # noqa: F811
    _, _, rows = lab_view(conn, settings, used_only=True)
    assert list(rows) == ['192.0.2.51', '192.0.2.53', '192.0.2.60', '192.0.2.120']


def test_comments_come_from_where_they_live(conn, settings, world):  # noqa: F811
    model.set_note(conn, '192.0.2.7', 'kept for the NAS', 'alice')
    model.set_note(conn, '192.0.2.51', 'ignored: the record has one', 'alice')
    _, _, rows = lab_view(conn, settings)
    pc1, printer, laptop, free = (rows[k] for k in ('192.0.2.51', '192.0.2.60', '192.0.2.120', '192.0.2.7'))
    assert pc1['comment'] == "Dan's desk" and pc1['comment_from'] == {
        'kind': 'dns', 'zone': 'lab.example', 'name': 'pc1', 'fqdn': 'pc1.lab.example', 'draft': False}
    # the A record has no comment, its reservation has
    assert printer['comment'] == '2nd floor' and printer['comment_from']['kind'] == 'reservation'
    # a dynamic zone's name keeps no comment: an IPAM note
    assert laptop['comment'] == '' and laptop['comment_from'] == {'kind': 'note'}
    assert free['comment'] == 'kept for the NAS' and free['comment_from'] == {'kind': 'note'}
    # an address with an A record and no comment anywhere: an edit goes to the record
    assert rows['192.0.2.53']['comment_from']['kind'] == 'dns'


def test_the_view_checks(conn, settings, world):  # noqa: F811
    _, _, rows = lab_view(conn, settings)
    texts = lambda k: [t for _, t, _ in rows[k]['checks']]
    assert texts('192.0.2.51') == [] and texts('192.0.2.7') == []
    assert texts('192.0.2.60') == [
        'The PTR points to old-printer.lab.example, but no A record for old-printer.lab.example has this address.']
    assert texts('192.0.2.120') == ['No PTR record for it in 2.0.192.in-addr.arpa.']


def test_paging_by_256(conn):
    big = model.get(conn, add(conn, '10.0.0.0/22'))
    small = model.get(conn, add(conn, '10.1.0.0/26'))
    assert (view.pages(big), view.pages(small)) == (4, 1)
    assert view.page_bounds(big, 2) == (ip('10.0.2.0'), ip('10.0.2.255'))
    assert view.page_bounds(small, 0) == (ip('10.1.0.0'), ip('10.1.0.63'))
    assert view.page_of(big, '10.0.3.7') == 3
    facts = view.Facts()
    rows = view.rows(facts, big, [], {}, page=3)
    assert len(rows) == 256 and rows[-1]['kind'] == 'broadcast' and rows[0]['kind'] == 'host'
    assert len(view.rows(facts, small, [], {})) == 64


def test_blocks_of_a_bigger_network(conn, settings, world):  # noqa: F811
    n = model.get(conn, add(conn, '192.0.2.0/23'))
    facts = view.gather(conn, settings)
    blocks = view.blocks(facts, n)
    assert [(str(b['first']), b['used'], b['size']) for b in blocks] == [('192.0.2.0', 4, 255), ('192.0.3.0', 0, 255)]
    assert [b['level'] for b in blocks] == [1, 0]
    assert view.blocks(facts, model.get(conn, add(conn, '10.0.0.0/24'))) == []
    assert (view.level(0, 256), view.level(1, 256), view.level(200, 256), view.level(256, 256)) == (0, 1, 3, 4)


def test_the_address_map(conn, settings, world):  # noqa: F811
    n, facts, _ = lab_view(conn, settings)
    ranges = model.all_ranges(conn, n, facts.subnets)
    cells = view.cells(view.rows(facts, n, ranges, {}), ranges)
    by_ip = {str(c['ip']): c for c in cells}
    assert by_ip['192.0.2.0']['state'] == 'edge' and by_ip['192.0.2.60']['state'] == 'reserved'
    assert by_ip['192.0.2.60']['checks'] and not by_ip['192.0.2.51']['checks']
    assert by_ip['192.0.2.120']['band'] == 0 and by_ip['192.0.2.51']['band'] is None
    assert by_ip['192.0.2.51']['title'] == '192.0.2.51: DNS · pc1.lab.example'


def test_the_donut():
    parts = view.svg_donut([('reserved', 1), ('leased', 0), ('free', 3)])
    assert [p[0] for p in parts] == ['reserved', 'free']
    length = float(parts[0][2].split()[0])
    assert abs(length - 2 * 3.14159 * 40 / 4) < 0.01 and parts[0][3] == '-0.00'
    assert view.svg_donut([('free', 0)]) == []


def test_a_containers_map(conn):
    add(conn, '192.168.1.0/24', 'LAN')
    add(conn, '192.168.2.0/25')
    home = model.get(conn, add(conn, '192.168.0.0/16'))
    cells = view.container_map(view.Facts(), home)
    assert len(cells) == 256
    assert cells[0]['child'] is None and cells[0]['level'] == 0 and cells[0]['title'].endswith('not assigned')
    assert cells[1]['child'].name == 'LAN' and cells[1]['level'] == 4
    assert cells[2]['share'] == 0.5 and cells[2]['level'] == 2
    assert view.container_counts(home) == {'assigned': 384, 'free': 65536 - 384, 'unit': 'addresses'}
    small = model.get(conn, add(conn, '10.0.0.0/24'))
    add(conn, '10.0.0.0/26')
    small = model.get(conn, small.id)
    assert len(view.container_map(view.Facts(), small)) == 64       # /30 cells


# ── checks and form warnings ───────────────────────────────────────────────────

def hit(fqdn, address, zone='lab.example', rtype='A', target=''):
    from liteblox.search import Rec
    return {'zone': zone, 'rec': Rec(1, fqdn.split('.')[0], fqdn, rtype, address, '', ip(address), target),
            'draft': False, 'dynamic': False}


def test_several_names_on_one_address_are_fine():
    a = ip('192.0.2.9')
    found = checks.address_checks(a, [hit('a.lab.example', '192.0.2.9'), hit('b.lab.example', '192.0.2.9')], [],
                                  None, None, None, None, False)
    assert not any('names point here' in t for _, t, _ in found)
    assert [t for _, t, _ in found] == ['No reverse zone in LiteBlox covers this address, so it has no PTR here.']


def test_a_reservation_named_differently_from_dns():
    r = Reservation(4, 1, 'aa:bb:cc:00:00:02', '192.0.2.9', 'nas')
    found = checks.address_checks(ip('192.0.2.9'), [hit('fileserver.lab.example', '192.0.2.9')], [], None, r, None,
                                  None, False)
    assert ('warn', "It's reserved for nas, but DNS names it fileserver.lab.example.",
            '/dhcp/subnets/1/addresses?filter=192.0.2.9') in found
    same = Reservation(4, 1, 'aa:bb:cc:00:00:02', '192.0.2.9', 'fileserver')
    assert not [c for c in checks.address_checks(ip('192.0.2.9'), [hit('fileserver.lab.example', '192.0.2.9')], [],
                                                 None, same, None, None, False) if 'reserved for' in c[1]]


def test_record_warnings(conn, settings, world):  # noqa: F811
    assert checks.record_warnings(conn, 'printer.lab.example.', 'A', '192.0.2.60') == []
    assert checks.record_warnings(conn, 'scanner.lab.example.', 'A', '192.0.2.60') == [
        '192.0.2.60 is reserved in DHCP for printer (aa:bb:cc:00:00:01) in 192.0.2.0/24.']
    assert checks.record_warnings(conn, 'tv.lab.example.', 'A', '192.0.2.150') == [
        "192.0.2.150 is in 192.0.2.0/24's DHCP pool with no reservation: DHCP can hand it to another client."]
    assert checks.record_warnings(conn, 'tv.lab.example.', 'A', '192.0.2.20') == []
    assert checks.record_warnings(conn, 'tv.lab.example.', 'TXT', '"192.0.2.150"') == []


def test_record_warnings_show_when_a_record_is_saved(conn, settings, world):  # noqa: F811
    from liteblox.dns import editing
    edit = editing.ZoneEdit(settings, conn, 'lab.example')
    _, warnings, _ = editing.apply_row(edit, None, 'tv', '', 'A', '192.0.2.150', '', False, None, 'alice')
    assert any('DHCP pool with no reservation' in w for w in warnings)
    # a comment-only change of a record doesn't repeat it
    edit = editing.ZoneEdit(settings, conn, 'lab.example')
    rec = next(r for r in edit.zone.records() if r.rtype == 'A' and r.rdata == '192.0.2.150')
    _, warnings, _ = editing.apply_row(edit, rec, 'tv', '', 'A', '192.0.2.150', 'the TV', False, None, 'alice')
    assert not any('DHCP pool' in w for w in warnings)


def test_reservation_warnings(conn, settings, world):  # noqa: F811
    r = Reservation(None, 1, 'aa:bb:cc:00:00:07', '192.0.2.51', 'laptop2')
    assert checks.reservation_warnings(conn, settings, r) == ['DNS names 192.0.2.51 pc1.lab.example, not laptop2.']
    assert checks.reservation_warnings(conn, settings, Reservation(None, 1, 'aa:bb:cc:00:00:07', '192.0.2.51',
                                                                   'pc1')) == []
    assert checks.reservation_warnings(conn, settings, Reservation(None, 1, 'aa:bb:cc:00:00:07', '192.0.2.52',
                                                                   'x')) == []


# ── nodes' own networks ────────────────────────────────────────────────────────

def test_own_networks():
    status = {'interfaces': [
        {'name': 'ens18', 'up': True, 'addresses': ['192.168.1.213/24', 'fe80::1/64']},
        {'name': 'ens19', 'up': True, 'addresses': ['192.168.0.213/24', '192.168.0.13/24', 'bad']},
        {'name': 'lo', 'up': True, 'addresses': ['127.0.0.1/8']}]}
    assert own_networks(status) == ['192.168.1.0/24', '192.168.0.0/24']
    assert own_networks(None) == [] and own_networks({}) == []


def test_the_schema(conn):
    assert db.schema_version(conn) == len(db.MIGRATIONS) >= 28
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(nodes)')}
    assert 'networks' in cols


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


def test_the_pages(admin, conn, settings, world):  # noqa: F811
    home = admin.get('/ipam').text
    assert 'Not in IPAM yet' in home and '192.0.2.0/24' in home and 'Add a network' in home
    r = post(admin, '/ipam/networks', prefix='192.0.2.0/24', name='Lab')
    assert r.status_code == 303 and r.headers['location'].startswith('/ipam/networks/')
    page = admin.get(r.headers['location']).text
    assert 'id="ip-192.0.2.51"' in page and 'pc1.lab.example' in page and "Dan&#39;s desk" in page
    assert 'Utilization' in page and '4 of 254 in use' in page and '>Settings<' in page
    assert 'no LiteBlox node is on this network' in page
    nid = r.headers['location'].rsplit('/', 1)[1]
    used = admin.get(f'/ipam/networks/{nid}?used=1').text
    assert used.count('<tr id="ip-') == 4
    assert 'class="addresses ipam-table"' in admin.get(f'/ipam/networks/{nid}?ip=192.0.2.60').text
    assert 'Ranges' in admin.get(f'/ipam/networks/{nid}/settings').text
    # the container page
    r = post(admin, '/ipam/networks', prefix='192.0.0.0/16', name='Site')
    page = admin.get(r.headers['location']).text
    assert 'It holds 1 network' in page and '/ipam/networks/' + nid in page
    assert admin.get('/ipam/networks/999').status_code == 404


def test_adding_a_network_with_an_error(admin, conn):
    r = post(admin, '/ipam/networks', prefix='192.168.1.0', name='x')
    assert r.status_code == 422 and 'like 192.168.0.0/24' in r.text and 'value="x"' in r.text


def test_ranges_from_the_settings_page(admin, conn):
    nid = add(conn, '192.168.1.0/24')
    r = post(admin, f'/ipam/networks/{nid}/ranges', first='192.168.1.1', last='192.168.1.9', kind='infrastructure',
             name='Switches')
    assert r.status_code == 303
    rid = model.ranges(conn, nid)[0].id
    r = post(admin, f'/ipam/networks/{nid}/ranges', first='192.168.1.5', last='192.168.1.20', kind='static')
    assert r.status_code == 422 and 'it overlaps Switches' in r.text
    r = post(admin, f'/ipam/networks/{nid}/ranges', range_id=str(rid), first='192.168.1.1', last='192.168.1.12',
             kind='infrastructure', name='Switches')
    assert r.status_code == 303 and str(model.ranges(conn, nid)[0].last) == '192.168.1.12'
    assert 'Change the range' in admin.get(f'/ipam/networks/{nid}/settings?edit={rid}').text
    assert post(admin, f'/ipam/networks/{nid}/ranges/{rid}/delete').status_code == 303
    assert model.ranges(conn, nid) == []
    assert post(admin, f'/ipam/networks/{nid}/settings', name='LAN', comment='house').status_code == 303
    assert model.get(conn, nid).name == 'LAN'
    assert post(admin, f'/ipam/networks/{nid}/delete').status_code == 303 and model.get(conn, nid) is None
    actions = [r['action'] for r in conn.execute('SELECT action FROM audit WHERE action LIKE ?', ('ipam%',))]
    assert actions == ['ipam_range_add', 'ipam_range_edit', 'ipam_range_delete', 'ipam_network_edit',
                       'ipam_network_delete']


def test_comments_write_back(admin, conn, settings, world):  # noqa: F811
    from liteblox.dns.drafts import Drafts
    nid = add(conn, '192.0.2.0/24')
    back = f'/ipam/networks/{nid}'
    r = post(admin, '/ipam/comment', ip='192.0.2.7', kind='note', comment='the NAS', back=back)
    assert r.status_code == 303 and 'ip=192.0.2.7' in r.headers['location']
    assert model.notes(conn) == {'192.0.2.7': 'the NAS'}
    r = post(admin, '/ipam/comment', ip='192.0.2.51', kind='dns', zone='lab.example', fqdn='pc1.lab.example',
             comment="Dan's new desk", back=back)
    assert 'draft' in r.headers['location']
    text, draft = Drafts(settings).load(conn.execute("SELECT * FROM zones WHERE name = 'lab.example'").fetchone())
    assert draft and [line for line in text.splitlines() if line.startswith('pc1')][0].endswith("; Dan's new desk")
    rid = subnets(conn)[0].reservations[0].id
    r = post(admin, '/ipam/comment', ip='192.0.2.60', kind='reservation', id=str(rid), comment='3rd floor', back=back)
    assert subnets(conn)[0].reservations[0].comment == '3rd floor'
    # a reservation that moved away: refused, nothing changed
    r = post(admin, '/ipam/comment', ip='192.0.2.61', kind='reservation', id=str(rid), comment='x', back=back)
    assert 'error=' in r.headers['location'] and subnets(conn)[0].reservations[0].comment == '3rd floor'
    # only back to IPAM pages
    r = post(admin, '/ipam/comment', ip='192.0.2.7', kind='note', comment='x', back='https://example.com/')
    assert r.headers['location'].startswith('/ipam?')


def test_read_only_users_look_but_dont_change(viewer, conn, settings, world):  # noqa: F811
    nid = add(conn, '192.0.2.0/24')
    page = viewer.get(f'/ipam/networks/{nid}').text
    assert 'pc1.lab.example' in page and '>Settings<' not in page and 'hx-post="/ipam/check"' not in page
    assert 'action="/ipam/comment"' not in page
    home = viewer.get('/ipam').text
    assert 'Add a network' not in home and 'Not in IPAM yet' not in home
    assert viewer.get(f'/ipam/networks/{nid}/settings').status_code == 403
    for path, data in (('/ipam/networks', {'prefix': '10.0.0.0/24'}), (f'/ipam/networks/{nid}/delete', {}),
                       ('/ipam/comment', {'ip': '192.0.2.7', 'kind': 'note', 'comment': 'x'}),
                       ('/ipam/check', {'ip': '192.0.2.7'})):
        assert post(viewer, path, **data).status_code == 403
    assert model.notes(conn) == {} and len(model.networks(conn)) == 1


class FakeAgent:
    def __init__(self, answer):
        self.answer = answer
        self.asked = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def probe(self, addresses, wait=2.0):
        self.asked.append(addresses)
        return self.answer


@pytest.fixture
def node_on_lab(conn):
    with conn:
        conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp, status, networks) "
                     "VALUES ('ns1', '192.0.2.53', 'k', 'fp', 'ready', ?)", (json.dumps(['192.0.2.0/24']),))


@pytest.mark.parametrize('result, shown', [
    ({'replied': True, 'rtt_ms': 0.4, 'state': 'REACHABLE', 'mac': 'aa:bb:cc:00:00:09', 'confirmed': 0},
     'answers (0.4 ms)'),
    ({'replied': False, 'rtt_ms': None, 'state': 'REACHABLE', 'mac': 'aa:bb:cc:00:00:09', 'confirmed': 1},
     'no ping reply, but aa:bb:cc:00:00:09 answers ARP'),
    # an old STALE entry proves nothing
    ({'replied': False, 'rtt_ms': None, 'state': 'STALE', 'mac': 'aa:bb:cc:00:00:09', 'confirmed': 900},
     'nothing answers'),
    ({'replied': False, 'rtt_ms': None, 'state': None, 'mac': None, 'confirmed': None}, 'nothing answers'),
])
def test_check(admin, conn, monkeypatch, node_on_lab, result, shown):
    from liteblox.ipam import routes
    agent = FakeAgent({'method': 'icmp', 'elapsed': 2.1, 'results': {'192.0.2.7': result}})
    monkeypatch.setattr(routes.nodes, 'agent_client', lambda s, n, timeout=10.0: agent)
    r = post(admin, '/ipam/check', ip='192.0.2.7')
    assert shown in r.text and agent.asked == [['192.0.2.7']]
    page = admin.get(f"/ipam/networks/{add(conn, '192.0.2.0/24')}").text
    assert 'seen from <a href="/nodes/' in page and 'hx-post="/ipam/check"' in page


def test_check_with_no_node_or_an_old_agent(admin, conn, monkeypatch, node_on_lab):
    from liteblox.ipam import routes
    from liteblox.nodes.client import AgentError
    assert 'no node on this network' in post(admin, '/ipam/check', ip='10.9.9.9').text

    class Old(FakeAgent):
        def probe(self, addresses, wait=2.0):
            raise AgentError(404, 'not found')
    monkeypatch.setattr(routes.nodes, 'agent_client', lambda s, n, timeout=10.0: Old(None))
    assert 'agent is too old' in post(admin, '/ipam/check', ip='192.0.2.7').text
