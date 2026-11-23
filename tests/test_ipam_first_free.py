"""First available on an IPAM network page: a link to the lowest Free address with no name in DNS, on
whichever page it is."""

import ipaddress

from liteblox.ipam import model, names, view
from test_ipam import admin, viewer  # noqa: F401 (fixtures)


class Facts:
    def __init__(self, *used, rdns=()):
        self.used = sorted(int(ipaddress.IPv4Address(u)) for u in used)
        self.rdns = {ipaddress.IPv4Address(ip): {'name': name} for ip, name in rdns}

    def used_between(self, first, last):
        return [u for u in self.used if first <= u <= last]


def net(prefix):
    return model.Network(0, prefix)


def test_first_free_skips_what_is_used():
    assert str(view.first_free(Facts(), net('10.0.0.0/24'))) == '10.0.0.1'
    assert str(view.first_free(Facts('10.0.0.1', '10.0.0.2', '10.0.0.4'), net('10.0.0.0/24'))) == '10.0.0.3'
    # the network address never counts as free, and a gap below the first used one is found
    assert str(view.first_free(Facts('10.0.0.0', '10.0.0.5'), net('10.0.0.0/24'))) == '10.0.0.1'
    assert view.first_free(Facts(*(f'10.0.0.{i}' for i in range(1, 7))), net('10.0.0.0/29')) is None
    assert view.first_free(Facts(), net('10.0.0.7/32')) is None


def test_an_address_with_an_rdns_name_is_skipped():
    # Free on paper, but the resolver has a name for it: something probably uses it
    facts = Facts('10.0.0.1', rdns=[('10.0.0.2', 'printer.example.'), ('10.0.0.3', ''), ('10.9.9.9', 'x.example.')])
    assert str(view.first_free(facts, net('10.0.0.0/24'))) == '10.0.0.3'


def test_first_free_on_a_later_page():
    used = [f'10.1.{b}.{i}' for b in range(2) for i in range(256)]
    assert str(view.first_free(Facts(*used), net('10.1.0.0/22'))) == '10.1.2.0'


def test_the_link(viewer, conn):
    model.add_network(conn, '10.9.9.0/29', 'Small')
    page = viewer.get('/ipam/networks/1').text
    assert '<a class="small" href="/ipam/networks/1?ip=10.9.9.1#ip-10.9.9.1"' in page and '>First available</a>' in page
    names.save(conn, '10.9.9.1', 'one')
    page = viewer.get('/ipam/networks/1?used=1').text
    assert 'href="/ipam/networks/1?ip=10.9.9.2#ip-10.9.9.2"' in page
    # following it shows the row, highlighted, even from Used only
    page = viewer.get('/ipam/networks/1?ip=10.9.9.2').text
    assert '<tr id="ip-10.9.9.2" class="free focus' in page
    # one the resolver has a name for is passed over
    conn.execute("INSERT INTO ipam_ptr (ip, name, looked_up_at) VALUES ('10.9.9.2', 'old.example.', 0)")
    conn.commit()
    assert 'href="/ipam/networks/1?ip=10.9.9.3#ip-10.9.9.3"' in viewer.get('/ipam/networks/1').text
    for i in range(2, 7):
        names.save(conn, f'10.9.9.{i}', f'h{i}')
    page = viewer.get('/ipam/networks/1').text
    assert 'First available' not in page and 'No free address' in page
