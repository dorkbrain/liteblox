import dns.zone
import pytest

from liteblox.dns.canonical import SortError, note_lines, sorted_text, why_unsorted
from liteblox.dns.validate import ToolMissing, named_checkzone

from test_zonefile import EXAMPLE, private_zones

# the sample zone minus its $GENERATE line, which sits under another $ORIGIN and so can't be sorted
SORTABLE = ''.join(line for line in EXAMPLE.splitlines(keepends=True) if not line.startswith('$GENERATE'))


def rrsets(text, origin):
    # dnspython reads LF only; the zone files themselves may be CRLF
    zone = dns.zone.from_text(text.replace('\r\n', '\n'), origin, relativize=False, check_origin=False)
    return {(name, rds.rdtype, rds.ttl, frozenset(rds)) for name, node in zone.nodes.items() for rds in node}


def check_same_zone(text, origin, checkzone=False):
    out = sorted_text(text, origin)
    assert rrsets(out, origin) == rrsets(text, origin)        # same records, TTLs included
    assert sorted_text(out, origin) == out                    # sorting again changes nothing
    if checkzone:
        try:
            ok, msg = named_checkzone(origin.rstrip('.'), out)
            assert ok, msg
        except ToolMissing:
            pass
    return out


def test_sample_zone_keeps_its_records():
    out = check_same_zone(SORTABLE, 'example.com.', checkzone=True)
    assert '$ORIGIN' not in out and out.count('$TTL') == 1


def test_hierarchy_order():
    text = ('@ 3600 SOA ns1 hostmaster 1 3600 900 1209600 300\n@ 3600 NS ns1\n'
            'a.host 3600 A 192.0.2.3\nzz 3600 A 192.0.2.4\nhost 3600 A 192.0.2.2\n*.wild 3600 A 192.0.2.5\n'
            'b 3600 A 192.0.2.1\n')
    out = check_same_zone(text, 'example.com.')
    assert [line.split()[0] for line in out.splitlines()[3:]] == ['b', 'host', 'a.host', '*.wild', 'zz']


def test_names_are_written_out_and_comments_go_to_the_notes():
    text = ('$TTL 1h\n@ IN SOA ns1 hostmaster 1 3600 900 1209600 300\n\tIN NS ns1\n'
            'zeta\tIN A 192.0.2.9\n\tIN AAAA 2001:db8::9\n'
            '; --- printers ---\nprinter9 IN A 192.0.2.109 ; upstairs\nprinter10 IN A 192.0.2.110\n'
            'ns1 IN A 192.0.2.53\n')
    out = check_same_zone(text, 'example.com.', checkzone=True)
    assert out == ('$TTL 1h\n@ IN SOA ns1 hostmaster 1 3600 900 1209600 300\n@\tIN NS ns1\n\n'
                   'ns1 IN A 192.0.2.53\n'
                   'printer9 IN A 192.0.2.109 ; upstairs\n'           # a comment on the record's own line stays
                   'printer10 IN A 192.0.2.110\n'
                   'zeta\tIN A 192.0.2.9\nzeta\tIN AAAA 2001:db8::9\n')
    moved = []
    sorted_text(text, 'example.com.', moved)
    assert moved == [('; --- printers ---', 'printer9')]
    assert note_lines(moved + [(';', 'x'), ('; old stuff', None)]) == ['--- printers ---  (above printer9)',
                                                                      'old stuff  (at the end)']


def test_reverse_zone_numeric_order():
    text = ('$TTL 1h\n@ SOA ns1.example.com. hostmaster.example.com. 1 1h 15m 1w 5m\n@ NS ns1.example.com.\n'
            '10 PTR ten.example.com.\n2 PTR two.example.com.\n1 PTR one.example.com.\n')
    out = check_same_zone(text, '0.168.192.in-addr.arpa.')
    assert [line.split()[0] for line in out.splitlines()[4:]] == ['1', '2', '10']


def test_values_within_a_name():
    text = ('@ 3600 SOA ns1 hostmaster 1 3600 900 1209600 300\n@ 3600 NS ns1\n'
            'h 3600 TXT "b"\nh 3600 A 192.0.2.10\nh 3600 A 192.0.2.9\nh 3600 MX 20 b\nh 3600 MX 10 z\n')
    out = check_same_zone(text, 'example.com.')
    assert [line.split(None, 2)[2] for line in out.splitlines()[3:]] == [
        'A 192.0.2.9', 'A 192.0.2.10', 'MX 10 z', 'MX 20 b', 'TXT "b"']


def test_later_ttl_and_origin_are_folded_in():
    text = ('$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n@ NS ns1\n'
            '$TTL 5m\nshort A 192.0.2.5\n'
            '$ORIGIN lab.example.com.\nhost CNAME other\n')
    out = check_same_zone(text, 'example.com.')
    assert 'short\t300\tA 192.0.2.5' in out or 'short 300 A 192.0.2.5' in out.replace('\t', ' ')
    assert 'host.lab\t300\tCNAME\tother.lab' in out


@pytest.mark.parametrize('line, message', [
    ('$INCLUDE /etc/bind/other\n', '\\$INCLUDE'),
    ('$ORIGIN sub.example.com.\n$GENERATE 1-3 h$ A 192.0.2.$\n', '\\$GENERATE on line 3 depends on the \\$ORIGIN'),
    ('$GENERATE 1-3 h$ A 192.0.2.$\n$TTL 5m\n', '\\$GENERATE on line 2 depends on the \\$ORIGIN or \\$TTL'),
])
def test_refuses_positional_directives(line, message):
    text = '@ 3600 SOA ns1 hostmaster 1 3600 900 1209600 300\n' + line
    with pytest.raises(SortError, match=message):
        sorted_text(text, 'example.com.')
    assert why_unsorted(text, 'example.com.').startswith('$')


def test_generate_keeps_its_place_after_the_records():
    text = ('$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n; the DHCP range\n$GENERATE 10-12 dyn$ A 192.0.2.$\n'
            'b A 192.0.2.2\na A 192.0.2.1\n')
    out = sorted_text(text, 'example.com.')
    assert out == ('$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n\na A 192.0.2.1\nb A 192.0.2.2\n'
                   '\n; the DHCP range\n$GENERATE 10-12 dyn$ A 192.0.2.$\n')
    assert sorted_text(out, 'example.com.') == out and why_unsorted(out, 'example.com.') is None


def test_crlf_is_kept():
    text = '$TTL 1h\r\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\r\nb A 192.0.2.2\r\na A 192.0.2.1\r\n'
    out = sorted_text(text, 'example.com.')
    assert out == '$TTL 1h\r\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\r\n\r\na A 192.0.2.1\r\nb A 192.0.2.2\r\n'


@pytest.mark.parametrize('path, origin', private_zones())
def test_private_zones_keep_their_records_and_every_comment(path, origin):
    text = path.read_bytes().decode()
    out = check_same_zone(text, origin, checkzone=True)
    moved = []
    sorted_text(text, origin, moved)
    kept = [line.strip() for line in out.splitlines() if line.lstrip().startswith(';')]
    own_line = [line.strip() for line in text.splitlines() if line.lstrip().startswith(';')]
    assert sorted(kept + [c for c, _ in moved]) == sorted(own_line)        # each one in the file or the notes


def test_header_and_soa_comments():
    text = ('; zone file for example.com\n\n$TTL 1h\n; the SOA\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n'
            'b A 192.0.2.2\na A 192.0.2.1\n; the end\n')
    out = check_same_zone(text, 'example.com.')
    assert out == ('; zone file for example.com\n\n$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n'
                   '\na A 192.0.2.1\nb A 192.0.2.2\n')            # the file's own header stays at the top
    moved = []
    sorted_text(text, 'example.com.', moved)
    assert moved == [('; the SOA', '@'), ('; the end', None)]
