from pathlib import Path

import dns.name
import pytest

from liteblox.dns.zonefile import Directive, Unparsed, Zone, ZoneParseError

from conftest import private_zone_params

FIXTURES = Path(__file__).parent / 'fixtures'
EXAMPLE = (FIXTURES / 'zones' / 'example.com.zone').read_text()



def private_zones():
    # real zones (gitignored): fixtures/private/db.<origin>
    return private_zone_params()


def parse(text=EXAMPLE):
    return Zone.parse(text, 'example.com.')


def by_name(zone, name, rtype=None):
    target = dns.name.from_text(name, zone.origin)
    matches = [r for r in zone.records() if r.name == target and (rtype is None or r.rtype == rtype)]
    assert len(matches) == 1, matches
    return matches[0]


def line_of(text, needle):
    return next(line for line in text.splitlines(keepends=True) if needle in line)


def semantic(zone):
    """What the zone means, ignoring layout: comparable across a render/re-parse."""
    return [(r.name, r.ttl, r.rtype, r.rdata.split()) for r in zone.records()]


# ── Round-trips ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('text', [
    EXAMPLE,
    EXAMPLE.replace('\n', '\r\n'),
    EXAMPLE.rstrip('\n'),
    '',
], ids=['lf', 'crlf', 'no-final-newline', 'empty'])
def test_roundtrip_synthetic(text):
    assert parse(text).render() == text


@pytest.mark.parametrize('path, origin', private_zones())
def test_roundtrip_private(path, origin):
    text = path.read_bytes().decode()
    zone = Zone.parse(text, origin)
    assert zone.render() == text
    assert zone.unsupported == []
    assert zone.soa.relative_name() == '@'


# ── Parsing ────────────────────────────────────────────────────────────────────

def test_parse_fields():
    zone = parse()
    assert zone.serial == 2026010101
    assert zone.newline == '\n'

    mail = by_name(zone, 'mail', 'A')
    assert (mail.ttl, mail.rclass, mail.rdata, mail.comment) == (3600, 'IN', '192.0.2.25', 'mail server')

    sip = by_name(zone, 'sip', 'A')            # class before TTL
    assert (sip.ttl, sip.rclass) == (120, 'IN')

    txt = by_name(zone, 'txt')
    assert txt.rdata == '"semicolon ; inside quotes" "and \\"escaped\\" quotes"'
    assert txt.comment is None

    long = by_name(zone, 'long')
    assert long.rdata == '"first part of a long record " "second part"'


def test_implicit_owners_inherit():
    zone = parse()
    ns = [r for r in zone.records() if r.rtype == 'NS']
    assert all(r.name == zone.origin and not r.owner_explicit for r in ns)
    assert by_name(zone, 'mail', 'AAAA').owner_explicit is False
    wild = [r for r in zone.records() if r.name == dns.name.from_text('*.wild.example.com.')]
    assert [r.rdata for r in wild] == ['192.0.2.99', '192.0.2.100']
    assert wild[1].ttl == 600


def test_origin_and_ttl_context():
    zone = parse()
    host = by_name(zone, 'host.sub')
    assert host.origin == dns.name.from_text('sub.example.com.')
    assert host.relative_name() == 'host'
    assert host.relative_name(zone.origin) == 'host.sub'
    assert by_name(zone, 'last').origin == zone.origin
    assert host.default_ttl == 3600


def test_unsupported_entries_are_listed():
    zone = parse()
    assert [e.name for e in zone.unsupported if isinstance(e, Directive)] == ['$GENERATE']


def test_unknown_type_is_kept_verbatim():
    text = 'foo IN BOGUS something\nbar IN A 192.0.2.1\n'
    zone = parse(text)
    assert isinstance(zone.entries[0], Unparsed)
    assert zone.render() == text


@pytest.mark.parametrize('text, line', [
    ('a IN TXT ( "x"\n', 1),
    ('a IN A 192.0.2.1 )\n', 1),
    ('ok IN A 192.0.2.1\nb IN TXT "unterminated\n', 2),
])
def test_parse_errors(text, line):
    with pytest.raises(ZoneParseError) as exc:
        parse(text)
    assert exc.value.line == line


# ── Editing ────────────────────────────────────────────────────────────────────

def test_value_change_touches_only_that_token():
    zone = parse()
    zone.update(by_name(zone, 'ns1', 'A'), rdata='192.0.2.54')
    out = zone.render()
    assert line_of(out, 'ns1\tIN\tA') == 'ns1\tIN\tA\t192.0.2.54\n'
    assert out.replace('192.0.2.54', '192.0.2.53') == EXAMPLE


def test_rename_realigns_to_the_original_columns():
    zone = parse()
    zone.update(by_name(zone, 'ns1', 'A'), name='nameserver1')
    zone.update(by_name(zone, '_sip._tcp'), name='_sip._udp')
    out = zone.render()
    assert 'nameserver1\tIN\tA\t192.0.2.53\n' in out
    assert '_sip._udp\tIN\tSRV\t10 60 5060 sip\n' in out


def test_space_aligned_line_keeps_spaces_and_trailing_whitespace():
    zone = parse()
    zone.update(by_name(zone, 'www'), rdata='ns1')
    assert line_of(zone.render(), 'www') == 'www  IN  CNAME  ns1   \n'


def test_comment_add_change_remove():
    zone = parse()
    zone.update(by_name(zone, 'ns1', 'A'), comment='primary')
    zone.update(by_name(zone, 'mail', 'A'), comment='smtp relay')
    zone.update(by_name(zone, 'caa'), comment=None)
    out = zone.render()
    assert 'ns1\tIN\tA\t192.0.2.53\t; primary\n' in out
    assert 'mail\t3600\tIN\tA\t192.0.2.25\t; smtp relay\n' in out
    assert by_name(Zone.parse(out, 'example.com.'), 'ns1', 'A').comment == 'primary'


def test_delete_makes_following_implicit_owner_explicit():
    zone = parse()
    zone.delete(by_name(zone, 'mail', 'A'))
    out = zone.render()
    assert 'mail\tIN\tAAAA\t2001:db8::25\n' in out
    reparsed = Zone.parse(out, 'example.com.')
    assert by_name(reparsed, 'mail', 'AAAA').rdata == '2001:db8::25'


def test_insert_before_implicit_owners_keeps_their_owner():
    zone = parse()
    zone.add('first', 'A', '192.0.2.7', after=zone.soa)
    out = zone.render()
    assert '@\tIN\tNS\tns1\n' in out
    reparsed = Zone.parse(out, 'example.com.')
    assert all(r.name == reparsed.origin for r in reparsed.records() if r.rtype in ('NS', 'MX'))


def test_add_uses_neighbour_layout_and_section():
    zone = parse()
    rec = zone.add('www2', 'A', '192.0.2.80', after=by_name(zone, 'ns1', 'A'))
    out = zone.render()
    lines = out.splitlines()
    assert lines[lines.index('ns1\tIN\tA\t192.0.2.53') + 1] == 'www2\tIN\tA\t192.0.2.80'
    assert rec.is_new and rec.id not in [r.id for r in parse().records()]

    zone.add('caa2', 'CAA', '0 issuewild ";"')      # no position: after the last CAA
    assert 'caa2\tIN\tCAA\t0 issuewild ";"\n' in zone.render()


def test_add_in_sub_origin_renders_relative_to_local_origin():
    zone = parse()
    zone.add('db.sub', 'A', '192.0.2.201', after=by_name(zone, 'host.sub'))
    assert 'db\tIN\tA\t192.0.2.201\n' in zone.render()
    assert by_name(Zone.parse(zone.render(), 'example.com.'), 'db.sub').rdata == '192.0.2.201'


def test_ttl_added_and_removed():
    zone = parse()
    zone.update(by_name(zone, 'ns1', 'A'), ttl=300)
    zone.update(by_name(zone, 'mail', 'A'), ttl=None)
    reparsed = Zone.parse(zone.render(), 'example.com.')
    assert by_name(reparsed, 'ns1', 'A').ttl == 300
    assert by_name(reparsed, 'mail', 'A').ttl is None


def test_serial_change_is_in_place_in_multiline_soa():
    zone = parse()
    zone.serial = 2026010102
    out = zone.render()
    assert out == EXAMPLE.replace('2026010101', '2026010102')
    assert Zone.parse(out, 'example.com.').serial == 2026010102


def test_multiline_txt_edits():
    zone = parse()
    zone.update(by_name(zone, 'long'), rdata='"first part changed " "second part"')
    out = zone.render()
    assert '( "first part changed "\n\t\t  "second part" )\t; split over lines\n' in out

    zone.update(by_name(zone, 'long'), rdata='"now just one string"')   # token count changed: flattened
    assert 'long\tIN\tTXT\t"now just one string"\n' in zone.render()


def test_crlf_zone_writes_crlf_for_new_lines():
    zone = parse(EXAMPLE.replace('\n', '\r\n'))
    zone.add('new', 'A', '192.0.2.9', after=by_name(zone, 'ns1', 'A'))
    zone.update(by_name(zone, 'mail', 'A'), rdata='192.0.2.26')
    out = zone.render()
    assert '\n' not in out.replace('\r\n', '')
    assert 'new\tIN\tA\t192.0.2.9\r\n' in out


def test_append_to_file_without_final_newline():
    text = 'last IN A 192.0.2.250'
    zone = parse(text)
    zone.add('after', 'A', '192.0.2.251')
    assert zone.render() == 'last IN A 192.0.2.250\nafter IN A 192.0.2.251\n'


def test_many_edits_reparse_to_the_same_meaning():
    zone = parse()
    zone.update(by_name(zone, 'ns1', 'A'), name='ns01', rdata='192.0.2.153', ttl=60)
    zone.update(by_name(zone, '_sip._tcp'), rdata='20 50 5061 sip')
    zone.delete(by_name(zone, 'txt'))
    zone.add('extra', 'MX', '20 mail', after=by_name(zone, 'last'))
    zone.serial = 2026010150
    assert semantic(Zone.parse(zone.render(), 'example.com.')) == semantic(zone)


@pytest.mark.parametrize('path, origin', private_zones())
def test_private_zone_edit_diff_is_minimal(path, origin):
    text = path.read_bytes().decode()
    zone = Zone.parse(text, origin)
    target = next(r for r in zone.records() if r.owner_explicit and r.rtype in ('A', 'PTR'))
    zone.update(target, comment='edited by test')
    zone.serial = zone.serial + 1
    before, after = text.splitlines(), zone.render().splitlines()
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert len(before) == len(after) and len(changed) == 2
