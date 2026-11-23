"""Canonical record order for zones LiteBlox keeps sorted.

The zone's apex comes first (SOA, then NS and the rest), then every other name
in DNS hierarchy order (example.com, host.example.com, a.host.example.com),
with numbers compared as numbers so a reverse zone runs 1, 2, 10. Within a
name, records follow a fixed type order, then their values (addresses
numerically).

Untouched records keep their original text. A comment at the end of a record's
line moves with it; a comment block at the very top of the file stays there.
Other comment lines would end up next to the wrong records once sorted, so they
leave the file: sort_zone hands them back (with the name they sat above) for
the zone's notes in LiteBlox. Blank lines are dropped and a blank line is put
after the apex. $GENERATE lines (with the comments just above them) keep their
order in a block after the records, when nothing but the zone's own $ORIGIN
and top $TTL applies to them; $INCLUDE can't be sorted. Owners are always written out, every
name is relative to the zone itself (no $ORIGIN), and there is one $TTL at the
top; a record that relied on a later $TTL gets that TTL written on it.
"""

import functools
import ipaddress
import re

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.ttl

from .zonefile import Blank, Comment, Directive, Record, Unparsed, Zone, ZoneParseError, _rdata_tokens


class SortError(ZoneParseError):
    def __init__(self, message, line=None):
        ValueError.__init__(self, message)      # the message already names the line
        self.line = line


TYPE_ORDER = ['SOA', 'NS', 'DS', 'A', 'AAAA', 'CNAME', 'DNAME', 'PTR', 'MX', 'SRV', 'NAPTR', 'TXT', 'SPF',
              'CAA', 'SSHFP', 'TLSA', 'HTTPS', 'SVCB', 'HINFO', 'LOC', 'RP']
_DIGITS = re.compile(r'(\d+)')


def _natural(text):
    """'host10' sorts after 'host9': digit runs compare as numbers."""
    return tuple((0, int(p), '') if p.isdigit() else (1, 0, p) for p in _DIGITS.split(text.lower()) if p)


def _name_key(name, origin):
    if not name.is_subdomain(origin):
        return (2, ())
    labels = name.relativize(origin).labels if name != origin else ()
    return (0 if name == origin else 1, tuple(_natural(label.decode(errors='replace')) for label in reversed(labels)))


def _type_key(rtype):
    return (TYPE_ORDER.index(rtype), '') if rtype in TYPE_ORDER else (len(TYPE_ORDER), rtype)


def _value_key(rec):
    tokens = _rdata_tokens(rec.rdata)
    try:
        if rec.rtype in ('A', 'AAAA') and tokens:
            return (0, int(ipaddress.ip_address(tokens[0])), ())
        if rec.rtype == 'MX' and len(tokens) >= 2:
            return (1, int(tokens[0]), _natural(tokens[1]))
        if rec.rtype == 'SRV' and len(tokens) >= 4:
            return (1, int(tokens[0]) * 1_000_000 + int(tokens[1]) * 100_000 + int(tokens[2]), _natural(tokens[3]))
    except ValueError:
        pass
    return (2, 0, _natural(rec.rdata))


def sort_key(rec, origin, position):
    return (_name_key(rec.name, origin), _type_key(rec.rtype), _value_key(rec), position)


def _fresh_line(rec, origin, ttl):
    """A record written from scratch, for one whose names were relative to another $ORIGIN."""
    rdclass = dns.rdataclass.from_text(rec.rclass or 'IN')
    rdata = dns.rdata.from_text(rdclass, dns.rdatatype.from_text(rec.rtype), rec.rdata, origin=rec.origin,
                              relativize=False)
    fields = [rec.name.relativize(origin).to_text() if rec.name != origin else '@']
    if ttl is not None:
        fields.append(str(ttl))
    if rec.rclass:
        fields.append(rec.rclass)
    fields += [rec.rtype, rdata.to_text(origin=origin, relativize=True)]
    return '\t'.join(fields) + (f'\t; {rec.comment}' if rec.comment else '')


def _record_text(rec, origin, top_ttl, newline):
    ttl = rec.ttl
    if ttl is None and rec.default_ttl is not None and rec.default_ttl != top_ttl:
        ttl = rec.default_ttl
    if rec.origin != origin:
        return _fresh_line(rec, origin, ttl) + newline
    rec.ttl = ttl
    text = rec.render(rec.name, newline)     # prev_name = own name: no owner forced into the old layout
    if text[:1] in (' ', '\t'):
        owner = rec.name.relativize(origin).to_text() if rec.name != origin else '@'
        text = owner + text
    return text if text.endswith(('\n', '\r')) else text + newline


def sort_zone(zone, moved=None):
    """The zone's text in canonical order. Raises SortError for files that can't be reordered safely.

    moved: a list that gets (comment, name) for each comment line taken out (name None: after the last record)."""
    for e in zone.entries:
        if isinstance(e, Unparsed):
            raise SortError(f'line {e.line} could not be read, so the zone can\'t be sorted: {e.raw.strip()}', e.line)
        if isinstance(e, Directive) and e.name not in ('$TTL', '$ORIGIN', '$GENERATE'):
            raise SortError(f'{e.name} on line {e.line} depends on its position, so the zone can\'t be sorted', e.line)
    nl, origin = zone.newline, zone.origin

    # the file's own header: comments before the first directive or record
    start = next((i for i, e in enumerate(zone.entries) if not isinstance(e, (Comment, Blank))), len(zone.entries))
    header = [e.raw for e in zone.entries[:start]]
    while header and not header[-1].strip():
        header.pop()
    ttl_dir = next((e for e in zone.entries if isinstance(e, Directive) and e.name == '$TTL' and e.args), None)
    top_ttl = dns.ttl.from_text(ttl_dir.args[0]) if ttl_dir is not None else None

    items, pending, generate = [], [], []
    for e in zone.entries[start:]:
        if isinstance(e, Comment):
            pending.append(e.raw.strip())
        elif isinstance(e, Directive) and e.name == '$GENERATE':
            if e.origin != origin or e.default_ttl != top_ttl:
                raise SortError(f'$GENERATE on line {e.line} depends on the $ORIGIN or $TTL above it, '
                                'so the zone can\'t be sorted', e.line)
            generate += pending + [e.raw.rstrip('\r\n')]
            pending = []
        elif isinstance(e, Record):
            if moved is not None:
                owner = e.name.relativize(origin).to_text() if e.name != origin else '@'
                moved += [(c, owner) for c in pending]
            items.append((sort_key(e, origin, len(items)), e))
            pending = []
    if moved is not None:
        moved += [(c, None) for c in pending]

    out = [line if line.endswith(('\n', '\r')) else line + nl for line in header]
    if out:
        out.append(nl)
    if ttl_dir is not None:
        out.append(ttl_dir.raw if ttl_dir.raw.endswith(('\n', '\r')) else ttl_dir.raw + nl)
    first, in_apex = True, True
    for _, rec in sorted(items, key=lambda item: item[0]):
        leaving_apex = in_apex and rec.name != origin
        if not first and leaving_apex:
            out.append(nl)
        first, in_apex = False, in_apex and not leaving_apex
        out.append(_record_text(rec, origin, top_ttl, nl))
    if generate:
        out += [nl] + [line + nl for line in generate]
    return ''.join(out)


def sorted_text(text, origin, moved=None):
    return sort_zone(Zone.parse(text, origin), moved)


def note_lines(moved):
    """Comments sort_zone took out, as lines for the zone's notes: '### printers ###  (above printer1)'."""
    return [c.lstrip(';').strip() + (f'  (above {name})' if name else '  (at the end)') for c, name in moved
            if c.lstrip(';').strip()]


@functools.lru_cache(maxsize=256)
def why_unsorted(text, origin):
    """Why this zone file can't be kept sorted, or None (cached: the Dashboard asks every minute)."""
    try:
        sorted_text(text, origin)
    except ZoneParseError as e:
        return str(e)
    return None
