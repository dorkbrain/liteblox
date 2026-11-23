"""Row editing helpers: per-type form fields, validation, previews and change summaries."""

from collections import Counter

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.ttl

from .validate import check_rdata
from .zonefile import _rdata_tokens

COMMON_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'NS', 'PTR', 'CAA']
# per-type form fields; types not listed use a single free-text "value"
FIELDS = {
    'MX': [('priority', 'Priority'), ('exchange', 'Mail server')],
    # every name is unique across types: the edit row sends all of them, hidden ones included
    'SRV': [('srv_priority', 'Priority'), ('weight', 'Weight'), ('port', 'Port'), ('target', 'Target')],
    'CAA': [('flags', 'Flags'), ('tag', 'Tag'), ('caa_value', 'Value')],
    'TXT': [('text', 'Text')],
}
# which form field holds a domain name (for previews and the missing-dot warning)
NAME_FIELD = {'CNAME': 'value', 'NS': 'value', 'PTR': 'value', 'DNAME': 'value',
              'MX': 'exchange', 'SRV': 'target'}
TXT_CHUNK = 255


class RecordError(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors.values()))
        self.errors = errors


def _unquote(token):
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return token[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    return token


def _quote(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def decompose(rtype, rdata):
    """Form field values for an existing record's data."""
    tokens = _rdata_tokens(rdata) if rdata else []
    if rtype == 'MX' and len(tokens) == 2:
        return {'priority': tokens[0], 'exchange': tokens[1]}
    if rtype == 'SRV' and len(tokens) == 4:
        return dict(zip(('srv_priority', 'weight', 'port', 'target'), tokens))
    if rtype == 'CAA' and len(tokens) == 3:
        return {'flags': tokens[0], 'tag': tokens[1], 'caa_value': _unquote(tokens[2])}
    if rtype == 'TXT':
        parts = [_unquote(t) for t in tokens]
        # one long string split into 255-byte chunks reads as plain text; several
        # deliberate strings stay quoted so saving the form doesn't merge them
        if all(len(p.encode()) == TXT_CHUNK for p in parts[:-1]):
            return {'text': ''.join(parts)}
        return {'text': rdata}
    return {'value': rdata}


def compose(rtype, form):
    """Record data text from form fields (the inverse of decompose)."""
    get = lambda k: (form.get(k) or '').strip()
    if rtype == 'MX':
        return f"{get('priority')} {get('exchange')}"
    if rtype == 'SRV':
        return ' '.join(get(k) for k in ('srv_priority', 'weight', 'port', 'target'))
    if rtype == 'CAA':
        return f"{get('flags') or '0'} {get('tag')} {_quote(get('caa_value'))}"
    if rtype == 'TXT':
        text = form.get('text') or ''
        if text.strip().startswith('"'):            # already written as quoted strings
            return text.strip()
        data = text.encode()
        chunks = [data[i:i + TXT_CHUNK].decode(errors='ignore') for i in range(0, len(data), TXT_CHUNK)] or ['']
        return ' '.join(_quote(c) for c in chunks)
    return get('value')


def same_data(rtype, a, b, origin):
    """True when two rdata texts encode the same record (so an unchanged edit keeps the original text)."""
    try:
        t = dns.rdatatype.from_text(rtype)
        return (dns.rdata.from_text(dns.rdataclass.IN, t, a, origin=origin, relativize=False)
                == dns.rdata.from_text(dns.rdataclass.IN, t, b, origin=origin, relativize=False))
    except (dns.exception.DNSException, ValueError):
        return a == b


def target_preview(rtype, rdata, origin):
    """The absolute name a name-type record points at, when written relative ('www' -> 'www.example.com.')."""
    field = NAME_FIELD.get(rtype)
    if not field:
        return None
    value = decompose(rtype, rdata).get(field, '')
    if not value or value.endswith('.') or value == '@':
        return None
    try:
        return dns.name.from_text(value, origin).to_text()
    except dns.exception.DNSException:
        return None


def check(zone, rec, name, ttl, rtype, rdata):
    """Validate one row. Returns (owner Name, ttl int|None, rtype, warnings); raises RecordError."""
    errors, warnings = {}, []
    owner = None
    try:
        owner = zone.name_from_text(name or '@')
        if not owner.is_subdomain(zone.origin):
            errors['name'] = f'{owner} is outside the zone {zone.origin}'
    except dns.exception.DNSException as e:
        errors['name'] = f'bad name: {e}'

    ttl_value = None
    if str(ttl or '').strip():
        try:
            ttl_value = dns.ttl.from_text(str(ttl).strip())
        except (dns.ttl.BadTTL, ValueError):
            errors['ttl'] = 'TTL must be seconds or like 1h, 30m'

    rtype = (rtype or '').strip().upper()
    try:
        rtype = dns.rdatatype.to_text(dns.rdatatype.from_text(rtype))
    except (dns.rdatatype.UnknownRdatatype, ValueError):
        errors['type'] = f'unknown record type {rtype!r}'
    if rtype == 'SOA' and (rec is None or rec.rtype != 'SOA'):
        errors['type'] = 'edit the SOA in the SOA card'

    if 'type' not in errors:
        problem = check_rdata(rtype, rdata, zone.origin)
        if problem:
            errors['value'] = problem

    if owner is not None and 'type' not in errors:
        others = [r for r in zone.records() if r.name == owner and r is not rec]
        if rtype == 'CNAME' and owner == zone.origin:
            errors['type'] = 'the zone apex cannot be a CNAME'
        elif rtype == 'CNAME' and others:
            errors['type'] = f'{owner} already has other records; a CNAME must be the only record at its name'
        elif rtype != 'CNAME' and any(r.rtype == 'CNAME' for r in others):
            errors['type'] = f'{owner} is a CNAME; it cannot have other records'

    field = NAME_FIELD.get(rtype)
    if field and 'value' not in errors:
        value = decompose(rtype, rdata).get(field, '')
        zone_text = zone.origin.to_text().rstrip('.')
        if not value.endswith('.') and (value == zone_text or value.endswith('.' + zone_text)):
            warnings.append(f'"{value}" has no trailing dot, so it means '
                            f'{dns.name.from_text(value, zone.origin)}; add a dot if you meant {value}.')
    if errors:
        raise RecordError(errors)
    return owner, ttl_value, rtype, warnings


def _key(rec, origin):
    return (rec.relative_name(origin), rec.rtype)


def summarize(old_zone, new_zone):
    """Row-level changes between two parses: added, removed and changed (same name and type) records.
    A comment is part of the row: changing only a comment is a change too."""
    origin = new_zone.origin

    def rows(zone):
        return [(_key(r, origin), r.ttl, ' '.join(_rdata_tokens(r.rdata)), r.comment or '') for r in zone.records()]

    old_count, new_count = Counter(rows(old_zone)), Counter(rows(new_zone))
    removed = list((old_count - new_count).elements())
    added = list((new_count - old_count).elements())

    changed = []
    for item in list(removed):
        # pair with the same name and type, preferring the same data (a TTL or comment edit)
        match = next((a for a in added if a[:3:2] == item[:3:2]), None) or \
            next((a for a in added if a[0] == item[0]), None)
        if match:
            changed.append((item, match))
            removed.remove(item)
            added.remove(match)

    def fmt(item):
        (name, rtype), ttl, data, comment = item
        return {'name': name, 'type': rtype, 'ttl': ttl, 'data': data, 'comment': comment}
    return {'added': [fmt(a) for a in added], 'removed': [fmt(r) for r in removed],
            'changed': [(fmt(o), fmt(n)) for o, n in changed]}


def count(summary):
    return len(summary['added']) + len(summary['removed']) + len(summary['changed'])
