"""Many records at once: pasted zone-file lines or a CSV, previewed line by line, then added as one change.

Both become Lines (name, ttl, type, value, comment and where they came from). plan() stages them in a working
copy the way the grid would, one by one, so each line gets its own outcome: adds, changes (Replace), already
there, or its error, and Replace's removals get rows of their own. Adding runs the same plan on the zone itself
and saves it once (editing.commit), so what was previewed is what's saved.
"""

import csv
import io
import ipaddress
from types import SimpleNamespace

import dns.exception
import dns.name
import dns.ttl

from . import editing, records
from .zonefile import Zone, ZoneParseError

COLUMNS = ('name', 'ttl', 'type', 'value', 'comment')
MAX_LINES = 2000


class Line:
    def __init__(self, where, name='', ttl=None, rtype='', value='', comment=None, error=None, raw=''):
        self.where, self.name, self.ttl, self.rtype, self.value = where, name, ttl, rtype, value
        self.comment, self.error, self.raw = comment, error, raw
        self.outcome = 'error' if error else None      # add / change / same / remove / error
        self.warnings, self.note = [], ''

    @property
    def text(self):
        ttl = f' {self.ttl}' if self.ttl not in (None, '') else ''
        comment = f' ; {self.comment}' if self.comment else ''
        return f'{self.name}{ttl} {self.rtype} {self.value}{comment}'.strip() if self.rtype else self.raw.strip()


def _too_many(count):
    return [Line('', error=f'{count} lines: at most {MAX_LINES} at a time')] if count > MAX_LINES else None


def from_text(text, origin):
    """Pasted zone-file lines → [Line]. Directives are refused: one record (or continuation) per line."""
    physical = text.replace('\r\n', '\n').split('\n')
    if (too := _too_many(sum(1 for p in physical if p.strip()))):
        return too
    out, kept = [], []
    for n, raw in enumerate(physical, 1):
        if raw.lstrip().startswith('$'):
            out.append(Line(f'line {n}', error="directives ($ORIGIN, $TTL, $GENERATE…) aren't taken here: "
                                                'write each record out, names relative to the zone', raw=raw))
            kept.append('')
        else:
            kept.append(raw)
    origin = dns.name.from_text(str(origin)) if not isinstance(origin, dns.name.Name) else origin
    try:
        zone = Zone.parse('\n'.join(kept), origin.to_text())
    except ZoneParseError as e:
        out.append(Line(f'line {e.line}', error=str(e).split(': ', 1)[-1], raw=physical[e.line - 1] if
                        0 < e.line <= len(physical) else ''))
        return sorted(out, key=_order)
    for r in zone.records():
        out.append(Line(f'line {r.line}', r.relative_name(origin), r.ttl, r.rtype, r.rdata, r.comment, raw=r.raw))
    for u in zone.unsupported:
        out.append(Line(f'line {u.line}', error='not a record line: name, optional TTL, type and value',
                        raw=u.raw))
    return sorted(out, key=_order)


def _order(line):
    return int(line.where.split()[-1]) if line.where.split()[-1].isdigit() else 0


def from_csv(data):
    """CSV (name, ttl, type, value, comment) → [Line]. Rows whose first cell starts with # and blank rows are
    skipped, and so is a header row; the comment column may be left off."""
    text = data.decode('utf-8-sig') if isinstance(data, bytes) else data
    reader = csv.reader(io.StringIO(text.replace('\r\n', '\n')))
    out, header_seen, rows = [], False, 0
    try:
        for row in reader:
            where = f'line {reader.line_num}'
            if not any(cell.strip() for cell in row) or row[0].lstrip().startswith('#'):
                continue
            if not header_seen and [c.strip().lower() for c in row[:5]] == list(COLUMNS[:len(row[:5])]):
                header_seen = True
                continue
            header_seen = True
            rows += 1
            if len(row) not in (4, 5):
                out.append(Line(where, error=f'{len(row)} columns; a row has 4 or 5: {", ".join(COLUMNS)}',
                                raw=','.join(row)))
                continue
            name, ttl, rtype, value, comment = (row + [''])[:5]
            if not name.strip():
                out.append(Line(where, error='no name: use @ for the zone itself', raw=','.join(row)))
                continue
            out.append(Line(where, name.strip(), ttl.strip() or None, rtype.strip().upper(), value.strip(),
                            comment.strip() or None, raw=','.join(row)))
    except csv.Error as e:
        out.append(Line(f'line {reader.line_num}', error=f'not CSV: {e}'))
    return _too_many(rows) or out


def _ttl(value):
    try:
        return None if value in (None, '') else dns.ttl.from_text(str(value))
    except (dns.ttl.BadTTL, ValueError):
        return 'bad'


def plan(edit, lines, replace=False):
    """Stage the lines in edit (a ZoneEdit, or a scratch copy) one by one. Returns (lines with outcomes, plus
    a row per record Replace removes; [(old, new)] staged; warnings)."""
    zone, origin = edit.zone, edit.zone.origin
    rows, staged, warnings = [], [], []

    def owner_of(line):
        try:
            return zone.name_from_text(line.name or '@')
        except dns.exception.DNSException:
            return None

    good = [line for line in lines if not line.error]
    if replace:
        keys = {}
        for line in good:
            owner = owner_of(line)
            if owner is not None:
                keys.setdefault((owner, line.rtype), []).append(line)
        for (owner, rtype), group in keys.items():
            for rec in [r for r in zone.records() if r.name == owner and r.rtype == rtype]:
                if any(_same(rec, line, origin) for line in group):
                    continue
                removal = Line('', rec.relative_name(origin), rec.ttl, rec.rtype, rec.rdata, rec.comment)
                removal.outcome = 'remove'
                old, new, _ = editing._stage(edit, editing.Op.removing(rec))
                staged.append((old, new))
                rows.append(removal)
    for line in lines:
        rows.append(line)
        if line.error:
            continue
        owner = owner_of(line)
        existing = next((r for r in zone.records() if owner is not None and r.name == owner
                         and r.rtype == line.rtype and _same(r, line, origin)), None)
        if existing is not None:
            ttl = _ttl(line.ttl)
            if replace and ((ttl != existing.ttl and line.ttl is not None) or (line.comment or None) != existing.comment):
                op = editing.Op(existing, line.name, line.ttl if line.ttl is not None else existing.ttl, line.rtype,
                                existing.rdata, line.comment)
                line.outcome = 'change'
            else:
                line.outcome, line.note = 'same', 'already there'
                continue
        else:
            op = editing.Op(None, line.name, line.ttl, line.rtype, line.value, line.comment)
            line.outcome = 'add'
            if line.rtype in ('A', 'AAAA') and owner is not None and not replace and any(
                    r.name == owner and r.rtype == line.rtype for r in zone.records()):
                line.warnings.append(f'adds a second {line.rtype} for {line.name}')
        try:
            old, new, op_warnings = editing._stage(edit, op)
        except records.RecordError as e:
            line.outcome, line.error = 'error', '; '.join(e.errors.values())
            continue
        line.warnings += op_warnings
        staged.append((old, new))
    return rows, staged, warnings


def _same(rec, line, origin):
    try:
        return records.same_data(line.rtype, rec.rdata, line.value, origin)
    except Exception:       # a value that doesn't parse can't be the same; check() reports it
        return False


def preview(edit, lines, replace=False):
    """plan() in a scratch copy of the zone: nothing is changed."""
    scratch = SimpleNamespace(zone=Zone.parse(edit.text, edit.name + '.'), conn=edit.conn, name=edit.name)
    rows, _, _ = plan(scratch, lines, replace)
    return rows


def add(edit, lines, replace, ptr_on, username):
    """plan() on the zone itself, then one save. Returns (rows, notes, warnings); refuses (ValueError) while
    any line has an error, leaving the zone as it was."""
    rows, staged, warnings = plan(edit, lines, replace)
    if any(r.outcome == 'error' for r in rows):
        editing.unstage(edit)
        raise ValueError('fix the lines marked as errors first')
    if not staged:
        return rows, [], []
    notes, more, _ = editing.commit(edit, staged, ptr_on, username)
    return rows, notes, warnings + more


def counts(rows):
    out = {}
    for r in rows:
        out[r.outcome] = out.get(r.outcome, 0) + 1
    return out


# ── CSV out ────────────────────────────────────────────────────────────────────

def grid_records(zone):
    """The records the grid shows (no SOA, no apex NS), in file order."""
    return [r for r in zone.records() if r.rtype != 'SOA' and not (r.rtype == 'NS' and r.name == zone.origin)]


def to_csv(zone):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(COLUMNS)
    for r in grid_records(zone):
        w.writerow([r.relative_name(zone.origin), '' if r.ttl is None else r.ttl, r.rtype, r.rdata, r.comment or ''])
    return buf.getvalue()


def template(zone_name, forward_zone='example.com'):
    """A CSV with the header and commented samples for this zone (# rows are skipped on import)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(COLUMNS)
    notes = [f'Rows starting with # are skipped: remove the # from a sample to use it. Names are relative to '
             f'{zone_name} (@ is {zone_name} itself; a name ending in a dot is absolute).',
             'Leave ttl empty for the zone default, or give seconds or 30m, 1h, 1d. comment is optional.']
    for note in notes:
        buf.write(f'# {note}\n')
    network = reverse_network(zone_name)
    if network is not None:
        hosts = list(network.hosts())[:3] if network.num_addresses > 2 else list(network)
        samples = []
        for i, address in enumerate(hosts[:2] or [network.network_address]):
            label = address.reverse_pointer[:-len(zone_name) - 1] if address.reverse_pointer.endswith(zone_name) else str(address)
            samples.append([label, '', 'PTR', f'host{i + 1}.{forward_zone}.', 'the PTR for ' + str(address)])
    else:
        samples = [['host1', '', 'A', '192.0.2.10', 'office printer'],
                   ['host2', '3600', 'A', '192.0.2.11', ''],
                   ['www', '', 'CNAME', 'host1', ''],
                   ['@', '', 'MX', '10 mail', ''],
                   ['@', '', 'TXT', '"v=spf1 mx -all"', ''],
                   ['_sip._tcp', '', 'SRV', '10 5 5060 host1', 'quoted values keep their quotes']]
    for row in samples:
        line = io.StringIO()
        csv.writer(line, lineterminator='\n').writerow(row)
        buf.write('#' + line.getvalue())
    return buf.getvalue()


def reverse_network(zone_name):
    """192.168.1.0/24 for 1.168.192.in-addr.arpa; None for a forward zone."""
    if not zone_name.endswith('.in-addr.arpa'):
        return None
    labels = zone_name[:-len('.in-addr.arpa')].split('.')
    try:
        octets = [int(x) for x in reversed(labels)]
        if not 1 <= len(octets) <= 4 or any(not 0 <= o <= 255 for o in octets):
            return None
        return ipaddress.ip_network('.'.join(map(str, octets + [0] * (4 - len(octets)))) + f'/{8 * len(octets)}')
    except ValueError:
        return None
