"""CSV downloads of the web UI's tables (DHCP addresses and leases, IPAM, every zone at once).

Cells a spreadsheet would run as a formula (=, +, -, @ first) get a leading ' : DHCP hostnames come from the
clients, so anyone on the network picks them. The per-zone export (dns/many.to_csv) doesn't do this, since
it has to import back exactly.
"""

import csv
import io
from datetime import date

from fastapi.responses import Response

from .timefmt import _parse

_FORMULA = ('=', '+', '-', '@', '\t', '\r')


def cell(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else ''
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        value = '; '.join(str(v) for v in value)
    s = str(value)
    return "'" + s if s.startswith(_FORMULA) else s


def when(value):
    """A stored time (SQLite UTC text or unix time) in local time, without the zone name."""
    if value in (None, ''):
        return ''
    try:
        return _parse(value).astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value)


def text(header, rows, notes=(), guard=True):
    """notes become # lines above the header (what couldn't be read). guard=False keeps cells exactly as
    they are, for data that has to import back (zone records)."""
    buf = io.StringIO()
    for note in notes:
        buf.write('# ' + ' '.join(str(note).split()) + '\n')
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(header)
    for row in rows:
        w.writerow([cell(v) for v in row] if guard else ['' if v is None else v for v in row])
    return buf.getvalue()


def filename(*parts, dated=False):
    """'dhcp', '192.168.1.0/24' → dhcp-192.168.1.0_24.csv; dated adds today's date (for live data)."""
    name = '-'.join(str(p).replace('/', '_').replace(':', '_') for p in parts if p)
    return f'{name}-{date.today().isoformat()}.csv' if dated else f'{name}.csv'


def response(header, rows, name, notes=()):
    return Response(text(header, rows, notes), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{name}"'})
