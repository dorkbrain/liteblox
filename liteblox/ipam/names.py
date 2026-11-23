"""IPAM records: a name kept in IPAM only, with an optional MAC and a comment, for addresses no DNS LiteBlox runs
holds a name for (the DNS module is off, or no zone in LiteBlox covers the address).

They're rows of ipam_assignments with kind 'ipam': Name this address (the network page, the address card) makes
them, and so does assign when the DNS module is off or target 'ipam' is asked. Nothing goes to DNS or DHCP.
"""

import ipaddress
import re
import time

from .model import IpamError

LABEL = r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?'
NAME = re.compile(rf'^{LABEL}(?:\.{LABEL})*$')


def clean_name(name):
    """The name lowercase without a trailing dot; IpamError when it isn't a host name."""
    name = (name or '').strip().rstrip('.').lower()
    if not name:
        raise IpamError({'name': 'give a name'})
    if len(name) > 253 or not NAME.match(name):
        raise IpamError({'name': f'{name} is not a host name (letters, digits and hyphens, dots between labels)'})
    return name


def _ip(ip):
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except ValueError:
        raise IpamError({'ip': f'{ip} is not an IPv4 address'})


def records(conn):
    """{IPv4Address: row} of every IPAM record."""
    return {ipaddress.IPv4Address(r['ip']): dict(r)
            for r in conn.execute("SELECT * FROM ipam_assignments WHERE kind = 'ipam'")}


def get(conn, ip):
    row = conn.execute("SELECT * FROM ipam_assignments WHERE kind = 'ipam' AND ip = ?", (str(ip),)).fetchone()
    return dict(row) if row else None


def save(conn, ip, name, mac='', comment='', username=None):
    """Add or change the IPAM record at ip. Returns True when it's new. An IPAM note at ip becomes its comment
    when none is given (one comment per address)."""
    from ..dhcp.validate import normalize_mac
    errors = {}
    ip = _ip(ip)
    try:
        name = clean_name(name)
    except IpamError as e:
        errors.update(e.errors)
    mac = (mac or '').strip()
    if mac:
        mac = normalize_mac(mac)
        if mac is None:
            errors['mac'] = 'not a MAC address (aa:bb:cc:dd:ee:ff)'
    comment = (comment or '').strip()[:200]
    other = conn.execute('SELECT kind FROM ipam_assignments WHERE ip = ?', (ip,)).fetchone()
    if other is not None and other['kind'] != 'ipam':
        errors['ip'] = f"{ip} was assigned as a {'reservation' if other['kind'] == 'reservation' else 'DNS record'}: unassign it first"
    if errors:
        raise IpamError(errors)
    note = conn.execute('SELECT note FROM ipam_notes WHERE ip = ?', (ip,)).fetchone()
    if note and not comment:
        comment = note['note']
    with conn:
        conn.execute('DELETE FROM ipam_notes WHERE ip = ?', (ip,))
        if other is None:
            conn.execute("INSERT INTO ipam_assignments (ip, kind, name, mac, comment, username, created_at) "
                         "VALUES (?, 'ipam', ?, ?, ?, ?, ?)", (ip, name, mac or None, comment, username,
                                                               int(time.time())))
        else:
            conn.execute("UPDATE ipam_assignments SET name = ?, mac = ?, comment = ?, username = ? WHERE ip = ?",
                         (name, mac or None, comment, username, ip))
    return other is None


def set_comment(conn, ip, text):
    with conn:
        n = conn.execute("UPDATE ipam_assignments SET comment = ? WHERE kind = 'ipam' AND ip = ?",
                         ((text or '').strip()[:200], str(ip))).rowcount
    if not n:
        raise ValueError(f'the IPAM record for {ip} is gone')


def delete(conn, ip):
    """True when there was one."""
    with conn:
        return conn.execute("DELETE FROM ipam_assignments WHERE kind = 'ipam' AND ip = ?", (str(ip),)).rowcount > 0


def matching(conn, query):
    """The IPAM records a search query matches: an address, a network, a MAC (whole or in part) or text in the
    name or comment."""
    from ..search import bare_mac
    out = []
    for ip, r in sorted(records(conn).items()):
        if query.kind == 'ip':
            hit = ip == query.ip
        elif query.kind == 'network':
            hit = ip in query.network
        elif query.kind == 'mac':
            hit = bool(r['mac']) and query.mac in bare_mac(r['mac'])
        else:
            hit = bool(query.needle) and (query.needle in r['name'] or query.needle in r['comment'].lower())
        if hit:
            out.append(r)
    return out
