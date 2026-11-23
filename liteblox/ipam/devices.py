"""Devices: a label and a comment per MAC, shown wherever the MAC shows (with its vendor) and found by search.

A label alone changes nothing in DNS or DHCP. A device's page offers the steps up from there: a name-only
reservation (its name in DNS, any pool address), then a fixed address, and back down again.
"""

import re
import time

from .seen import mac_text


def _mac(mac):
    from ..dhcp.validate import normalize_mac
    return normalize_mac(mac)


def get(conn, mac):
    """{mac, label, comment, repeater, created_at, updated_at} or None."""
    row = conn.execute('SELECT * FROM devices WHERE mac = ?', (mac_text(mac),)).fetchone()
    return {**dict(row), 'repeater': bool(row['repeater'])} if row else None


def labels(conn):
    """{mac: label} of the labelled devices."""
    return {r['mac']: r['label'] for r in conn.execute("SELECT mac, label FROM devices WHERE label != ''")}


def repeaters(conn):
    """The MACs marked as a Wi-Fi repeater's: one stands in for every device connected through it, so seeing it
    on an address says nothing about which device is there."""
    return frozenset(r['mac'] for r in conn.execute('SELECT mac FROM devices WHERE repeater = 1'))


def save(conn, mac, label, comment, repeater=None, now=None):
    """Set a device's label and comment, and whether it's a repeater (None: as it was); a device with none of
    them is forgotten. Raises ValueError for a bad MAC."""
    m = _mac(mac)
    if m is None:
        raise ValueError(f'{mac or "(empty)"} is not a MAC address')
    label, comment = (label or '').strip()[:64], (comment or '').strip()[:500]
    now = int(now if now is not None else time.time())
    if repeater is None:
        held = get(conn, m)
        repeater = bool(held and held['repeater'])
    with conn:
        if not label and not comment and not repeater:
            conn.execute('DELETE FROM devices WHERE mac = ?', (m,))
            return None
        conn.execute('INSERT INTO devices (mac, label, comment, repeater, created_at, updated_at) '
                     'VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (mac) DO UPDATE SET label = excluded.label, '
                     'comment = excluded.comment, repeater = excluded.repeater, updated_at = excluded.updated_at',
                     (m, label, comment, int(bool(repeater)), now, now))
    return get(conn, m)


def matching(conn, needle):
    """The devices whose label or comment holds needle (lowercase)."""
    like = f"%{needle.replace('%', '').replace('_', '')}%"
    return [dict(r) for r in conn.execute('SELECT * FROM devices WHERE lower(label) LIKE ? OR lower(comment) LIKE ? '
                                          'ORDER BY label, mac', (like, like))]


def line(label, vendor, repeater=False):
    """The muted line under a MAC: 'label · Wi-Fi repeater · vendor', any of them alone, or ''."""
    return ' · '.join(x for x in (label, 'Wi-Fi repeater' if repeater else '', vendor) if x)


def hostname_for(label):
    """A DNS label from a device label ('Kitchen tablet' → 'kitchen-tablet'), or ''."""
    name = re.sub(r'[^a-z0-9]+', '-', (label or '').lower()).strip('-')[:63].strip('-')
    return name


def steps(conn, settings, mac, subnets, found):
    """Per DHCP subnet the device is in (by a reservation or an active lease): {subnet, reservation, lease, node,
    ddns, names}. names: the A records at its address in the static zones."""
    from .checks import static_names_at
    from ..search import _v4
    mine = [(s, r) for s in subnets for r in s.reservations if r.hw_address.lower() == mac]
    active = {lease['subnet_id']: (node, lease) for node, lease in found
              if lease['mac'].lower() == mac and lease['state'] == 'active'}
    out = []
    for s in subnets:
        r = next((r for sub, r in mine if sub.id == s.id), None)
        node, lease = active.get(s.id, (None, None))
        if r is None and lease is None:
            continue
        ip = _v4(r.ip_address if r and r.ip_address else lease['ip'] if lease else '')
        out.append({'subnet': s, 'reservation': r, 'lease': lease, 'node': node, 'ddns': s.registers,
                    'names': static_names_at(conn, settings, ip) if ip else []})
    return out
