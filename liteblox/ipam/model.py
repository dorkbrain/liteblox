"""IPAM networks, their ranges and address notes, in the DB.

Networks nest by their prefixes alone: a network's parent is the smallest other network that contains it, worked
out on every read, so adding a /16 adopts the /24s inside it and deleting it hands them back up. A network with
children is a container: it holds no addresses or ranges of its own. DHCP pools are never stored as ranges; they
come from the DHCP subnets inside a network, so they can't drift.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Optional

KINDS = {'static': 'Static', 'infrastructure': 'Infrastructure', 'reserved': 'Reserved', 'other': 'Other'}
SWEEPS = ('off', 'hourly', 'daily')
SMALLEST = 30           # a /31 or /32 isn't a network to manage


class IpamError(ValueError):
    """Per-field errors: {field: message}."""

    def __init__(self, errors):
        super().__init__('; '.join(errors.values()))
        self.errors = errors


@dataclass
class Range:
    id: Optional[int]
    network_id: Optional[int]
    first: ipaddress.IPv4Address
    last: ipaddress.IPv4Address
    kind: str = 'static'
    name: str = ''
    comment: str = ''
    subnet_id: Optional[int] = None         # a DHCP pool's subnet (read-only, not in ipam_ranges)

    @property
    def dhcp(self):
        return self.kind == 'dhcp'

    @property
    def label(self):
        return self.name or (KINDS.get(self.kind) or 'DHCP pool')

    @property
    def size(self):
        return int(self.last) - int(self.first) + 1

    def __contains__(self, ip):
        return self.first <= ip <= self.last

    @classmethod
    def from_row(cls, row):
        return cls(row['id'], row['network_id'], ipaddress.IPv4Address(row['first']),
                   ipaddress.IPv4Address(row['last']), row['kind'], row['name'], row['comment'])


@dataclass
class Network:
    id: Optional[int]
    prefix: str
    name: str = ''
    comment: str = ''
    sweep: str = 'off'
    sweep_node_id: Optional[int] = None
    swept_at: Optional[str] = None
    parent_id: Optional[int] = None
    children: list = field(default_factory=list)
    depth: int = 0

    @property
    def net(self):
        return ipaddress.IPv4Network(self.prefix)

    @property
    def container(self):
        return bool(self.children)

    @property
    def label(self):
        return self.name or self.prefix

    @property
    def usable(self):
        """The addresses a host can have: all but the network and broadcast addresses."""
        return max(self.net.num_addresses - 2, 0)

    def hosts_range(self):
        net = self.net
        return net.network_address + 1, net.broadcast_address - 1

    @classmethod
    def from_row(cls, row):
        return cls(row['id'], row['prefix'], row['name'], row['comment'], row['sweep'], row['sweep_node_id'],
                   row['swept_at'])


def _key(n):
    net = n.net
    return int(net.network_address), net.prefixlen


def networks(conn):
    """Every network, in address order (a container before what it holds), with parent_id, children and depth
    filled in."""
    found = sorted((Network.from_row(r) for r in conn.execute('SELECT * FROM ipam_networks')), key=_key)
    by_id = {n.id: n for n in found}
    stack = []
    for n in found:
        while stack and not n.net.subnet_of(stack[-1].net):
            stack.pop()
        if stack:
            n.parent_id, n.depth = stack[-1].id, stack[-1].depth + 1
            by_id[n.parent_id].children.append(n)
        stack.append(n)
    return found


def roots(found):
    return [n for n in found if n.parent_id is None]


def get(conn, network_id):
    return next((n for n in networks(conn) if n.id == network_id), None)


def path(found, network):
    """The containers above a network, outermost first."""
    by_id = {n.id: n for n in found}
    out, at = [], network.parent_id
    while at:
        out.insert(0, by_id[at])
        at = by_id[at].parent_id
    return out


def leaf_for(found, ip):
    """The smallest network holding ip (a leaf, or a container when no child holds it), or None."""
    ip = ipaddress.IPv4Address(str(ip))
    best = None
    for n in found:
        if ip in n.net and (best is None or n.net.prefixlen > best.net.prefixlen):
            best = n
    return best


# ── changes ────────────────────────────────────────────────────────────────────

def parse_prefix(text):
    """'192.168.0.0/24' (or with host bits, '192.168.0.7/24') → IPv4Network; ValueError with a plain message."""
    text = (text or '').strip()
    if '/' not in text:
        raise ValueError('give it as an address and a prefix length, like 192.168.0.0/24')
    try:
        net = ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        raise ValueError(f'{text} is not an IPv4 network')
    if net.prefixlen > SMALLEST:
        raise ValueError(f'a /{net.prefixlen} is too small to manage (the smallest is a /{SMALLEST})')
    return net


def add_network(conn, prefix, name='', comment='', sweep='off', sweep_node_id=None):
    try:
        net = parse_prefix(prefix)
    except ValueError as e:
        raise IpamError({'prefix': str(e)})
    errors = {}
    found = networks(conn)
    if any(n.net == net for n in found):
        errors['prefix'] = f'{net} is already in IPAM'
    else:
        holders = [n for n in found if net.subnet_of(n.net)]
        parent = max(holders, key=lambda n: n.net.prefixlen) if holders else None
        if parent is not None and not parent.container and ranges(conn, parent.id):
            errors['prefix'] = (f'{parent.label} ({parent.prefix}) has ranges of its own: a network inside it would '
                                'make it a container, which holds no ranges. Delete its ranges first.')
    if sweep not in SWEEPS:
        errors['sweep'] = 'off, hourly or daily'
    if errors:
        raise IpamError(errors)
    with conn:
        cur = conn.execute('INSERT INTO ipam_networks (prefix, name, comment, sweep, sweep_node_id) '
                           'VALUES (?, ?, ?, ?, ?)', (str(net), name.strip(), comment.strip(), sweep, sweep_node_id))
    return cur.lastrowid


def update_network(conn, network_id, name, comment, sweep='off', sweep_node_id=None):
    """The prefix stays: to change it, add the new network and delete the old one."""
    if sweep not in SWEEPS:
        raise IpamError({'sweep': 'off, hourly or daily'})
    with conn:
        conn.execute('UPDATE ipam_networks SET name = ?, comment = ?, sweep = ?, sweep_node_id = ? WHERE id = ?',
                     (name.strip(), comment.strip(), sweep, sweep_node_id, network_id))


def delete_network(conn, network_id):
    """Its ranges go with it; networks inside it move up to its parent (nothing to do: nesting isn't stored)."""
    with conn:
        conn.execute('DELETE FROM ipam_networks WHERE id = ?', (network_id,))


# ── ranges ─────────────────────────────────────────────────────────────────────

def ranges(conn, network_id):
    return [Range.from_row(r) for r in conn.execute(
        'SELECT * FROM ipam_ranges WHERE network_id = ? ORDER BY id', (network_id,))]


def dhcp_pools(network, subnets):
    """The DHCP pools inside a network, as read-only ranges (clipped to it)."""
    from ..dhcp.leases import pool_ranges
    net, out = network.net, []
    lo, hi = net.network_address, net.broadcast_address
    for s in subnets:
        try:
            if not ipaddress.IPv4Network(s.prefix).overlaps(net):
                continue
        except ValueError:
            continue
        for first, last in pool_ranges(s):
            if last < lo or first > hi:
                continue
            out.append(Range(None, network.id, max(first, lo), min(last, hi), 'dhcp', f'DHCP pool ({s.prefix})',
                             s.comment or '', subnet_id=s.id))
    return out


def all_ranges(conn, network, subnets):
    """The network's own ranges and its DHCP pools, in address order."""
    return sorted(ranges(conn, network.id) + dhcp_pools(network, subnets), key=lambda r: int(r.first))


def _parse_ip(text, field_name, errors):
    try:
        return ipaddress.IPv4Address((text or '').strip())
    except ValueError:
        errors[field_name] = f'{text} is not an IPv4 address' if (text or '').strip() else 'required'
        return None


def save_range(conn, network, first, last, kind='static', name='', comment='', range_id=None, subnets=()):
    """Add (range_id None) or change a range. A range lies inside the network's host addresses and overlaps
    neither another range nor a DHCP pool. Returns the range's id."""
    errors = {}
    a = _parse_ip(first, 'first', errors)
    b = _parse_ip(last or first, 'last', errors)
    if kind not in KINDS:
        errors['kind'] = f"one of {', '.join(KINDS)}"
    if network.container:
        errors['first'] = f'{network.label} holds other networks: put ranges in those'
    if a and b and not errors:
        lo, hi = network.hosts_range()
        if b < a:
            errors['last'] = 'the last address comes before the first'
        elif not (lo <= a and b <= hi):
            errors['first'] = f'the range must lie within {lo} – {hi}'
        else:
            for r in ranges(conn, network.id) + dhcp_pools(network, subnets):
                if r.id is not None and r.id == range_id:
                    continue
                if a <= r.last and r.first <= b:
                    errors['first'] = f'it overlaps {r.label} ({r.first} – {r.last})'
                    break
    if errors:
        raise IpamError(errors)
    with conn:
        if range_id is None:
            return conn.execute('INSERT INTO ipam_ranges (network_id, first, last, kind, name, comment) '
                                'VALUES (?, ?, ?, ?, ?, ?)',
                                (network.id, str(a), str(b), kind, name.strip(), comment.strip())).lastrowid
        conn.execute('UPDATE ipam_ranges SET first = ?, last = ?, kind = ?, name = ?, comment = ? '
                     'WHERE id = ? AND network_id = ?', (str(a), str(b), kind, name.strip(), comment.strip(),
                                                          range_id, network.id))
        return range_id


def delete_range(conn, network_id, range_id):
    with conn:
        conn.execute('DELETE FROM ipam_ranges WHERE id = ? AND network_id = ?', (range_id, network_id))


# ── suggestions ────────────────────────────────────────────────────────────────

def suggestions(conn, found=None, subnets=None):
    """[{prefix, source, why}]: the DHCP subnets and reverse zones that no leaf network covers yet."""
    from ..dhcp.model import subnets as dhcp_subnets
    from ..search import reverse_network
    found = networks(conn) if found is None else found
    subnets = dhcp_subnets(conn) if subnets is None else subnets
    candidates = []
    for s in subnets:
        try:
            candidates.append((ipaddress.IPv4Network(s.prefix), 'dhcp', s.comment or 'DHCP subnet'))
        except ValueError:
            pass
    for (name,) in conn.execute("SELECT name FROM zones WHERE name LIKE '%.in-addr.arpa' ORDER BY name"):
        net = reverse_network(name)
        if net is not None and net.prefixlen <= SMALLEST:
            candidates.append((net, 'zone', name))
    out, seen = [], set()
    for net, source, why in candidates:
        if net in seen:
            continue
        seen.add(net)
        # covered: the same network is in IPAM, or a leaf (not a container) already holds it
        if any(n.net == net or (net.subnet_of(n.net) and not n.container) for n in found):
            continue
        out.append({'prefix': str(net), 'source': source, 'why': why})
    return sorted(out, key=lambda x: (int(ipaddress.IPv4Network(x['prefix']).network_address),
                                      ipaddress.IPv4Network(x['prefix']).prefixlen))


# ── notes ──────────────────────────────────────────────────────────────────────

def notes(conn):
    return {r['ip']: r['note'] for r in conn.execute('SELECT ip, note FROM ipam_notes')}


def set_note(conn, ip, text, username):
    ip = str(ipaddress.IPv4Address(str(ip)))
    text = (text or '').strip()
    with conn:
        if text:
            conn.execute('INSERT INTO ipam_notes (ip, note, username) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE '
                         "SET note = excluded.note, username = excluded.username, updated_at = datetime('now')",
                         (ip, text, username))
        else:
            conn.execute('DELETE FROM ipam_notes WHERE ip = ?', (ip,))
