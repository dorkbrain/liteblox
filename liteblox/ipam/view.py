"""What each address in a network is used for, put together from DNS and DHCP.

One search over every address (search.search with 0.0.0.0/0) gathers the A and PTR records, the reservations and
the active leases once per page, and IPAM's own table adds what the nodes have seen; each network's figures, rows
and maps are worked out from that. DNS and DHCP are never copied: IPAM keeps only networks, ranges, notes, its
own records (names kept in IPAM only), the PTR names a resolver gave, and the learned entries.
"""

import bisect
import ipaddress
import math
from dataclasses import dataclass, field

from .. import search
from ..dhcp import leases as lease_mod
from ..dns import ptr
from .checks import address_checks
from .model import KINDS

PAGE = 256              # one /24 per page
EVERYTHING = '0.0.0.0/0'

# an address's state: (label, pill class), in the order the Utilization donut and its legend show them
STATES = {
    'reserved': ('Reserved', 'reserved'),
    'named': ('Named', 'named'),
    'leased': ('Leased', 'leased'),
    'dns': ('DNS', 'dns'),
    'seen': ('Seen', 'seen'),
    'free': ('Free', 'free'),
}
USED = ('reserved', 'named', 'leased', 'dns', 'seen')


@dataclass
class Facts:
    """Every address DNS or DHCP knows of, from one search."""
    names: dict = field(default_factory=dict)           # ip → [A record hits]
    ptrs: dict = field(default_factory=dict)            # ip → [PTR record hits]
    reservations: dict = field(default_factory=dict)    # ip → [(subnet, reservation)]
    leases: dict = field(default_factory=dict)          # ip → (node, active lease)
    seen: dict = field(default_factory=dict)            # ip → {mac, last_seen, macs} (seen.latest): all kept
    in_use: set = field(default_factory=set)            # the ones seen within seen_hours, which count as used
    flapping: set = field(default_factory=set)          # IPv4Addresses
    vendors: dict = field(default_factory=dict)         # oui prefix → vendor
    labels: dict = field(default_factory=dict)          # mac → device label
    repeaters: frozenset = frozenset()                  # the MACs marked as a Wi-Fi repeater's
    ipam: dict = field(default_factory=dict)            # ip → IPAM record (names.records)
    rdns: dict = field(default_factory=dict)            # ip → PTR lookup {name, looked_up_at, error}
    subnets: list = field(default_factory=list)
    reverse_zones: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    stale: dict = field(default_factory=dict)
    used: list = field(default_factory=list)            # sorted ints of every address above

    def state(self, ip):
        if ip in self.reservations:
            return 'reserved'
        if ip in self.ipam:
            return 'named'
        if ip in self.leases:
            return 'leased'
        if ip in self.names or ip in self.ptrs:
            return 'dns'
        if ip in self.in_use:
            return 'seen'
        return 'free'

    def used_between(self, first, last):
        """[ints] of the used addresses from first to last (ints, inclusive)."""
        return self.used[bisect.bisect_left(self.used, first):bisect.bisect_right(self.used, last)]

    def subnet_for(self, ip):
        for s in self.subnets:
            try:
                if ip in ipaddress.IPv4Network(s.prefix, strict=False):
                    return s
            except ValueError:
                pass
        return None


def gather(conn, settings, prefix=EVERYTHING, transfer=None):
    from . import devices, names, oui, ptr as rdns, seen
    res = search.search(conn, settings, prefix, limit=math.inf, transfer=transfer)
    facts = Facts(subnets=search.dhcp_model.subnets(conn), errors=list(res.errors), stale=dict(res.stale),
                  seen=seen.latest(conn), vendors=oui.table(settings), labels=devices.labels(conn),
                  repeaters=devices.repeaters(conn),
                  ipam=names.records(conn), rdns=rdns.cached(conn),
                  flapping={ipaddress.IPv4Address(f['ip']) for f in seen.flapping(conn)})
    facts.reverse_zones = [h['zone']['name'] for h in res.zones.hits if h['zone']['name'].endswith('.in-addr.arpa')]
    for h in res.records.hits:
        rec = h['rec']
        if rec.address is None:
            continue
        if rec.rtype == 'A':
            facts.names.setdefault(rec.address, []).append(h)
        elif rec.rtype == 'PTR':
            facts.ptrs.setdefault(rec.address, []).append(h)
    for h in res.reservations.hits:
        ip = search._v4(h['r'].ip_address)
        if ip is not None:
            facts.reservations.setdefault(ip, []).append((h['subnet'], h['r']))
    for h in res.leases.hits:
        lease = h['lease']
        ip = search._v4(lease['ip'])
        if ip is not None and lease['state'] == 'active':
            facts.leases[ip] = (h['node'], lease)
    facts.in_use = seen.in_use(facts.seen, seen.settings(conn).seen_hours)
    facts.used = sorted({int(ip) for d in (facts.names, facts.ptrs, facts.reservations, facts.leases, facts.in_use,
                                           facts.ipam) for ip in d})
    return facts


# ── one network's figures ──────────────────────────────────────────────────────

def usage(facts, network):
    """(used, usable) host addresses of a leaf network."""
    lo, hi = network.hosts_range()
    return len(facts.used_between(int(lo), int(hi))), network.usable


def counts(facts, network):
    """{state: n} over the network's host addresses, free included."""
    lo, hi = network.hosts_range()
    out = {s: 0 for s in STATES}
    for n in facts.used_between(int(lo), int(hi)):
        out[facts.state(ipaddress.IPv4Address(n))] += 1
    out['free'] = network.usable - sum(out[s] for s in USED)
    return out


def range_counts(facts, ranges):
    """[(range, used)] for the network's ranges."""
    return [(r, len(facts.used_between(int(r.first), int(r.last)))) for r in ranges]


def pages(network):
    return max(1, network.net.num_addresses // PAGE)


def page_bounds(network, page):
    """(first, last) IPv4Address of page (0-based), one /24 (or the whole of a smaller network)."""
    net = network.net
    if net.num_addresses <= PAGE:
        return net.network_address, net.broadcast_address
    first = net.network_address + page * PAGE
    return first, first + PAGE - 1


def page_of(network, ip):
    return (int(ipaddress.IPv4Address(str(ip))) - int(network.net.network_address)) // PAGE


def blocks(facts, network):
    """For a leaf bigger than a /24: [{page, first, used, size, level}] per /24, level 0–4 by how full it is."""
    if network.net.num_addresses <= PAGE:
        return []
    out = []
    lo, hi = network.hosts_range()
    for page in range(pages(network)):
        first, last = page_bounds(network, page)
        a, b = max(first, lo), min(last, hi)
        size = int(b) - int(a) + 1
        used = len(facts.used_between(int(a), int(b)))
        out.append({'page': page, 'first': first, 'used': used, 'size': size, 'level': level(used, size)})
    return out


def level(used, size):
    """0 (empty) to 4 (full): the shade of a map cell."""
    if not used or not size:
        return 0
    return min(4, 1 + int(3 * used / size))


def svg_donut(parts, radius=40, width=14):
    """[(state, n, dasharray, offset)] stroke segments for an SVG donut of the given parts [(state, n)]."""
    total = sum(n for _, n in parts) or 1
    circumference = 2 * math.pi * radius
    out, at = [], 0.0
    for state, n in parts:
        if not n:
            continue
        length = circumference * n / total
        out.append((state, n, f'{length:.2f} {circumference - length:.2f}', f'{-at:.2f}'))
        at += length
    return out


# ── the rows ───────────────────────────────────────────────────────────────────

def row(facts, ip, network, ranges, notes):
    """Everything about one address: {ip, state, label, pill, kind, names, ptrs, reservation, rsubnet, lease,
    lease_node, mac, hostname, ipam, rdns, rdns_name, nameable, range, comment, comment_from, checks, subnet,
    in_pool}. rdns_name: the resolver's PTR name when no A record or IPAM record already says it; nameable: no
    zone in LiteBlox covers the address, so an IPAM record is where its name goes."""
    names = facts.names.get(ip, [])
    ptrs = facts.ptrs.get(ip, [])
    held = facts.reservations.get(ip, [])
    rsubnet, r = held[0] if held else (None, None)
    lease_node, active = facts.leases.get(ip, (None, None))
    subnet = facts.subnet_for(ip)
    in_pool = bool(subnet) and any(a <= ip <= b for a, b in lease_mod.pool_ranges(subnet))
    net = network.net
    kind = 'network' if ip == net.network_address else 'broadcast' if ip == net.broadcast_address else 'host'
    state = facts.state(ip)
    label, pill = STATES[state]
    record = facts.ipam.get(ip)
    looked = facts.rdns.get(ip)
    comment, comment_from = _comment(ip, names, r, notes, record)
    rzone = ptr.reverse_zone_for(str(ip), facts.reverse_zones)
    seen = facts.seen.get(ip)
    in_range = next((x for x in ranges if ip in x), None)
    mac = (r.hw_address if r else active['mac'] if active else record['mac'] if record and record['mac'] else
           seen['mac'] if seen else '')
    known = {h['rec'].fqdn for h in names} | ({record['name']} if record else set())
    rdns_name = looked['name'] if looked and looked['name'] and looked['name'] not in known else ''
    return {
        'ip': ip, 'state': state, 'label': label, 'pill': pill, 'kind': kind,
        'names': names, 'ptrs': ptrs, 'reservation': r, 'rsubnet': rsubnet, 'lease': active,
        'lease_node': lease_node, 'mac': mac, 'vendor': _vendor(facts, mac), 'seen': seen,
        'flapping': ip in facts.flapping,
        'hostname': (r.hostname if r and r.hostname else active['hostname'] if active else ''),
        'ipam': record, 'rdns': looked, 'rdns_name': rdns_name, 'nameable': rzone is None,
        'range': in_range, 'comment': comment, 'comment_from': comment_from,
        'checks': address_checks(ip, names, ptrs, rzone, r, active, subnet, in_pool, seen=seen,
                                 static_range=in_range is not None and in_range.kind == 'static', ipam=record,
                                 rdns=looked, repeaters=facts.repeaters)
        if state != 'free' else [],
        'subnet': subnet, 'in_pool': in_pool,
    }


def _vendor(facts, mac):
    """The line under a MAC: its device label and vendor."""
    from .devices import line
    from .oui import vendor
    from .seen import mac_text
    m = mac_text(mac)
    return line(facts.labels.get(m, ''), vendor(None, mac, facts.vendors), m in facts.repeaters) if mac else ''


def _comment(ip, names, r, notes, record=None):
    """(text, where) for an address's one comment, and where an edit of it goes: the first A record in a static
    zone, else its reservation, else its IPAM record, else IPAM's own note. where = {kind:
    dns|reservation|ipam|note, ...}."""
    static = [h for h in names if not h['dynamic']]
    places = []
    for h in static:
        places.append((h['rec'].comment, {'kind': 'dns', 'zone': h['zone'], 'name': h['rec'].name,
                                          'fqdn': h['rec'].fqdn, 'draft': h['draft']}))
    if r is not None:
        places.append((r.comment, {'kind': 'reservation', 'id': r.id, 'subnet_id': r.subnet_id}))
    if record is not None:
        places.append((record['comment'], {'kind': 'ipam'}))
    else:
        places.append((notes.get(str(ip), ''), {'kind': 'note'}))
    for text, where in places:
        if text:
            return text, where
    return '', places[0][1]


def rows(facts, network, ranges, notes, page=0, used_only=False):
    first, last = page_bounds(network, page)
    out = []
    if used_only:
        for n in facts.used_between(int(first), int(last)):
            out.append(row(facts, ipaddress.IPv4Address(n), network, ranges, notes))
        return out
    for n in range(int(first), int(last) + 1):
        out.append(row(facts, ipaddress.IPv4Address(n), network, ranges, notes))
    return out


def item(a):
    """A row as plain data, for the API and the CSV export (last_seen stays a unix time)."""
    return {
        'ip': str(a['ip']), 'state': a['state'], 'names': [h['rec'].fqdn for h in a['names']],
        'ipam_name': a['ipam']['name'] if a['ipam'] else None, 'rdns': (a['rdns'] or {}).get('name') or None,
        'ptr': [h['rec'].target or h['rec'].rdata for h in a['ptrs']], 'mac': a['mac'], 'vendor': a['vendor'],
        'hostname': a['hostname'], 'range': a['range'].label if a['range'] else None, 'comment': a['comment'] or '',
        'comment_from': a['comment_from']['kind'] if a['comment_from'] else None,
        'last_seen': a['seen']['last_seen'] if a['seen'] else None,
        'flapping': a['flapping'], 'checks': [{'level': lv, 'text': t} for lv, t, _ in a['checks']]}


def cells(page_rows, ranges):
    """The address map of one page: [{ip, state, last octet, range index, title}]."""
    index = {id(r): i for i, r in enumerate(ranges)}
    out = []
    for x in page_rows:
        what = (', '.join(h['rec'].fqdn for h in x['names']) or (x['ipam']['name'] if x['ipam'] else '') or
                x['hostname'] or x['rdns_name'])
        title = f"{x['ip']}: {x['label'] if x['kind'] == 'host' else x['kind'] + ' address'}"
        if what:
            title += f' · {what}'
        if x['range'] is not None:
            title += f" · {x['range'].label}"
        out.append({'ip': x['ip'], 'state': x['state'] if x['kind'] == 'host' else 'edge',
                    'octet': int(x['ip']) & 255, 'band': index.get(id(x['range'])), 'title': title,
                    'checks': bool(x['checks']) or x['flapping']})
    return out


# ── a container ────────────────────────────────────────────────────────────────

def container_map(facts, network):
    """A container's block map: [{first, prefix, child, share, level, title}], one cell per unit block (a /24
    in a /16, a /16 in a /8: 256 cells, fewer below a /22), shaded by how much of it child networks cover."""
    net = network.net
    out = []
    for block in net.subnets(new_prefix=min(net.prefixlen + 8, 30)):
        covering = [c for c in network.children if c.net.overlaps(block)]
        covered = sum(min(c.net.num_addresses, block.num_addresses) for c in covering)
        share = min(1.0, covered / block.num_addresses)
        child = max(covering, key=lambda c: c.net.num_addresses) if covering else None
        title = f'{block}: ' + (', '.join(f'{c.label} ({c.prefix})' if c.name else c.prefix for c in covering[:3])
                                if covering else 'not assigned')
        out.append({'first': block.network_address, 'prefix': str(block), 'child': child,
                    'share': share, 'level': 0 if not covering else max(1, round(4 * share)), 'title': title})
    return out


def container_counts(network):
    """{'assigned': n, 'free': n} addresses of a container."""
    assigned = sum(c.net.num_addresses for c in network.children)
    return {'assigned': assigned, 'free': network.net.num_addresses - assigned}


def describe(kind):
    return KINDS.get(kind, 'DHCP pool')
