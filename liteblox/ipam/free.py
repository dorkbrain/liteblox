"""Next free: the first addresses nothing uses on paper, checked on the network itself, and held for a few minutes.

On paper, an address is used when DNS has an A or PTR record for it, DHCP a reservation or an active lease, a node
or a router has it, it's held, or the nodes saw something there within keep_days. The candidates then go through
/probe on a node with an interface on that network: an address is in use when it answers a ping, or when a MAC
answered ARP during the probe (a device that drops pings). An older neighbour entry proves nothing.

A network no node is on can't be checked: its address comes back with checked false and a warning.
"""

import ipaddress
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

MAX_BLOCK = 64           # the agent's /probe limit
BATCH = 8                # single addresses are probed a few at a time
ROUNDS = 8               # probes before giving up
_lock = threading.Lock()


class FreeError(Exception):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.message, self.status = message, status


@dataclass
class Target:
    kind: str                       # network, range, subnet
    label: str
    first: ipaddress.IPv4Address
    last: ipaddress.IPv4Address
    skip: list = field(default_factory=list)       # [(first, last)] ints left out (DHCP pools, reserved ranges)
    network_id: Optional[int] = None


def _ip(text):
    return ipaddress.IPv4Address(str(text).strip())


def target(conn, network=None, range_id=None, subnet=None):
    """What to look in: an IPAM network (id or prefix), a range (id), or a DHCP subnet (id or prefix: outside its
    pools, for a reservation). Both leave out the DHCP pools and IPAM's reserved and infrastructure ranges."""
    from ..dhcp.leases import pool_ranges
    from ..dhcp.model import subnets as dhcp_subnets
    from . import model
    given = [x for x in (network, range_id, subnet) if x not in (None, '')]
    if len(given) != 1:
        raise FreeError('give one of network, range or subnet')
    if range_id not in (None, ''):
        row = conn.execute('SELECT * FROM ipam_ranges WHERE id = ?', (int(range_id),)).fetchone()
        if row is None:
            raise FreeError('no such range', 404)
        r = model.Range.from_row(row)
        if r.first.version == 6:
            raise FreeError(NO_V6)
        return Target('range', f'{r.label} ({r.first}-{r.last})', r.first, r.last, network_id=r.network_id)
    if subnet not in (None, ''):
        found = dhcp_subnets(conn)
        s = next((x for x in found if str(x.id) == str(subnet).strip() or x.prefix == str(subnet).strip()), None)
        if s is None:
            raise FreeError('no such DHCP subnet', 404)
        net = ipaddress.IPv4Network(s.prefix)
        skip = [(int(a), int(b)) for a, b in pool_ranges(s)] + _kept_back(conn, net)
        return Target('subnet', s.prefix, net.network_address + 1, net.broadcast_address - 1, skip)
    found = model.networks(conn)
    text = str(network).strip()
    n = next((x for x in found if str(x.id) == text or x.prefix == text), None)
    if n is None:
        raise FreeError('no such network in IPAM', 404)
    if n.container:
        raise FreeError(f'{n.prefix} holds other networks: pick one of them')
    if n.version == 6:
        raise FreeError(NO_V6)
    first, last = n.hosts_range()
    skip = [(int(a), int(b)) for s in dhcp_subnets(conn) for a, b in pool_ranges(s)]
    return Target('network', n.label, first, last, skip + _kept_back(conn, n.net), n.id)


def _kept_back(conn, net):
    """[(first, last)] of the reserved and infrastructure ranges of the IPAM networks overlapping net."""
    from . import model
    return [(int(r.first), int(r.last)) for n in model.networks(conn) if not n.container and n.net.overlaps(net)
            for r in model.ranges(conn, n.id) if r.kind in ('reserved', 'infrastructure')]


NO_V6 = ('IPv6 has no next free: a /64 has 2^64 addresses. Pick one yourself (or let DHCPv6 or SLAAC hand them out) '
         'and give it a name with Add DNS or a DHCPv6 reservation')


# scanners first: placed on a network for this, they spare the DNS/DHCP servers the probes
SCANNERS_FIRST = 'ORDER BY (bind = 1 OR dhcp = 1 OR ntp = 1), id'


def node_on(conn, ip):
    """A ready node with an interface on ip's network (a scanner when there is one), or None."""
    for node in conn.execute(f"SELECT * FROM nodes WHERE status = 'ready' {SCANNERS_FIRST}"):
        for prefix in json.loads(node['networks'] or '[]'):
            try:
                if ip in ipaddress.ip_network(prefix):
                    return node
            except ValueError:
                pass
    return None


# ── holds ──────────────────────────────────────────────────────────────────────

def expire(conn, now=None):
    now = int(now if now is not None else time.time())
    with conn:
        conn.execute('DELETE FROM ipam_holds WHERE expires_at <= ?', (now,))


def holds(conn, now=None):
    """{ip: {hold_id, expires_at, username, note}} of the holds still running."""
    now = int(now if now is not None else time.time())
    return {r['ip']: dict(r) for r in conn.execute('SELECT * FROM ipam_holds WHERE expires_at > ?', (now,))}


def release(conn, ip=None, hold_id=None):
    """Drop a hold, or a block's holds; returns the addresses released."""
    if ip:
        rows = conn.execute('SELECT ip FROM ipam_holds WHERE ip = ?', (str(ip),)).fetchall()
    else:
        rows = conn.execute('SELECT ip FROM ipam_holds WHERE hold_id = ?', (hold_id or '',)).fetchall()
    with conn:
        conn.executemany('DELETE FROM ipam_holds WHERE ip = ?', [(r['ip'],) for r in rows])
    return [r['ip'] for r in rows]


# ── used on paper ──────────────────────────────────────────────────────────────

def taken(conn, facts, now=None):
    """The addresses (ints) used on paper: everything IPAM knows of (facts.used: DNS, reservations, active leases,
    seen lately), anything the nodes saw within keep_days, the nodes' and routers' own addresses, and the holds still
    running."""
    from ..dhcp.model import Dhcp4Settings
    # stricter than the map: a quiet device seen a few days ago still keeps its address from next free
    out = set(facts.used) | {int(ip) for ip in facts.seen}
    for node in conn.execute('SELECT host, addresses FROM nodes'):
        for a in [node['host'], *json.loads(node['addresses'] or '[]')]:
            try:
                out.add(int(_ip(a)))
            except ValueError:
                pass
    row = conn.execute('SELECT * FROM dhcp4_settings WHERE id = 1').fetchone()
    routers = list((Dhcp4Settings.from_row(row).options if row else {}).get('routers') or [])
    for s in facts.subnets:
        routers += s.options.get('routers') or []
        routers += [r.ip_address for r in s.reservations if r.ip_address]
    for a in routers:
        try:
            out.add(int(_ip(a)))
        except ValueError:
            pass
    out |= {int(_ip(ip)) for ip in holds(conn, now)}
    return out


def _skipped(tgt, n):
    return any(a <= n <= b for a, b in tgt.skip)


def _in_use(r, elapsed):
    """A ping reply, or a MAC confirmed during the probe (it answered ARP)."""
    r = r or {}
    return bool(r.get('replied') or (r.get('mac') and r.get('confirmed') is not None and r['confirmed'] <= elapsed))


def _agent_probe(settings, node, ips):
    from ..nodes import service as nodes
    with nodes.agent_client(settings, node, timeout=60.0) as c:
        return c.probe(ips, wait=1.5)


# ── next free ──────────────────────────────────────────────────────────────────

def next_free(conn, settings, tgt, count=1, align=False, hold=True, minutes=10, username=None, note='',
              facts=None, probe=None, now=None):
    """{ips, checked, node, probed, hold_id, hold_until, warnings}: count contiguous addresses free in tgt (aligned
    on a multiple of count when align), probed on the network, and held for minutes unless hold is false.
    probe(node, ips) → the agent's /probe answer (tests pass their own)."""
    from ..nodes.client import AgentError
    from . import seen, view
    if not 1 <= count <= MAX_BLOCK:
        raise FreeError(f'count is 1 to {MAX_BLOCK}')
    if not 1 <= minutes <= 24 * 60:
        raise FreeError('minutes is 1 to 1440')
    probe = probe or (lambda node, ips: _agent_probe(settings, node, ips))
    with _lock:      # pick and hold under one lock: two callers never get the same address
        now = int(now if now is not None else time.time())
        expire(conn, now)
        facts = facts if facts is not None else view.gather(conn, settings)
        used = taken(conn, facts, now)
        node = node_on(conn, tgt.first)
        warnings, probed, checked = [], {}, node is not None
        if node is None:
            warnings.append(f'No node is on {tgt.label}, so nothing checked that the address is really free.')
        start, lo, hi = int(tgt.first), int(tgt.first), int(tgt.last)
        found = None
        for _ in range(ROUNDS):
            run = _next_run(start, lo, hi, count, align, used, tgt)
            if run is None:
                break
            if not checked:
                found = run
                break
            batch = run if count > 1 else _more(run[0], hi, used, tgt, BATCH)
            ips = [str(ipaddress.IPv4Address(n)) for n in batch]
            try:
                answer = probe(node, ips)
            except AgentError as e:
                checked = False
                warnings.append(f"{node['name']} couldn't check the addresses ({e.message}): nothing checked that "
                                'they are really free.')
                found = run
                break
            elapsed = answer.get('elapsed') or 0
            results = answer.get('results') or {}
            probed.update(results)
            seen.record(conn, node['id'], [{'ip': ip, 'mac': r.get('mac'), 'confirmed': r.get('confirmed')}
                                           for ip, r in results.items() if r.get('mac')], now=now, source='probe')
            busy = [int(_ip(ip)) for ip in ips if _in_use(results.get(ip), elapsed)]
            used |= set(busy)
            if count > 1:
                if not busy:
                    found = run
                    break
                start = max(busy) + 1
            else:
                free = [int(_ip(ip)) for ip in ips if int(_ip(ip)) not in used]
                if free:
                    found = [free[0]]
                    break
                start = max(int(_ip(ip)) for ip in ips) + 1
        if found is None:
            what = f'{count} free addresses in a row' if count > 1 else 'a free address'
            raise FreeError(f'No {what} in {tgt.label}' + (' among those probed' if probed else ''), 409)
        out = [str(ipaddress.IPv4Address(n)) for n in found]
        hold_id = hold_until = None
        if hold:
            hold_id, hold_until = secrets.token_hex(6), now + minutes * 60
            with conn:
                conn.executemany('INSERT INTO ipam_holds (ip, hold_id, expires_at, username, note) VALUES (?, ?, ?, ?, ?)',
                                 [(ip, hold_id, hold_until, username, (note or '')[:200]) for ip in out])
    return {'ips': out, 'checked': checked, 'node': node['name'] if node else None,
            'probed': {ip: probed[ip] for ip in sorted(probed, key=ipaddress.IPv4Address)},
            'hold_id': hold_id, 'hold_until': hold_until, 'warnings': warnings}


def _free(n, used, tgt):
    return n not in used and not _skipped(tgt, n)


def _next_run(start, lo, hi, count, align, used, tgt):
    """The first count addresses in a row from start that are free on paper, or None."""
    n = max(start, lo)
    while True:
        if align and count > 1:
            n = -(-n // count) * count
        if n + count - 1 > hi:
            return None
        bad = [m for m in range(n, n + count) if not _free(m, used, tgt)]
        if not bad:
            return list(range(n, n + count))
        n = bad[-1] + 1


def _more(n, hi, used, tgt, k):
    """Up to k addresses from n on that are free on paper (n is one)."""
    out = []
    while n <= hi and len(out) < k:
        if _free(n, used, tgt):
            out.append(n)
        n += 1
    return out
