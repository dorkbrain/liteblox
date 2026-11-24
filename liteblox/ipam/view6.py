"""An IPv6 network's page: the addresses LiteBlox knows of there, put together like an IPv4 network's rows.

A /64 holds 2^64 addresses, so there's no map, free count, next free or sweep: the page lists what DNS (AAAA, PTR),
DHCPv6 (reservations, leases, delegated prefixes), IPAM's own records and notes, and the nodes' neighbour tables
(NDP) know of inside the network, with the same row (view.row) and checks as an IPv4 network's.
"""

import ipaddress
import math

from .. import search
from . import view


EVERYTHING = ipaddress.IPv6Network('::/0')


def gather(conn, settings, network=None, transfer=None):
    """(Facts for the IPv6 addresses inside network (every one without it), [delegated prefixes in it]). transfer:
    for tests."""
    from . import devices, names, oui, ptr as rdns, seen
    net = network.net if network is not None else EVERYTHING
    res = search.search(conn, settings, str(net), limit=math.inf, transfer=transfer)

    def inside(d):
        return {ip: v for ip, v in d.items() if ip.version == 6 and ip in net}

    facts = view.Facts(subnets=search.dhcp_model.subnets6(conn), errors=list(res.errors), stale=dict(res.stale),
                       seen=inside(seen.latest(conn)), vendors=oui.table(settings), labels=devices.labels(conn),
                       repeaters=devices.repeaters(conn), ipam=inside(names.records(conn)),
                       rdns=inside(rdns.cached(conn)),
                       flapping={a for a in map(ipaddress.ip_address, (f['ip'] for f in seen.flapping(conn)))
                                 if a.version == 6 and a in net})
    facts.reverse_zones = [r['name'] for r in conn.execute("SELECT name FROM zones WHERE name LIKE '%.ip6.arpa'")]
    for h in res.records.hits:
        rec = h['rec']
        if rec.address is None or rec.address.version != 6:
            continue
        if rec.rtype == 'AAAA':
            facts.names.setdefault(rec.address, []).append(h)
        elif rec.rtype == 'PTR':
            facts.ptrs.setdefault(rec.address, []).append(h)
    prefixes = []
    for h in res.reservations.hits:
        r = h['r']
        if h['subnet'].family != 6:
            continue
        ip = search._v6(r.ip_address)
        if ip is not None and ip in net:
            facts.reservations.setdefault(ip, []).append((h['subnet'], r))
        if r.prefix and _within(r.prefix, net):
            prefixes.append({'prefix': r.prefix, 'kind': 'reserved', 'subnet': h['subnet'], 'reservation': r,
                             'client': r.duid or r.hw_address, 'hostname': r.hostname, 'lease': None})
    for h in res.leases.hits:
        lease = h['lease']
        if 'duid' not in lease or lease['state'] != 'active':
            continue
        if lease['type'] == 'prefix':
            if not _within(lease['prefix'], net):
                continue
            held = next((p for p in prefixes if p['prefix'] == lease['prefix']), None)
            if held is not None:
                held['lease'] = lease
            else:
                prefixes.append({'prefix': lease['prefix'], 'kind': 'delegated', 'subnet': h['subnet'],
                                 'reservation': None, 'client': lease['duid'], 'hostname': lease['hostname'],
                                 'lease': lease})
            continue
        ip = search._v6(lease['ip'])
        if ip is not None and ip in net:
            facts.leases[ip] = (h['node'], lease)
    facts.in_use = seen.in_use(facts.seen, seen.settings(conn).seen_hours)
    facts.used = sorted({int(ip) for d in (facts.names, facts.ptrs, facts.reservations, facts.leases, facts.in_use,
                                           facts.ipam) for ip in d})
    prefixes.sort(key=lambda p: (int(ipaddress.ip_network(p['prefix']).network_address),
                                 ipaddress.ip_network(p['prefix']).prefixlen))
    return facts, prefixes


def _within(prefix, net):
    try:
        p = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False
    return p.version == 6 and p.subnet_of(net)


def known(facts, network, notes):
    """The addresses to list: everything facts knows of in the network (seen ones too, however long ago, while
    they're kept), plus addresses with an IPAM note."""
    net = network.net
    out = {a for d in (facts.reservations, facts.names, facts.ptrs, facts.leases, facts.ipam, facts.seen) for a in d
           if a in net}
    for text in notes:
        a = search._v6(text)
        if a is not None and a in net:
            out.add(a)
    return sorted(out)


def prefixes_in(prefixes, network):
    return [p for p in prefixes if _within(p['prefix'], network.net)]


def rows(facts, network, ranges, notes):
    return [view.row(facts, ip, network, ranges, notes) for ip in known(facts, network, notes)]


def counts(page_rows):
    """{state: n} over the listed addresses (no Free: an IPv6 network's free addresses aren't counted)."""
    out = {s: 0 for s in view.USED}
    for a in page_rows:
        if a['state'] in out and a['kind'] == 'host':
            out[a['state']] += 1
    return out


def names(conn, settings, transfer=None):
    """{IPv6Address: [fqdn]} of every AAAA record (static zones as drafted, dynamic ones live): Devices seen's names
    for the IPv6 addresses it lists."""
    res = search.Results(search.Query('::/0', 'network', network=ipaddress.IPv6Network('::/0'), needle='::/0'),
                         limit=math.inf)
    zones = conn.execute('SELECT * FROM zones ORDER BY name').fetchall()
    search._records(conn, settings, res, zones, transfer)
    out = {}
    for h in res.records.hits:
        if h['rec'].rtype == 'AAAA' and h['rec'].fqdn not in out.setdefault(h['rec'].address, []):
            out[h['rec'].address].append(h['rec'].fqdn)
    return out
