"""The zone's nameservers (apex NS records) and how they line up with the nodes serving it.

Addresses come only from zones LiteBlox holds (drafts included), never from DNS
lookups, so the checks describe what is about to be published.
"""

import ipaddress

import dns.name

from .zonefile import _rdata_tokens


def apex_ns(zone):
    return [r for r in zone.records() if r.rtype == 'NS' and r.name == zone.origin]


def addresses_in(zone, name):
    return [_rdata_tokens(r.rdata)[0] for r in zone.records() if r.name == name and r.rtype in ('A', 'AAAA')]


def _same_address(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def check(zone, nodes, lookup):
    """Describe each NS and what's wrong overall.

    nodes: the nodes serving the zone (dicts with id, name, host).
    lookup(name) -> list of addresses, or None when no zone in LiteBlox holds that name.
    Returns (entries, problems, notes): entries are dicts with rec, target, addresses (None = unknown)
    and nodes (those whose address it points at).
    """
    entries, problems, notes = [], [], []
    for rec in apex_ns(zone):
        target = dns.name.from_text(_rdata_tokens(rec.rdata)[0], rec.origin)
        inside = target.is_subdomain(zone.origin)
        addresses = addresses_in(zone, target) if inside else lookup(target)
        matched = [n for n in nodes if n['host'].rstrip('.').lower() == target.to_text(omit_final_dot=True).lower()
                   or any(_same_address(n['host'], a) for a in addresses or [])]
        entries.append({'rec': rec, 'target': target.to_text(), 'addresses': addresses, 'nodes': matched})
        if inside and not addresses:
            problems.append(f'{target} is inside this zone but has no A or AAAA record, so the zone won\'t load')
        elif addresses and not matched:
            notes.append(f'{target} isn\'t one of the nodes serving this zone (fine for a secondary elsewhere)')
    if not entries:
        problems.append('the zone has no NS records')
    unknown = [e['target'] for e in entries if e['addresses'] is None]
    for n in nodes:
        if not any(n in e['nodes'] for e in entries):
            if unknown:
                notes.append(f"can't tell whether {n['name']} is listed: LiteBlox doesn't hold the address of "
                             + ', '.join(unknown))
            else:
                problems.append(f"{n['name']} ({n['host']}) serves this zone but isn't one of its nameservers, "
                                'so resolvers never ask it')
    return entries, problems, notes
