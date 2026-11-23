"""Automatic PTR records: keep reverse zones in step with A/AAAA edits.

When an A/AAAA record is added, changed or deleted and LiteBlox holds a reverse
zone covering the address, the matching PTR is added, moved or removed in that
zone's draft. A PTR that already points somewhere else is never overwritten:
the edit reports it and leaves it for the user.
"""

import ipaddress
import re

import dns.exception
import dns.name
import dns.reversename

FORWARD_TYPES = ('A', 'AAAA')
_HOST_LABEL = re.compile(rb'[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?')


def is_host_name(name):
    """True when every label is letters, digits and inner hyphens: what BIND's check-names wants of a PTR target.

    Wildcards (*.lab.example.com) and service names (_sip._tcp) fail, so they never get a PTR.
    """
    return all(_HOST_LABEL.fullmatch(label) for label in name.labels if label)


def address_of(rtype, rdata):
    """The address an A/AAAA record points at, or None."""
    if rtype not in FORWARD_TYPES:
        return None
    try:
        return str(ipaddress.ip_address((rdata or '').strip()))
    except ValueError:
        return None


def changes(old, new):
    """PTR changes for a forward record going from old to new; each is (name, rtype, rdata) or None.

    Returns [('remove'|'add', address, target Name)].
    """
    def key(rec):
        if rec is None:
            return None
        addr = address_of(rec[1], rec[2])
        return (addr, rec[0]) if addr else None
    before, after = key(old), key(new)
    if before == after:
        return []
    out = []
    if before:
        out.append(('remove', *before))
    if after:
        out.append(('add', *after))
    return out


def reverse_zone_for(address, zone_names):
    """The most specific reverse zone among zone_names that covers address, or None."""
    owner = dns.reversename.from_address(address)
    best = None
    for name in zone_names:
        try:
            zone = dns.name.from_text(name + '.')
        except dns.exception.DNSException:
            continue
        if owner.is_subdomain(zone) and (best is None or len(zone) > len(best[1])):
            best = (name, zone)
    return best[0] if best else None


def _target(rec):
    try:
        return dns.name.from_text(rec.rdata.strip(), rec.origin)
    except dns.exception.DNSException:
        return None


def _sort_key(rec):
    try:
        return int(ipaddress.ip_address(dns.reversename.to_address(rec.name)))
    except (dns.exception.DNSException, ValueError):
        return None


def _insert_after(rzone, address):
    """Keep PTRs in address order: after the PTR for the nearest lower address."""
    value = int(ipaddress.ip_address(address))
    ptrs = [r for r in rzone.records() if r.rtype == 'PTR']
    lower = [r for r in ptrs if (_sort_key(r) is not None and _sort_key(r) < value)]
    if lower:
        return max(lower, key=_sort_key)
    if ptrs:
        idx = rzone.records().index(ptrs[0])
        return rzone.records()[idx - 1] if idx > 0 else None
    return None


def apply(rzone, kind, address, target):
    """Apply one change to a parsed reverse zone. Returns (changed, message or None)."""
    owner = dns.reversename.from_address(address)
    here = [r for r in rzone.records() if r.name == owner and r.rtype == 'PTR']
    if kind == 'add':
        if any(_target(r) == target for r in here):
            return False, None
        if here:
            return False, (f'PTR for {address} already points to {here[0].rdata}; left it unchanged '
                           f'(edit {rzone.origin.to_text().rstrip(".")} if {target} should replace it)')
        rzone.add(owner.relativize(rzone.origin).to_text(), 'PTR', target.to_text(),
                  after=_insert_after(rzone, address))
        return True, f'added PTR {address} → {target} in {rzone.origin.to_text().rstrip(".")}'
    matching = [r for r in here if _target(r) == target]
    for r in matching:
        rzone.delete(r)
    if matching:
        return True, f'removed PTR {address} → {target} from {rzone.origin.to_text().rstrip(".")}'
    return False, None
