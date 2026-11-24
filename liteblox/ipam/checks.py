"""What doesn't add up about one address: the search card and IPAM's network view share these.

Each check is (level, text, link): 'warn' for something likely wrong, 'info' for something worth knowing. They
warn, never block: a home network has good reasons for most oddities.
"""


def _mac(mac):
    from ..search import bare_mac
    return bare_mac(mac)


def _subnet_url(r):
    """A reservation's subnet page (DHCPv6 reservations have a DUID field; their subnets are numbered apart)."""
    return f"/dhcp/{'v6/' if hasattr(r, 'duid') else ''}subnets/{r.subnet_id}"


def _client(x):
    """Who a reservation or lease is for: its DUID when it has one (DHCPv6), else its MAC, as (label, bare)."""
    duid = x.get('duid') if isinstance(x, dict) else getattr(x, 'duid', '')
    mac = x.get('mac') if isinstance(x, dict) else x.hw_address
    return (duid, _mac(duid)) if duid else (mac or '', _mac(mac) if mac else '')


def _named(host, names):
    """True when the short or full host name is one of names (fqdns, lowercase, no trailing dot)."""
    host = (host or '').lower().rstrip('.')
    return any(n == host or n.startswith(host + '.') for n in names)


def address_checks(ip, names, ptrs, rzone, reservation, active, subnet, in_pool, seen=None, static_range=False,
                   ipam=None, rdns=None, repeaters=frozenset()):
    """names/ptrs: the A and PTR record hits at ip (search's {zone, rec, ...}); rzone: the reverse zone that
    covers ip, or None; reservation: the DHCP reservation at ip, or None; active: its active lease, or None;
    subnet: the DHCP subnet holding ip, or None; in_pool: ip is in one of that subnet's pools; seen: what the
    nodes saw there last ({mac, last_seen}, seen.latest), or None; static_range: ip is in an IPAM static range;
    ipam: its IPAM record ({name, mac, ...}), or None; rdns: its PTR lookup ({name, error, ...}), or None;
    repeaters: the MACs marked as a Wi-Fi repeater's, which say nothing about which device is on an address."""
    from ..search import record_link
    checks = []

    def check(level, text, link=None):
        checks.append((level, text, link))

    a_names = list(dict.fromkeys(h['rec'].fqdn for h in names))
    r = reservation
    # a PTR is owed to a name in DNS; a reservation or lease without one doesn't need it
    if names and rzone is None:
        check('info', 'No reverse zone in LiteBlox covers this address, so it has no PTR here.')
    elif names and not ptrs:
        check('warn', f'No PTR record for it in {rzone}.', f'/zones/{rzone}')
    for h in ptrs:
        target = h['rec'].target
        if target and target not in a_names:
            kind = 'AAAA' if ':' in str(ip) else 'A'
            check('warn', f"The PTR points to {target}, but no {kind} record for {target} has this address.",
                  record_link(h))
    if r and r.hostname and a_names and not _named(r.hostname, a_names):
        check('warn', f"It's reserved for {r.hostname}, but DNS names it {a_names[0]}.",
              f'{_subnet_url(r)}/addresses?filter={ip}')
    if r and active:
        (want, want_bare), (has, has_bare) = _client(r), _client({'duid': active.get('duid') if getattr(r, 'duid', '')
                                                                  else '', 'mac': active['mac']})
        if want_bare and has_bare and want_bare != has_bare:
            check('warn', f"It's reserved for {want}, but {has} holds the lease.",
                  f'{_subnet_url(r)}/addresses?filter={ip}')
    if active and active['hostname'] and subnet and subnet.registers:
        # registered at another DNS server: LiteBlox doesn't hold its zones, so only a PTR lookup can tell
        if subnet.ddns_mode != 'external' and not _named(active['hostname'], a_names):
            check('warn', f"The lease's hostname {active['hostname']} isn't in DNS at this address.",
                  f'{subnet.url}/addresses?filter={ip}')
        elif subnet.ddns_mode == 'external' and rdns and rdns['name'] and not _named(active['hostname'],
                                                                                    [rdns['name']]):
            check('warn', f"The lease's hostname is {active['hostname']}, but its PTR at the resolver says "
                          f"{rdns['name']}.", f'{subnet.url}/addresses?filter={ip}')
    other = seen and not any(_mac(seen['mac']) == _mac(m) for m in repeaters)
    if other and r and r.hw_address and _mac(seen['mac']) != _mac(r.hw_address) and not (
            active and active['mac'] and _mac(active['mac']) == _mac(seen['mac'])):
        check('warn', f"It's reserved for {r.hw_address}, but the nodes last saw {seen['mac']} on it.",
              f'/ipam/seen?q={ip}')
    if ipam and rdns and rdns['name'] and not (_named(ipam['name'], [rdns['name']]) or
                                               _named(rdns['name'], [ipam['name']])):
        check('warn', f"IPAM names it {ipam['name']}, but its PTR at the resolver says {rdns['name']}.")
    if other and ipam and ipam['mac'] and _mac(seen['mac']) != _mac(ipam['mac']) and not r:
        check('warn', f"IPAM has it for {ipam['mac']}, but the nodes last saw {seen['mac']} on it.",
              f'/ipam/seen?q={ip}')
    if seen and static_range and not names and not r and not active and not ipam:
        check('info', f"Something is here ({seen['mac']}), in a static range, with no name in DNS: an unknown "
                      'device?', f'/ipam/seen?q={ip}')
    if names and in_pool and not r and not (active and active['hostname']):
        check('warn', f"{names[0]['rec'].fqdn} points here, but the address is in {subnet.prefix}'s pool with "
                      "no reservation: DHCP can hand it to another client.",
              f'{subnet.url}/settings')
    return checks


# ── warnings when a record or a reservation is saved ───────────────────────────

def _pool_subnet(subnets, ip):
    """The DHCP subnet whose pools hold ip, or None."""
    import ipaddress
    from ..dhcp.leases import pool_ranges
    for s in subnets:
        try:
            if ip not in ipaddress.IPv4Network(s.prefix, strict=False):
                continue
        except ValueError:
            continue
        if any(a <= ip <= b for a, b in pool_ranges(s)):
            return s
    return None


def record_warnings(conn, fqdn, rtype, rdata):
    """An A record about to be saved: its address reserved for another host, or in a DHCP pool with no
    reservation (DHCP can hand it to another client)."""
    from ..dhcp.model import subnets as dhcp_subnets
    from ..search import _v4
    ip = _v4(rdata) if rtype == 'A' else None
    if ip is None:
        return []
    fqdn = fqdn.lower().rstrip('.')
    subnets = dhcp_subnets(conn)
    reserved = [(s, r) for s in subnets for r in s.reservations if _v4(r.ip_address) == ip]
    if reserved:
        s, r = reserved[0]
        if r.hostname and not _named(r.hostname, [fqdn]):
            return [f'{ip} is reserved in DHCP for {r.hostname} ({r.hw_address}) in {s.prefix}.']
        return []
    s = _pool_subnet(subnets, ip)
    if s is not None:
        return [f"{ip} is in {s.prefix}'s DHCP pool with no reservation: DHCP can hand it to another client."]
    return []


def static_names_at(conn, settings, ip):
    """The fqdns of the A records at ip in the static zones, as the grid shows them (drafts included)."""
    from ..dns.drafts import Drafts
    from ..search import _index
    drafts = Drafts(settings)
    out = []
    for z in conn.execute("SELECT * FROM zones WHERE kind = 'primary' AND dynamic = 0 ORDER BY name"):
        text, _ = drafts.load(z)
        recs, _ = _index(text, z['name'] + '.')
        out += [r.fqdn for r in recs if r.rtype == 'A' and r.address == ip]
    return out


def reservation_warnings(conn, settings, r, now=None):
    """A reservation about to be saved: DNS already names its address for another host, or the nodes saw
    another MAC on it in the last day."""
    from ..search import _v4
    from .devices import repeaters
    from .seen import recent_mac
    ip = _v4(r.ip_address)
    if ip is None:
        return []
    out = []
    names = static_names_at(conn, settings, ip) if r.hostname else []
    if names and not _named(r.hostname, names):
        out.append(f"DNS names {ip} {names[0]}, not {r.hostname}.")
    behind = repeaters(conn)
    others = sorted(m for m in recent_mac(conn, ip, now=now) if _mac(m) != _mac(r.hw_address) and m not in behind)
    if others:
        out.append(f"The nodes saw {', '.join(others)} on {ip} in the last day: another device may be using it.")
    return out
