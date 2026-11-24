"""IPv4 and IPv6 addresses and networks, read and sorted the same way everywhere.

Code that only makes sense for IPv4 (the IPAM map, next free, sweeps) keeps using IPv4Address and says so.
"""

import ipaddress


def ip(text):
    """An IPv4Address or IPv6Address from text (surrounding space and [brackets] allowed); ValueError if neither."""
    return ipaddress.ip_address(str(text or '').strip().strip('[]'))


def ip_or_none(text):
    try:
        return ip(text)
    except ValueError:
        return None


def net(text, strict=False):
    """An IPv4Network or IPv6Network from 'prefix/len' (host bits allowed unless strict); ValueError if neither."""
    return ipaddress.ip_network(str(text or '').strip(), strict=strict)


def sort_key(value):
    """Sorts addresses (or their text) numerically, IPv4 before IPv6; text that isn't one goes last."""
    a = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip_or_none(value)
    return (a.version, int(a)) if a is not None else (7, 0)


def net_sort_key(value):
    n = value if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else net(value)
    return (n.version, int(n.network_address), n.prefixlen)


def is_host_scope(a):
    """An address a device on a network uses (not link-local, multicast, loopback or unspecified)."""
    a = a if isinstance(a, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ip_or_none(a)
    return a is not None and not (a.is_link_local or a.is_multicast or a.is_loopback or a.is_unspecified)


def family(value):
    """4 or 6 for an address or network (as text or object); None when it's neither."""
    for parse in (ip, net):
        try:
            return parse(value).version
        except (ValueError, TypeError):
            continue
    return None
