"""Checks for DHCPv6 settings, subnets and reservations, with messages for the forms (as validate.py does for
DHCPv4: each check_* returns {field: message})."""

import ipaddress
import re

import dns.exception
import dns.name

from .model import LIFETIMES6
from .validate import _overlaps_never, check_extra_options, normalize_mac, split

PD_LINE = re.compile(r'^\s*(\S+/\d+)\s+(?:delegate\s+)?/?(\d+)\s*$', re.I)
_DUID = re.compile(r'[0-9a-f]{2}')


def interface_networks6(iface):
    """The global and unique-local IPv6 networks of an interface from the agent's status (not link-local)."""
    out = []
    for cidr in iface.get('addresses') or []:
        a = ipaddress.ip_interface(cidr)
        if a.version == 6 and not a.ip.is_link_local:
            out.append(a)
    return out


def has_ipv6(iface):
    """IPv6 is on for the interface (it has at least a link-local address)."""
    return any(ipaddress.ip_interface(c).version == 6 for c in iface.get('addresses') or [])


def pool_range6(text, network):
    """(first, last) of a pool line: 'a - b' or a CIDR inside `network`. Raises ValueError."""
    text = text.strip()
    if '-' in text:
        first, last = (ipaddress.ip_address(p.strip()) for p in text.split('-', 1))
    else:
        net = ipaddress.ip_network(text, strict=True)
        first, last = net.network_address, net.broadcast_address
    if first.version != 6 or last.version != 6 or first > last:
        raise ValueError(f'{text}: a pool is "first - last" (IPv6, first not after last) or a prefix')
    if first not in network or last not in network:
        raise ValueError(f'{text} is not inside {network}')
    if first == network.network_address:
        raise ValueError(f"{text} includes {network}'s first address (the subnet-router anycast address)")
    return first, last


def parse_pd_pool(text):
    """'fd00:1:2:f000::/52 60' (or '… /60', '… delegate /60') → {prefix, delegated_len}. Raises ValueError."""
    m = PD_LINE.match(text or '')
    if not m:
        raise ValueError(f'{text.strip()}: a delegated-prefix pool is "prefix/len delegated-length", '
                         'e.g. fd00:1:2:f000::/52 60')
    try:
        net = ipaddress.ip_network(m.group(1), strict=True)
    except ValueError:
        raise ValueError(f'{m.group(1)} is not an IPv6 prefix (no bits set after its length)')
    if net.version != 6:
        raise ValueError(f'{m.group(1)} is not an IPv6 prefix')
    length = int(m.group(2))
    if not net.prefixlen <= length <= 128:
        raise ValueError(f'{text.strip()}: the delegated length is from /{net.prefixlen} to /128')
    if length - net.prefixlen > 24:
        raise ValueError(f'{text.strip()}: more than 16 million prefixes; delegate larger ones')
    return {'prefix': str(net), 'delegated_len': length}


def pd_text(p):
    return f"{p['prefix']} {p['delegated_len']}"


def check_options6(options, prefix=''):
    errors = {}
    for key in ('dns', 'ntp'):
        for value in options.get(key) or []:
            try:
                a = ipaddress.ip_address(value)
                if a.version != 6:
                    raise ValueError
            except ValueError:
                errors[f'{prefix}{key}'] = f'{value} is not an IPv6 address'
                continue
            if a.is_link_local or a.is_multicast:
                errors[f'{prefix}{key}'] = f'{value}: a global or unique-local address (not link-local or multicast)'
    for name in options.get('search') or []:
        try:
            dns.name.from_text(name)
            if not re.fullmatch(r'[A-Za-z0-9._-]+', name.rstrip('.')):
                raise dns.exception.SyntaxError
        except dns.exception.DNSException:
            errors[f'{prefix}search'] = f'{name} is not a domain name'
    return errors


def check_lifetimes6(obj):
    """Each one a number of seconds; renew < rebind, both before the address stops being preferred, and
    preferred not after valid."""
    errors = {}
    values = {}
    for key in LIFETIMES6:
        value = getattr(obj, key)
        if value is not None and (not isinstance(value, int) or value <= 0):
            errors[key] = 'a number of seconds above 0'
        values[key] = value
    if errors:
        return errors
    p, v, r1, r2 = (values[k] for k in LIFETIMES6)
    if p and v and p > v:
        errors['preferred_lifetime'] = 'an address stops being preferred before (or when) it ends'
    elif r1 and r2 and r1 >= r2:
        errors['renew_timer'] = 'renew must come before rebind'
    elif (p or v) and ((r2 and r2 > (p or v)) or (r1 and r1 > (p or v))):
        errors['rebind_timer'] = 'renew and rebind come before the address stops being preferred'
    return errors


def check_settings6(s):
    return {**check_options6(s.options), **check_lifetimes6(s), **check_extra_options(s.extra_options)}


def parse_options6(form, prefix=''):
    out = {}
    for key in ('dns', 'search', 'ntp'):
        raw = (form.get(f'{prefix}{key}') or '').strip()
        if raw:
            out[key] = split(raw)
    return out


def _v6_network(text):
    try:
        network = ipaddress.ip_network((text or '').strip(), strict=True)
        if network.version != 6:
            raise ValueError
    except ValueError:
        return None
    return network


def check_subnet6(subnet, others, served, unserved=(), others4=()):
    """Errors for `subnet` (model.Subnet6) given the other v6 subnets and the DHCP nodes' live interfaces it may
    be placed on (as validate.check_subnet); sets subnet.interface."""
    errors = {}
    network = _v6_network(subnet.prefix)
    if network is None:
        return {'prefix': f'{subnet.prefix or "(empty)"} is not an IPv6 prefix such as fd00:1:2:100::/64 '
                          '(no bits set after its length)'}
    subnet.prefix = str(network)
    if network.is_link_local or network.is_multicast or network.is_loopback or network.prefixlen < 16:
        errors['prefix'] = f'{network}: a global or unique-local prefix (fd…, 2…)'
    elif network.prefixlen > 120:
        errors['prefix'] = 'a subnet needs room for clients (/120 or larger; /64 is usual)'
    taken = _overlaps_never(network)
    if taken:
        errors['prefix'] = f'{network} overlaps {taken}, which this development instance never serves'
    for o in others:
        if o.id != subnet.id and ipaddress.ip_network(o.prefix).overlaps(network):
            errors['prefix'] = f'{network} overlaps subnet {o.prefix}'
    if errors:
        return errors

    own = []
    places = [i for i in served for a in interface_networks6(i) if a.network.overlaps(network)]
    waiting = [i for i in unserved for a in interface_networks6(i) if a.network.overlaps(network)]
    for i in [*served, *unserved]:
        own += [a.ip for a in interface_networks6(i) if a.ip in network]
    names = sorted({p['name'] for p in places or waiting})
    if not names:
        errors['prefix'] = (f"no DHCP node has an address in {network} on any interface: give the serving node one "
                            '(a static address on that link) so Kea knows where to answer')
    elif len(names) > 1:
        errors['prefix'] = (f"more than one {'served ' if places else ''}interface is on {network}: "
                            f"{', '.join(names)}" + ('' if places else ': tick the one to serve it under Servers first'))
    else:
        subnet.interface = names[0]

    ranges = []
    for line in subnet.pools:
        try:
            ranges.append((line, *pool_range6(line, network)))
        except ValueError as e:
            errors['pools'] = str(e)
    if not subnet.pools and not subnet.pd_pools:
        errors['pools'] = 'at least one pool of addresses, or of delegated prefixes'
    for i, (a, first, last) in enumerate(ranges):
        for b, f2, l2 in ranges[i + 1:]:
            if first <= l2 and f2 <= last:
                errors['pools'] = f'pools {a} and {b} overlap'
        for addr in own:
            if first <= addr <= last:
                errors['pools'] = f"{a} includes {addr}, this server's own address"
    errors.update(_check_pd_pools(subnet, network, others))
    errors.update(check_options6(subnet.options))
    errors.update(check_lifetimes6(subnet))
    errors.update(check_extra_options(subnet.extra_options))
    if not isinstance(subnet.extra, dict):
        errors['extra'] = 'a JSON object of Kea subnet parameters'
    else:
        clash = sorted({'id', 'subnet', 'interface', 'pools', 'pd-pools'} & set(subnet.extra))
        if clash:
            errors['extra'] = f"{', '.join(clash)} {'is' if len(clash) == 1 else 'are'} LiteBlox's: set them above"
    return errors


def _check_pd_pools(subnet, network, others):
    nets = []
    for p in subnet.pd_pools:
        try:
            p.update(parse_pd_pool(pd_text(p)))
        except (ValueError, KeyError, TypeError) as e:
            return {'pd_pools': str(e)}
        nets.append(ipaddress.ip_network(p['prefix']))
    for i, n in enumerate(nets):
        if n.overlaps(network):
            return {'pd_pools': f'{n} overlaps the subnet {network} itself: delegated prefixes come from elsewhere'}
        for m in nets[i + 1:]:
            if n.overlaps(m):
                return {'pd_pools': f'{n} and {m} overlap'}
        for o in others:
            if o.id == subnet.id:
                continue
            for q in [ipaddress.ip_network(o.prefix)] + [ipaddress.ip_network(x['prefix']) for x in o.pd_pools]:
                if n.overlaps(q):
                    return {'pd_pools': f'{n} overlaps {q} of subnet {o.prefix}'}
    return {}


def normalize_duid(text):
    """'00:03:00:01:aa:bb:cc:dd:ee:ff', '0003-0001-…', '000300…' → colon-separated lowercase hex, or None.
    A DUID is 3 to 130 bytes."""
    digits = re.sub(r'[\s:.-]', '', (text or '').lower())
    if len(digits) % 2 or not 6 <= len(digits) <= 260 or not all(_DUID.fullmatch(digits[i:i + 2])
                                                                 for i in range(0, len(digits), 2)):
        return None
    return ':'.join(digits[i:i + 2] for i in range(0, len(digits), 2))


def check_reservation6(r, subnet, served, elsewhere=()):
    """(errors, warnings) for reservation r (model.Reservation6) in subnet (model.Subnet6 with its reservations).
    elsewhere: the reservations of the other v6 subnets (an address or prefix is reserved once)."""
    errors, warnings = {}, []
    network = ipaddress.ip_network(subnet.prefix)
    duid = mac = None
    if (r.duid or '').strip():
        duid = normalize_duid(r.duid)
        if duid is None:
            errors['duid'] = f'{r.duid} is not a DUID: hex bytes such as 00:01:00:01:2c:…'
        else:
            r.duid = duid
    if (r.hw_address or '').strip():
        mac = normalize_mac(r.hw_address)
        if mac is None:
            errors['hw_address'] = f'{r.hw_address} is not a MAC address, e.g. aa:bb:cc:dd:ee:ff'
        else:
            r.hw_address = mac
    if duid and mac:
        errors['duid'] = 'a DUID or a MAC address, not both: Kea finds the client by one'
    elif not (r.duid or '').strip() and not (r.hw_address or '').strip():
        errors['duid'] = "the client's DUID (or its MAC address)"
    name = (r.hostname or '').strip().rstrip('.').lower()
    r.ip_address = (r.ip_address or '').strip()
    r.prefix = (r.prefix or '').strip()
    if r.ip_address:
        try:
            ip = ipaddress.ip_address(r.ip_address)
            if ip.version != 6:
                raise ValueError(f'{r.ip_address} is not an IPv6 address')
            if ip not in network:
                raise ValueError(f'{ip} is not in {network}')
            if ip == network.network_address:
                raise ValueError(f"{ip} is {network}'s subnet-router anycast address")
            r.ip_address = str(ip)
            if ip in [a.ip for i in served for a in interface_networks6(i)]:
                raise ValueError(f"{ip} is the DHCP server's own address")
        except ValueError as e:
            errors['ip_address'] = str(e) if 'does not appear' not in str(e) else f'{r.ip_address} is not an IPv6 address'
    if r.prefix:
        pref = _v6_network(r.prefix)
        if pref is None:
            errors['prefix'] = f'{r.prefix} is not an IPv6 prefix such as fd00:1:2:f010::/60'
        elif pref.overlaps(network):
            errors['prefix'] = f'{pref} overlaps the subnet {network}: a delegated prefix is a network of its own'
        elif pref.prefixlen > 128 or pref.prefixlen < 32:
            errors['prefix'] = 'a delegated prefix from /32 to /128'
        else:
            r.prefix = str(pref)
            if not any(pref.subnet_of(ipaddress.ip_network(p['prefix'])) for p in subnet.pd_pools):
                warnings.append(f'{pref} is outside the delegated-prefix pools: the router needs a route to it as well')
    if not r.ip_address and not r.prefix:
        if not subnet.registers:
            errors['ip_address'] = ("an address or a prefix, since this subnet doesn't register clients in DNS "
                                    '(a name-only reservation needs that)')
        elif not name:
            errors['hostname'] = 'a name, for a reservation without an address or prefix'
    for o in list(subnet.reservations) + list(elsewhere):
        if o.id == r.id and o.id is not None:
            continue
        same_subnet = o.subnet_id == subnet.id
        if same_subnet and duid and o.duid == duid:
            errors['duid'] = f'{duid} already has a reservation here'
        if same_subnet and mac and o.hw_address == mac:
            errors['hw_address'] = f'{mac} already has a reservation here'
        if 'ip_address' not in errors and r.ip_address and o.ip_address == r.ip_address:
            errors['ip_address'] = f'{r.ip_address} is already reserved for {o.duid or o.hw_address}'
        if 'prefix' not in errors and r.prefix and o.prefix and \
                ipaddress.ip_network(o.prefix).overlaps(ipaddress.ip_network(r.prefix)):
            errors['prefix'] = f'{r.prefix} overlaps {o.prefix}, reserved for {o.duid or o.hw_address}'
    if name and not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', name):
        errors['hostname'] = 'one name such as printer (letters, digits and -), without the domain'
    r.hostname = name
    errors.update({f'opt_{k}': v for k, v in check_options6(r.options).items()})
    if mac:
        warnings.append('Kea learns a client\'s MAC from its packets, its link-local address or its DUID, and not '
                        'every client gives it one: a DUID is the surer match')
    return errors, warnings


def check_interface_ipv6(subnet, served):
    """A warning when the subnet's interface has IPv6 off (no link-local address): Kea can't answer there."""
    for i in served:
        if i['name'] == subnet.interface and not has_ipv6(i):
            return f'IPv6 is off on {subnet.interface}: Kea can\'t answer DHCPv6 there'
    return None
