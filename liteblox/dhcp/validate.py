"""Checks for DHCP settings, subnets and served interfaces, with messages for the forms.

Each check_* returns {field: message} (empty when fine). They run on the form's
values before a preview, and again in apply_dhcp before anything reaches a node.
"""

import ipaddress
import json
import os
import re

import dns.exception
import dns.name

from .model import LIFETIMES, OPTION_FIELDS

DEV_NEVER_SERVE = 'LITEBLOX_DEV_DHCP_NEVER_SERVE'
_SPLIT = re.compile(r'[\s,]+')


class Invalid(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors.values()))
        self.errors = errors


def split(text):
    return [t for t in _SPLIT.split(text or '') if t]


def never_serve():
    """Networks a development instance must never serve DHCP on (the developer's own LAN), from the
    environment. Unset in a real install."""
    out = []
    for item in split(os.environ.get(DEV_NEVER_SERVE, '')):
        try:
            out.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            pass
    return out


def _overlaps_never(network):
    return next((n for n in never_serve() if n.version == network.version and n.overlaps(network)), None)


def interface_networks(iface):
    """IPv4 networks of an interface from the agent's status ({'name', 'addresses': ['a/len', ...]})."""
    out = []
    for cidr in iface.get('addresses') or []:
        net = ipaddress.ip_interface(cidr)
        if net.version == 4:
            out.append(net)
    return out


def pool_range(text, network):
    """(first, last) addresses of a pool line: 'a - b' or a CIDR inside `network`. Raises ValueError."""
    text = text.strip()
    if '-' in text:
        first, last = (ipaddress.ip_address(p.strip()) for p in text.split('-', 1))
    else:
        net = ipaddress.ip_network(text, strict=True)
        first, last = net.network_address, net.broadcast_address
    if first.version != 4 or last.version != 4 or first > last:
        raise ValueError(f'{text}: a pool is "first - last" (IPv4, first not after last) or a CIDR')
    if first not in network or last not in network:
        raise ValueError(f'{text} is not inside {network}')
    if network.prefixlen < 31 and (first == network.network_address or last == network.broadcast_address):
        raise ValueError(f"{text} includes {network}'s network or broadcast address")
    return first, last


def check_options(options, prefix=''):
    errors = {}
    for key in ('routers', 'dns', 'ntp'):
        for value in options.get(key) or []:
            try:
                if ipaddress.ip_address(value).version != 4:
                    raise ValueError
            except ValueError:
                errors[f'{prefix}{key}'] = f'{value} is not an IPv4 address'
    names = ([options['domain']] if options.get('domain') else []) + list(options.get('search') or [])
    for name in names:
        try:
            dns.name.from_text(name)
            if not re.fullmatch(r'[A-Za-z0-9._-]+', name.rstrip('.')):
                raise dns.exception.SyntaxError
        except dns.exception.DNSException:
            errors[f'{prefix}{"domain" if name == options.get("domain") else "search"}'] = f'{name} is not a domain name'
    return errors


def check_lifetimes(obj):
    errors = {}
    values = {}
    for key in LIFETIMES:
        value = getattr(obj, key)
        if value is not None and (not isinstance(value, int) or value <= 0):
            errors[key] = 'a number of seconds above 0'
        values[key] = value
    v, r1, r2 = values['valid_lifetime'], values['renew_timer'], values['rebind_timer']
    if not errors and r1 and r2 and r1 >= r2:
        errors['renew_timer'] = 'renew must come before rebind'
    if not errors and v and ((r2 and r2 >= v) or (r1 and r1 >= v)):
        errors['rebind_timer'] = 'renew and rebind must come before the lease ends'
    return errors


def check_extra_options(items, key='extra_options'):
    if not isinstance(items, list) or not all(isinstance(i, dict) and ('name' in i or 'code' in i) for i in items):
        return {key: 'a JSON list of option-data entries, e.g. [{"name": "time-offset", "data": "3600"}]'}
    return {}


def check_settings(s):
    return {**check_options(s.options), **check_lifetimes(s), **check_extra_options(s.extra_options)}


def check_subnet(subnet, others, served, unserved=()):
    """Errors for `subnet` (model.Subnet) given the other subnets and the DHCP nodes' live interfaces
    [{'name', 'addresses'}] it may be placed on: those ticked for DHCP (served), else one that isn't ticked yet
    (unserved), where it's saved but not served until that interface is ticked."""
    errors = {}
    try:
        network = ipaddress.ip_network(subnet.prefix, strict=True)
        if network.version != 4:
            raise ValueError
    except ValueError:
        return {'prefix': f'{subnet.prefix or "(empty)"} is not an IPv4 network such as 192.168.0.0/24'}
    if network.prefixlen > 30:
        errors['prefix'] = 'a subnet needs room for at least two clients (/30 or larger)'
    taken = _overlaps_never(network)
    if taken:
        errors['prefix'] = f'{network} overlaps {taken}, which this development instance never serves'
    for o in others:
        if o.id != subnet.id and ipaddress.ip_network(o.prefix).overlaps(network):
            errors['prefix'] = f'{network} overlaps subnet {o.prefix}'
    if errors:
        return errors

    # placement: the served interface with an address in this network, else one that isn't served yet
    own = []
    places = [i for i in served for a in interface_networks(i) if a.network == network]
    waiting = [i for i in unserved for a in interface_networks(i) if a.network == network]
    for i in [*served, *unserved]:
        own += [a.ip for a in interface_networks(i) if a.ip in network]
    names = sorted({p['name'] for p in places or waiting})
    if not names:
        errors['prefix'] = (f'no DHCP node has an address in {network} on any interface, so Kea couldn\'t answer '
                            'there')
    elif len(names) > 1:
        errors['prefix'] = (f"more than one {'served ' if places else ''}interface is on {network}: "
                            f"{', '.join(names)}" + ('' if places else ': tick the one to serve it under Servers first'))
    else:
        subnet.interface = names[0]

    ranges = []
    for line in subnet.pools:
        try:
            ranges.append((line, *pool_range(line, network)))
        except ValueError as e:
            errors['pools'] = str(e)
    if not subnet.pools:
        errors['pools'] = 'at least one pool: the addresses Kea hands out'
    for i, (a, first, last) in enumerate(ranges):
        for b, f2, l2 in ranges[i + 1:]:
            if first <= l2 and f2 <= last:
                errors['pools'] = f'pools {a} and {b} overlap'
        for addr in own + [ipaddress.ip_address(r) for r in subnet.options.get('routers') or []
                           if _is_v4(r)]:
            if first <= addr <= last:
                errors['pools'] = f'{a} includes {addr}, which is a router or this server\'s own address'
    errors.update(check_options(subnet.options))
    errors.update(check_lifetimes(subnet))
    errors.update(check_extra_options(subnet.extra_options))
    if not isinstance(subnet.extra, dict):
        errors['extra'] = 'a JSON object of Kea subnet parameters'
    else:
        clash = sorted({'id', 'subnet', 'interface', 'pools'} & set(subnet.extra))
        if clash:
            errors['extra'] = f"{', '.join(clash)} {'is' if len(clash) == 1 else 'are'} LiteBlox's: set them above"
    return errors


def _is_v4(text):
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


def _all_networks(iface):
    """Every address of an interface, both families, but not link-local (every IPv6 interface has fe80::)."""
    out = []
    for cidr in iface.get('addresses') or []:
        net = ipaddress.ip_interface(cidr)
        if not net.is_link_local:
            out.append(net)
    return out


def check_interfaces(node, chosen, available, others_serving):
    """Errors for serving `chosen` interface names on `node`, given the node's live interfaces and
    the other nodes already serving some (one serving node until failover pairs arrive)."""
    errors = {}
    names = {i['name']: i for i in available or []}
    unknown = [c for c in chosen if c not in names]
    if unknown:
        errors['interfaces'] = f"{', '.join(unknown)}: not an interface on {node['name']}"
    for c in chosen:
        for a in _all_networks(names.get(c, {})):
            taken = _overlaps_never(a.network)
            if taken:
                errors['interfaces'] = (f'{c} ({a}) is on {taken}, which this development instance never serves')
    if chosen and others_serving:
        errors['interfaces'] = (f"{', '.join(n['name'] for n in others_serving)} already serves DHCP: one node "
                                'serves until failover pairs arrive in a later version')
    return errors


def guard_rendered(files):
    """The last check before Kea's config leaves LiteBlox: nothing served on a never-serve network."""
    never = never_serve()
    if not never:
        return
    body = json.loads(files['kea-dhcp4.conf'])['Dhcp4']
    body6 = json.loads(files['kea-dhcp6.conf'])['Dhcp6'] if 'kea-dhcp6.conf' in files else {}
    for sub in body.get('subnet4', []) + body6.get('subnet6', []):
        net = ipaddress.ip_network(sub['subnet'])
        if any(n.version == net.version and n.overlaps(net) for n in never):
            raise Invalid({'subnet': f"refusing to write {sub['subnet']}: this development instance never serves it"})
    for hook in body.get('hooks-libraries', []) + body6.get('hooks-libraries', []):
        for ha in (hook.get('parameters') or {}).get('high-availability', []):
            for peer in ha.get('peers', []):
                host = peer['url'].split('//', 1)[1].rsplit(':', 1)[0]
                if any(n.overlaps(ipaddress.ip_network(f'{host}/32')) for n in never):
                    raise Invalid({'ha': f"refusing a failover listener on {host}: this development instance never "
                                         'serves that network'})
    from .render import radvd_prefixes
    for prefix in radvd_prefixes(files.get('radvd.conf', '')):
        net = ipaddress.ip_network(prefix)
        if any(n.version == 6 and n.overlaps(net) for n in never):
            raise Invalid({'ra': f'refusing router advertisements for {prefix}: this development instance never '
                                 'serves it'})


def parse_options(form, prefix=''):
    """The option fields of a form as the JSON the DB keeps."""
    out = {}
    for key in OPTION_FIELDS:
        raw = (form.get(f'{prefix}{key}') or '').strip()
        if not raw:
            continue
        out[key] = raw if key == 'domain' else split(raw)
    return out


# ── DDNS ───────────────────────────────────────────────────────────────────────

def check_ddns(conn, subnet, dhcp_settings):
    """Errors for a subnet that registers its clients in DNS (sets subnet.ddns_zone from its id; with DNS
    registration at another server, checks its domain and reverse zones instead)."""
    subnet.ddns_mode = dhcp_settings.ddns_mode
    if not subnet.ddns:
        return {}
    if dhcp_settings.ddns_mode == 'off':
        return {'ddns': 'DNS registration is off: choose where it goes first (DHCP → Settings → DNS registration)'}
    if dhcp_settings.ddns_mode == 'external':
        return _check_external(subnet, dhcp_settings)
    errors = {}
    zone = conn.execute("SELECT * FROM zones WHERE id = ? AND kind = 'primary'", (subnet.ddns_zone_id,)).fetchone() \
        if subnet.ddns_zone_id else None
    if zone is None or not zone['dynamic'] or zone['name'].endswith('.arpa'):
        errors['ddns_zone_id'] = 'pick a dynamic forward zone (Zones → the zone\'s Settings → Dynamic updates)'
        return errors
    subnet.ddns_zone = zone['name']
    suffix = (subnet.ddns_suffix or '').strip().lower().rstrip('.')
    if suffix:
        try:
            name = dns.name.from_text(suffix + '.')
        except dns.exception.DNSException:
            name = None
        if name is None or not name.is_subdomain(dns.name.from_text(zone['name'] + '.')):
            errors['ddns_suffix'] = f'the names go in {zone["name"]}: the suffix is {zone["name"]} or a name inside it'
        subnet.ddns_suffix = '' if suffix == zone['name'] else suffix
    if not dhcp_settings.ddns_key_id:
        errors['ddns'] = 'pick the key DHCP signs its updates with first (DHCP → Settings → DNS registration key)'
    return errors


def _check_external(subnet, dhcp_settings):
    from .render import reverse_network
    errors = {}
    domain = (subnet.ddns_suffix or subnet.ddns_zone or '').strip().lower().rstrip('.')
    try:
        if not domain or domain.endswith('.arpa'):
            raise ValueError
        dns.name.from_text(domain + '.')
    except (ValueError, dns.exception.DNSException):
        errors['ddns_suffix'] = 'the domain clients are registered in at the DNS server, e.g. dhcp.home.lan'
    subnet.ddns_suffix = domain
    zones = (subnet.ddns_reverse or '').replace(',', ' ').lower().split()
    network = ipaddress.ip_network(subnet.prefix, strict=False)
    bad = [z for z in zones if reverse_network(z.rstrip('.')) is None or
           not reverse_network(z.rstrip('.')).overlaps(network)]
    if bad:
        kind = 'ip6.arpa' if network.version == 6 else 'in-addr.arpa'
        errors['ddns_reverse'] = f"{', '.join(bad)}: a reverse zone (…{kind}) that covers part of {subnet.prefix}"
    subnet.ddns_reverse = ' '.join(z.rstrip('.') for z in zones)
    if not dhcp_settings.ddns_server or not dhcp_settings.ddns_external_key:
        errors['ddns'] = 'set the DNS server and its key first (DHCP → Settings → DNS registration)'
    return errors


def _covers(grant, zone, owner):
    """Does a key_grants row let its key update `owner` (a dns.name) in `zone`?"""
    if grant['zone'] != zone:
        return False
    if grant['scope'] == 'zonesub':
        return True
    name = dns.name.from_text(grant['name'].rstrip('.') + '.')
    return owner == name if grant['scope'] == 'name' else owner.is_subdomain(name)


def missing_grants(conn, key_name, subnet, reverse_zones):
    """[(zone, scope, owner, types)] the DDNS key still needs for this subnet's registrations.

    Forward: A (AAAA for a DHCPv6 subnet) and DHCID for names under the suffix; reverse: PTR and DHCID.
    """
    if not key_name or not subnet.ddns or not subnet.ddns_zone or subnet.ddns_mode != 'liteblox':
        return []
    rows = [dict(r) for r in conn.execute(
        'SELECT g.scope, g.name, g.types, z.name AS zone FROM key_grants g JOIN tsig_keys k ON k.id = g.key_id '
        'JOIN zones z ON z.id = g.zone_id WHERE k.name = ?', (key_name,))]
    suffix = subnet.qualifying_suffix
    probe = dns.name.from_text('host.' + suffix + '.')        # a name a client would get
    out = []
    wants = [(subnet.ddns_zone, probe, ('AAAA', 'DHCID') if getattr(subnet, 'family', 4) == 6 else ('A', 'DHCID'),
              ('zonesub', '', 'A AAAA DHCID') if suffix == subnet.ddns_zone else ('subdomain', suffix, 'A AAAA DHCID'))]
    for zone in reverse_zones:
        wants.append((zone, dns.name.from_text('1.' + zone + '.'), ('PTR', 'DHCID'), ('zonesub', '', 'PTR DHCID')))
    for zone, owner, needed, suggestion in wants:
        have = set()
        for g in rows:
            if _covers(g, zone, owner):
                have |= set(g['types'].upper().split())
        if 'ANY' not in have and not set(needed) <= have:
            out.append((zone, *suggestion))
    return out


# ── reservations ───────────────────────────────────────────────────────────────

_HEX = re.compile(r'[0-9a-f]{12}')


def normalize_mac(text):
    """'AA-BB-CC-DD-EE-FF', 'aabb.ccdd.eeff', 'aabbccddeeff' → 'aa:bb:cc:dd:ee:ff', or None."""
    digits = re.sub(r'[\s:.-]', '', (text or '').lower())
    if not _HEX.fullmatch(digits):
        return None
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def check_reservation(r, subnet, served):
    """(errors, warnings) for reservation r in subnet (model.Subnet with its reservations)."""
    errors, warnings = {}, []
    mac = normalize_mac(r.hw_address)
    if mac is None:
        errors['hw_address'] = f'{r.hw_address or "(empty)"} is not a MAC address, e.g. aa:bb:cc:dd:ee:ff'
    else:
        r.hw_address = mac
    network = ipaddress.ip_network(subnet.prefix)
    name = (r.hostname or '').strip().rstrip('.').lower()
    r.ip_address = (r.ip_address or '').strip()
    if not r.ip_address:
        # name-only: Kea gives the client a pool address and registers the reserved name, so it needs DDNS
        if not subnet.registers:
            errors['ip_address'] = ("an address, since this subnet doesn't register clients in DNS (a name-only "
                                    'reservation needs that)')
        elif not name:
            errors['hostname'] = 'a name, for a reservation without an address'
    try:
        if not r.ip_address:
            raise LookupError
        ip = ipaddress.ip_address(r.ip_address)
        if ip.version != 4 or ip not in network:
            raise ValueError(f'{r.ip_address} is not in {network}')
        if network.prefixlen < 31 and ip in (network.network_address, network.broadcast_address):
            raise ValueError(f"{ip} is {network}'s network or broadcast address")
        r.ip_address = str(ip)
        own = [a.ip for i in served for a in interface_networks(i) if a.ip in network]
        routers = [ipaddress.ip_address(x) for x in subnet.options.get('routers') or [] if _is_v4(x)]
        if ip in own or ip in routers:
            raise ValueError(f"{ip} is the router's or the DHCP server's own address")
    except LookupError:
        pass
    except ValueError as e:
        errors['ip_address'] = str(e) if 'does not appear' not in str(e) else f'{r.ip_address} is not an IPv4 address'
    for o in subnet.reservations:
        if o.id == r.id:
            continue
        if mac and o.hw_address == mac:
            errors['hw_address'] = f"{mac} already has a reservation here ({o.ip_address or 'name ' + o.hostname})"
        if 'ip_address' not in errors and r.ip_address and o.ip_address == r.ip_address:
            errors['ip_address'] = f'{r.ip_address} is already reserved for {o.hw_address}'
    if name and not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?', name):
        errors['hostname'] = 'one name such as printer (letters, digits and -), without the domain'
    r.hostname = name
    errors.update({f'opt_{k}': v for k, v in check_options(r.options).items()})
    # Kea serves a reservation inside a pool (unlike ISC dhcpd), unless the subnet's own extra settings
    # say reservations are all outside the pools: then Kea would skip this one
    if r.ip_address and 'ip_address' not in errors and subnet.extra.get('reservations-out-of-pool') is True:
        for line in subnet.pools:
            try:
                first, last = pool_range(line, network)
            except ValueError:
                continue
            if first <= ipaddress.ip_address(r.ip_address) <= last:
                warnings.append(f'{r.ip_address} is inside the pool {line}, but this subnet sets '
                                'reservations-out-of-pool: Kea will not look for it there')
    return errors, warnings


# ── the failover pair ──────────────────────────────────────────────────────────

def match_interfaces(primary, standby, primary_live, standby_live, served):
    """({primary's interface: the standby's}, error or None): for each interface the primary serves on, the
    standby's interface on the same IPv4 network (names may differ between machines); one of the same name only
    when the primary's has no address to go by."""
    by_name = {i['name']: i for i in primary_live or []}
    mapping, problems = {}, []
    for name in served:
        networks = {a.network for a in interface_networks(by_name.get(name, {}))}
        same = sorted({i['name'] for i in standby_live or [] for a in interface_networks(i) if a.network in networks})
        where = ', '.join(str(n) for n in sorted(networks)) or 'its network'
        if len(same) == 1:
            mapping[name] = same[0]
        elif len(same) > 1:
            problems.append(f"more than one interface of {standby['name']} is on {where}: {', '.join(same)}")
        elif not networks and name in {i['name'] for i in standby_live or []}:
            mapping[name] = name            # no address on the primary's to go by: the same name, as before 4.8
        else:
            problems.append(f"{standby['name']} has no interface on {where} ({primary['name']}'s {name}): the standby "
                            'serves the same networks as the primary')
    return mapping, '; '.join(problems) or None


def check_pair(primary, standby, primary_address, standby_address, port, live, served, port6=8002):
    """Errors for pairing `primary` with `standby` (node rows). live: {node id: its interfaces from the agent};
    served: the interface names the primary serves on (the standby needs one on each of their networks)."""
    errors = {}
    if not primary or not standby or primary['id'] == standby['id']:
        return {'nodes': 'pick two different DHCP nodes'}
    for node in (primary, standby):
        if not node['dhcp']:
            errors['nodes'] = f"{node['name']} doesn't run Kea yet (its page → Set up DHCP)"
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        errors['port'] = 'a TCP port from 1024 to 65535'
    if not isinstance(port6, int) or not 1024 <= port6 <= 65535:
        errors['port6'] = 'a TCP port from 1024 to 65535'
    elif port6 == port:
        errors['port6'] = "DHCPv6's failover needs a port of its own (kea-dhcp4 listens on the other)"
    for node, address, key in ((primary, primary_address, 'primary_address'),
                               (standby, standby_address, 'standby_address')):
        mine = [a.ip for i in live.get(node['id']) or [] for a in interface_networks(i)]
        try:
            ip = ipaddress.ip_address((address or '').strip())
        except ValueError:
            errors[key] = f"pick one of {node['name']}'s addresses"
            continue
        if ip not in mine:
            errors[key] = f"{ip} isn't an address of {node['name']}"
            continue
        taken = _overlaps_never(ipaddress.ip_network(f'{ip}/32'))
        if taken:
            errors[key] = f'{ip} is on {taken}, which this development instance never serves'
    _, problem = match_interfaces(primary, standby, live.get(primary['id']), live.get(standby['id']), served)
    if problem:
        errors['nodes'] = problem
    return errors
