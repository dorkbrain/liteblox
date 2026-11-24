"""Kea's config files for one node, as JSON text (sorted keys, so equal configs render equal)."""

import hashlib
import ipaddress
import json

from .model import DEBIAN, LIFETIMES, LIFETIMES6

GENERATED = {'generated-by': 'LiteBlox'}


def _loggers(name, layout):
    return [{'name': name, layout.logger_output_key: [{'output': 'syslog'}], 'severity': 'INFO'}]


# form field → Kea option name; list fields are joined with commas, as Kea's option-data takes them
OPTION_NAMES = {'routers': 'routers', 'dns': 'domain-name-servers', 'domain': 'domain-name',
                'search': 'domain-search', 'ntp': 'ntp-servers'}


def option_data(options, extra=()):
    out = []
    for key, name in OPTION_NAMES.items():
        value = options.get(key)
        if value:
            out.append({'name': name, 'data': ', '.join(value) if isinstance(value, list) else value})
    return out + list(extra)


# the DHCPv6 form fields → Kea's option names (dns-servers 23, domain-search 24, sntp-servers 31)
OPTION_NAMES6 = {'dns': 'dns-servers', 'search': 'domain-search', 'ntp': 'sntp-servers'}


def option_data6(options, extra=()):
    out = []
    for key, name in OPTION_NAMES6.items():
        value = options.get(key)
        if value:
            out.append({'name': name, 'data': ', '.join(value) if isinstance(value, list) else value})
    return out + list(extra)


def _lifetimes(obj, keys=LIFETIMES):
    return {key.replace('_', '-'): getattr(obj, key) for key in keys if getattr(obj, key) is not None}


def reverse_network(zone):
    """The network a reverse zone covers ('0.168.192.in-addr.arpa' → 192.168.0.0/24,
    '0.0.1.0.0.0.d.f.ip6.arpa' → fd00:100::/32), or None."""
    labels = zone.lower().rstrip('.').split('.')
    if labels[-2:] == ['ip6', 'arpa'] and 1 <= len(labels) - 2 <= 32:
        nibbles = list(reversed(labels[:-2]))
        if not all(len(n) == 1 and n in '0123456789abcdef' for n in nibbles):
            return None
        digits = ''.join(nibbles).ljust(32, '0')
        return ipaddress.ip_network(':'.join(digits[i:i + 4] for i in range(0, 32, 4)) + f'/{4 * len(nibbles)}')
    if labels[-2:] != ['in-addr', 'arpa'] or not 1 <= len(labels) - 2 <= 4:
        return None
    octets = list(reversed(labels[:-2]))
    try:
        return ipaddress.ip_network('.'.join(octets + ['0'] * (4 - len(octets))) + f'/{8 * len(octets)}')
    except ValueError:
        return None


def reverse_zones_for(prefix, zones):
    """The reverse zones (names) whose addresses overlap the subnet's."""
    network = ipaddress.ip_network(prefix)
    return [z for z in zones if (reverse_network(z) is not None and reverse_network(z).overlaps(network))]


def ddns_active(config, subnets=None):
    """Subnets that register clients, when DDNS can work at all (a key, and a server to send to)."""
    if not config.settings.ddns_key or not config.primary:
        return []
    return [s for s in (config.subnets if subnets is None else subnets) if s.registers]


def ddns_active6(config):
    return ddns_active(config, config.subnets6)


def derived_reverse_zones(prefix):
    """The reverse zones a subnet's PTRs go in at another DNS server, on octet boundaries: a /24 (or smaller) →
    its /24's zone, a /22 → its four /24 zones, a /16 → its /16's; more than 16 zones → the one enclosing it.
    IPv6 goes by nibbles the same way: a /64 (or smaller) → its /64's zone, a /62 → four /64 zones."""
    net = ipaddress.ip_network(prefix, strict=False)
    if net.version == 6:
        if net.prefixlen >= 64:
            net = net.supernet(new_prefix=64)
        bits = -(-net.prefixlen // 4) * 4
        if 2 ** (bits - net.prefixlen) > 16:
            bits -= 4
        blocks = [net.supernet(new_prefix=bits)] if bits <= net.prefixlen else list(net.subnets(new_prefix=bits))
        if bits == 0:
            return ['ip6.arpa']
        return ['.'.join(reversed(b.network_address.exploded.replace(':', '')[:bits // 4])) + '.ip6.arpa'
                for b in blocks]
    if net.prefixlen >= 24:
        net = net.supernet(new_prefix=24)
    bits = -(-net.prefixlen // 8) * 8          # the next octet boundary
    if 2 ** (bits - net.prefixlen) > 16:
        bits -= 8
    blocks = [net.supernet(new_prefix=bits)] if bits <= net.prefixlen else list(net.subnets(new_prefix=bits))
    if bits == 0:
        return ['in-addr.arpa']
    return [('.'.join(reversed(str(b.network_address).split('.')[:bits // 8])) + '.in-addr.arpa') for b in blocks]


def subnet_reverse_zones(subnet, config):
    """The reverse zones (names) a registering subnet's PTRs go in."""
    if subnet.ddns_mode == 'external':
        override = subnet.ddns_reverse.replace(',', ' ').split()
        return [z.lower().rstrip('.') for z in override] or derived_reverse_zones(subnet.prefix)
    return reverse_zones_for(subnet.prefix, config.reverse_zones)


def reservation_order(r):
    """By address, the name-only ones last (by MAC)."""
    return (0, int(ipaddress.ip_address(r.ip_address)), '') if r.ip_address else (1, 0, r.hw_address)


def reservation(r):
    out = {'hw-address': r.hw_address}
    if r.ip_address:       # name-only: Kea picks a pool address and registers the reserved hostname
        out['ip-address'] = r.ip_address
    if r.hostname:
        out['hostname'] = r.hostname
    options = option_data(r.options)
    if options:
        out['option-data'] = options
    return out


def ddns_fields(subnet, config, layout):
    out = {
        'ddns-send-updates': True,
        'ddns-qualifying-suffix': subnet.qualifying_suffix.rstrip('.') + '.',
        # Kea skips the update when only the address changed (a client moved onto its reservation),
        # leaving the old A record: refresh the name on every allocation and renewal instead
        'ddns-update-on-renew': True,
        # a client may ask to update its own A record (option 81 with S=0, as Windows does), and Kea leaves
        # it to the client by default: the name is never registered, only the PTR. Register it regardless
        'ddns-override-client-update': True,
    }
    if config is not None and subnet.ddns_domain in config.shared_domains and not layout.before_2_5:
        # a dual-stack client's DHCPv4 and DHCPv6 DHCIDs differ, so the second family's update would be refused as
        # another client's name: accept any DHCID (a name made by hand, without one, is still never touched)
        out['ddns-conflict-resolution-mode'] = 'check-exists-with-dhcid'
    return out


def subnet4(subnet, ddns=False, config=None, layout=DEBIAN):
    body = {
        'id': subnet.id,
        'subnet': subnet.prefix,
        'interface': subnet.interface,      # Kea answers for this subnet on that interface only
        'pools': [{'pool': p} for p in subnet.pools],
        'option-data': option_data(subnet.options, subnet.extra_options),
        'user-context': {'liteblox-subnet': subnet.id},
        **_lifetimes(subnet),
    }
    if subnet.reservations:
        body['reservations'] = [reservation(r) for r in sorted(subnet.reservations,
                                                                key=reservation_order)]
    if ddns:
        body.update(ddns_fields(subnet, config, layout))
    return {**body, **{k: v for k, v in subnet.extra.items() if k not in body}}


def reservation6_order(r):
    """By address, then by delegated prefix, the name-only ones last (by DUID or MAC)."""
    if r.ip_address:
        return (0, int(ipaddress.ip_address(r.ip_address)), '')
    if r.prefix:
        return (1, int(ipaddress.ip_network(r.prefix, strict=False).network_address), '')
    return (2, 0, r.duid or r.hw_address)


def reservation6(r):
    kind, value = r.identifier
    out = {kind: value}
    if r.ip_address:
        out['ip-addresses'] = [r.ip_address]
    if r.prefix:
        out['prefixes'] = [r.prefix]
    if r.hostname:
        out['hostname'] = r.hostname
    options = option_data6(r.options)
    if options:
        out['option-data'] = options
    return out


def pd_pool(p):
    net = ipaddress.ip_network(p['prefix'], strict=False)
    return {'prefix': str(net.network_address), 'prefix-len': net.prefixlen, 'delegated-len': int(p['delegated_len'])}


def subnet6(subnet, ddns=False, config=None, layout=DEBIAN):
    body = {
        'id': subnet.id,
        'subnet': subnet.prefix,
        'interface': subnet.interface,      # clients on that link only (no relays)
        'pools': [{'pool': p} for p in subnet.pools],
        'pd-pools': [pd_pool(p) for p in subnet.pd_pools],
        'option-data': option_data6(subnet.options, subnet.extra_options),
        'user-context': {'liteblox-subnet6': subnet.id},
        **_lifetimes(subnet, LIFETIMES6),
    }
    if subnet.reservations:
        body['reservations'] = [reservation6(r) for r in sorted(subnet.reservations, key=reservation6_order)]
    if ddns:
        body.update(ddns_fields(subnet, config, layout))
    return {**body, **{k: v for k, v in subnet.extra.items() if k not in body}}


TLS_FILES = {'tls/ca.crt': 'ca', 'tls/ha.crt': 'cert', 'tls/ha.key': 'key'}


def ha_hook(config, layout=DEBIAN, family=4):
    """Kea's HA hook for a node in the pair: hot-standby, the peer link on its own listener (one port per
    family), mutual TLS."""
    pair = config.ha['pair']
    port = pair.port6 if family == 6 else pair.port
    peers = [{'name': pair.primary_name, 'url': f'https://{pair.primary_address}:{port}/', 'role': 'primary',
              'auto-failover': True},
             {'name': pair.standby_name, 'url': f'https://{pair.standby_address}:{port}/', 'role': 'standby',
              'auto-failover': True}]
    return {'library': f'{layout.hooks_dir}/libdhcp_ha.so', 'parameters': {'high-availability': [{
        'this-server-name': config.ha['this'], 'mode': 'hot-standby',
        'heartbeat-delay': 10000, 'max-response-delay': 60000, 'max-ack-delay': 5000, 'max-unacked-clients': 0,
        # Kea listens for its partner itself (no kea-ctrl-agent), on the peer-link address only
        'multi-threading': {'enable-multi-threading': True, 'http-dedicated-listener': True,
                            'http-listener-threads': 0, 'http-client-threads': 0},
        'peers': peers,
        'trust-anchor': f'{layout.config_dir}/tls/ca.crt', 'cert-file': f'{layout.config_dir}/tls/ha.crt',
        'key-file': f'{layout.config_dir}/tls/ha.key', 'require-client-certs': True,
    }]}}


SOCKET_RETRIES, SOCKET_RETRY_WAIT_MS = 120, 5000


def dhcp4(config, layout=DEBIAN):
    s = config.settings
    hooks = [{'library': f'{layout.hooks_dir}/libdhcp_lease_cmds.so'}]
    if config.ha and config.ha.get('tls'):
        hooks.append(ha_hook(config, layout))
    body = {
        'control-socket': {'socket-type': 'unix', 'socket-name': layout.dhcp4_socket},
        'hooks-libraries': hooks,
        # Kea can start before an interface is up (at boot): without retries it listens on nothing for good,
        # and in a failover pair the other server stays on standby. Retry for 10 minutes.
        'interfaces-config': {'interfaces': list(config.interfaces), 'service-sockets-max-retries': SOCKET_RETRIES,
                              'service-sockets-retry-wait-time': SOCKET_RETRY_WAIT_MS},
        'lease-database': {'type': 'memfile', 'name': layout.lease_file, 'persist': True, 'lfc-interval': 3600},
        'loggers': _loggers('kea-dhcp4', layout),
        'subnet4': [subnet4(sub, sub in ddns_active(config), config, layout)
                    for sub in sorted(config.subnets, key=lambda x: x.id)],
        'user-context': GENERATED,
        **_lifetimes(s),
    }
    if ddns_active(config):
        # D2 on this node does the updates; only the subnets that register send them
        body.update({'dhcp-ddns': {'enable-updates': True, 'server-ip': '127.0.0.1', 'server-port': layout.d2_port},
                     'ddns-send-updates': False, 'hostname-char-set': '[^A-Za-z0-9.-]',
                     'hostname-char-replacement': '-'})
    options = option_data(s.options, s.extra_options)
    if options:
        body['option-data'] = options
    if s.authoritative:
        body['authoritative'] = True
    return {'Dhcp4': body}


def dhcp6(config, layout=DEBIAN):
    """kea-dhcp6's config: the node's DHCPv6 subnets on the interfaces that have one (none: it listens nowhere)."""
    s = config.settings6
    hooks = [{'library': f'{layout.hooks_dir}/libdhcp_lease_cmds.so'}]
    if config.ha6 and config.ha6.get('tls'):
        hooks.append(ha_hook(config, layout, family=6))
    active = ddns_active6(config)
    body = {
        'control-socket': {'socket-type': 'unix', 'socket-name': layout.dhcp6_socket},
        'hooks-libraries': hooks,
        # a reservation names its client by MAC (learned from the packet, its link-local address or its DUID) or DUID
        'host-reservation-identifiers': ['hw-address', 'duid'],
        'interfaces-config': {'interfaces': list(config.interfaces6), 'service-sockets-max-retries': SOCKET_RETRIES,
                              'service-sockets-retry-wait-time': SOCKET_RETRY_WAIT_MS},
        'lease-database': {'type': 'memfile', 'name': layout.lease_file6, 'persist': True, 'lfc-interval': 3600},
        'loggers': _loggers('kea-dhcp6', layout),
        'subnet6': [subnet6(sub, sub in active, config, layout) for sub in sorted(config.subnets6, key=lambda x: x.id)],
        'user-context': GENERATED,
        **_lifetimes(s, LIFETIMES6),
    }
    if active:
        # the same D2 as DHCPv4's: AAAA records, PTRs in ip6.arpa
        body.update({'dhcp-ddns': {'enable-updates': True, 'server-ip': '127.0.0.1', 'server-port': layout.d2_port},
                     'ddns-send-updates': False, 'hostname-char-set': '[^A-Za-z0-9.-]',
                     'hostname-char-replacement': '-'})
    options = option_data6(s.options, s.extra_options)
    if options:
        body['option-data'] = options
    return {'Dhcp6': body}


def dhcp_ddns(config, layout=DEBIAN):
    active = ddns_active(config) + ddns_active6(config)
    key = config.settings.ddns_key
    servers = [{'ip-address': config.primary, 'port': config.ddns_port}]
    forward = sorted({s.ddns_domain for s in active})
    reverse = sorted({z for s in active for z in subnet_reverse_zones(s, config)})
    return {'DhcpDdns': {
        'control-socket': {'socket-type': 'unix', 'socket-name': layout.d2_socket},
        'forward-ddns': {'ddns-domains': [{'name': z + '.', 'key-name': key['name'], 'dns-servers': servers}
                                          for z in forward]},
        'ip-address': '127.0.0.1',
        'loggers': _loggers('kea-dhcp-ddns', layout),
        'port': layout.d2_port,
        'reverse-ddns': {'ddns-domains': [{'name': z + '.', 'key-name': key['name'], 'dns-servers': servers}
                                          for z in reverse]},
        'tsig-keys': [{'name': key['name'], 'algorithm': key['algorithm'], 'secret': key['secret']}] if active else [],
        'user-context': GENERATED,
    }}


RADVD_HEADER = ('# Generated by LiteBlox. Router advertisements for its DHCPv6 subnets: router lifetime 0, so never a '
                'default route.\n')
RADVD_INTERVALS = (30, 100)         # seconds between unsolicited advertisements (min, max)


def radvd(config):
    """radvd.conf: one block per interface with a subnet that sends router advertisements; just the header when
    none does (the node then stops radvd). M when DHCPv6 hands out addresses there, O always (its options), A on
    a prefix only with SLAAC."""
    by_interface = {}
    for sub in sorted(config.subnets6, key=lambda x: x.id or 0):
        if sub.ra:
            by_interface.setdefault(sub.interface, []).append(sub)
    out = [RADVD_HEADER]
    for name, subs in sorted(by_interface.items()):
        managed = any(s.pools or any(r.ip_address for r in s.reservations) for s in subs)
        out += [f'interface {name}\n{{\n', '    AdvSendAdvert on;\n',
                f"    AdvManagedFlag {'on' if managed else 'off'};\n", '    AdvOtherConfigFlag on;\n',
                '    AdvDefaultLifetime 0;\n', f'    MinRtrAdvInterval {RADVD_INTERVALS[0]};\n',
                f'    MaxRtrAdvInterval {RADVD_INTERVALS[1]};\n']
        for sub in subs:
            out += [f'    prefix {ipaddress.ip_network(sub.prefix)}\n    {{\n', '        AdvOnLink on;\n',
                    f"        AdvAutonomous {'on' if sub.ra_slaac else 'off'};\n", '    };\n']
        out.append('};\n')
    return ''.join(out)


def radvd_interfaces(text):
    """The interfaces a rendered radvd.conf advertises on."""
    return [line.split()[1] for line in text.splitlines() if line.startswith('interface ')]


def radvd_prefixes(text):
    return [line.split()[1] for line in text.splitlines() if line.strip().startswith('prefix ')]


def render(config, layout=DEBIAN):
    files = {'kea-dhcp4.conf': json.dumps(dhcp4(config, layout), indent=2, sort_keys=True) + '\n',
             'kea-dhcp-ddns.conf': json.dumps(dhcp_ddns(config, layout), indent=2, sort_keys=True) + '\n'}
    if config.dhcp6:
        files['kea-dhcp6.conf'] = json.dumps(dhcp6(config, layout), indent=2, sort_keys=True) + '\n'
    if config.ha and config.ha.get('tls'):
        files.update({role: config.ha['tls'][key] for role, key in TLS_FILES.items()})
    if config.radvd:
        files['radvd.conf'] = radvd(config)
    return files


def file_hashes(files):
    return {role: hashlib.sha256(text.encode()).hexdigest() for role, text in files.items()}
