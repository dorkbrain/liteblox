"""Kea's config files for one node, as JSON text (sorted keys, so equal configs render equal)."""

import hashlib
import ipaddress
import json

from .model import DEBIAN, LIFETIMES

GENERATED = {'generated-by': 'LiteBlox'}


def _loggers(name):
    return [{'name': name, 'output-options': [{'output': 'syslog'}], 'severity': 'INFO'}]


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


def _lifetimes(obj):
    return {key.replace('_', '-'): getattr(obj, key) for key in LIFETIMES if getattr(obj, key) is not None}


def reverse_network(zone):
    """The IPv4 network a reverse zone covers ('0.168.192.in-addr.arpa' → 192.168.0.0/24), or None."""
    labels = zone.lower().rstrip('.').split('.')
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


def ddns_active(config):
    """Subnets that register clients, when DDNS can work at all (a key, and a server to send to)."""
    if not config.settings.ddns_key or not config.primary:
        return []
    return [s for s in config.subnets if s.registers]


def derived_reverse_zones(prefix):
    """The reverse zones a subnet's PTRs go in at another DNS server, on octet boundaries: a /24 (or smaller) →
    its /24's zone, a /22 → its four /24 zones, a /16 → its /16's; more than 16 zones → the one enclosing it."""
    net = ipaddress.ip_network(prefix, strict=False)
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


def subnet4(subnet, ddns=False):
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
        body['ddns-send-updates'] = True
        body['ddns-qualifying-suffix'] = subnet.qualifying_suffix.rstrip('.') + '.'
        # Kea skips the update when only the address changed (a client moved onto its reservation),
        # leaving the old A record: refresh the name on every allocation and renewal instead
        body['ddns-update-on-renew'] = True
        # a client may ask to update its own A record (option 81 with S=0, as Windows does), and Kea leaves
        # it to the client by default: the name is never registered, only the PTR. Register it regardless
        body['ddns-override-client-update'] = True
    return {**body, **{k: v for k, v in subnet.extra.items() if k not in body}}


TLS_FILES = {'tls/ca.crt': 'ca', 'tls/ha.crt': 'cert', 'tls/ha.key': 'key'}


def ha_hook(config, layout=DEBIAN):
    """Kea's HA hook for a node in the pair: hot-standby, the peer link on its own listener, mutual TLS."""
    pair = config.ha['pair']
    peers = [{'name': pair.primary_name, 'url': f'https://{pair.primary_address}:{pair.port}/', 'role': 'primary',
              'auto-failover': True},
             {'name': pair.standby_name, 'url': f'https://{pair.standby_address}:{pair.port}/', 'role': 'standby',
              'auto-failover': True}]
    return {'library': f'{layout.hooks_dir}/libdhcp_ha.so', 'parameters': {'high-availability': [{
        'this-server-name': config.ha['this'], 'mode': 'hot-standby',
        'heartbeat-delay': 10000, 'max-response-delay': 60000, 'max-ack-delay': 5000, 'max-unacked-clients': 0,
        # kea-dhcp4 listens for its partner itself (no kea-ctrl-agent), on the peer-link address only
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
        'loggers': _loggers('kea-dhcp4'),
        'subnet4': [subnet4(sub, sub in ddns_active(config)) for sub in sorted(config.subnets, key=lambda x: x.id)],
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


def dhcp_ddns(config, layout=DEBIAN):
    active = ddns_active(config)
    key = config.settings.ddns_key
    servers = [{'ip-address': config.primary, 'port': config.ddns_port}]
    forward = sorted({s.ddns_domain for s in active})
    reverse = sorted({z for s in active for z in subnet_reverse_zones(s, config)})
    return {'DhcpDdns': {
        'control-socket': {'socket-type': 'unix', 'socket-name': layout.d2_socket},
        'forward-ddns': {'ddns-domains': [{'name': z + '.', 'key-name': key['name'], 'dns-servers': servers}
                                          for z in forward]},
        'ip-address': '127.0.0.1',
        'loggers': _loggers('kea-dhcp-ddns'),
        'port': layout.d2_port,
        'reverse-ddns': {'ddns-domains': [{'name': z + '.', 'key-name': key['name'], 'dns-servers': servers}
                                          for z in reverse]},
        'tsig-keys': [{'name': key['name'], 'algorithm': key['algorithm'], 'secret': key['secret']}] if active else [],
        'user-context': GENERATED,
    }}


def render(config, layout=DEBIAN):
    files = {'kea-dhcp4.conf': json.dumps(dhcp4(config, layout), indent=2, sort_keys=True) + '\n',
             'kea-dhcp-ddns.conf': json.dumps(dhcp_ddns(config, layout), indent=2, sort_keys=True) + '\n'}
    if config.ha and config.ha.get('tls'):
        files.update({role: config.ha['tls'][key] for role, key in TLS_FILES.items()})
    return files


def file_hashes(files):
    return {role: hashlib.sha256(text.encode()).hexdigest() for role, text in files.items()}
