"""Checking the sources and the networks a node serves time to (the agent checks the file again on the node)."""

import ipaddress
import os
import re

from .model import Source

HOSTNAME = re.compile(r'(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?')
FLAGS = ('iburst', 'prefer', 'nts')


class Invalid(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors.values()))
        self.errors = errors


def _address(word):
    try:
        ipaddress.ip_address(word)
        return True
    except ValueError:
        return bool(HOSTNAME.fullmatch(word))


def parse_sources(text):
    """'pool 2.debian.pool.ntp.org iburst' per line → ([Source], errors). iburst is on unless 'noiburst'."""
    out, errors, seen = [], [], set()
    for n, raw in enumerate((text or '').splitlines(), 1):
        words = raw.split('#', 1)[0].split()
        if not words:
            continue
        if words[0] not in ('server', 'pool'):
            words = ['server'] + words          # a bare address or name is a server
        kind, rest = words[0], words[1:]
        if not rest or not _address(rest[0]):
            errors.append(f'line {n}: {kind} needs a host name or an address')
            continue
        source = Source(kind, rest[0].rstrip('.').lower())
        opts = rest[1:]
        while opts:
            opt = opts.pop(0)
            if opt in FLAGS:
                setattr(source, opt, True)
            elif opt == 'noiburst':
                source.iburst = False
            elif opt in ('minpoll', 'maxpoll') and opts and re.fullmatch(r'-?\d{1,2}', opts[0]):
                value = int(opts.pop(0))
                if not -6 <= value <= 24:
                    errors.append(f'line {n}: {opt} is -6 to 24')
                setattr(source, opt, value)
            else:
                errors.append(f'line {n}: unknown option {opt!r} (iburst, noiburst, prefer, nts, minpoll N, maxpoll N)')
        if source.address in seen:
            errors.append(f'line {n}: {source.address} is listed twice')
        seen.add(source.address)
        out.append(source)
    if not out and not errors:
        errors.append('list at least one server or pool')
    return out, errors


def sources_text(source_list):
    return ''.join(s.line() + '\n' for s in source_list)


def parse_networks(text):
    """Networks a node serves time to, one per line → ([str], errors)."""
    out, errors = [], []
    for item in re.split(r'[\s,]+', (text or '').strip()):
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            errors.append(f'{item} is not a network (like 192.168.0.0/24)')
            continue
        if net.prefixlen == 0:
            errors.append('serving time to every address is not allowed: name your networks')
            continue
        if str(net) not in out:
            out.append(str(net))
    return out, errors


def serve_only():
    """The development safeguard: networks LiteBlox may serve time to (none set: no limit)."""
    raw = os.environ.get('LITEBLOX_DEV_NTP_SERVE_ONLY', '')
    return [ipaddress.ip_network(n.strip(), strict=False) for n in raw.split(',') if n.strip()]


def guard(networks):
    """Errors for networks outside LITEBLOX_DEV_NTP_SERVE_ONLY (a dev lab sharing a network with real clients)."""
    limit = serve_only()
    if not limit:
        return []
    return [f'{n} is outside LITEBLOX_DEV_NTP_SERVE_ONLY ({", ".join(map(str, limit))})'
            for n in networks if not any(ipaddress.ip_network(n).subnet_of(l) for l in limit
                                         if ipaddress.ip_network(n).version == l.version)]
