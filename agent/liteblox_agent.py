#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dorkbrain (https://dorkbrain.com)
"""liteblox-agent: the small service LiteBlox talks to on each BIND node.

Standard library only (Python 3.9+), so nodes never need pip. It listens on
HTTPS with mutual TLS: only a client certificate signed by the LiteBlox CA
with CN=liteblox gets in.

It runs as an unprivileged user in group `bind`. It can only write:
  - zone files of primary zones that named itself declares (named-checkconf -p)
  - the config files LiteBlox generates (named.conf and liteblox/*.conf), each
    checked against its own allow-list, and new zone files they declare
Every change is staged and checked with this node's own named-checkzone or
named-checkconf before it replaces the live files, and rolled back if
`rndc reload` / `rndc reconfig` fails.

For IPAM it also reads the node's neighbour table and pings addresses on the
networks the node is directly on, with an unprivileged ICMP socket (no extra
capabilities).
"""

import argparse
import datetime
import grp
import hashlib
import ipaddress
import io
import json
import logging
import os
import pwd
import re
import secrets
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import ProxyHandler, build_opener

log = logging.getLogger('liteblox-agent')

DEFAULT_CONFIG = {
    'listen': '0.0.0.0',
    'port': 8530,
    'cert': '/etc/liteblox-agent/agent.crt',
    'key': '/etc/liteblox-agent/agent.key',
    'ca': '/etc/liteblox-agent/ca.crt',
    'client_cn': 'liteblox',
    'allowed_ips': [],
    'version': 'dev',
    'state_dir': '/var/lib/liteblox-agent',
    # where the agent and its root installer live (root-owned); install_rev: the install layout Repair last
    # put here (0: no installer, so the agent can only be upgraded by Repair over SSH)
    'agent_lib': '/usr/local/lib/liteblox-agent',
    'install_rev': 0,
    # false on a node without BIND (a scanner, or a DHCP/Time-only node): no BIND checks, and the zone and
    # config endpoints answer 404
    'bind': True,
    'named_conf': '/etc/bind/named.conf',
    'managed_dir': '/etc/bind/liteblox',      # also where the generated *.conf files live
    'dyn_dir': '/var/lib/bind/liteblox/dyn',  # dynamic zones: named writes them and their journals
    'sec_dir': '/var/lib/bind/liteblox/sec',  # secondary copies
    'jnl_dir': '/var/lib/bind/liteblox/jnl',  # journals of static primaries (ixfr-from-differences)
    'pre_dir': '/etc/bind/pre-liteblox',      # the node's own config, kept at takeover
    'directory': '/var/cache/bind',
    # the distro's built-in zones, included from the generated named.conf as found
    'distro_includes': ['/etc/bind/named.conf.default-zones', '/etc/bind/named.conf.root-hints',
                        '/etc/bind/rndc.key'],
    'log_dirs': ['/var/log/named', '/var/lib/bind'],
    'bind_group': 'bind',
    'backup_paths': ['/etc/bind', '/var/lib/bind/liteblox', '/etc/kea', '/var/lib/kea', '/etc/chrony'],
    'backup_keep': 10,
    # Kea (DHCP): it only opens config files inside kea_dir, so candidates are checked there too
    'kea_dir': '/etc/kea',
    'kea_hooks_dir': None,      # found at start: /usr/lib/<multiarch>/kea/hooks on Debian
    'kea_lease_dir': '/var/lib/kea',
    'kea_log_dir': '/var/log/kea',
    # Kea's own control sockets (written into its config) and the ones the agent connects to: Kea
    # makes its sockets 0750 _kea, so a systemd-socket-proxyd running as _kea opens them to the agent
    'kea_sockets': {'dhcp4': '/run/kea/kea4-ctrl-socket', 'd2': '/run/kea/kea-ddns-ctrl-socket'},
    'kea_access': {'dhcp4': '/run/liteblox-kea/kea4-ctrl-socket', 'd2': '/run/liteblox-kea/kea-ddns-ctrl-socket'},
    'kea_group': '_kea',
    # chrony (time): its AppArmor profile only lets chronyd read config inside chrony_dir, so candidates are
    # checked there; a systemd path unit restarts chrony when chrony_conf is replaced
    'chrony_dir': '/etc/chrony',
    'chrony_conf': '/etc/chrony/chrony.conf',
    'chrony_unit': 'chrony.service',
    'chrony_restart_wait': 20,
    # the Dashboard's figures: BIND's statistics channel (LiteBlox writes it into top.conf, localhost only),
    # and the filesystems whose use is reported
    'bind_stats_url': 'http://127.0.0.1:8053/json/v1/server',
    'stats_disks': ['/', '/var/lib/bind'],
    'proc_dir': '/proc',
    # absolute paths: /usr/sbin isn't on a regular user's PATH on Debian
    'tools': {
        'named': '/usr/sbin/named',
        'named_checkconf': '/usr/bin/named-checkconf',
        'named_checkzone': '/usr/bin/named-checkzone',
        'rndc': '/usr/sbin/rndc',
        'kea_dhcp4': '/usr/sbin/kea-dhcp4',
        'kea_dhcp_ddns': '/usr/sbin/kea-dhcp-ddns',
        'ip': '/usr/sbin/ip',
        'timedatectl': '/usr/bin/timedatectl',
        'chronyd': '/usr/sbin/chronyd',
        'chronyc': '/usr/bin/chronyc',
        'systemctl': '/usr/bin/systemctl',
    },
}

PRIMARY_TYPES = ('primary', 'master')
BUILTIN_ZONES = ('localhost', '127.in-addr.arpa', '0.in-addr.arpa', '255.in-addr.arpa')
MAX_BODY = 16 * 1024 * 1024
MAX_AGENT_SIZE = 2 * 1024 * 1024
UPGRADE_EXIT = 75           # exits with this after staging an upgrade: systemd restarts it, the installer runs first
# backup metadata lives here inside the archive, so restoring with `tar zxf X -C /`
# drops it into the agent's state dir instead of creating /liteblox at the root
BACKUP_META = 'var/lib/liteblox-agent/restored-backup'
STAGE_TTL = 600
STAGE_SUFFIX = '.liteblox-new'
NOTIFY_VALUES = ('yes', 'no', 'explicit', 'primary-only', 'master-only')
# the files LiteBlox generates; everything but named.conf lives in managed_dir
CONFIG_ROLES = ('named.conf', 'acls.conf', 'keys.conf', 'options.conf', 'top.conf', 'zones.conf')
# options that name a file or directory: refused in generated config (directory is LiteBlox's own)
PATH_OPTIONS = frozenset((
    'directory', 'pid-file', 'key-directory', 'dump-file', 'statistics-file', 'memstatistics-file',
    'session-keyfile', 'managed-keys-directory', 'bindkeys-file', 'secroots-file', 'recursing-file',
    'lock-file', 'geoip-directory', 'dnstap-output', 'key-file', 'cert-file', 'ca-file', 'dhparam-file',
    'zone-directory', 'new-zones-directory', 'tkey-gssapi-keytab', 'database'))
# top-level statements top.conf may not hold: they belong in another file, or load code
TOP_REFUSED = ('include', 'options', 'acl', 'key', 'zone', 'view', 'plugin', 'dyndb', 'dlz')
ZONE_OPTIONS = {
    'primary': {'type': 'word', 'file': 'path', 'notify': 'word', 'also-notify': 'list',
                'allow-transfer': 'list', 'allow-query': 'list', 'allow-update': 'list',
                'update-policy': 'list', 'ixfr-from-differences': 'word', 'journal': 'path'},
    'secondary': {'type': 'word', 'file': 'path', 'notify': 'word', 'primaries': 'list', 'masters': 'list',
                  'masterfile-format': 'word', 'also-notify': 'list', 'allow-transfer': 'list',
                  'allow-query': 'list', 'allow-notify': 'list'},
    'forward': {'type': 'word', 'forward': 'word', 'forwarders': 'list'},
}
ZONE_TYPES = {'primary': 'primary', 'master': 'primary', 'secondary': 'secondary', 'slave': 'secondary',
              'forward': 'forward'}
DPKG_SUFFIXES = ('.dpkg-dist', '.dpkg-new', '.dpkg-old', '.dpkg-bak', '.ucf-dist', '.ucf-new', '.ucf-old')


class AgentError(Exception):
    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# ── named.conf parsing ─────────────────────────────────────────────────────────

class ConfError(ValueError):
    pass


def conf_tokens(text):
    """Tokens as (kind, value): kind 'p' for { } ;, 'w' for words, 's' for quoted strings."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith('//', i) or c == '#':
            j = text.find('\n', i)
            i = n if j < 0 else j
        elif text.startswith('/*', i):
            j = text.find('*/', i + 2)
            if j < 0:
                raise ConfError('unterminated /* comment')
            i = j + 2
        elif c in '{};':
            out.append(('p', c))
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == '\\' else 1
            if j >= n:
                raise ConfError('unterminated string')
            out.append(('s', text[i + 1:j]))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in '{};"':
                j += 1
            out.append(('w', text[i:j]))
            i = j
    return out


class Statement:
    def __init__(self, words, block):
        self.words = words      # [(kind, value)]
        self.block = block      # [Statement] or None

    @property
    def keyword(self):
        return self.words[0][1] if self.words else ''

    def child(self, keyword):
        for st in self.block or ():
            if st.keyword == keyword:
                return st
        return None

    def value(self, keyword):
        st = self.child(keyword)
        return st.words[1][1] if st and len(st.words) > 1 else None


def parse_conf(text):
    stmts, pos = _parse_block(conf_tokens(text), 0, top=True)
    return stmts


def _parse_block(toks, pos, top):
    stmts = []
    while pos < len(toks):
        if toks[pos] == ('p', '}'):
            if top:
                raise ConfError("unexpected '}'")
            return stmts, pos + 1
        words, block = [], None
        while pos < len(toks) and toks[pos][0] != 'p':
            words.append(toks[pos])
            pos += 1
        if pos < len(toks) and toks[pos] == ('p', '{'):
            block, pos = _parse_block(toks, pos + 1, top=False)
        if pos >= len(toks) or toks[pos] != ('p', ';'):
            raise ConfError(f"expected ';' after {' '.join(w for _, w in words) or 'block'}")
        pos += 1
        stmts.append(Statement(words, block))
    if not top:
        raise ConfError("missing '}'")
    return stmts, pos


def normalize_zone(name):
    name = unquote(name).strip().lower()
    return name[:-1] if name.endswith('.') and name != '.' else name


def zones_from_conf(stmts):
    """Zone declarations from parsed `named-checkconf -p` output."""
    directory = None
    for st in stmts:
        if st.keyword == 'options':
            directory = st.value('directory')

    def zone(st, view):
        ztype = st.value('type')
        file = st.value('file')
        if file and directory and not os.path.isabs(file):
            file = os.path.join(directory, file)
        name = normalize_zone(st.words[1][1])
        return {
            'name': name,
            'view': view,
            'type': {'master': 'primary', 'slave': 'secondary'}.get(ztype, ztype),
            'file': file,
            'builtin': name in BUILTIN_ZONES,
        }

    zones = []
    for st in stmts:
        if st.keyword == 'zone' and len(st.words) > 1:
            zones.append(zone(st, None))
        elif st.keyword == 'view' and len(st.words) > 1:
            for inner in st.block or ():
                if inner.keyword == 'zone' and len(inner.words) > 1:
                    zones.append(zone(inner, st.words[1][1]))
    return zones



def role_paths(cfg):
    """{role: live path} for the generated config files."""
    return {r: cfg['named_conf'] if r == 'named.conf' else os.path.join(cfg['managed_dir'], r)
            for r in CONFIG_ROLES}


def _no_paths(stmts, cfg, where, in_channel=False):
    """Refuse include and file/directory options at any depth (logging channel files excepted)."""
    for st in stmts:
        kw = st.keyword
        if kw == 'include':
            raise ConfError(f'{where}: include is not allowed')
        if kw in PATH_OPTIONS:
            raise ConfError(f'{where}: {kw} is not allowed (it names a file or directory)')
        if kw == 'file':
            path = st.words[1][1] if len(st.words) > 1 else ''
            norm = os.path.normpath(path)
            if not in_channel or not os.path.isabs(path) or not any(
                    norm.startswith(d.rstrip('/') + '/') for d in cfg['log_dirs']):
                raise ConfError(f'{where}: file "{path}" is not allowed (log files go under '
                                f'{" or ".join(cfg["log_dirs"])})')
        if st.block:
            _no_paths(st.block, cfg, where, in_channel=kw == 'channel')


def _simple_list(opt, where):
    if len(opt.words) != 1 or opt.block is None or any(s.block is not None for s in opt.block):
        raise ConfError(f'{where}: {opt.keyword} must be a simple list')


def validate_named_conf(text, cfg):
    """Only include statements of the generated files and the distro's built-in zones. Returns the paths."""
    allowed = {p for r, p in role_paths(cfg).items() if r != 'named.conf'} | set(cfg['distro_includes'])
    paths = []
    for st in parse_conf(text):
        if st.keyword != 'include' or len(st.words) != 2 or st.words[1][0] != 's' or st.block is not None:
            raise ConfError(f'named.conf: only include statements are allowed (got {st.keyword!r})')
        if st.words[1][1] not in allowed:
            raise ConfError(f'named.conf: include "{st.words[1][1]}" is not a LiteBlox or distro file')
        paths.append(st.words[1][1])
    return paths


def validate_acls(text, cfg):
    names = []
    for st in parse_conf(text):
        if st.keyword != 'acl' or len(st.words) != 2 or st.block is None:
            raise ConfError(f'acls.conf: only acl "name" {{ ... }}; statements are allowed (got {st.keyword!r})')
        _no_paths(st.block, cfg, f'acl {st.words[1][1]}')
        names.append(st.words[1][1])
    return names


def validate_keys(text, cfg):
    names = []
    for st in parse_conf(text):
        if st.keyword != 'key' or len(st.words) != 2 or st.block is None:
            raise ConfError(f'keys.conf: only key "name" {{ ... }}; statements are allowed (got {st.keyword!r})')
        name = st.words[1][1]
        if sorted(o.keyword for o in st.block) != ['algorithm', 'secret'] or any(
                len(o.words) != 2 or o.block is not None for o in st.block):
            raise ConfError(f'key {name}: exactly one algorithm and one secret are allowed')
        names.append(name)
    return names


def validate_options(text, cfg):
    stmts = parse_conf(text)
    if len(stmts) != 1 or stmts[0].keyword != 'options' or len(stmts[0].words) != 1 or stmts[0].block is None:
        raise ConfError('options.conf: exactly one options { ... }; statement is allowed')
    rest = []
    for st in stmts[0].block:
        if st.keyword == 'directory':
            if len(st.words) != 2 or st.words[1][1] != cfg['directory']:
                raise ConfError(f'options: directory must be "{cfg["directory"]}"')
        else:
            rest.append(st)
    _no_paths(rest, cfg, 'options')
    return []


def validate_top(text, cfg):
    stmts = parse_conf(text)
    for st in stmts:
        if st.keyword in TOP_REFUSED:
            raise ConfError(f'top.conf: {st.keyword} statements are not allowed here')
    _no_paths(stmts, cfg, 'top.conf')
    return [st.keyword for st in stmts]


def validate_zones(text, cfg):
    """Zone statements of the kinds LiteBlox writes. Returns [{name, type, file, dynamic}]."""
    dirs = {'static': os.path.realpath(cfg['managed_dir']), 'dyn': os.path.realpath(cfg['dyn_dir']),
            'sec': os.path.realpath(cfg['sec_dir']), 'jnl': os.path.realpath(cfg['jnl_dir'])}
    zones, seen = [], set()
    for st in parse_conf(text):
        if st.keyword != 'zone' or len(st.words) not in (2, 3) or st.words[1][0] != 's' or st.block is None:
            raise ConfError(f'zones.conf: only zone "name" {{ ... }}; statements are allowed (got {st.keyword!r})')
        if len(st.words) == 3 and st.words[2][1].upper() != 'IN':
            raise ConfError('only class IN is allowed')
        name = normalize_zone(st.words[1][1])
        if name in seen:
            raise ConfError(f'zone {name} declared twice')
        seen.add(name)
        ztype = ZONE_TYPES.get(st.value('type') or '')
        if ztype is None:
            raise ConfError(f'zone {name}: type must be primary, secondary or forward')
        allowed = ZONE_OPTIONS[ztype]
        for opt in st.block:
            kind = allowed.get(opt.keyword)
            if kind is None:
                raise ConfError(f'zone {name}: option {opt.keyword!r} is not allowed in a {ztype} zone')
            if opt.keyword == 'update-policy' and len(opt.words) == 2 and opt.words[1][1] == 'local':
                continue
            if kind == 'list':
                _simple_list(opt, f'zone {name}')
            elif len(opt.words) != 2 or opt.block is not None:
                raise ConfError(f'zone {name}: {opt.keyword} takes one value')
            elif opt.keyword == 'notify' and opt.words[1][1] not in NOTIFY_VALUES:
                raise ConfError(f'zone {name}: bad notify value')
            elif opt.keyword == 'forward' and opt.words[1][1] not in ('first', 'only'):
                raise ConfError(f'zone {name}: forward must be first or only')
            elif opt.keyword == 'masterfile-format' and opt.words[1][1] != 'text':
                raise ConfError(f'zone {name}: masterfile-format must be text')
            elif opt.keyword == 'ixfr-from-differences' and opt.words[1][1] not in ('yes', 'no'):
                raise ConfError(f'zone {name}: ixfr-from-differences must be yes or no')
            elif opt.keyword == 'journal':
                journal = opt.words[1][1]
                if not os.path.isabs(journal) or os.path.dirname(os.path.realpath(journal)) != dirs['jnl']:
                    raise ConfError(f'zone {name}: journal must be directly inside {dirs["jnl"]}')
        file = st.value('file')
        dynamic = st.child('update-policy') is not None or st.child('allow-update') is not None
        if ztype == 'forward':
            where = None
        elif file is None:
            raise ConfError(f'zone {name}: file is required')
        else:
            where = 'sec' if ztype == 'secondary' else 'dyn' if dynamic else 'static'
            if not os.path.isabs(file) or os.path.dirname(os.path.realpath(file)) != dirs[where]:
                raise ConfError(f'zone {name}: file must be directly inside {dirs[where]}')
        if ztype == 'secondary' and st.child('primaries') is None and st.child('masters') is None:
            raise ConfError(f'zone {name}: a secondary zone needs primaries')
        zones.append({'name': name, 'type': ztype, 'file': file, 'dynamic': dynamic, 'journal': st.value('journal')})
    return zones


CONFIG_VALIDATORS = {
    'named.conf': validate_named_conf, 'acls.conf': validate_acls, 'keys.conf': validate_keys,
    'options.conf': validate_options, 'top.conf': validate_top, 'zones.conf': validate_zones,
}


# ── Kea config (DHCP) ──────────────────────────────────────────────────────────

# role: (top-level key, service)
KEA_ROLES = {'kea-dhcp4.conf': ('Dhcp4', 'dhcp4'), 'kea-dhcp-ddns.conf': ('DhcpDdns', 'd2')}
KEA_TOOLS = {'dhcp4': 'kea_dhcp4', 'd2': 'kea_dhcp_ddns'}
# config-reload's error for a subnet on an interface Kea hasn't seen yet (made or renamed after Kea started)
KEA_NEW_INTERFACE = 'is not present in the system'
# the failover pair's mutual-TLS files (in kea_dir/tls): role -> the PEM block it must be
KEA_TLS = {'tls/ha.crt': 'CERTIFICATE', 'tls/ha.key': 'PRIVATE KEY', 'tls/ca.crt': 'CERTIFICATE'}
HA_KEYS = frozenset(('this-server-name', 'mode', 'heartbeat-delay', 'max-response-delay', 'max-ack-delay',
                     'max-unacked-clients', 'multi-threading', 'peers', 'trust-anchor', 'cert-file', 'key-file',
                     'require-client-certs', 'send-lease-updates', 'sync-leases', 'sync-timeout', 'wait-backup-ack',
                     'delayed-updates-limit'))
HA_URL = re.compile(r'https?://(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})/')
KEA_HOOKS = ('libdhcp_lease_cmds.so', 'libdhcp_ha.so')
# what LiteBlox writes into Dhcp4 now or in later milestones; anything else (config-control,
# hosts-databases, a config backend...) is refused
DHCP4_KEYS = frozenset((
    'authoritative', 'boot-file-name', 'cache-max-age', 'cache-threshold', 'calculate-tee-times',
    'client-classes', 'comment', 'control-socket', 'ddns-conflict-resolution-mode', 'ddns-generated-prefix',
    'ddns-override-client-update', 'ddns-override-no-update', 'ddns-qualifying-suffix',
    'ddns-replace-client-name', 'ddns-send-updates', 'ddns-ttl-percent', 'ddns-update-on-renew',
    'decline-probation-period', 'dhcp-ddns', 'echo-client-id', 'expired-leases-processing',
    'host-reservation-identifiers', 'hooks-libraries', 'hostname-char-replacement', 'hostname-char-set',
    'interfaces-config', 'lease-database', 'loggers', 'match-client-id', 'max-valid-lifetime',
    'min-valid-lifetime', 'multi-threading', 'next-server', 'option-data', 'option-def', 'rebind-timer',
    'renew-timer', 'reservations', 'reservations-global', 'reservations-in-subnet', 'reservations-out-of-pool',
    'sanity-checks', 'server-hostname', 'shared-networks', 'store-extended-info', 'subnet4', 't1-percent',
    't2-percent', 'user-context', 'valid-lifetime'))
D2_KEYS = frozenset(('comment', 'control-socket', 'dns-server-timeout', 'forward-ddns', 'ip-address', 'loggers',
                     'ncr-format', 'ncr-protocol', 'port', 'reverse-ddns', 'tsig-keys', 'user-context'))
LOOPBACK = ('127.0.0.1', '::1')
# commands LiteBlox may send through /dhcp/command, per service
KEA_COMMANDS = {
    'dhcp4': ('status-get', 'config-get', 'version-get', 'lease4-get-page', 'lease4-get', 'lease4-del',
              'ha-heartbeat', 'ha-maintenance-start', 'ha-maintenance-cancel', 'ha-sync-complete-notify'),
    'd2': ('status-get', 'version-get'),
}


def _under(path, folder):
    norm = os.path.normpath(path)
    return isinstance(path, str) and os.path.isabs(path) and norm == path and norm.startswith(folder.rstrip('/') + '/')


def _loggers(loggers, cfg, where):
    if not isinstance(loggers, list):
        raise ConfError(f'{where}: loggers must be a list')
    for logger in loggers:
        # output_options: the name before Kea 2.5 (which still reads it)
        outputs = [o for key in ('output-options', 'output_options') for o in (logger.get(key) or [])] \
            if isinstance(logger, dict) else []
        for out in outputs:
            target = out.get('output') if isinstance(out, dict) else None
            if not (target in ('stdout', 'stderr', 'syslog') or (isinstance(target, str) and target.startswith('syslog:'))
                    or (isinstance(target, str) and _under(target, cfg['kea_log_dir']))):
                raise ConfError(f'{where}: logger output {target!r} is not allowed (stdout, syslog or a file '
                                f'under {cfg["kea_log_dir"]})')


def validate_tls(role, text):
    """One PEM block of the kind the role holds, and nothing else."""
    kind = KEA_TLS[role]
    body = text.strip()
    begin, end = f'-----BEGIN {kind}-----', f'-----END {kind}-----'
    if not body.startswith(begin) or not body.endswith(end) or body.count('-----BEGIN') != 1:
        raise ConfError(f'{role}: one PEM {kind.lower()} block expected')


def _check_ha(params, cfg, where):
    """The HA hook's parameters: one hot-standby relationship of two peers, TLS files only from kea_dir/tls."""
    if not isinstance(params, dict) or list(params) != ['high-availability'] \
            or not isinstance(params['high-availability'], list) or len(params['high-availability']) != 1:
        raise ConfError(f'{where}: the HA hook takes one high-availability relationship')
    ha = params['high-availability'][0]
    if not isinstance(ha, dict):
        raise ConfError(f'{where}: high-availability must be an object')
    extra = sorted(set(ha) - HA_KEYS)
    if extra:
        raise ConfError(f'{where}: HA {", ".join(extra)} not allowed')
    if ha.get('mode') != 'hot-standby':
        raise ConfError(f'{where}: HA mode must be hot-standby')
    peers = ha.get('peers')
    if not isinstance(peers, list) or len(peers) != 2 or not all(isinstance(x, dict) for x in peers):
        raise ConfError(f'{where}: HA needs exactly two peers')
    if sorted(x.get('role') for x in peers) != ['primary', 'standby']:
        raise ConfError(f'{where}: the HA peers are one primary and one standby')
    if ha.get('this-server-name') not in [x.get('name') for x in peers]:
        raise ConfError(f'{where}: this-server-name must be one of the peers')
    for x in peers:
        if set(x) - {'name', 'url', 'role', 'auto-failover'} or not HA_URL.fullmatch(str(x.get('url'))):
            raise ConfError(f'{where}: HA peer {x.get("name")!r}: name, url (http(s)://IP:PORT/), role, auto-failover')
    tls = {'trust-anchor': 'tls/ca.crt', 'cert-file': 'tls/ha.crt', 'key-file': 'tls/ha.key'}
    for key, role in tls.items():
        if key in ha and ha[key] != os.path.join(cfg['kea_dir'], role):
            raise ConfError(f'{where}: HA {key} must be {os.path.join(cfg["kea_dir"], role)}')


def _control_socket(value, cfg, service, where):
    want = {'socket-type': 'unix', 'socket-name': cfg['kea_sockets'][service]}
    if value != want:
        raise ConfError(f'{where}: control-socket must be {json.dumps(want)}')


def validate_kea(role, text, cfg):
    """The parsed config if `text` is a Kea config LiteBlox may write as `role`, else ConfError."""
    if '<?include' in text:
        raise ConfError(f'{role}: <?include is not allowed')
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ConfError(f'{role}: not strict JSON ({e})')
    top, service = KEA_ROLES[role]
    if not isinstance(data, dict) or list(data) != [top] or not isinstance(data[top], dict):
        raise ConfError(f'{role}: must be {{"{top}": {{...}}}} and nothing else')
    body = data[top]
    allowed = DHCP4_KEYS if service == 'dhcp4' else D2_KEYS
    extra = sorted(set(body) - allowed)
    if extra:
        raise ConfError(f'{role}: {", ".join(extra)} not allowed')
    _control_socket(body.get('control-socket'), cfg, service, role)
    _loggers(body.get('loggers', []), cfg, role)
    if service == 'dhcp4':
        db = body.get('lease-database')
        if not isinstance(db, dict) or db.get('type') != 'memfile' or not _under(db.get('name', ''), cfg['kea_lease_dir']):
            raise ConfError(f'{role}: lease-database must be memfile with its file under {cfg["kea_lease_dir"]}')
        for hook in body.get('hooks-libraries', []):
            lib = hook.get('library') if isinstance(hook, dict) else None
            if not (isinstance(lib, str) and os.path.dirname(lib) == cfg['kea_hooks_dir']
                    and os.path.basename(lib) in KEA_HOOKS):
                raise ConfError(f'{role}: hooks library {lib!r} is not allowed ({", ".join(KEA_HOOKS)} '
                                f'from {cfg["kea_hooks_dir"]})')
            if set(hook) - {'library', 'parameters'}:
                raise ConfError(f'{role}: a hooks library takes only library and parameters')
            if os.path.basename(lib) == 'libdhcp_ha.so':
                _check_ha(hook.get('parameters'), cfg, role)
            elif hook.get('parameters'):
                raise ConfError(f'{role}: {os.path.basename(lib)} takes no parameters here')
        ddns = body.get('dhcp-ddns', {})
        if not isinstance(ddns, dict) or ddns.get('server-ip', '127.0.0.1') not in LOOPBACK:
            raise ConfError(f'{role}: dhcp-ddns server-ip must be loopback')
    else:
        if body.get('ip-address', '127.0.0.1') not in LOOPBACK:
            raise ConfError(f'{role}: D2 must listen on loopback')
        for key in body.get('tsig-keys', []):
            if not isinstance(key, dict) or 'secret-file' in key:
                raise ConfError(f'{role}: tsig-keys take name, algorithm and secret (no secret-file)')
    return data


CHRONY_HEADER = '# Generated by LiteBlox.'
# directives LiteBlox writes with one fixed value each (Debian 13's paths)
CHRONY_FIXED = {
    'keyfile': '/etc/chrony/chrony.keys',
    'driftfile': '/var/lib/chrony/chrony.drift',
    'ntsdumpdir': '/var/lib/chrony',
    'logdir': '/var/log/chrony',
    'leapseclist': '/usr/share/zoneinfo/leap-seconds.list',
    'leapsectz': 'right/UTC',           # chrony before 4.6 (Ubuntu 24.04), which has no leapseclist
}
CHRONY_SOURCE_FLAGS = ('iburst', 'prefer', 'nts')
CHRONY_SOURCE_VALUES = ('minpoll', 'maxpoll')
HOSTNAME = re.compile(r'(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?')


def _chrony_address(word):
    try:
        ipaddress.ip_address(word)
        return True
    except ValueError:
        return bool(HOSTNAME.fullmatch(word))


def validate_chrony(text):
    """chrony.conf as LiteBlox writes it: sources, the fixed lines, and serving (allow/deny/local); nothing that
    reads other files, opens other sockets or runs anything."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith(CHRONY_HEADER):
        raise ConfError('chrony.conf must start with the LiteBlox header')
    sources = 0
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line[0] in '#%!;':
            continue
        words = line.split()
        kw, args = words[0], words[1:]
        where = f'chrony.conf line {n}'
        if kw in ('server', 'pool'):
            if not args or not _chrony_address(args[0]):
                raise ConfError(f'{where}: {kw} needs a host name or address')
            rest = args[1:]
            while rest:
                opt = rest.pop(0)
                if opt in CHRONY_SOURCE_FLAGS:
                    continue
                if opt in CHRONY_SOURCE_VALUES and rest and re.fullmatch(r'-?\d{1,2}', rest[0]):
                    rest.pop(0)
                    continue
                raise ConfError(f'{where}: source option {opt!r} not allowed')
            sources += 1
        elif kw in ('allow', 'deny'):
            if len(args) != 1:
                raise ConfError(f'{where}: {kw} takes one network')
            try:
                net = ipaddress.ip_network(args[0], strict=False)
            except ValueError:
                raise ConfError(f'{where}: {args[0]} is not a network')
            if kw == 'allow' and net.prefixlen == 0:
                raise ConfError(f'{where}: serving time to every address is not allowed')
        elif kw == 'local':
            if not (len(args) in (2, 3) and args[0] == 'stratum' and re.fullmatch(r'\d{1,2}', args[1])
                    and 1 <= int(args[1]) <= 15 and args[2:] in ([], ['orphan'])):
                raise ConfError(f'{where}: local takes "stratum N [orphan]"')
        elif kw in CHRONY_FIXED:
            if args != [CHRONY_FIXED[kw]]:
                raise ConfError(f'{where}: {kw} must be {CHRONY_FIXED[kw]}')
        elif kw == 'makestep':
            if len(args) != 2 or not re.fullmatch(r'\d+(\.\d+)?', args[0]) or not re.fullmatch(r'-?\d+', args[1]):
                raise ConfError(f'{where}: makestep takes a threshold and a limit')
        elif kw == 'maxupdateskew':
            if len(args) != 1 or not re.fullmatch(r'\d+(\.\d+)?', args[0]):
                raise ConfError(f'{where}: maxupdateskew takes a number')
        elif kw == 'rtcsync':
            if args:
                raise ConfError(f'{where}: rtcsync takes no arguments')
        else:
            raise ConfError(f'{where}: directive {kw!r} not allowed')
    if not sources:
        raise ConfError('chrony.conf has no server or pool to sync from')


def chrony_tracking(out):
    """chronyc -c tracking (CSV) → a dict, or None."""
    f = out.strip().split(',')
    if len(f) < 14:
        return None
    try:
        return {'reference': f[1], 'stratum': int(f[2]), 'offset': float(f[4]), 'leap': f[13]}
    except ValueError:
        return None


def chrony_sources(out):
    """chronyc -c sources (CSV) → [{address, state, stratum, reach, offset}]."""
    rows = []
    for line in out.splitlines():
        f = line.split(',')
        if len(f) < 10:
            continue
        try:
            rows.append({'address': f[2], 'state': f[1], 'stratum': int(f[3]), 'reach': int(f[5], 8),
                         'offset': float(f[8])})
        except ValueError:
            continue
    return rows


def find_kea_hooks():
    """Kea's hooks directory (multiarch on Debian: x86_64-linux-gnu, aarch64-linux-gnu, ...)."""
    for base in sorted(os.listdir('/usr/lib')) if os.path.isdir('/usr/lib') else ():
        path = os.path.join('/usr/lib', base, 'kea', 'hooks')
        if os.path.isdir(path):
            return path
    return '/usr/lib/kea/hooks'


def system_stats(proc, disks):
    """Load, memory, uptime and filesystem use, from /proc and statvfs."""
    with open(os.path.join(proc, 'loadavg')) as f:
        load = [float(x) for x in f.read().split()[:3]]
    mem = {}
    with open(os.path.join(proc, 'meminfo')) as f:
        for line in f:
            key, _, rest = line.partition(':')
            if key in ('MemTotal', 'MemAvailable'):
                mem[key] = int(rest.split()[0]) * 1024
    with open(os.path.join(proc, 'uptime')) as f:
        uptime = float(f.read().split()[0])
    used = {}
    for path in disks:
        try:
            st = os.statvfs(path)
        except OSError:
            continue
        used[path] = {'total': st.f_blocks * st.f_frsize, 'used': (st.f_blocks - st.f_bfree) * st.f_frsize,
                      'available': st.f_bavail * st.f_frsize}
    return {'load': load, 'cpus': os.cpu_count(), 'mem_total': mem.get('MemTotal'),
            'mem_available': mem.get('MemAvailable'), 'uptime': uptime, 'disks': used}


def bind_counters(url, timeout=5.0):
    """BIND's query counters from its statistics channel (JSON). They count up from named's start."""
    # no proxy: the channel is on localhost, and a proxy from the environment must not see it
    with build_opener(ProxyHandler({})).open(url, timeout=timeout) as r:
        data = json.loads(r.read())
    ns, rcodes = data.get('nsstats') or {}, data.get('rcodes') or {}
    return {'boot_time': data.get('boot-time'), 'config_time': data.get('config-time'),
            'queries': (data.get('opcodes') or {}).get('QUERY', 0),
            'noerror': rcodes.get('NOERROR', 0), 'nxdomain': rcodes.get('NXDOMAIN', 0),
            'servfail': rcodes.get('SERVFAIL', 0), 'refused': rcodes.get('REFUSED', 0),
            'recursive': ns.get('QryRecursion', 0), 'updates': ns.get('UpdateDone', 0),
            'xfr_out': ns.get('XfrReqDone', 0)}


# ── neighbours and probes (IPAM) ───────────────────────────────────────────────

PROBE_MAX = 64          # addresses per /probe call: a /24 sweep is four calls


def parse_neigh(rows):
    """`ip -4 -s -j neigh` rows → [{ip, mac, dev, state, used, confirmed, updated, probes}]; entries without a
    MAC (INCOMPLETE, FAILED) are dropped. used/confirmed/updated: seconds ago. confirmed is when the neighbour
    last proved it's there (an ARP reply, or traffic from it, a TCP ACK say): the one to trust as "last seen";
    used is only when this node last sent to it. probes: ARP requests sent without an answer since then."""
    out = []
    for r in rows or []:
        mac = (r.get('lladdr') or '').lower()
        if not mac or not r.get('dst'):
            continue
        state = r.get('state') or []
        out.append({'ip': r['dst'], 'mac': mac, 'dev': r.get('dev'),
                    'state': state[0] if isinstance(state, list) and state else str(state or ''),
                    'used': r.get('used'), 'confirmed': r.get('confirmed'), 'updated': r.get('updated'),
                    'probes': r.get('probes')})
    return out


def _icmp_checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return ~total & 0xffff


def _icmp_socket():
    # an unprivileged ICMP socket: allowed by net.ipv4.ping_group_range (systemd's default covers every group),
    # so the agent needs no CAP_NET_RAW; the kernel matches the replies to this socket
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)


def icmp_probe(addresses, interval=0.1, wait=2.0):
    """Send one echo request to each address, `interval` seconds apart, reading replies as they come, then
    wait up to `wait` seconds more. Returns ({ip: rtt_ms}, method). When ICMP sockets aren't allowed, a UDP
    datagram to the discard port still makes the kernel ARP for the address (method 'udp': no replies)."""
    try:
        sock = _icmp_socket()
    except OSError:
        sock = None
    if sock is None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            for a in addresses:
                try:
                    udp.sendto(b'', (a, 9))
                except OSError:
                    pass
                time.sleep(interval)
        time.sleep(wait)
        return {}, 'udp'
    sent, replied = {}, {}
    with sock:
        sock.setblocking(False)

        def read_until(deadline):
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                ready, _, _ = select.select([sock], [], [], left)
                if not ready:
                    return
                try:
                    data, (src, _port) = sock.recvfrom(1500)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if data[:1] == b'\0' and src in sent and src not in replied:     # type 0: echo reply
                    replied[src] = round((time.monotonic() - sent[src]) * 1000, 1)

        for seq, a in enumerate(addresses):
            packet = struct.pack('!BBHHH', 8, 0, 0, 0, seq & 0xffff) + b'liteblox'
            packet = packet[:2] + struct.pack('!H', _icmp_checksum(packet)) + packet[4:]
            sent[a] = time.monotonic()
            try:
                sock.sendto(packet, (a, 0))
            except OSError:
                pass        # no route, say: the neighbour table still answers
            read_until(time.monotonic() + interval)
        read_until(time.monotonic() + wait)
    return replied, 'icmp'


def kea_command(path, command, arguments=None, timeout=15.0):
    """One command over a Kea control socket (Kea answers once, then closes the connection)."""
    request = {'command': command}
    if arguments is not None:
        request['arguments'] = arguments
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    buf = b''
    try:
        s.connect(path)
        s.sendall(json.dumps(request).encode())
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            try:
                return json.loads(buf)
            except ValueError:
                continue
    except OSError as e:
        raise AgentError(HTTPStatus.BAD_GATEWAY, f'{command} over {path}: {e.strerror or e}')
    finally:
        s.close()
    try:
        return json.loads(buf)
    except ValueError:
        raise AgentError(HTTPStatus.BAD_GATEWAY, f'{command} over {path}: no complete answer')


def read_text(path):
    """File contents, or '' when it can't be read (e.g. a root-only key file)."""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            return f.read()
    except OSError:
        return ''


def conf_files(named_conf):
    """named.conf plus every file it includes, recursively."""
    seen, todo = [], [named_conf]
    while todo:
        path = todo.pop(0)
        if path in seen or not os.path.isfile(path):
            continue
        seen.append(path)
        todo += re.findall(r'^\s*include\s+"([^"]+)"\s*;', read_text(path), re.M)
    return seen


# ── Agent logic ────────────────────────────────────────────────────────────────

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tar_info(path, st, size=0):
    """TarInfo carrying the real owner, group and mode, so `tar zxf -C /` restores them."""
    info = tarfile.TarInfo(path.lstrip('/'))
    info.size, info.mode, info.mtime = size, st.st_mode & 0o7777, int(st.st_mtime)
    info.uid, info.gid = st.st_uid, st.st_gid
    try:
        info.uname = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        pass
    try:
        info.gname = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        pass
    return info


def _now_stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


class Agent:
    def __init__(self, config):
        self.cfg = config
        self.tools = config['tools']
        self.lock = threading.Lock()
        self.stages = {}        # stage_id -> dict
        self.frozen = {}        # zone -> when /zones/<zone>?freeze=1 froze it (thawed by the next config commit)
        self.source_sha = sha256(open(os.path.abspath(__file__), 'rb').read())
        # an agent the installer put in place says which version it is; Repair writes it too
        try:
            with open(os.path.join(config['agent_lib'], 'VERSION')) as f:
                config['version'] = f.read().strip() or config['version']
        except OSError:
            pass
        if not config.get('kea_hooks_dir'):
            config['kea_hooks_dir'] = find_kea_hooks()
        os.makedirs(os.path.join(config['state_dir'], 'backups'), exist_ok=True)

    # ── helpers ──

    def run(self, tool, *args, timeout=30):
        if not self.tools.get(tool):
            return 127, f'{tool}: not configured'
        argv = [self.tools[tool], *args]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, f'{argv[0]}: not found'
        except subprocess.TimeoutExpired:
            return 124, f'{argv[0]}: timed out'
        return r.returncode, (r.stdout + r.stderr).strip()

    def zones(self, secrets=False):
        # -x masks key secrets: this output is shown in the UI and stored in backups
        code, out = self.run('named_checkconf', '-p' if secrets else '-px', self.cfg['named_conf'])
        if code != 0:
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'named-checkconf failed', output=out)
        try:
            return zones_from_conf(parse_conf(out)), out
        except ConfError as e:
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, f'cannot parse named-checkconf output: {e}')

    def zone(self, name):
        """The writable primary zone `name` (default view only)."""
        name = normalize_zone(name)
        zones, _ = self.zones()
        matches = [z for z in zones if z['name'] == name]
        if not matches:
            raise AgentError(HTTPStatus.NOT_FOUND, f'zone {name} is not declared on this node')
        z = matches[0]
        if len(matches) > 1 or z['view']:
            raise AgentError(HTTPStatus.CONFLICT, f'zone {name} is inside a view; views are read-only')
        if z['type'] != 'primary' or not z['file']:
            raise AgentError(HTTPStatus.CONFLICT, f'zone {name} is not a primary zone with a file')
        if z['builtin']:
            raise AgentError(HTTPStatus.CONFLICT, f'zone {name} is a built-in zone')
        return z

    def read_bytes(self, path):
        try:
            with open(path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            raise AgentError(HTTPStatus.NOT_FOUND, f'{path} does not exist')
        except PermissionError:
            raise AgentError(HTTPStatus.FORBIDDEN, f'{path} is not readable by the agent')

    def stats(self, query):
        """The node's load, memory, disk and uptime, and BIND's query counters; each part fails on its own."""
        out = {'system': None, 'bind': None, 'errors': {}}
        try:
            out['system'] = system_stats(self.cfg['proc_dir'], self.cfg['stats_disks'])
        except (OSError, ValueError, IndexError) as e:
            out['errors']['system'] = str(e)
        if not self.cfg['bind']:
            return out
        try:
            out['bind'] = bind_counters(self.cfg['bind_stats_url'])
        except (OSError, ValueError) as e:
            out['errors']['bind'] = f"BIND's statistics channel: {getattr(e, 'reason', None) or e}"
        return out

    def loaded_serial(self, name):
        code, out = self.run('rndc', 'zonestatus', name, timeout=10)
        m = re.search(r'^serial:\s*(\d+)', out, re.M) if code == 0 else None
        return int(m.group(1)) if m else None

    def _expire_stages(self):
        cutoff = time.time() - STAGE_TTL
        for sid in [s for s, st in self.stages.items() if st['created'] < cutoff]:
            self._discard(self.stages.pop(sid))
        for name in [z for z, when in self.frozen.items() if when < cutoff]:
            self._thaw(name)            # a takeover that never came back mustn't hold updates forever

    def _thaw(self, name):
        self.frozen.pop(name, None)
        code, out = self.run('rndc', 'thaw', name, timeout=30)
        if code != 0:
            log.warning('rndc thaw %s: %s', name, out)
        return code, out

    def _thaw_all(self):
        for name in list(self.frozen):
            self._thaw(name)

    def _discard(self, stage):
        for staged, _ in stage['files']:
            try:
                os.unlink(staged)
            except FileNotFoundError:
                pass

    def _take_stage(self, stage_id, kind, zone=None):
        self._expire_stages()
        stage = self.stages.pop(stage_id, None)
        if stage is None or stage['kind'] != kind or stage.get('zone') != zone:
            raise AgentError(HTTPStatus.NOT_FOUND, 'unknown or expired stage')
        return stage

    def _backup_file(self, group, path):
        """Copy path into state_dir/backups/<group>/ and prune old copies. Returns the copy or None."""
        if not os.path.exists(path):
            return None
        folder = os.path.join(self.cfg['state_dir'], 'backups', group)
        os.makedirs(folder, exist_ok=True)
        dest = os.path.join(folder, f'{_now_stamp()}-{secrets.token_hex(3)}-{os.path.basename(path)}')
        shutil.copy2(path, dest)
        old = sorted(os.listdir(folder))[:-self.cfg['backup_keep']]
        for name in old:
            os.unlink(os.path.join(folder, name))
        return dest

    @staticmethod
    def _write_like(path, data, like=None):
        """Write data to path, copying mode and group from `like` when given."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        if like and os.path.exists(like):
            st = os.stat(like)
            os.chmod(path, st.st_mode & 0o7777)
            try:
                os.chown(path, -1, st.st_gid)
            except PermissionError:
                pass

    # ── endpoints ──

    def status(self, query, client=None):
        out = {
            'client_address': client,
            'bind': self.cfg['bind'],
            'agent_version': self.cfg['version'],
            'agent_sha256': self.source_sha,
            'install_rev': self.cfg.get('install_rev') or 0,
            'upgradable': self.upgradable(),
            'last_upgrade': self.last_upgrade(),
            'hostname': socket.getfqdn(),
            'python': sys.version.split()[0],
            'interfaces': self.interfaces(),
            'kea': self.kea_status(),
            'time': self.time_status(),
        }
        if self.cfg['bind']:
            out.update(self._bind_status())
        else:   # the same keys, empty: LiteBlox reads them from every node
            out.update(taken_over=False, config_files={}, dpkg_leftovers=[], named_version=None, rndc_ok=False,
                       rndc_status='', checkconf_ok=False, zones_writable={}, managed_dir_writable=False)
        out['clock'] = self.clock()     # last: LiteBlox measures the skew against when the answer arrives
        return out

    # ── upgrades over mTLS (the root installer does the swap) ──

    def upgradable(self):
        return bool(self.cfg.get('install_rev')) and os.path.isfile(
            os.path.join(self.cfg['agent_lib'], 'liteblox_agent_install.py'))

    def last_upgrade(self):
        try:
            with open(os.path.join(self.cfg['agent_lib'], 'last-upgrade.json')) as f:
                out = json.load(f)
            return out if isinstance(out, dict) else None
        except (OSError, ValueError):
            return None

    def mark_started(self):
        """Listening: tell the installer this agent started, so a new one's trial passes."""
        try:
            self._write_state(os.path.join(self.cfg['state_dir'], 'started-ok'), (self.source_sha + '\n').encode())
        except OSError as e:
            log.warning('could not write started-ok: %s', e)

    @staticmethod
    def _write_state(path, data):
        tmp = f'{path}.{secrets.token_hex(4)}.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    def upgrade_agent(self, body):
        """Stage a new agent for the installer and restart: {version, sha256, source}. Only the code changes."""
        if not self.upgradable():
            raise AgentError(HTTPStatus.CONFLICT, 'this node has no installer yet: run Repair / upgrade agent once')
        version, digest, source = body.get('version'), body.get('sha256'), body.get('source')
        if not isinstance(version, str) or not re.fullmatch(r'[0-9A-Za-z.+-]{1,40}', version):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'version must be a version string')
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'sha256 must be 64 lowercase hex digits')
        if not isinstance(source, str):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'source must be the agent as text')
        data = source.encode('utf-8')
        if len(data) > MAX_AGENT_SIZE:
            raise AgentError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, 'the agent is too big')
        if sha256(data) != digest:
            raise AgentError(HTTPStatus.BAD_REQUEST, "the agent's SHA-256 isn't the one sent with it")
        open_stages = [x for x in self.stages.values() if time.time() - x['created'] < STAGE_TTL]
        if open_stages:
            raise AgentError(HTTPStatus.CONFLICT, 'a change is staged on this node: try again when it is done')
        pending = os.path.join(self.cfg['state_dir'], 'pending')
        os.makedirs(pending, mode=0o700, exist_ok=True)
        self._write_state(os.path.join(pending, 'agent.py'), data)
        self._write_state(os.path.join(pending, 'manifest.json'),
                          json.dumps({'version': version, 'sha256': digest, 'size': len(data)}).encode())
        log.info('agent %s staged (%s): restarting so the installer puts it in place', version, digest[:12])
        threading.Timer(1.0, self._restart_for_upgrade).start()
        return {'staged': True, 'version': version, 'sha256': digest}

    def _restart_for_upgrade(self):
        logging.shutdown()
        os._exit(UPGRADE_EXIT)

    def _bind_status(self):
        named_code, named_v = self.run('named', '-v', timeout=10)
        rndc_code, rndc_out = self.run('rndc', 'status', timeout=10)
        writable = {}
        try:
            zones, _ = self.zones()
            for z in zones:
                if z['type'] == 'primary' and z['file'] and not z['builtin'] and not z['view']:
                    writable[z['name']] = (os.access(z['file'], os.W_OK)
                                           and os.access(os.path.dirname(z['file']), os.W_OK))
            checkconf_ok = True
        except AgentError:
            checkconf_ok = False
        paths = role_paths(self.cfg)
        try:
            taken_over = 'zones.conf' in [os.path.basename(p) for p in validate_named_conf(
                read_text(paths['named.conf']), self.cfg)]
        except ConfError:
            taken_over = False
        return {
            'taken_over': taken_over,
            'config_files': {r: self._file_sha(p) for r, p in paths.items()},
            'dpkg_leftovers': self.dpkg_leftovers(),
            'named_version': named_v if named_code == 0 else None,
            'rndc_ok': rndc_code == 0,
            'rndc_status': rndc_out,
            'checkconf_ok': checkconf_ok,
            'zones_writable': writable,
            'managed_dir_writable': os.access(
                self.cfg['managed_dir'] if os.path.isdir(self.cfg['managed_dir'])
                else os.path.dirname(self.cfg['managed_dir']), os.W_OK),
        }

    def clock(self):
        """The node's time (LiteBlox works out the skew) and whether NTP has it synchronized."""
        code, out = self.run('timedatectl', 'show', '-p', 'NTPSynchronized', '--value', timeout=10)
        synced = {'yes': True, 'no': False}.get(out.strip()) if code == 0 else None
        return {'time': time.time(), 'synchronized': synced}

    def interfaces(self):
        """[{name, up, addresses: [cidr, ...]}] from `ip -j addr` (where Kea may serve), or None."""
        code, out = self.run('ip', '-j', 'addr', timeout=10)
        try:
            rows = json.loads(out) if code == 0 else None
        except ValueError:
            rows = None
        if rows is None:
            return None
        return [{'name': r.get('ifname'), 'up': 'UP' in (r.get('flags') or []),
                 'addresses': [f"{a['local']}/{a['prefixlen']}" for a in r.get('addr_info', [])
                               if a.get('family') in ('inet', 'inet6') and 'local' in a]}
                for r in rows if r.get('ifname') != 'lo']

    def neigh(self, query):
        """The node's IPv4 neighbour table (`ip -4 -s -j neigh`): who it has talked to, with their MACs."""
        return {'neighbours': parse_neigh(self._neigh_rows())}

    def _neigh_rows(self):
        code, out = self.run('ip', '-4', '-s', '-j', 'neigh', timeout=10)
        if code != 0:
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'ip neigh failed', output=out)
        try:
            return json.loads(out or '[]')
        except ValueError:
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'cannot parse ip neigh output', output=out)

    def _local_networks(self):
        nets = []
        for i in self.interfaces() or []:
            for cidr in i['addresses']:
                try:
                    net = ipaddress.ip_interface(cidr).network
                except ValueError:
                    continue
                if net.version == 4 and not net.is_loopback and net.prefixlen < 32:
                    nets.append(net)
        return nets

    def probe(self, body):
        """Ping each address (at most PROBE_MAX, all on networks this node is directly on), then read the
        neighbour entry the ping left: a device that drops pings still answers ARP. Returns
        {method, elapsed, results: {ip: {replied, rtt_ms, state, mac, confirmed}}}."""
        addresses = body.get('addresses') or []
        if not isinstance(addresses, list) or not addresses or len(addresses) > PROBE_MAX:
            raise AgentError(HTTPStatus.BAD_REQUEST, f'addresses: a list of 1 to {PROBE_MAX} IPv4 addresses')
        nets = self._local_networks()
        wanted = []
        for a in addresses:
            try:
                ip = ipaddress.IPv4Address(str(a))
            except ValueError:
                raise AgentError(HTTPStatus.BAD_REQUEST, f'{a} is not an IPv4 address')
            # only the node's own networks: this isn't a tool for scanning anywhere else
            if not any(ip in n and ip not in (n.network_address, n.broadcast_address) for n in nets):
                raise AgentError(HTTPStatus.BAD_REQUEST, f'{a} is not on a network this node is directly on')
            if str(ip) not in wanted:
                wanted.append(str(ip))
        try:
            interval = min(max(float(body.get('interval_ms', 100)), 10.0), 300.0) / 1000     # 64 × 0.3 s + 5 s < 30 s
            wait = min(max(float(body.get('wait', 2.0)), 0.5), 5.0)
        except (TypeError, ValueError):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'interval_ms and wait must be numbers')
        started = time.monotonic()
        replied, method = icmp_probe(wanted, interval, wait)
        elapsed = time.monotonic() - started
        seen = {n['ip']: n for n in parse_neigh(self._neigh_rows())}
        results = {}
        for a in wanted:
            n = seen.get(a)
            results[a] = {'replied': a in replied, 'rtt_ms': replied.get(a),
                          'state': n['state'] if n else None, 'mac': n['mac'] if n else None,
                          'confirmed': n['confirmed'] if n else None}
        return {'method': method, 'elapsed': round(elapsed, 2), 'results': results}

    def _chrony_active(self):
        code, out = self.run('systemctl', 'show', self.cfg['chrony_unit'], '-p', 'ActiveState',
                             '-p', 'ExecMainStartTimestampMonotonic', timeout=10)
        props = dict(line.split('=', 1) for line in out.splitlines() if '=' in line) if code == 0 else {}
        return props.get('ActiveState') == 'active', props.get('ExecMainStartTimestampMonotonic')

    def time_status(self):
        """Who keeps the time (chrony, systemd-timesyncd or nothing), whether LiteBlox writes chrony's config,
        and chrony's own view: its reference and offset, and each source."""
        chrony = os.path.exists(self.tools.get('chronyd') or '')
        active = self._chrony_active()[0] if chrony else False
        out = {'daemon': 'chrony' if active else None, 'installed': chrony, 'managed': False,
               'files': {'chrony.conf': self._file_sha(self.cfg['chrony_conf'])}}
        if chrony:
            # which directives its config may use (chrony 4.5 has no leapseclist)
            code, text = self.run('chronyd', '-v', timeout=10)
            m = re.search(r'version (\d+\.\d+(?:\.\d+)?)', text) if code == 0 else None
            out['version'] = m.group(1) if m else None
        if not active:
            code, _ = self.run('systemctl', 'is-active', 'systemd-timesyncd', timeout=10)
            out['daemon'] = 'timesyncd' if code == 0 else None
            return out
        try:
            out['managed'] = read_text(self.cfg['chrony_conf']).startswith(CHRONY_HEADER)
        except (OSError, ConfError):
            pass
        # unprivileged chronyc reads over 127.0.0.1:323 (monitoring commands only)
        code, text = self.run('chronyc', '-n', '-c', 'tracking', timeout=10)
        out['tracking'] = chrony_tracking(text) if code == 0 else None
        code, text = self.run('chronyc', '-n', '-c', 'sources', timeout=10)
        out['sources'] = chrony_sources(text) if code == 0 else []
        return out

    def kea_paths(self):
        return {role: os.path.join(self.cfg['kea_dir'], role) for role in list(KEA_ROLES) + list(KEA_TLS)}

    def kea_status(self):
        """Kea's installed version, each service's status-get (or why not), and the config files' hashes."""
        if not os.path.exists(self.tools.get('kea_dhcp4') or ''):
            return {'installed': False}
        code, version = self.run('kea_dhcp4', '-v', timeout=10)
        services = {}
        for service, path in self.cfg['kea_access'].items():
            try:
                answer = kea_command(path, 'status-get', timeout=5)
                args = answer.get('arguments') or {}
                services[service] = {'running': answer.get('result') == 0,
                                     **{k: v for k, v in args.items() if k != 'high-availability'}}
                ha = (args.get('high-availability') or [{}])[0].get('ha-servers')
                if ha:
                    local, remote = ha.get('local') or {}, ha.get('remote') or {}
                    services[service]['ha'] = {
                        'local': {'name': local.get('server-name'), 'role': local.get('role'), 'state': local.get('state')},
                        'remote': {'name': remote.get('server-name'), 'role': remote.get('role'),
                                   'state': remote.get('last-state'), 'in_touch': remote.get('in-touch')}}
            except AgentError as e:
                services[service] = {'running': False, 'error': e.message}
        out = {'installed': True, 'version': version.strip() if code == 0 else None, 'services': services,
               'hooks_dir': self.cfg['kea_hooks_dir'], 'liteblox': False, 'subnets': 0,
               'files': {role: self._file_sha(path) for role, path in self.kea_paths().items()}}
        # whether a LiteBlox wrote this config, and serves anything with it (a lost LiteBlox's node is re-adopted)
        try:
            d4 = json.loads(read_text(self.kea_paths()['kea-dhcp4.conf'])).get('Dhcp4') or {}
            out['liteblox'] = (d4.get('user-context') or {}).get('generated-by') == 'LiteBlox'
            out['subnets'] = len(d4.get('subnet4') or [])
        except (OSError, ConfError, ValueError, AttributeError):
            pass
        return out

    def config(self, query):
        # secrets=1 is for LiteBlox's own import at takeover; it never shows that output
        zones, printed = self.zones(secrets=query.get('secrets', ['0'])[0] == '1')
        files = conf_files(self.cfg['named_conf'])
        texts = {p: read_text(p) for p in files}
        for z in zones:
            pattern = re.compile(r'^\s*zone\s+"?' + re.escape(z['name']) + r'\.?"?\s', re.M)
            z['declared_in'] = next((p for p, t in texts.items() if pattern.search(t)), None)
            # a secondary's serial is the copy it last transferred (the Zones list compares the two)
            z['loaded_serial'] = (self.loaded_serial(z['name'])
                                  if z['type'] in ('primary', 'secondary') and not z['builtin'] else None)
        # which file declares each top-level key and acl (a key from rndc.key stays the node's own)
        declared = {}
        for path, text in texts.items():
            for kind, name in re.findall(r'^\s*(key|acl)\s+"?([^"\s{]+)"?\s*\{', text, re.M):
                declared.setdefault(f'{kind} {name}', path)
        out = {
            'checkconf': printed,
            'declared': declared,
            'zones': zones,
            'conf_files': files,
        }
        if query.get('files', ['0'])[0] == '1':
            # the generated files as they are on disk, for LiteBlox's config drift diff; key secrets masked
            out['files'] = {role: re.sub(r'(\bsecret\s+)"[^"]*"', r'\1"????????"', read_text(path))
                            for role, path in role_paths(self.cfg).items()}
        return out

    def get_zone(self, query, zone):
        z = self.zone(zone)
        # a dynamic zone's latest changes may be only in its journal: sync=1 writes them into the file,
        # freeze=1 also holds updates until the next config commit or abort (a takeover moving the zone)
        for flag, command in (('freeze', 'freeze'), ('sync', 'sync')):
            if query.get(flag, ['0'])[0] == '1':
                with self.lock:
                    code, out = self.run('rndc', command, z['name'], timeout=60)
                    if code != 0:
                        raise AgentError(HTTPStatus.CONFLICT, f'rndc {command} {z["name"]} failed', output=out)
                    if command == 'freeze':
                        self.frozen[z['name']] = time.time()
                break
        data = self.read_bytes(z['file'])
        try:
            content = data.decode('utf-8')
        except UnicodeDecodeError:
            raise AgentError(HTTPStatus.CONFLICT, f'{z["file"]} is not UTF-8 text')
        return {'name': z['name'], 'file': z['file'], 'content': content, 'sha256': sha256(data),
                'loaded_serial': self.loaded_serial(z['name'])}

    def stage_zone(self, body, zone):
        z = self.zone(zone)
        if os.path.dirname(os.path.realpath(z['file'])) == os.path.realpath(self.cfg['dyn_dir']):
            raise AgentError(HTTPStatus.CONFLICT, f"{z['name']} is dynamic: named owns its file, so changes go "
                                                  'through DNS updates')
        content = body.get('content')
        if not isinstance(content, str):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'content (string) is required')
        data = content.encode('utf-8')
        with self.lock:
            self._expire_stages()
            current = self.read_bytes(z['file'])
            if sha256(current) != body.get('base_sha256'):
                raise AgentError(HTTPStatus.CONFLICT, 'zone file changed on the node (drift)',
                                 current_sha256=sha256(current))
            staged = z['file'] + STAGE_SUFFIX
            try:
                self._write_like(staged, data, like=z['file'])
            except PermissionError:
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot write next to {z["file"]}')
            code, out = self.run('named_checkzone', '-k', 'fail', z['name'], staged)
            if code != 0:
                os.unlink(staged)
                raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, 'named-checkzone rejected the zone',
                                 output=out)
            stage_id = secrets.token_urlsafe(16)
            self.stages[stage_id] = {'kind': 'zone', 'zone': z['name'], 'created': time.time(),
                                     'files': [(staged, z['file'])], 'base': sha256(current),
                                     'sha256': sha256(data)}
        log.info('staged zone %s (%s)', z['name'], stage_id)
        return {'stage_id': stage_id, 'output': out, 'sha256': sha256(data)}

    def commit_zone(self, body, zone):
        z = self.zone(zone)
        with self.lock:
            stage = self._take_stage(body.get('stage_id'), 'zone', z['name'])
            current = self.read_bytes(z['file'])
            if sha256(current) != stage['base']:
                self._discard(stage)
                raise AgentError(HTTPStatus.CONFLICT, 'zone file changed since it was staged',
                                 current_sha256=sha256(current))
            backup = self._backup_file(z['name'], z['file'])
            staged, live = stage['files'][0]
            os.replace(staged, live)
            code, out = self.run('rndc', 'reload', z['name'])
            if code != 0:
                if backup:
                    tmp = live + STAGE_SUFFIX
                    shutil.copy2(backup, tmp)
                    os.replace(tmp, live)
                    self.run('rndc', 'reload', z['name'])
                log.error('reload of %s failed, rolled back: %s', z['name'], out)
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'rndc reload failed; rolled back',
                                 output=out)
        log.info('committed zone %s', z['name'])
        return {'sha256': stage['sha256'], 'reload_output': out,
                'loaded_serial': self.loaded_serial(z['name'])}

    def thaw_zone(self, body, zone):
        name = normalize_zone(zone)
        with self.lock:
            if name not in self.frozen:
                raise AgentError(HTTPStatus.NOT_FOUND, f'{name} was not frozen by the agent')
            code, out = self._thaw(name)
        if code != 0:
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, f'rndc thaw {name} failed', output=out)
        return {'thawed': name}

    def abort_zone(self, body, zone):
        name = normalize_zone(zone)
        with self.lock:
            stage = self._take_stage(body.get('stage_id'), 'zone', name)
            self._discard(stage)
        return {'aborted': True}

    @staticmethod
    def _file_sha(path):
        try:
            with open(path, 'rb') as f:
                return sha256(f.read())
        except OSError:
            return None

    def dpkg_leftovers(self):
        """Files a bind9 upgrade left next to its config files (Debian treats them as conffiles)."""
        found = []
        for dirpath, dirnames, filenames in os.walk(os.path.dirname(self.cfg['named_conf'])):
            dirnames[:] = sorted(d for d in dirnames
                                 if os.path.join(dirpath, d) != os.path.realpath(self.cfg['pre_dir']))
            found += [os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith(DPKG_SUFFIXES)]
        return found

    def _set_group(self, path, mode):
        os.chmod(path, mode)
        try:
            os.chown(path, -1, grp.getgrnam(self.cfg['bind_group']).gr_gid)
        except (KeyError, PermissionError):
            pass        # tests run without a bind group; setgid dirs give the group anyway

    def _ensure_dir(self, path):
        """Create path (and parents) group-writable for bind, so named can write journals there."""
        missing = []
        while path and not os.path.isdir(path):
            missing.append(path)
            path = os.path.dirname(path)
        for d in reversed(missing):
            os.mkdir(d)
            self._group_dir(d)

    def _group_dir(self, path):
        # A dir created under setgid /etc/bind already has group bind, and any chmod would either
        # set setgid (refused by the unit's RestrictSUIDSGID) or clear it; named only reads there.
        # Elsewhere (/var/lib/bind) named writes journals and transferred copies, so the dir must be
        # group bind and group-writable, even when a setgid parent (bootstrap makes zone dirs g+s) gave
        # it setgid with the agent's umask (2750): this chmod clears setgid, which the unit allows.
        conf_dir = os.path.dirname(self.cfg['named_conf'])
        under_conf = (path + '/').startswith(conf_dir.rstrip('/') + '/')
        if not (under_conf and os.stat(path).st_mode & stat.S_ISGID):
            self._set_group(path, 0o775)

    def _var_dirs_writable(self):
        """Repair the agent's own dirs under /var/lib/bind that an older agent left 2750 (see _group_dir)."""
        dyn = self.cfg['dyn_dir']
        for d in (os.path.dirname(dyn), dyn, self.cfg['sec_dir'], self.cfg['jnl_dir']):
            try:
                st = os.stat(d)
            except OSError:
                continue
            if st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) & 0o070 != 0o070:
                try:
                    self._group_dir(d)
                except OSError as e:
                    log.warning('cannot make %s group-writable: %s', d, e)

    # ── generated config ──

    def _validate_set(self, files):
        """Check each generated file against its allow-list. Returns the zones the set declares."""
        if not isinstance(files, dict) or not files:
            raise AgentError(HTTPStatus.BAD_REQUEST, 'files (object of role: text) is required')
        for role, text in files.items():
            if role not in CONFIG_ROLES or not isinstance(text, str):
                raise AgentError(HTTPStatus.BAD_REQUEST, f'unknown config file {role!r}')
            try:
                CONFIG_VALIDATORS[role](text, self.cfg)
            except ConfError as e:
                raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, f'{role} rejected: {e}')
        live = role_paths(self.cfg)
        if 'named.conf' not in files:
            try:
                validate_named_conf(read_text(live['named.conf']), self.cfg)
            except ConfError:
                raise AgentError(HTTPStatus.CONFLICT, 'this node is not taken over yet: send the whole set, '
                                                      'named.conf included')
        zones_text = files['zones.conf'] if 'zones.conf' in files else read_text(live['zones.conf'])
        try:
            return validate_zones(zones_text, self.cfg)
        except ConfError as e:
            raise AgentError(HTTPStatus.CONFLICT, f'the live zones.conf is not valid: {e}')

    def _checkconf_set(self, candidates):
        """named-checkconf -px of the config as it would be with candidates {live path: file to use}.

        Only named.conf includes other files, so a scratch copy of it with those
        includes pointed at the candidates checks the whole set in place.
        """
        named_conf = self.cfg['named_conf']
        source = read_text(candidates.get(named_conf, named_conf))

        def repoint(m):
            return f'include "{candidates.get(m.group(1), m.group(1))}";'
        scratch = os.path.join(self.cfg['state_dir'], f'check-{secrets.token_hex(4)}')
        os.mkdir(scratch, 0o750)
        try:
            copy = os.path.join(scratch, 'named.conf')
            with open(copy, 'w') as f:
                f.write(re.sub(r'include\s+"([^"]+)"\s*;', repoint, source))
            return self.run('named_checkconf', '-px', copy)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def check_config(self, body):
        files = body.get('files')
        self._validate_set(files)
        live = role_paths(self.cfg)
        scratch = os.path.join(self.cfg['state_dir'], f'candidate-{secrets.token_hex(4)}')
        os.mkdir(scratch, 0o750)
        try:
            candidates = {}
            for role, text in files.items():
                path = os.path.join(scratch, role)
                with open(path, 'w') as f:
                    f.write(text)
                candidates[live[role]] = path
            code, out = self._checkconf_set(candidates)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if code != 0:
            raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, 'named-checkconf rejected the config', output=out)
        return {'ok': True, 'checkconf': out.replace(scratch + '/', '')}

    def stage_config(self, body):
        files = body.get('files')
        zone_files = body.get('zone_files') or {}
        retire = body.get('retire') or []
        if not isinstance(zone_files, dict) or not isinstance(retire, list):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'zone_files must be an object and retire a list')
        zones = self._validate_set(files)
        live = role_paths(self.cfg)
        bind_dir = os.path.dirname(self.cfg['named_conf'])
        current_files = conf_files(self.cfg['named_conf'])
        new_text = '\n'.join(files.values())
        for path in retire:
            if (not isinstance(path, str) or path not in current_files or path in live.values()
                    or os.path.dirname(path) != bind_dir or path in new_text):
                raise AgentError(HTTPStatus.BAD_REQUEST, f'cannot retire {path!r}: only config files named.conf '
                                                         'includes now, in its own directory, and unused by the new set')
        declared = {z['name']: z for z in zones}
        declared_now = {z['name']: os.path.realpath(z['file']) for z in self.zones()[0] if z['file']}
        # a zone leaving dynamic (switched off, or a demoted primary now a secondary) leaves named's file
        # and journal in dyn_dir: they go with the commit (its rollback set keeps them)
        dyn_dir = os.path.realpath(self.cfg['dyn_dir'])
        leaving = [p for name, z in declared.items() if name in declared_now
                   and os.path.dirname(declared_now[name]) == dyn_dir
                   and os.path.realpath(z['file'] or '/') != declared_now[name]
                   for p in (declared_now[name], declared_now[name] + '.jnl')]
        for name, z in declared.items():
            if z['type'] == 'primary' and name not in zone_files and not os.path.exists(z['file']):
                raise AgentError(HTTPStatus.BAD_REQUEST, f'zone {name}: {z["file"]} does not exist and no '
                                                         'content was sent for it')
        with self.lock:
            self._expire_stages()
            staged, remove = [], [p for p in leaving if os.path.exists(p)]
            outputs = {}
            try:
                self._var_dirs_writable()
                for z in declared.values():
                    for path in (z['file'], z['journal']):
                        if path:
                            self._ensure_dir(os.path.dirname(path))
                for name, content in zone_files.items():
                    name = normalize_zone(name)
                    z = declared.get(name)
                    if z is None or z['type'] != 'primary':
                        raise AgentError(HTTPStatus.BAD_REQUEST, f'zone file for {name} is not a primary zone '
                                                                 'in zones.conf')
                    if declared_now.get(name) == os.path.realpath(z['file']):
                        # the file named loads now only changes through /zones (with its drift check)
                        raise AgentError(HTTPStatus.CONFLICT,
                                         f'{name} is already declared; change its file through /zones/{name}')
                    # moving to a path named isn't using (a dynamic switch, a relocation): a journal left there
                    # from an earlier spell would be replayed onto the new file, so it goes (kept for rollback)
                    remove += [j for j in (z['file'] + '.jnl', z['journal']) if j and os.path.exists(j)]
                    path = z['file'] + STAGE_SUFFIX
                    self._write_like(path, content.encode('utf-8'))
                    self._set_group(path, 0o664 if z['dynamic'] else 0o640)
                    staged.append((path, z['file']))
                    code, out = self.run('named_checkzone', '-k', 'fail', name, path)
                    outputs[name] = out
                    if code != 0:
                        raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, f'named-checkzone rejected {name}',
                                         output=out)
                self._ensure_dir(self.cfg['managed_dir'])
                for role, text in files.items():
                    path = live[role] + STAGE_SUFFIX
                    self._write_like(path, text.encode('utf-8'))
                    self._set_group(path, 0o640 if role == 'keys.conf' else 0o644)
                    staged.append((path, live[role]))
                code, out = self._checkconf_set({lv: st for st, lv in staged})
                if code != 0:
                    raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, 'named-checkconf rejected the config',
                                     output=out)
            except OSError as e:
                self._discard({'files': staged})
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot write the new config: {e}')
            except BaseException:
                self._discard({'files': staged})
                raise
            stage_id = secrets.token_urlsafe(16)
            self.stages[stage_id] = {
                'kind': 'config', 'created': time.time(), 'files': staged, 'retire': retire, 'remove': remove,
                'takeover': bool(body.get('takeover')),
                'base': {lv: self._file_sha(lv) for _, lv in staged},
            }
        log.info('staged config (%s)', stage_id)
        return {'stage_id': stage_id, 'zones': sorted(declared), 'output': outputs, 'checkconf': out}

    def _rollback_dir(self, service='_config'):
        return os.path.join(self.cfg['state_dir'], 'backups', service)

    def _save_rollback(self, stage):
        """Copy every live file the stage touches, so the change can be undone later."""
        root = self._rollback_dir(stage.get('rollback', '_config'))
        os.makedirs(root, exist_ok=True)
        # sortable even for two commits within one second: rollback takes the newest
        folder = os.path.join(root, f'{time.time_ns():020d}')
        os.mkdir(folder)
        entries = []
        for i, live in enumerate([lv for _, lv in stage['files']] + stage.get('remove', [])):
            entry = {'path': live, 'existed': os.path.exists(live), 'copy': None}
            if entry['existed']:
                entry['copy'] = os.path.join(folder, f'{i}-{os.path.basename(live)}')
                shutil.copy2(live, entry['copy'])
                # the copy (and so the restored file) would get the agent's own group: Kea, for one,
                # can't read a config file that isn't group _kea
                entry['gid'] = os.stat(live).st_gid
            entries.append(entry)
        manifest = {'created': _now_stamp(), 'takeover': stage.get('takeover', False), 'entries': entries,
                    'retired': [], 'preserved': None, 'rolled_back': False}
        self._write_manifest(folder, manifest)
        for old in sorted(os.listdir(root))[:-self.cfg['backup_keep']]:
            shutil.rmtree(os.path.join(root, old), ignore_errors=True)
        return folder, manifest

    @staticmethod
    def _write_manifest(folder, manifest):
        with open(os.path.join(folder, 'manifest.json'), 'w') as f:
            json.dump(manifest, f, indent=2)

    def _preserve(self, stage, folder, manifest):
        """Takeover: keep the node's own config in pre_dir/<stamp>/ (copies of replaced files, retired ones moved)."""
        bind_dir = os.path.dirname(self.cfg['named_conf'])
        self._ensure_dir(self.cfg['pre_dir'])
        dest = os.path.join(self.cfg['pre_dir'], _now_stamp())
        if os.path.exists(dest):
            dest += '-' + secrets.token_hex(2)
        os.mkdir(dest)
        self._group_dir(dest)
        manifest['preserved'] = dest
        for entry in manifest['entries']:
            if entry['existed'] and os.path.dirname(entry['path']) == bind_dir:
                shutil.copy2(entry['path'], os.path.join(dest, os.path.basename(entry['path'])))
        for path in stage['retire']:
            moved = os.path.join(dest, os.path.basename(path))
            os.replace(path, moved)
            manifest['retired'].append({'path': path, 'moved_to': moved})
        self._write_manifest(folder, manifest)

    def _restore(self, manifest):
        for entry in manifest['entries']:
            if entry['existed']:
                tmp = entry['path'] + STAGE_SUFFIX
                shutil.copy2(entry['copy'], tmp)
                if entry.get('gid') is not None:
                    try:
                        os.chown(tmp, -1, entry['gid'])
                    except PermissionError:
                        pass
                os.replace(tmp, entry['path'])
            elif os.path.exists(entry['path']):
                os.unlink(entry['path'])
        for r in manifest['retired']:
            if os.path.exists(r['moved_to']):
                os.replace(r['moved_to'], r['path'])
        if manifest.get('preserved'):
            shutil.rmtree(manifest['preserved'], ignore_errors=True)

    def _undo(self, folder, manifest):
        """Put back a commit that failed; its rollback set goes too, since nothing is left to undo."""
        self._restore(manifest)
        shutil.rmtree(folder, ignore_errors=True)

    def commit_config(self, body):
        with self.lock:
            try:
                return self._commit_config(body)
            finally:
                # zones frozen for this change (a takeover moving them) load their file and take updates
                # again, whether the change went in or was rolled back
                self._thaw_all()

    def _commit_config(self, body):
        stage = self._take_stage(body.get('stage_id'), 'config')
        changed = [lv for lv, sha in stage['base'].items() if self._file_sha(lv) != sha]
        if changed:
            self._discard(stage)
            raise AgentError(HTTPStatus.CONFLICT, 'config changed on the node since it was staged',
                             changed=changed)
        folder, manifest = self._save_rollback(stage)
        try:
            if stage['takeover']:
                self._preserve(stage, folder, manifest)
            for staged, live in stage['files']:
                os.replace(staged, live)
            for path in stage.get('remove', []):
                if os.path.exists(path):
                    os.unlink(path)
        except OSError as e:
            self._undo(folder, manifest)
            self._discard(stage)
            raise AgentError(HTTPStatus.FORBIDDEN, f'cannot replace the config: {e}; nothing changed')
        code, out = self.run('named_checkconf', self.cfg['named_conf'])
        if code != 0:
            self._undo(folder, manifest)
            raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY,
                             'named-checkconf rejected the config; rolled back', output=out)
        code, out = self.run('rndc', 'reconfig')
        if code != 0:
            self._undo(folder, manifest)
            self.run('rndc', 'reconfig')
            raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'rndc reconfig failed; rolled back',
                             output=out)
        # a zone that just became a secondary (a demoted primary, a new primary's address) serves
        # its old local copy until its refresh timer, up to an hour: have every secondary check now
        try:
            zones = validate_zones(read_text(role_paths(self.cfg)['zones.conf']), self.cfg)
        except ConfError:
            zones = []
        for z in zones:
            if z['type'] == 'secondary':
                self.run('rndc', 'refresh', z['name'], timeout=10)
        log.info('committed config%s', ' (takeover)' if stage['takeover'] else '')
        return {'committed': True, 'reconfig_output': out, 'preserved': manifest.get('preserved'),
                'config_files': {r: self._file_sha(p) for r, p in role_paths(self.cfg).items()}}

    def abort_config(self, body):
        with self.lock:
            self._discard(self._take_stage(body.get('stage_id'), 'config'))
            self._thaw_all()
        return {'aborted': True}

    def _newest_change(self, service):
        """(name, folder, manifest) of the newest committed change not rolled back yet, or 404."""
        root = self._rollback_dir(service)
        for name in sorted(os.listdir(root) if os.path.isdir(root) else (), reverse=True):
            folder = os.path.join(root, name)
            try:
                with open(os.path.join(folder, 'manifest.json')) as f:
                    manifest = json.load(f)
            except (OSError, ValueError):
                continue
            if not manifest.get('rolled_back'):
                return name, folder, manifest
        raise AgentError(HTTPStatus.NOT_FOUND, 'no config change to roll back')

    def rollback_config(self, body):
        """Undo the newest committed config change that hasn't been rolled back yet."""
        with self.lock:
            name, folder, manifest = self._newest_change('_config')
            self._restore(manifest)
            manifest['rolled_back'] = True
            self._write_manifest(folder, manifest)
            code, check = self.run('named_checkconf', self.cfg['named_conf'])
            if code != 0:
                raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, 'restored the previous config, but '
                                 'named-checkconf rejects it; named still runs the newer one', output=check)
            code, out = self.run('rndc', 'reconfig')
            if code != 0:
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'restored the previous config, but '
                                 'rndc reconfig failed', output=out)
        log.info('rolled back config change %s', name)
        return {'rolled_back': name, 'takeover': manifest['takeover'], 'reconfig_output': out}

    # ── Kea config (DHCP) ──

    def _kea_ready(self):
        if not os.path.isdir(self.cfg['kea_dir']) or not os.path.exists(self.tools.get('kea_dhcp4') or ''):
            raise AgentError(HTTPStatus.CONFLICT, 'Kea is not set up on this node')

    def _kea_files(self, files):
        if not isinstance(files, dict) or not files:
            raise AgentError(HTTPStatus.BAD_REQUEST, 'files (object of role: text) is required')
        for role, text in files.items():
            if (role not in KEA_ROLES and role not in KEA_TLS) or not isinstance(text, str):
                raise AgentError(HTTPStatus.BAD_REQUEST, f'unknown Kea config file {role!r}')
            try:
                if role in KEA_TLS:
                    validate_tls(role, text)
                else:
                    validate_kea(role, text, self.cfg)
            except ConfError as e:
                raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, str(e))

    def _kea_test_set(self, written):
        """kea -t on each JSON candidate in `written` {role: path}, with its TLS paths pointed at the
        TLS candidates (on a first pairing the live ones don't exist yet). Returns {role: output}."""
        live = self.kea_paths()
        outputs = {}
        for role, path in written.items():
            if role in KEA_TLS:
                continue
            text = read_text(path)
            for tls_role in KEA_TLS:
                if tls_role in written:
                    text = text.replace(json.dumps(live[tls_role]), json.dumps(written[tls_role]))
            probe = path
            if text != read_text(path):
                probe = os.path.join(self.cfg['kea_dir'], f'{role}.liteblox-check-{secrets.token_hex(4)}')
                self._kea_write(probe, text)
            try:
                outputs[role] = self._kea_test(role, probe)
            finally:
                if probe != path and os.path.exists(probe):
                    os.unlink(probe)
        return outputs

    def _kea_test(self, role, path):
        """kea-dhcp4 -t / kea-dhcp-ddns -t on a candidate (Kea only opens files inside kea_dir)."""
        code, out = self.run(KEA_TOOLS[KEA_ROLES[role][1]], '-t', path)
        if code != 0:
            raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, f'Kea rejected {role}', output=out)
        return out

    def _kea_write(self, path, text):
        self._write_like(path, text.encode('utf-8'))
        os.chmod(path, 0o640)       # D2's file holds TSIG secrets
        try:
            os.chown(path, -1, grp.getgrnam(self.cfg['kea_group']).gr_gid)
        except (KeyError, PermissionError):
            pass                    # tests run without a _kea group

    def check_dhcp(self, body):
        files = body.get('files')
        self._kea_ready()
        self._kea_files(files)
        written = {}
        try:
            for role, text in files.items():
                written[role] = os.path.join(self.cfg['kea_dir'], f'{role}.liteblox-check-{secrets.token_hex(4)}')
                self._ensure_kea_dir(written[role])
                self._kea_write(written[role], text)
            outputs = self._kea_test_set(written)
        finally:
            for path in written.values():
                if os.path.exists(path):
                    os.unlink(path)
        return {'ok': True, 'output': outputs}

    def _ensure_kea_dir(self, path):
        # kea_dir/tls, made by the agent under setgid kea_dir: group _kea, 2750 with the agent's umask
        folder = os.path.dirname(path)
        if not os.path.isdir(folder):
            os.mkdir(folder, 0o750)

    def stage_dhcp(self, body):
        files = body.get('files')
        self._kea_ready()
        self._kea_files(files)
        live = self.kea_paths()
        with self.lock:
            self._expire_stages()
            staged, outputs = [], {}
            try:
                for role, text in files.items():
                    path = live[role] + STAGE_SUFFIX
                    self._ensure_kea_dir(path)
                    self._kea_write(path, text)
                    staged.append((path, live[role]))
                outputs = self._kea_test_set({os.path.relpath(lv, self.cfg['kea_dir']): st for st, lv in staged})
            except OSError as e:
                self._discard({'files': staged})
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot write the new Kea config: {e}')
            except BaseException:
                self._discard({'files': staged})
                raise
            stage_id = secrets.token_urlsafe(16)
            self.stages[stage_id] = {'kind': 'dhcp', 'created': time.time(), 'files': staged, 'rollback': '_dhcp',
                                     'base': {lv: self._file_sha(lv) for _, lv in staged}}
        log.info('staged Kea config (%s)', stage_id)
        return {'stage_id': stage_id, 'output': outputs}

    def _kea_reload(self, roles):
        """config-reload each service whose file is in `roles`; [(service, error)] for those that failed."""
        failed = []
        for service in dict.fromkeys(KEA_ROLES[r][1] if r in KEA_ROLES else 'dhcp4' for r in roles):
            try:
                answer = kea_command(self.cfg['kea_access'][service], 'config-reload', timeout=30)
                if answer.get('result') != 0:
                    failed.append((service, answer.get('text') or 'config-reload failed'))
            except AgentError as e:
                failed.append((service, e.message))
        return failed

    def _kea_learn_interfaces(self):
        """Kea learns the system's interfaces when it starts, and config-reload checks a subnet's interface against
        that list before it looks again (which it does when it opens its sockets), so an interface made or renamed
        after Kea started (a VLAN, say) fails the reload until Kea restarts. Instead: set the new config once with
        the subnets' interface names left out, which opens the sockets and so re-detects the interfaces, then
        reload the real file. [(service, error)] like _kea_reload."""
        path = self.kea_paths()['kea-dhcp4.conf']
        try:
            with open(path) as f:
                config = json.load(f)
            dhcp4 = config['Dhcp4']
            for subnet in dhcp4.get('subnet4') or []:
                subnet.pop('interface', None)
            for network in dhcp4.get('shared-networks') or []:
                network.pop('interface', None)
                for subnet in network.get('subnet4') or []:
                    subnet.pop('interface', None)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            return [('dhcp4', f'cannot read {path} to retry: {e}')]
        try:
            answer = kea_command(self.cfg['kea_access']['dhcp4'], 'config-set', config, timeout=30)
        except AgentError as e:
            return [('dhcp4', e.message)]
        if answer.get('result') != 0:
            return [('dhcp4', answer.get('text') or 'config-set failed')]
        log.info('Kea did not know an interface yet: loaded the config without subnet interfaces so it looked again')
        return self._kea_reload(['kea-dhcp4.conf'])

    def commit_dhcp(self, body):
        with self.lock:
            stage = self._take_stage(body.get('stage_id'), 'dhcp')
            changed = [lv for lv, sha in stage['base'].items() if self._file_sha(lv) != sha]
            if changed:
                self._discard(stage)
                raise AgentError(HTTPStatus.CONFLICT, 'Kea config changed on the node since it was staged',
                                 changed=changed)
            folder, manifest = self._save_rollback(stage)
            try:
                for staged, live in stage['files']:
                    os.replace(staged, live)
            except OSError as e:
                self._undo(folder, manifest)
                self._discard(stage)
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot replace the Kea config: {e}; nothing changed')
            roles = [os.path.relpath(lv, self.cfg['kea_dir']) for _, lv in stage['files']]
            failed = self._kea_reload(roles)
            if any(service == 'dhcp4' and KEA_NEW_INTERFACE in message for service, message in failed):
                failed = [f for f in failed if f[0] != 'dhcp4'] + self._kea_learn_interfaces()
            if failed:
                self._undo(folder, manifest)
                self._kea_reload(roles)          # back to the previous files
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'Kea did not take the new config; rolled back',
                                 output='; '.join(f'{s}: {m}' for s, m in failed))
        log.info('committed Kea config')
        return {'committed': True, 'files': {r: self._file_sha(p) for r, p in self.kea_paths().items()}}

    def abort_dhcp(self, body):
        with self.lock:
            self._discard(self._take_stage(body.get('stage_id'), 'dhcp'))
        return {'aborted': True}

    def rollback_dhcp(self, body):
        """Undo the newest committed Kea config change that hasn't been rolled back yet."""
        with self.lock:
            name, folder, manifest = self._newest_change('_dhcp')
            self._restore(manifest)
            manifest['rolled_back'] = True
            self._write_manifest(folder, manifest)
            failed = self._kea_reload([os.path.relpath(e['path'], self.cfg['kea_dir']) for e in manifest['entries']])
            if failed:
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, 'restored the previous Kea config, but the '
                                 'reload failed', output='; '.join(f'{s}: {m}' for s, m in failed))
        log.info('rolled back Kea config change %s', name)
        return {'rolled_back': name}

    # ── chrony ──

    def _chrony_ready(self):
        if not os.path.exists(self.tools.get('chronyd') or '') or not os.path.isdir(self.cfg['chrony_dir']):
            raise AgentError(HTTPStatus.CONFLICT, 'chrony is not set up on this node')

    def _chrony_text(self, body):
        files = body.get('files')
        if not isinstance(files, dict) or set(files) != {'chrony.conf'} or not isinstance(files['chrony.conf'], str):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'files must be {"chrony.conf": text}')
        try:
            validate_chrony(files['chrony.conf'])
        except ConfError as e:
            raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, str(e))
        return files['chrony.conf']

    def _chrony_test(self, path):
        """chronyd -p: parse the candidate and print it, or fail (it must be inside chrony_dir: AppArmor)."""
        code, out = self.run('chronyd', '-p', '-f', path, timeout=20)
        if code != 0:
            raise AgentError(HTTPStatus.UNPROCESSABLE_ENTITY, 'chronyd rejected chrony.conf', output=out)
        return out

    def check_ntp(self, body):
        self._chrony_ready()
        text = self._chrony_text(body)
        probe = os.path.join(self.cfg['chrony_dir'], f'chrony.conf.liteblox-check-{secrets.token_hex(4)}')
        try:
            self._write_like(probe, text.encode(), like=self.cfg['chrony_conf'])
            return {'ok': True, 'output': self._chrony_test(probe)}
        finally:
            if os.path.exists(probe):
                os.unlink(probe)

    def stage_ntp(self, body):
        self._chrony_ready()
        text = self._chrony_text(body)
        live = self.cfg['chrony_conf']
        staged = live + STAGE_SUFFIX
        with self.lock:
            self._expire_stages()
            try:
                self._write_like(staged, text.encode(), like=live)
                output = self._chrony_test(staged)
            except OSError as e:
                self._discard({'files': [(staged, live)]})
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot write the new chrony config: {e}')
            except BaseException:
                self._discard({'files': [(staged, live)]})
                raise
            stage_id = secrets.token_urlsafe(16)
            self.stages[stage_id] = {'kind': 'ntp', 'created': time.time(), 'files': [(staged, live)],
                                     'rollback': '_ntp', 'base': {live: self._file_sha(live)}}
        log.info('staged chrony config (%s)', stage_id)
        return {'stage_id': stage_id, 'output': output}

    def _chrony_restarted(self, before):
        """Wait for the path unit to restart chrony after chrony.conf was replaced: (active, error)."""
        deadline = time.time() + self.cfg['chrony_restart_wait']
        while time.time() < deadline:
            active, started = self._chrony_active()
            if active and started != before:
                return True, None
            time.sleep(0.5)
        active, started = self._chrony_active()
        if not active:
            return False, 'chrony is not running after the change'
        return False, 'chrony was not restarted (is liteblox-chrony.path enabled?)'

    def commit_ntp(self, body):
        with self.lock:
            stage = self._take_stage(body.get('stage_id'), 'ntp')
            changed = [lv for lv, sha in stage['base'].items() if self._file_sha(lv) != sha]
            if changed:
                self._discard(stage)
                raise AgentError(HTTPStatus.CONFLICT, 'chrony.conf changed on the node since it was staged',
                                 changed=changed)
            folder, manifest = self._save_rollback(stage)
            before = self._chrony_active()[1]
            try:
                for staged, live in stage['files']:
                    os.replace(staged, live)
            except OSError as e:
                self._undo(folder, manifest)
                self._discard(stage)
                raise AgentError(HTTPStatus.FORBIDDEN, f'cannot replace chrony.conf: {e}; nothing changed')
            ok, error = self._chrony_restarted(before)
            if not ok:
                before = self._chrony_active()[1]
                self._undo(folder, manifest)
                self._chrony_restarted(before)          # back on the previous file
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, f'{error}; the previous chrony.conf is back')
        log.info('committed chrony config')
        return {'committed': True, 'files': {'chrony.conf': self._file_sha(self.cfg['chrony_conf'])}}

    def abort_ntp(self, body):
        with self.lock:
            self._discard(self._take_stage(body.get('stage_id'), 'ntp'))
        return {'aborted': True}

    def rollback_ntp(self, body):
        """Undo the newest committed chrony config change that hasn't been rolled back yet."""
        with self.lock:
            name, folder, manifest = self._newest_change('_ntp')
            before = self._chrony_active()[1]
            self._restore(manifest)
            manifest['rolled_back'] = True
            self._write_manifest(folder, manifest)
            ok, error = self._chrony_restarted(before)
            if not ok:
                raise AgentError(HTTPStatus.INTERNAL_SERVER_ERROR, f'restored the previous chrony.conf, but {error}')
        log.info('rolled back chrony config change %s', name)
        return {'rolled_back': name}

    def ntp_files(self, query):
        try:
            text = read_text(self.cfg['chrony_conf'])
        except (OSError, ConfError):
            text = None
        return {'files': {'chrony.conf': text}}

    def dhcp_files(self, query):
        """Kea's config files as they are on disk (for LiteBlox's drift diff), TSIG secrets masked; secrets=1 leaves
        D2's in (LiteBlox's re-adopt reads a key for another DNS server back from it, and never shows that output)."""
        unmasked = query.get('secrets', ['0'])[0] == '1'
        out = {}
        for role, path in self.kea_paths().items():
            try:
                text = read_text(path)
            except (OSError, ConfError):
                text = None
            if role == 'tls/ha.key' and text:
                text = '(private key, not shown)'
            elif text is not None and not (unmasked and role == 'kea-dhcp-ddns.conf'):
                text = re.sub(r'("secret"\s*:\s*)"[^"]*"', r'\1"????????"', text)
            out[role] = text
        return {'files': out}

    def dhcp_command(self, body):
        service, command = body.get('service'), body.get('command')
        if command not in KEA_COMMANDS.get(service, ()):
            raise AgentError(HTTPStatus.FORBIDDEN, f'{command!r} is not a command LiteBlox sends to {service!r}')
        arguments = body.get('arguments')
        if arguments is not None and not isinstance(arguments, dict):
            raise AgentError(HTTPStatus.BAD_REQUEST, 'arguments must be an object')
        self._kea_ready()
        return kea_command(self.cfg['kea_access'][service], command, arguments)

    def backup(self, query):
        """tar.gz of the BIND config and every zone file, plus a manifest."""
        include_keys = query.get('keys', ['1'])[0] != '0'
        exclude_journals = query.get('journals', ['0'])[0] != '1'
        zones, printed = [], ''
        if self.cfg['bind']:
            try:
                zones, printed = self.zones()
            except AgentError as e:
                printed = e.extra.get('output', '')

        paths, dirs = [], []
        for root in self.cfg['backup_paths']:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames.sort()
                dirs.append(dirpath)
                paths += [os.path.join(dirpath, f) for f in sorted(filenames)]
        paths += [z['file'] for z in zones if z['file']]

        manifest = {'node': socket.getfqdn(), 'created': _now_stamp(),
                    'agent_version': self.cfg['version'], 'agent_sha256': self.source_sha,
                    'named_version': self.run('named', '-V', timeout=10)[1] if self.cfg['bind'] else None,
                    'keys_included': include_keys, 'files': {}, 'skipped': {}}
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for d in dirs:      # directory entries keep owner/mode (e.g. /etc/bind root:bind 2775)
                info = tar_info(d, os.stat(d))
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            for path in dict.fromkeys(paths):
                base = os.path.basename(path)
                if path.endswith(STAGE_SUFFIX) or (exclude_journals and base.endswith('.jnl')):
                    continue
                # keys.conf: the TSIG keys LiteBlox writes (taken-over nodes)
                if not include_keys and (base.endswith('.key') or base in ('rndc.conf', 'bind.keys', 'keys.conf',
                                                                           'kea-dhcp-ddns.conf')):  # incl. tls/ha.key
                    manifest['skipped'][path] = 'key excluded'
                    continue
                try:
                    data = open(path, 'rb').read()
                    st = os.stat(path)
                except OSError as e:
                    manifest['skipped'][path] = e.strerror or str(e)
                    continue
                tar.addfile(tar_info(path, st, len(data)), io.BytesIO(data))
                manifest['files'][path] = {'sha256': sha256(data), 'size': len(data),
                                           'mode': oct(st.st_mode & 0o7777)}
            meta = [(f'{BACKUP_META}/manifest.json', json.dumps(manifest, indent=2).encode())]
            if self.cfg['bind']:
                meta.insert(0, (f'{BACKUP_META}/named-checkconf.txt', printed.encode()))
            for name, data in meta:
                info = tarfile.TarInfo(name)
                info.size, info.mtime = len(data), int(time.time())
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue(), 'application/gzip', {'X-Manifest-SHA256': sha256(
            json.dumps(manifest['files'], sort_keys=True).encode())}


# ── HTTP ───────────────────────────────────────────────────────────────────────

ROUTES = [
    ('GET', re.compile(r'/status'), 'status'),
    ('GET', re.compile(r'/stats'), 'stats'),
    ('GET', re.compile(r'/neigh'), 'neigh'),
    ('POST', re.compile(r'/probe'), 'probe'),
    ('GET', re.compile(r'/config'), 'config'),
    ('GET', re.compile(r'/backup'), 'backup'),
    ('GET', re.compile(r'/zones/(?P<zone>[^/]+)'), 'get_zone'),
    ('POST', re.compile(r'/zones/(?P<zone>[^/]+)/stage'), 'stage_zone'),
    ('POST', re.compile(r'/zones/(?P<zone>[^/]+)/commit'), 'commit_zone'),
    ('POST', re.compile(r'/zones/(?P<zone>[^/]+)/abort'), 'abort_zone'),
    ('POST', re.compile(r'/zones/(?P<zone>[^/]+)/thaw'), 'thaw_zone'),
    ('POST', re.compile(r'/config/check'), 'check_config'),
    ('POST', re.compile(r'/config/stage'), 'stage_config'),
    ('POST', re.compile(r'/config/commit'), 'commit_config'),
    ('POST', re.compile(r'/config/abort'), 'abort_config'),
    ('POST', re.compile(r'/config/rollback'), 'rollback_config'),
    ('GET', re.compile(r'/dhcp/files'), 'dhcp_files'),
    ('POST', re.compile(r'/dhcp/check'), 'check_dhcp'),
    ('POST', re.compile(r'/dhcp/stage'), 'stage_dhcp'),
    ('POST', re.compile(r'/dhcp/commit'), 'commit_dhcp'),
    ('POST', re.compile(r'/dhcp/abort'), 'abort_dhcp'),
    ('POST', re.compile(r'/dhcp/rollback'), 'rollback_dhcp'),
    ('POST', re.compile(r'/dhcp/command'), 'dhcp_command'),
    ('GET', re.compile(r'/ntp/files'), 'ntp_files'),
    ('POST', re.compile(r'/ntp/check'), 'check_ntp'),
    ('POST', re.compile(r'/ntp/stage'), 'stage_ntp'),
    ('POST', re.compile(r'/ntp/commit'), 'commit_ntp'),
    ('POST', re.compile(r'/ntp/abort'), 'abort_ntp'),
    ('POST', re.compile(r'/ntp/rollback'), 'rollback_ntp'),
    ('POST', re.compile(r'/agent/upgrade'), 'upgrade_agent'),
]
# what a node without BIND (config "bind": false) doesn't answer
BIND_HANDLERS = frozenset(('config', 'get_zone', 'stage_zone', 'commit_zone', 'abort_zone', 'thaw_zone',
                           'check_config', 'stage_config', 'commit_config', 'abort_config', 'rollback_config'))


class Handler(BaseHTTPRequestHandler):
    server_version = 'liteblox-agent'
    protocol_version = 'HTTP/1.1'

    def setup(self):
        self.request.settimeout(30)
        self.request.do_handshake()
        super().setup()

    def log_message(self, fmt, *args):
        log.info('%s %s', self.client_address[0], fmt % args)

    def _authorized(self):
        allowed = self.server.agent.cfg['allowed_ips']
        if allowed and self.client_address[0] not in allowed:
            return False
        cert = self.request.getpeercert() or {}
        cns = [v for rdn in cert.get('subject', ()) for k, v in rdn if k == 'commonName']
        return self.server.agent.cfg['client_cn'] in cns

    def _send(self, status, payload, content_type='application/json', headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        if self.close_connection:
            self.send_header('Connection', 'close')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, status, message):
        # the request body (if any) is left unread, so this connection can't carry another request
        self.close_connection = True
        return self._send(status, {'error': message})

    def _dispatch(self, method):
        if not self._authorized():
            return self._refuse(HTTPStatus.FORBIDDEN, 'client not authorized')
        url = urlsplit(self.path)
        for route_method, pattern, handler in ROUTES:
            m = pattern.fullmatch(url.path)
            if m and route_method == method:
                break
        else:
            return self._refuse(HTTPStatus.NOT_FOUND, f'no route for {method} {url.path}')
        agent = self.server.agent
        if handler in BIND_HANDLERS and not agent.cfg['bind']:
            return self._refuse(HTTPStatus.NOT_FOUND, 'this node runs no BIND for LiteBlox ("bind": false)')

        try:
            if method == 'POST':
                length = int(self.headers.get('Content-Length') or 0)
                if length > MAX_BODY:
                    return self._refuse(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, 'request body too large')
                try:
                    arg = json.loads(self.rfile.read(length) or b'{}')
                except ValueError:
                    raise AgentError(HTTPStatus.BAD_REQUEST, 'body must be JSON')
            else:
                arg = parse_qs(url.query)
            kwargs = m.groupdict()
            if handler == 'status':
                kwargs['client'] = self.client_address[0]
            result = getattr(agent, handler)(arg, **kwargs)
            if isinstance(result, tuple):
                data, ctype, headers = result
                return self._send(HTTPStatus.OK, data, ctype, headers)
            return self._send(HTTPStatus.OK, result)
        except AgentError as e:
            return self._send(e.status, {'error': e.message, **e.extra})
        except Exception:
            log.exception('%s %s failed', method, url.path)
            return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {'error': 'internal agent error'})

    def do_GET(self):
        self._dispatch('GET')

    def do_POST(self):
        self._dispatch('POST')


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, agent, context):
        self.agent = agent
        self.context = context
        family = socket.AF_INET6 if ':' in agent.cfg['listen'] else socket.AF_INET
        self.address_family = family
        super().__init__((agent.cfg['listen'], agent.cfg['port']), Handler)

    def get_request(self):
        # handshake happens in the handler thread so a slow client can't block accept()
        sock, addr = self.socket.accept()
        return self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        log.warning('connection from %s failed: %s', client_address[0], sys.exc_info()[1])


def tls_context(cfg):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg['cert'], cfg['key'])
    ctx.load_verify_locations(cfg['ca'])
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    with open(path) as f:
        user = json.load(f)
    tools = dict(cfg['tools'], **user.pop('tools', {}))
    cfg.update(user)
    cfg['tools'] = tools
    return cfg


def make_server(cfg):
    return AgentServer(Agent(cfg), tls_context(cfg))


def main(argv=None):
    parser = argparse.ArgumentParser(description='LiteBlox node agent')
    parser.add_argument('--config', default='/etc/liteblox-agent/config.json')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    cfg = load_config(args.config)
    server = make_server(cfg)
    log.info('listening on %s:%s (agent %s)', cfg['listen'], cfg['port'], cfg['version'])
    server.agent.mark_started()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
