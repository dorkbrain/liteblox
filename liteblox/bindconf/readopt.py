"""Re-adopt nodes after LiteBlox's own data is lost: rebuild the database from their generated config.

A node LiteBlox took over holds everything it was given: keys with their secrets, ACLs, server
settings, zone declarations with their grants, and with Kea the subnets, reservations and the
failover pair. rebuild() reads that back (the renderers, inverted); nothing is recorded unless
rendering from the rebuilt model gives every node's files back byte for byte, which is proved in
a scratch database first. Nothing on the nodes changes, except the DHCP failover pair's TLS
certificates: the lost CA issued them, and their private keys can't be read back.

A node an older LiteBlox wrote lacks what this one renders since (ADDITIONS): it matches once those
are taken out of the rendered text, and the hashes recorded are the node's own, so the health check
finds it behind and writes the current config.
"""

import difflib
import hashlib
import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional

from .. import db
from ..nodes import agent_module
from ..nodes import service as nodes
from ..nodes.client import AgentError
from .importconf import ImportPlan, _options, inline
from .model import DEBIAN, ROLES, UPDATE_KEY, XFR_KEY, Acl, NodeConfig, TsigKey, for_node, node_address
from .render import HEADER, STATS_CHANNEL, file_hashes, own_top, render

KEA_ROLES = ('kea-dhcp4.conf', 'kea-dhcp-ddns.conf')
EXTRA_MARK = '\n\n\t// extra statements\n'
OWN_GRANT = f'grant {UPDATE_KEY} zonesub ANY'


class ReadoptError(RuntimeError):
    pass


@dataclass
class Read:
    """What one node's agent gave back."""
    node: dict
    status: dict
    files: dict                     # BIND role: text, key secrets masked
    secrets: dict                   # key name: secret (named-checkconf -p)
    kea: Optional[dict] = None      # Kea role: text (secrets masked), when the config is LiteBlox's
    ntp: Optional[str] = None       # chrony.conf, when LiteBlox wrote it
    kea_keys: dict = field(default_factory=dict)    # D2's tsig-keys: name: {name, algorithm, secret}


@dataclass
class Plan:
    reads: list
    nodes: dict = field(default_factory=dict)       # node id: {nodes column: value}
    acls: list = field(default_factory=list)
    keys: list = field(default_factory=list)        # (TsigKey, purpose)
    zones: list = field(default_factory=list)       # zone columns + _grants [(key, scope, name, types)], _serving {id: file}
    dhcp: Optional[dict] = None                     # {settings, subnets, pair}
    ntp: Optional[list] = None                      # the time sources (ntp.model.Source), when nodes run chrony
    blockers: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def name(self, node_id):
        return next(r.node['name'] for r in self.reads if r.node['id'] == node_id)


@dataclass
class Preview:
    plan: Plan
    diffs: Optional[dict] = None    # node name: diff text ('' = identical); None when blocked before comparing
    older: dict = field(default_factory=dict)   # node name: [roles an older LiteBlox wrote]

    @property
    def blockers(self):
        return self.plan.blockers

    @property
    def ready(self):
        return not self.plan.blockers and self.diffs is not None and not any(self.diffs.values())


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def candidates(conn):
    """Nodes whose BIND config another LiteBlox generated (they report it taken over, but aren't managed here)."""
    return conn.execute('SELECT * FROM nodes WHERE other_liteblox = 1 AND managed = 0 ORDER BY name').fetchall()


def not_fresh(conn):
    """Why this LiteBlox can't take a re-adopt (it only rebuilds into an empty one)."""
    out = []
    for table, what in (('zones', 'zones'), ('acls', 'ACLs'), ('tsig_keys', 'TSIG keys'),
                        ('dhcp4_subnets', 'DHCP subnets')):
        if conn.execute(f'SELECT 1 FROM {table}').fetchone():
            out.append(f'LiteBlox has {what} already')
    if conn.execute("SELECT 1 FROM ntp_settings WHERE sources != '[]'").fetchone():
        out.append('LiteBlox has time sources already')
    managed = [r['name'] for r in conn.execute('SELECT name FROM nodes WHERE managed = 1 ORDER BY name')]
    if managed:
        out.append(f"LiteBlox manages {', '.join(managed)} already")
    return out


# ── reading the nodes ──────────────────────────────────────────────────────────

def _secrets(printed):
    agent = agent_module()
    return {st.words[1][1]: st.value('secret') for st in agent.parse_conf(printed or '')
            if st.keyword == 'key' and len(st.words) > 1 and st.block is not None}


def _liteblox_kea(text):
    try:
        return (json.loads(text or '').get('Dhcp4', {}).get('user-context') or {}).get('generated-by') == 'LiteBlox'
    except (ValueError, AttributeError):
        return False


def _d2_keys(text):
    """{name: {name, algorithm, secret}} from kea-dhcp-ddns.conf (read with its secrets)."""
    try:
        keys = json.loads(text or '{}').get('DhcpDdns', {}).get('tsig-keys') or []
    except (ValueError, AttributeError):
        return {}
    return {k['name']: {'name': k['name'], 'algorithm': k.get('algorithm'), 'secret': k.get('secret')}
            for k in keys if isinstance(k, dict) and k.get('name')}


def collect(settings, rows):
    """([Read], blockers) from each node's agent; read-only. A node without BIND brings only its Kea and chrony."""
    reads, blockers = [], []
    for node in rows:
        node = dict(node)
        bind = node.get('bind', 1)
        try:
            with nodes.agent_client(settings, node, timeout=60.0) as c:
                status = c.status()
                if bind and not status.get('taken_over'):
                    blockers.append(f"{node['name']}: LiteBlox didn't generate its BIND config (Take over is for that)")
                    continue
                files = c.config(files=True).get('files') or {} if bind else {}
                secrets = _secrets(c.config(secrets=True).get('checkconf')) if bind else {}
                kea, kea_keys = None, {}
                if (status.get('kea') or {}).get('installed'):
                    # with D2's secrets: a key for another DNS server is only there (masked again for the diffs)
                    got = c.dhcp_files(secrets=True)
                    if _liteblox_kea(got.get('kea-dhcp4.conf')):
                        kea = {role: _mask_kea(got.get(role) or '') for role in KEA_ROLES}
                        kea_keys = _d2_keys(got.get('kea-dhcp-ddns.conf'))
                ntp = c.ntp_files().get('chrony.conf') if (status.get('time') or {}).get('managed') else None
        except AgentError as e:
            blockers.append(f"{node['name']} is unreachable: {e.message}")
            continue
        if not bind and kea is None and ntp is None:
            blockers.append(f"{node['name']}: nothing on it was written by a LiteBlox (a scanner has nothing to "
                            're-adopt: it works as it is)')
            continue
        reads.append(Read(node, status, files, secrets, kea, ntp, kea_keys))
    return reads, blockers


# ── the generated BIND files, read back ────────────────────────────────────────

def _body(read, role, plan):
    header = HEADER.format(pre_dir=DEBIAN.pre_dir)
    text = read.files.get(role)
    if text is None or not text.startswith(header):
        plan.blockers.append(f"{read.node['name']}: {DEBIAN.path(role)} isn't the file LiteBlox generated")
        return None
    return text[len(header):]


def _items(st):
    return [inline(c, quote=False) for c in (st.block or [])] if st is not None else []


def _zone(st):
    agent = agent_module()
    policy = st.child('update-policy')
    return {'name': agent.normalize_zone(st.words[1][1]), 'type': st.value('type'), 'file': st.value('file'),
            'notify': st.value('notify'), 'primaries': _items(st.child('primaries')),
            'also_notify': _items(st.child('also-notify')), 'allow_transfer': _items(st.child('allow-transfer')),
            'allow_query': _items(st.child('allow-query')), 'journal': st.child('journal') is not None,
            'forward': st.value('forward'), 'forwarders': _items(st.child('forwarders')),
            'update_policy': _items(policy) if policy is not None else None}


def parse_node(read, plan):
    """{options, top_extra, distro_includes, acls, keys: {name: algorithm}, zones: {name: zone}} or None."""
    agent = agent_module()
    bodies = {role: _body(read, role, plan) for role in ROLES}
    if any(b is None for b in bodies.values()):
        return None
    try:
        own = {DEBIAN.path(r) for r in ROLES if r != 'named.conf'}
        includes = [st.words[1][1] for st in agent.parse_conf(bodies['named.conf']) if st.keyword == 'include']
        opts = bodies['options.conf']
        extra = None
        if EXTRA_MARK in opts:
            opts, tail = opts.split(EXTRA_MARK, 1)
            tail = tail[:-len('\n};\n')] if tail.endswith('\n};\n') else tail
            extra = '\n'.join(line[1:] if line.startswith('\t') else line for line in tail.split('\n'))
            opts += '\n};\n'
        stub = ImportPlan(NodeConfig())
        options = next((_options(st, DEBIAN, stub) for st in agent.parse_conf(opts) if st.keyword == 'options'), None)
        if options is None or stub.blockers:
            plan.blockers += [f"{read.node['name']}: options.conf: {b}" for b in stub.blockers or ['no options block']]
            return None
        if extra is not None:
            options.extra = extra
        return {
            'options': options,
            'top_extra': own_top(bodies['top.conf']),
            'distro_includes': [p for p in includes if p not in own],
            'acls': [Acl(st.words[1][1], _items(st)) for st in agent.parse_conf(bodies['acls.conf'])
                     if st.keyword == 'acl'],
            'keys': {st.words[1][1]: st.value('algorithm') for st in agent.parse_conf(bodies['keys.conf'])
                     if st.keyword == 'key'},
            'zones': {z['name']: z for z in (_zone(st) for st in agent.parse_conf(bodies['zones.conf'])
                                             if st.keyword == 'zone')},
        }
    except agent.ConfError as e:
        plan.blockers.append(f"{read.node['name']}: its generated config doesn't parse: {e}")
        return None


def _addresses(read):
    """Every IP the node answers on: its address (when it's an IP) and its interfaces'."""
    out = set()
    for a in [read.node['host']] + [a.split('/')[0] for i in read.status.get('interfaces') or []
                                    for a in i.get('addresses') or []]:
        try:
            out.add(str(ipaddress.ip_address(a)))
        except ValueError:
            pass
    return out


def _strip(items, added):
    """items without the keys LiteBlox put in front of them (render._with_key)."""
    items, added = list(items), set(added)
    while items and items[0] in added:
        added.discard(items.pop(0))
    return items


def _also_notify(rendered, secondaries):
    """The stored also-notify list: render appends the secondaries the list doesn't name yet."""
    for k in range(len(rendered) + 1):
        stored = rendered[:k]
        if stored + [a for a in secondaries if a not in stored] == rendered:
            return stored
    return rendered


def _grant(line):
    words = line.split()
    if words[2] == 'zonesub':
        return (words[1], 'zonesub', '', ' '.join(words[3:]))
    return (words[1], words[2], words[3].rstrip('.'), ' '.join(words[4:]))


def _roles(plan, parsed, by_id):
    """{node id: role}, the primary's id (or None), and {node id: DNS address} where it isn't the host."""
    secondaries = [i for i, p in parsed.items() if any(z['type'] == 'secondary' for z in p['zones'].values())]
    targets = {z['primaries'][0].split()[0] for p in parsed.values() for z in p['zones'].values()
               if z['type'] == 'secondary' and z['primaries']}
    if not targets:
        # no secondaries: DHCP's DNS updates (D2) still go to the primary
        mine = set().union(*(_addresses(by_id[i]) for i in parsed))
        for r in plan.reads:
            if r.kea:       # (D2 sending to another DNS server says nothing about the primary)
                targets |= {a for a in _d2_servers(r)[:1] if a in mine}
    addrs = {i: _addresses(by_id[i]) for i in parsed}
    dns_address = {}
    if len(targets) > 1:
        plan.blockers.append(f"the secondaries name more than one primary ({', '.join(sorted(targets))})")
        return {}, None, {}
    if targets:
        target = next(iter(targets))
        owners = [i for i, a in addrs.items() if target in a]
        if len(owners) != 1:
            plan.blockers.append(f'the primary, at {target}, is not one of the nodes being re-adopted: add it as a '
                                 'node and repair it first' if not owners else
                                 f'more than one node answers on {target}, the primary\'s address')
            return {}, None, {}
        primary = owners[0]
        roles = {i: 'primary' if i == primary else 'secondary' for i in parsed}
        if target != by_id[primary].node['host']:
            dns_address[primary] = target
        notified = {a for z in parsed[primary]['zones'].values() for a in z['also_notify']}
        for i in roles:
            if i != primary:
                mine = sorted(notified & addrs[i])
                if len(mine) == 1 and mine[0] != by_id[i].node['host']:
                    dns_address[i] = mine[0]
        holding = sorted(by_id[i].node['name'] for i, p in parsed.items() if i != primary
                         and any(z['type'] == 'primary' for z in p['zones'].values()))
        if holding:
            plan.blockers.append(f"{', '.join(holding)} still hold their own primary copies while "
                                 f"{by_id[primary].node['name']} is the primary (a demotion they missed, or not its "
                                 'secondaries yet): re-adopt without them')
        return roles, primary, dns_address
    if secondaries:
        plan.blockers.append('the secondaries name no primary')
        return {}, None, {}
    if len(parsed) == 1:
        only = next(iter(parsed))
        return {only: 'primary'}, only, {}
    return {i: None for i in parsed}, None, {}


def rebuild(conn, reads):
    """The Plan: everything LiteBlox knew, read back from the nodes' generated files."""
    plan = Plan(reads)
    by_id = {r.node['id']: r for r in reads}
    parsed = {}
    for r in reads:
        if not r.node.get('bind', 1):
            continue
        p = parse_node(r, plan)
        if p is not None:
            parsed[r.node['id']] = p
    if plan.blockers or not reads:
        if not reads and not plan.blockers:
            plan.blockers.append('no node to re-adopt')
        return plan
    # nodes without BIND bring only DHCP and time
    for r in reads:
        if r.node['id'] not in parsed:
            plan.nodes[r.node['id']] = {'other_liteblox': 0}
    if not parsed:
        _rebuild_dhcp(plan, by_id, parsed, None)
        _rebuild_ntp(plan, by_id, parsed)
        return plan
    first = next(iter(parsed.values()))
    # every node gets every ACL and key, so they're the same everywhere
    for i, p in parsed.items():
        if [(a.name, a.items) for a in p['acls']] != [(a.name, a.items) for a in first['acls']]:
            plan.blockers.append(f"{by_id[i].node['name']}: its ACLs differ from the other nodes'")
        if p['keys'] != first['keys']:
            plan.blockers.append(f"{by_id[i].node['name']}: its keys differ from the other nodes'")
        missing = sorted(k for k in p['keys'] if not by_id[i].secrets.get(k))
        if missing:
            plan.blockers.append(f"{by_id[i].node['name']}: could not read the secret of {', '.join(missing)}")
        elif any(by_id[i].secrets[k] != by_id[next(iter(parsed))].secrets.get(k) for k in p['keys']):
            plan.blockers.append(f"{by_id[i].node['name']}: its key secrets differ from the other nodes'")
    if plan.blockers:
        return plan
    plan.acls = first['acls']
    secrets = by_id[next(iter(parsed))].secrets

    roles, primary, dns_address = _roles(plan, parsed, by_id)
    if plan.blockers:
        return plan
    for i, p in parsed.items():
        plan.nodes[i] = {'managed': 1, 'role': roles[i], 'dns_address': dns_address.get(i),
                         'options': p['options'].to_json(), 'top_extra': p['top_extra'],
                         'distro_includes': json.dumps(p['distro_includes']), 'taken_over_at': _now(),
                         'other_liteblox': 0}
    planned = {i: dict(by_id[i].node, **plan.nodes[i]) for i in parsed}

    granted = set()
    for name in sorted({z for p in parsed.values() for z in p['zones']}):
        decls = {i: p['zones'][name] for i, p in parsed.items() if name in p['zones']}
        zone = _rebuild_zone(plan, name, decls, primary, planned, parsed)
        if zone:
            plan.zones.append(zone)
            granted |= {g[0] for g in zone['_grants']}
    if primary is not None and any(z['type'] == 'primary' and z['journal'] for z in parsed[primary]['zones'].values()) \
            and not any(r == 'secondary' for r in roles.values()):
        plan.blockers.append(f"{plan.name(primary)} had secondaries that aren't being re-adopted with it: add them as "
                             'nodes and repair them first')
    _rebuild_dhcp(plan, by_id, parsed, primary)
    _rebuild_ntp(plan, by_id, parsed)
    dhcp_settings = (plan.dhcp or {}).get('settings') or {}
    ddns_key = dhcp_settings.get('ddns_key') if dhcp_settings.get('ddns_mode') != 'external' else None
    plan.keys = [(TsigKey(k, alg, secrets[k]), k if k in (XFR_KEY, UPDATE_KEY)
                  else 'user' if k in granted or k == ddns_key else 'imported')
                 for k, alg in sorted(first['keys'].items())]
    return plan


def _rebuild_zone(plan, name, decls, primary, planned, parsed):
    kinds = {z['type'] for z in decls.values()}
    if kinds == {'forward'}:
        src = next(iter(decls.values()))
        if any((z['forwarders'], z['forward']) != (src['forwarders'], src['forward']) for z in decls.values()):
            plan.blockers.append(f'zone {name}: the nodes forward it differently')
            return None
        return {'name': name, 'kind': 'forwarding', 'forwarders': '\n'.join(src['forwarders']),
                'forward_mode': src['forward'] or '', 'dynamic': 0, '_grants': [], '_serving': {i: '' for i in decls}}
    if 'forward' in kinds or not kinds <= {'primary', 'secondary'}:
        plan.blockers.append(f"zone {name}: declared as {', '.join(sorted(k or '?' for k in kinds))} on different nodes")
        return None
    holders = [i for i, z in decls.items() if z['type'] == 'primary']
    if not holders:
        plan.blockers.append(f'zone {name}: only secondary copies, its primary is not being re-adopted')
        return None
    src = decls[primary] if primary in decls else decls[holders[0]]
    secondaries = sorted(i for i, z in decls.items() if z['type'] == 'secondary')
    sec_addrs = [node_address(planned[i]) for i in secondaries]
    dynamic = src['update_policy'] is not None
    added = ([f'key {XFR_KEY}'] if secondaries else []) + ([f'key {UPDATE_KEY}'] if dynamic else [])
    if secondaries:
        sec = decls[secondaries[0]]
        allow_transfer, allow_query = _strip(sec['allow_transfer'], [f'key {XFR_KEY}']), sec['allow_query']
    else:
        allow_transfer = _strip(src['allow_transfer'], added)
        allow_query = src['allow_query']
        if added and allow_query:
            allow_query = _strip(allow_query, added)
            holder = planned[primary if primary in decls else holders[0]]
            if allow_query == (json.loads(holder['options']).get('allow_query') or []):
                allow_query = []        # the node's own, which LiteBlox repeats with its keys
    grants = []
    if dynamic:
        policy = list(src['update_policy'])
        if policy[:1] == [OWN_GRANT]:
            policy = policy[1:]
        try:
            grants = [_grant(line) for line in policy]
        except IndexError:
            plan.blockers.append(f'zone {name}: an update-policy rule LiteBlox does not write')
            return None
    notify = src['notify'] or ''
    serving = {i: (decls[i]['file'] or '') for i in decls}
    return {'name': name, 'kind': 'primary', 'dynamic': int(dynamic), 'notify': notify,
            'also_notify': '\n'.join(_also_notify(src['also_notify'], sec_addrs) if secondaries
                                     else src['also_notify']),
            'allow_transfer': '\n'.join(allow_transfer), 'allow_query': '\n'.join(allow_query),
            '_grants': grants, '_serving': serving, '_holders': holders}


# ── Kea, read back ─────────────────────────────────────────────────────────────

def _split_options(items, known_only=False):
    """option-data → ({form field: value}, [the rest as Kea takes them]) (render.option_data, inverted)."""
    from ..dhcp.render import OPTION_NAMES
    names = list(OPTION_NAMES.items())
    fields, extra, pos = {}, [], 0
    for item in items or []:
        match = next((j for j in range(pos, len(names)) if names[j][1] == item.get('name')), None)
        if not extra and match is not None and set(item) == {'name', 'data'}:
            key = names[match][0]
            data = item['data']
            fields[key] = data if key == 'domain' else data.split(', ')
            pos = match + 1
        else:
            extra.append(item)
    if known_only and extra:
        return None, extra
    return fields, extra


LIFETIME_KEYS = {'valid-lifetime': 'valid_lifetime', 'renew-timer': 'renew_timer', 'rebind-timer': 'rebind_timer'}
SUBNET_KEYS = {'id', 'subnet', 'interface', 'pools', 'option-data', 'user-context', 'reservations', *LIFETIME_KEYS}
DDNS_KEYS = {'ddns-send-updates', 'ddns-qualifying-suffix', 'ddns-update-on-renew', 'ddns-override-client-update'}


def _rebuild_ntp(plan, by_id, parsed):
    """chrony.conf read back: the sources (the same on every node), and what each node serves."""
    from ..ntp.model import Source
    from ..ntp.render import file_hashes
    found = None
    for i, r in by_id.items():
        if i not in plan.nodes or not r.ntp:
            continue
        source_list, allow, local = [], [], None
        for line in r.ntp.splitlines():
            words = line.split('#', 1)[0].split()
            if not words:
                continue
            if words[0] in ('server', 'pool') and len(words) > 1:
                opts = words[2:]
                value = lambda k: int(opts[opts.index(k) + 1]) if k in opts and opts.index(k) + 1 < len(opts) else None
                source_list.append(Source(words[0], words[1], 'iburst' in opts, 'prefer' in opts, 'nts' in opts,
                                          value('minpoll'), value('maxpoll')))
            elif words[0] == 'allow' and len(words) == 2:
                allow.append(words[1])
            elif words[:2] == ['local', 'stratum'] and len(words) > 2:
                local = int(words[2])
        if found is not None and found != source_list:
            plan.blockers.append(f"{r.node['name']}: its time sources differ from the other nodes'")
        found = source_list if found is None else found
        plan.nodes[i].update({'ntp': 1, 'ntp_serve': int(bool(allow)), 'ntp_allow': json.dumps(allow),
                              'ntp_local': local, 'ntp_files': json.dumps(file_hashes({'chrony.conf': r.ntp})),
                              'chrony_version': (r.status.get('time') or {}).get('version')})
    plan.ntp = found


def _d2_servers(read):
    try:
        d2 = json.loads(read.kea['kea-dhcp-ddns.conf'] or '{}').get('DhcpDdns', {})
    except ValueError:
        return []
    return [s.get('ip-address') for d in (d2.get('forward-ddns') or {}).get('ddns-domains', [])
            for s in d.get('dns-servers', [])]


def _rebuild_dhcp(plan, by_id, parsed, primary):
    from ..dhcp.model import Dhcp4Settings, Reservation, Subnet
    kea_reads = [r for r in plan.reads if r.kea and r.node['id'] in plan.nodes]
    if not kea_reads:
        return
    settings, per_node, served_by, pair = None, {}, {}, None
    zones = {z['name'] for z in plan.zones if z['kind'] == 'primary'}
    bind_addrs = set().union(*(_addresses(by_id[i]) for i in parsed)) if parsed else set()
    for r in kea_reads:
        i = r.node['id']
        try:
            d4 = json.loads(r.kea['kea-dhcp4.conf'])['Dhcp4']
            d2 = json.loads(r.kea['kea-dhcp-ddns.conf'] or '{}').get('DhcpDdns', {})
        except (ValueError, KeyError) as e:
            plan.blockers.append(f"{r.node['name']}: its Kea config doesn't parse ({e})")
            continue
        served_by[i] = d4.get('interfaces-config', {}).get('interfaces', [])
        plan.nodes[i].update({'dhcp': 1, 'kea_hooks_dir': (r.status.get('kea') or {}).get('hooks_dir'),
                              'kea_version': (r.status.get('kea') or {}).get('version'),
                              'dhcp_interfaces': json.dumps(d4.get('interfaces-config', {}).get('interfaces', [])),
                              'dhcp_files': json.dumps({k: v for k, v in ((r.status.get('kea') or {}).get('files')
                                                                          or {}).items() if v})})
        options, extra = _split_options(d4.get('option-data'))
        keys = [k['name'] for k in d2.get('tsig-keys') or []]
        mine = Dhcp4Settings(**{v: d4.get(k) for k, v in LIFETIME_KEYS.items()}, options=options, extra_options=extra,
                             authoritative=bool(d4.get('authoritative')))
        external = _external(r, d2, keys, bind_addrs)
        if external:
            mine.ddns_mode, mine.ddns_server, mine.ddns_port = 'external', external['server'], external['port']
            mine.ddns_external_key = external['key']
        if settings is None or (keys and not settings.ddns_key):
            settings = mine
            settings.ddns_key = (external['key'] if external else keys[0]) if keys else None
        forward = sorted({d['name'].rstrip('.') for d in (d2.get('forward-ddns') or {}).get('ddns-domains', [])})
        reverse = sorted({d['name'].rstrip('.') for d in (d2.get('reverse-ddns') or {}).get('ddns-domains', [])})
        for s in d4.get('subnet4', []):
            sub = _subnet(plan, r, s, forward, zones, Subnet, Reservation, reverse if external else None)
            if sub is not None:
                per_node.setdefault(i, {})[sub.id] = sub
        for hook in d4.get('hooks-libraries', []):
            ha = ((hook.get('parameters') or {}).get('high-availability') or [None])[0]
            if not ha:
                continue
            if ha.get('this-server-name') != r.node['name']:
                plan.blockers.append(f"{r.node['name']}: its Kea failover config calls it {ha.get('this-server-name')!r}: "
                                     'add the node under that name')
                continue
            peers = {p['role']: p for p in ha.get('peers', [])}
            found = _pair(plan, peers)
            if found and pair and found != pair:
                plan.blockers.append('the two failover nodes describe the pair differently')
            pair = pair or found
    subnets = _merge_subnets(plan, per_node, served_by, pair)
    plan.dhcp = {'settings': vars(settings) if settings else {}, 'subnets': sorted(subnets.values(), key=lambda s: s.id),
                 'pair': pair}
    if pair:
        missing = [n for n in (pair['primary_id'], pair['standby_id']) if n not in {r.node['id'] for r in kea_reads}]
        if missing:
            plan.blockers.append('the DHCP failover pair needs both its nodes re-adopted together')


def _merge_subnets(plan, per_node, served_by, pair):
    """One set of subnets from every node's. In a failover pair the standby may name its interfaces differently
    (4.8): its subnets are compared without the interface, and pair['interface_map'] ({primary's: standby's}) is
    rebuilt from the subnets both have, then from the names left over."""
    from dataclasses import replace
    subnets, mapping = {}, {}
    primary = pair['primary_id'] if pair else None
    standby = pair['standby_id'] if pair else None
    order = sorted(per_node, key=lambda n: (n == standby, n))     # the primary's (or any) first
    for node_id in order:
        for sub in per_node[node_id].values():
            have = subnets.get(sub.id)
            if node_id == standby and have is not None:
                if mapping.setdefault(have.interface, sub.interface) != sub.interface:
                    plan.blockers.append(f'the standby serves {have.interface} under two names')
                sub = replace(sub, interface=have.interface)
            if have is not None and have != sub:
                plan.blockers.append(f'DHCP subnet {sub.prefix} (id {sub.id}): the nodes have it differently')
            subnets.setdefault(sub.id, sub)
    if pair:
        left = [n for n in served_by.get(primary, []) if n not in mapping]
        theirs = [n for n in served_by.get(standby, []) if n not in mapping.values()]
        for name in list(left):
            if name in theirs:
                mapping[name] = name
                left.remove(name)
                theirs.remove(name)
        if len(left) == 1 and len(theirs) == 1:
            mapping[left[0]] = theirs[0]
        elif left:
            plan.blockers.append(f"can't tell which of the standby's interfaces serve the primary's {', '.join(left)}")
        pair['interface_map'] = {k: v for k, v in mapping.items() if k != v}
    return subnets


def _pair(plan, peers):
    names = {r.node['name']: r.node['id'] for r in plan.reads}
    out = {}
    for role in ('primary', 'standby'):
        p = peers.get(role) or {}
        m = re.fullmatch(r'https://([0-9.]+):(\d+)/', p.get('url') or '')
        if not m or p.get('name') not in names:
            plan.blockers.append(f"the DHCP failover pair's {role}, {p.get('name')!r}, is not one of the nodes being "
                                 're-adopted (add it under that name)')
            return None
        out.update({f'{role}_id': names[p['name']], f'{role}_address': m.group(1), 'port': int(m.group(2))})
    return out


def _external(read, d2, keys, bind_addrs):
    """{server, port, key} when D2 sends to a DNS server that isn't one of the re-adopted BIND nodes, else None."""
    servers = [x for d in (d2.get('forward-ddns') or {}).get('ddns-domains', []) for x in d.get('dns-servers', [])]
    if not servers or not keys or servers[0].get('ip-address') in bind_addrs:
        return None
    key = read.kea_keys.get(keys[0]) or {'name': keys[0], 'algorithm': None, 'secret': None}
    return {'server': servers[0].get('ip-address'), 'port': servers[0].get('port', 53), 'key': key}


def _external_reverse(prefix, reverse):
    """A subnet's reverse zones at another DNS server, as stored: '' when they're the ones derived from its prefix."""
    from ..dhcp.render import derived_reverse_zones, reverse_network
    net = ipaddress.ip_network(prefix, strict=False)
    found = [z for z in reverse if reverse_network(z) is not None and reverse_network(z).overlaps(net)]
    return '' if set(found) == set(derived_reverse_zones(prefix)) else ' '.join(found)


def _subnet(plan, r, s, forward, zones, Subnet, Reservation, external_reverse=None):
    """external_reverse: D2's reverse zones when it sends to another DNS server (no LiteBlox zone is needed then)."""
    options, extra_options = _split_options(s.get('option-data'))
    ddns = bool(s.get('ddns-send-updates'))
    zone, suffix, ddns_reverse = None, '', ''
    if ddns and external_reverse is not None:
        suffix = (s.get('ddns-qualifying-suffix') or '').rstrip('.').lower()
        ddns_reverse = _external_reverse(s['subnet'], external_reverse)
    elif ddns:
        wanted = (s.get('ddns-qualifying-suffix') or '').rstrip('.').lower()
        under = sorted((z for z in forward if wanted == z or wanted.endswith('.' + z)), key=len, reverse=True)
        if not under or under[0] not in zones:
            plan.blockers.append(f"DHCP subnet {s.get('subnet')}: it registers names in {wanted}, a zone that isn't "
                                 'being re-adopted')
            return None
        zone, suffix = under[0], '' if wanted == under[0] else wanted
    reservations = []
    for x in s.get('reservations') or []:
        opts, rest = _split_options(x.get('option-data'), known_only=True)
        if opts is None or set(x) - {'hw-address', 'ip-address', 'hostname', 'option-data'}:
            plan.blockers.append(f"DHCP reservation {x.get('ip-address') or x.get('hw-address')}: it has settings LiteBlox does not write")
            continue
        reservations.append(Reservation(None, s['id'], x['hw-address'], x.get('ip-address', ''), x.get('hostname', ''), opts))
    known = SUBNET_KEYS | (DDNS_KEYS if ddns else set())
    return Subnet(s['id'], s['subnet'], s.get('interface', ''), [p['pool'] for p in s.get('pools', [])], options,
                  extra_options, {k: v for k, v in s.items() if k not in known},
                  *(s.get(k) for k in LIFETIME_KEYS), ddns=ddns, ddns_zone=zone, ddns_suffix=suffix,
                  reservations=reservations, ddns_reverse=ddns_reverse,
                  ddns_mode='external' if external_reverse is not None else 'liteblox')


# ── recording, and the proof ───────────────────────────────────────────────────

def record(conn, plan, tls):
    """Write the plan into conn (the scratch DB or the real one). tls(conn, node_id, address) gives a
    failover node its peer certificate."""
    from ..dhcp import store
    with conn:
        for node_id, cols in plan.nodes.items():
            conn.execute(f"UPDATE nodes SET {', '.join(f'{c} = ?' for c in cols)} WHERE id = ?",
                         (*cols.values(), node_id))
        for a in plan.acls:
            conn.execute('INSERT INTO acls (name, items) VALUES (?, ?)', (a.name, json.dumps(a.items)))
        for k, purpose in plan.keys:
            conn.execute('INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES (?, ?, ?, ?)',
                         (k.name, k.algorithm, k.secret, purpose))
        from ..dns.repo import zone_file
        for z in plan.zones:
            cols = {k: v for k, v in z.items() if not k.startswith('_')}
            cols.update(mode='managed', repo_file='' if z['kind'] == 'forwarding' else zone_file(z['name']))
            zone_id = conn.execute(f"INSERT INTO zones ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                                   tuple(cols.values())).lastrowid
            for node_id, node_file in sorted(z['_serving'].items()):
                conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?)',
                             (zone_id, node_id, node_file, z.get('_deployed', {}).get(node_id)))
            for key, scope, name, types in z['_grants']:
                key_id = conn.execute('SELECT id FROM tsig_keys WHERE name = ?', (key,)).fetchone()
                if key_id is None:
                    raise ReadoptError(f"zone {z['name']}: its update-policy names key {key}, which the nodes don't have")
                conn.execute('INSERT INTO key_grants (key_id, zone_id, scope, name, types) VALUES (?, ?, ?, ?, ?)',
                             (key_id[0], zone_id, scope, name, types))
    if plan.ntp is not None:
        from ..ntp.model import to_json
        with conn:
            conn.execute('UPDATE ntp_settings SET sources = ? WHERE id = 1', (to_json(plan.ntp),))
    # what came back is switched on (a module chosen off at the first run would hide it)
    on = {'dns': bool(plan.zones or any(c.get('managed') for c in plan.nodes.values())),
          'dhcp': bool(plan.dhcp and (plan.dhcp['subnets'] or any(c.get('dhcp') for c in plan.nodes.values()))),
          'ntp': plan.ntp is not None}
    with conn:
        conn.execute('UPDATE modules SET dns = MAX(dns, ?), dhcp = MAX(dhcp, ?), ntp = MAX(ntp, ?) WHERE id = 1',
                     (int(on['dns']), int(on['dhcp']), int(on['ntp'])))
    if not plan.dhcp:
        return
    from ..dhcp.model import Dhcp4Settings
    s = dict(plan.dhcp['settings'])
    key = s.pop('ddns_key', None)
    if s.get('ddns_mode') == 'external':        # D2 sent to another DNS server: its key came from D2's file
        s['ddns_key_id'] = None
    else:
        s['ddns_key_id'] = (conn.execute('SELECT id FROM tsig_keys WHERE name = ?', (key,)).fetchone() or [None])[0] \
            if key else None
        s['ddns_mode'] = 'liteblox' if s['ddns_key_id'] else 'off'      # D2 sent to LiteBlox's primary
    store.save_settings(conn, Dhcp4Settings(**s))
    for sub in plan.dhcp['subnets']:
        if sub.ddns and sub.ddns_mode != 'external':
            sub.ddns_zone_id = conn.execute('SELECT id FROM zones WHERE name = ?', (sub.ddns_zone,)).fetchone()[0]
        store.save_subnet(conn, sub)
        for res in sub.reservations:
            store.save_reservation(conn, replace(res, id=None))     # save_reservation sets the id it got
    pair = plan.dhcp['pair']
    if pair:
        tls(conn, pair['primary_id'], pair['primary_address'])
        tls(conn, pair['standby_id'], pair['standby_address'])
        with conn:
            conn.execute('UPDATE dhcp4_ha SET primary_node_id = ?, standby_node_id = ?, primary_address = ?, '
                         'standby_address = ?, port = ?, interface_map = ? WHERE id = 1',
                         (pair['primary_id'], pair['standby_id'], pair['primary_address'], pair['standby_address'],
                          pair['port'], json.dumps(pair.get('interface_map') or {}, sort_keys=True)))


def scratch(conn):
    """An in-memory DB with this one's schema and nodes, to record a plan into and render from."""
    s = sqlite3.connect(':memory:', check_same_thread=False)
    s.row_factory = sqlite3.Row
    s.execute('PRAGMA foreign_keys = ON')
    for sql in db.MIGRATIONS:
        s.executescript(sql)
    cols = [r[1] for r in conn.execute('PRAGMA table_info(nodes)')]
    with s:
        for row in conn.execute('SELECT * FROM nodes'):
            s.execute(f"INSERT INTO nodes ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(row))
    return s


def _placeholder_tls(conn, node_id, address):
    # the scratch DB only renders kea-dhcp4.conf, whose TLS paths don't depend on the certificate
    with conn:
        conn.execute('UPDATE nodes SET kea_tls = ? WHERE id = ?',
                     (json.dumps({'address': address, 'cert': '', 'key': '', 'ca': ''}), node_id))


def _mask_kea(text):
    return re.sub(r'("secret"\s*:\s*)"[^"]*"', r'\1"????????"', text or '')


def _diff(name, role, have, want):
    return ''.join(difflib.unified_diff((have or '').splitlines(True), (want or '').splitlines(True),
                                        f'{name} {role} now', f'{name} {role} rebuilt by LiteBlox'))


def rendered(conn, node):
    """({BIND role: text}, {Kea role: text} or None, {chrony role: text} or None) as LiteBlox renders the node."""
    from ..dhcp.apply import files_for
    from ..ntp.apply import files_for as ntp_files_for
    bind = render(for_node(conn, node)) if node['bind'] else {}
    kea = {r: t for r, t in files_for(conn, node).items() if r in KEA_ROLES} if node['dhcp'] else None
    return bind, kea, ntp_files_for(conn, node) if node['ntp'] else None


def _without_socket_retries(text):
    try:
        conf = json.loads(text)
        ifaces = conf['Dhcp4']['interfaces-config']
        ifaces.pop('service-sockets-max-retries', None)
        ifaces.pop('service-sockets-retry-wait-time', None)
    except (ValueError, KeyError, TypeError, AttributeError):
        return text
    return json.dumps(conf, indent=2, sort_keys=True) + '\n'


def _without_override(text):
    try:
        conf = json.loads(text)
        for s in conf['Dhcp4'].get('subnet4') or []:
            if s.get('ddns-send-updates'):
                s.pop('ddns-override-client-update', None)
    except (ValueError, KeyError, TypeError, AttributeError):
        return text
    return json.dumps(conf, indent=2, sort_keys=True) + '\n'


# (role, since version, normalize): what a LiteBlox version started rendering, and how to take it out of
# the rendered text again. A node's file lacks an addition when normalizing it changes nothing.
ADDITIONS = [
    ('top.conf', '3.3.0', lambda text: text.replace(f'\n{STATS_CHANNEL}\n', '', 1)),
    ('kea-dhcp4.conf', '3.3.0', _without_socket_retries),
    ('kea-dhcp4.conf', '3.3.4', _without_override),
]


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _as_written(role, text, have_sha, node_text):
    """(text as the node has it, whether an older LiteBlox wrote it): the rendered text, or that text
    without the additions the node's file lacks when only those tell them apart."""
    if _sha(text) == have_sha or node_text is None:
        return text, False
    older = text
    for r, _since, normalize in ADDITIONS:
        if r == role and normalize(node_text) == node_text:
            older = normalize(older)
    if older != text and _sha(older) == have_sha:
        return older, True
    return text, False


def as_written(conn, read):
    """rendered(), each file as the node has it where it's only behind (ADDITIONS), and the roles that are."""
    node = nodes.get_node(conn, read.node['id'])
    bind, kea, ntp = rendered(conn, node)
    older = []
    for files, have, texts in ((bind, read.status.get('config_files') or {}, read.files),
                               (kea, (read.status.get('kea') or {}).get('files') or {}, read.kea or {})):
        for role, text in sorted((files or {}).items()):
            files[role], behind = _as_written(role, text, have.get(role), texts.get(role))
            if behind:
                older.append(role)
    return bind, kea, ntp, older


def verify(conn, reads, older=None):
    """{node name: diff ('' = every file the same, byte for byte)} for the model in conn; older, when
    given, gets {node name: [roles]} for the files an older LiteBlox wrote."""
    out = {}
    for r in reads:
        bind, kea, ntp, behind = as_written(conn, r)
        if older is not None and behind:
            older[r.node['name']] = behind
        lines = []
        have = r.status.get('config_files') or {}
        for role, sha in sorted(file_hashes(bind).items()):
            if sha != have.get(role):
                text = _diff(r.node['name'], role, r.files.get(role), nodes.mask_secrets(bind[role]))
                lines.append(text or f'{role}: a key secret differs\n')
        if kea is not None:
            have = (r.status.get('kea') or {}).get('files') or {}
            for role, text in sorted(kea.items()):
                if _sha(text) != have.get(role):
                    shown = _diff(r.node['name'], role, (r.kea or {}).get(role), _mask_kea(text))
                    lines.append(shown or f'{role}: a key secret differs\n')
        if ntp is not None:
            have = ((r.status.get('time') or {}).get('files')) or {}
            for role, text in ntp.items():
                if _sha(text) != have.get(role):
                    lines.append(_diff(r.node['name'], role, r.ntp, text))
        out[r.node['name']] = ''.join(lines)
    return out


def preview(conn, settings, node_ids):
    """Everything a re-adopt would do, worked out with read-only agent calls and a scratch DB."""
    rows = [nodes.get_node(conn, int(i)) for i in node_ids]
    reads, blockers = collect(settings, rows)
    plan = rebuild(conn, reads) if reads else Plan(reads)
    plan.blockers = not_fresh(conn) + blockers + plan.blockers
    if not reads and not plan.blockers:
        plan.blockers.append('no node to re-adopt')
    pv = Preview(plan)
    if plan.blockers:
        return pv
    s = scratch(conn)
    try:
        record(s, plan, _placeholder_tls)
        pv.diffs = verify(s, reads, pv.older)
    except (ReadoptError, sqlite3.DatabaseError) as e:
        plan.blockers.append(str(e))
    finally:
        s.close()
    return pv


# ── the re-adopt ───────────────────────────────────────────────────────────────

def _contents(settings, plan, s, transfer=None):
    """{zone: text}: a static zone's file from the node holding its primary copy, a dynamic zone by AXFR
    (with LiteBlox's own key, from the scratch DB)."""
    from ..dns import dynamic
    out = {}
    by_id = {r.node['id']: r.node for r in plan.reads}
    for z in plan.zones:
        if z['kind'] == 'forwarding':
            continue
        holder = by_id[next((i for i in z['_holders'] if plan.nodes[i]['role'] == 'primary'), z['_holders'][0])]
        if z['dynamic']:
            row = s.execute('SELECT * FROM zones WHERE name = ?', (z['name'],)).fetchone()
            node = s.execute('SELECT * FROM nodes WHERE id = ?', (holder['id'],)).fetchone()
            try:
                out[z['name']] = dynamic.axfr_from(s, row, node_address(node) or node['host'], transfer=transfer,
                                                   where=f"{holder['name']} ")
            except dynamic.DynamicError as e:
                raise ReadoptError(str(e))
            continue
        try:
            with nodes.agent_client(settings, holder, timeout=60.0) as c:
                out[z['name']] = c.get_zone(z['name'])['content']
        except AgentError as e:
            raise ReadoptError(f"zone {z['name']}: can't read it from {holder['name']}: {e.message}")
    return out


def _forget(conn, plan, repo, written):
    """Put the fresh LiteBlox back as it was (it had none of this before)."""
    with conn:
        for table in ('key_grants', 'zone_nodes', 'zones', 'acls', 'dhcp4_reservations', 'dhcp4_subnets'):
            conn.execute(f'DELETE FROM {table}')
        conn.execute('UPDATE dhcp4_settings SET valid_lifetime = NULL, renew_timer = NULL, rebind_timer = NULL, '
                     "options = '{}', extra_options = '[]', authoritative = 0, ddns_key_id = NULL, "
                     "ddns_mode = 'off', ddns_server = '', ddns_port = 53, ddns_external_key = NULL WHERE id = 1")
        conn.execute('DELETE FROM tsig_keys')
        conn.execute("UPDATE ntp_settings SET sources = '[]' WHERE id = 1")
        conn.execute('UPDATE dhcp4_ha SET primary_node_id = NULL, standby_node_id = NULL, primary_address = NULL, '
                     'standby_address = NULL, port = 8001 WHERE id = 1')
        for node_id in plan.nodes:
            conn.execute("UPDATE nodes SET managed = 0, role = NULL, dns_address = NULL, options = NULL, "
                         "top_extra = '', distro_includes = NULL, taken_over_at = NULL, config_sha256 = NULL, "
                         "config_files = NULL, dhcp = 0, dhcp_interfaces = '[]', dhcp_files = NULL, kea_tls = NULL, "
                         "ntp = 0, ntp_serve = 0, ntp_allow = '[]', ntp_local = NULL, ntp_files = NULL, "
                         'other_liteblox = 1 WHERE id = ?', (node_id,))
    for path in written:
        try:
            repo.delete(path, 'Re-adopt undone', 'liteblox')
        except Exception:       # best effort: the zone rows are gone, so nothing reads these
            pass


def readopt(conn, settings, node_ids, username, log, pki=None, transfer=None):
    """Rebuild LiteBlox's data from the nodes; changes nothing on them but the failover pair's certificates."""
    from ..dhcp import apply as dhcp_apply
    from ..dhcp import store
    from ..dns import dynamic
    from ..dns.repo import Repo, zone_file
    from ..nodes import roles
    from ..pki import PKI
    pki = pki or PKI(settings.pki_dir)
    with roles.role_change():
        rows = [nodes.get_node(conn, int(i)) for i in node_ids]
        log(f"Re-adopting {', '.join(n['name'] for n in rows)}")
        pv = preview(conn, settings, node_ids)
        plan = pv.plan
        if plan.blockers:
            raise ReadoptError('cannot re-adopt:\n' + '\n'.join(f'  - {b}' for b in plan.blockers))
        bad = {n: d for n, d in pv.diffs.items() if d}
        if bad:
            raise ReadoptError('the rebuilt config is not the nodes\' own, so nothing was recorded:\n'
                               + ''.join(bad.values()))
        log('  ✓ read every node\'s config; rendering it back from the rebuilt model gives each file byte for byte')
        for name, roles_behind in pv.older.items():
            log(f"  ✓ {name}: {', '.join(roles_behind)} written by an older LiteBlox: brought up to date after re-adopt")
        s = scratch(conn)
        try:
            record(s, plan, _placeholder_tls)
            contents = _contents(settings, plan, s, transfer)
        finally:
            s.close()
        log(f'  ✓ read {len(contents)} zone(s) from their primary copies')
        for z in plan.zones:
            if z['kind'] != 'forwarding' and not z['dynamic']:
                digest = hashlib.sha256(contents[z['name']].encode()).hexdigest()
                z['_deployed'] = {i: digest for i in z['_holders']}

        repo = Repo(settings.repo_dir).ensure()
        written = []
        try:
            record(conn, plan, lambda c, node_id, address: store.ensure_tls(c, pki, node_id, address))
            for z in plan.zones:
                if z['kind'] == 'forwarding':
                    continue
                text = contents[z['name']]
                if z['dynamic']:
                    message = f"Re-adopted from the nodes (serial {dynamic.serial(text, z['name'] + '.')})"
                else:
                    message = f"Re-adopted from {plan.name(z['_holders'][0])}"
                repo.write(zone_file(z['name']), text, message, username)
                written.append(zone_file(z['name']))
            again = verify(conn, plan.reads)
            if any(again.values()):
                raise ReadoptError('the recorded model renders differently:\n' + ''.join(again.values()))
            from .render import record_commit
            # the files as the node has them: for one an older LiteBlox wrote, stale() then sees it's behind
            for r in plan.reads:
                record_commit(conn, r.node['id'], as_written(conn, r)[0])
        except Exception:
            _forget(conn, plan, repo, written)
            raise
        names = ', '.join(plan.name(i) for i in plan.nodes)
        db.audit(conn, username, 'node_readopt', names)
        _summary(plan, log)
        log(f'✓ LiteBlox manages {names} again')
        pair = (plan.dhcp or {}).get('pair')
        if pair:
            log('DHCP failover pair: new peer certificates from this LiteBlox\'s CA')
            try:
                dhcp_apply.apply_dhcp(settings, conn, [pair['standby_id'], pair['primary_id']],
                                      'new failover certificates (re-adopt)', username,
                                      lambda line: log('  ' + line))
                log('✓ the pair runs on certificates from this LiteBlox')
            except (dhcp_apply.DhcpError, AgentError) as e:
                log(f'  ⚠ not done yet ({e}): the pair keeps its old certificates, and the health check tries again')


def summary(plan):
    """[(heading, [line, ...])] for the preview and the job log (no key secrets)."""
    from .takeover import option_fields
    out = []
    lines = []
    for i, cols in plan.nodes.items():
        extra = [f'DNS address {cols["dns_address"]}'] if cols.get('dns_address') else []
        if cols.get('dhcp'):
            extra.append(f"DHCP on {', '.join(json.loads(cols['dhcp_interfaces'])) or 'no interface'}")
        what = (cols['role'] or 'no primary picked') if 'role' in cols else 'no BIND'
        lines.append(f"{plan.name(i)}: {what}" + ''.join(f'; {e}' for e in extra))
    out.append(('Nodes', lines))
    for i, cols in plan.nodes.items():
        from .model import NodeOptions
        if 'options' not in cols:
            continue
        o = NodeOptions.from_json(cols['options'])
        rows = [f'{k}: {v}' for k, v in option_fields(o)] + (['extra statements kept as written'] if o.extra else []) \
            + (['top-level statements kept as written'] if cols['top_extra'] else [])
        if rows:
            out.append((f'{plan.name(i)} server settings', rows))
    if plan.keys:
        out.append(('Keys', [f'{k.name} ({k.algorithm})' + (', LiteBlox\'s own' if purpose in (XFR_KEY, UPDATE_KEY) else '')
                             for k, purpose in plan.keys]))
    if plan.acls:
        out.append(('ACLs', [f"{a.name}: {', '.join(a.items)}" for a in plan.acls]))
    zones = []
    for z in plan.zones:
        where = ', '.join(sorted(plan.name(i) for i in z['_serving']))
        if z['kind'] == 'forwarding':
            zones.append(f"{z['name']}: forwarding to {z['forwarders'].replace(chr(10), ', ')} ({where})")
        else:
            grants = '; '.join(f'{k} {s}' + (f' {n}' if n else '') + f' {t}' for k, s, n, t in z['_grants'])
            zones.append(f"{z['name']}: {'dynamic' if z['dynamic'] else 'static'} ({where})"
                         + (f'; grants: {grants}' if grants else ''))
    if zones:
        out.append(('Zones', zones))
    if plan.dhcp:
        d = []
        st = plan.dhcp['settings']
        key = st.get('ddns_key')
        if key and st.get('ddns_mode') == 'external':
            port = '' if st['ddns_port'] == 53 else f" port {st['ddns_port']}"
            d.append(f"registers clients at another DNS server, {st['ddns_server']}{port}, with key {key['name']}")
        elif key:
            d.append(f'registers clients in DNS with key {key}')
        for sub in plan.dhcp['subnets']:
            d.append(f'subnet {sub.prefix} (id {sub.id}) on {sub.interface}: {len(sub.pools)} pool(s), '
                     f'{len(sub.reservations)} reservation(s)' + (f', DNS names in {sub.qualifying_suffix}' if sub.ddns else ''))
        pair = plan.dhcp['pair']
        if pair:
            d.append(f"failover pair: {plan.name(pair['primary_id'])} serves, {plan.name(pair['standby_id'])} stands by "
                     f"(link {pair['primary_address']} ↔ {pair['standby_address']}, port {pair['port']}); "
                     'new peer certificates')
        out.append(('DHCP', d))
    if plan.ntp is not None:
        t = ['sources: ' + '; '.join(s.line() for s in plan.ntp)]
        for i, cols in plan.nodes.items():
            if cols.get('ntp'):
                allow = json.loads(cols['ntp_allow'])
                t.append(f"{plan.name(i)}: chrony" + (f", serves {', '.join(allow)}" if allow else '')
                         + (', keeps serving without sources' if cols['ntp_local'] else ''))
        out.append(('Time', t))
    return out


def _summary(plan, log):
    for heading, lines in summary(plan):
        log(f'  {heading}:')
        for line in lines:
            log(f'    {line}')


def start(settings, node_ids, username, background=True, echo=None):
    from .. import jobs

    def run(log):
        conn = db.connect(settings.db_path)
        try:
            readopt(conn, settings, node_ids, username, log)
        finally:
            conn.close()
    return jobs.start(settings.db_path, 're-adopt', run, username=username, background=background, echo=echo)
