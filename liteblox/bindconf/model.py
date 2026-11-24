"""What LiteBlox knows about one node's BIND config: options, ACLs, keys, zones.

Plain dataclasses. A field set to None is not written, so BIND uses its own
default; that keeps a fresh node's model rendering back to what it had.
"""

import ipaddress
import json
from dataclasses import asdict, dataclass, field, fields
from typing import Optional

ROLES = ('named.conf', 'acls.conf', 'keys.conf', 'options.conf', 'top.conf', 'zones.conf')
ZONE_KINDS = ('primary', 'secondary', 'forward')
XFR_KEY = 'liteblox-xfr'        # LiteBlox's own key for zone transfers between its nodes
UPDATE_KEY = 'liteblox'         # LiteBlox's own key for reading (AXFR) and updating dynamic zones


@dataclass
class Layout:
    """Where the generated files live on a node (the agent's config uses the same paths)."""
    named_conf: str = '/etc/bind/named.conf'
    config_dir: str = '/etc/bind/liteblox'
    dyn_dir: str = '/var/lib/bind/liteblox/dyn'
    sec_dir: str = '/var/lib/bind/liteblox/sec'
    jnl_dir: str = '/var/lib/bind/liteblox/jnl'
    pre_dir: str = '/etc/bind/pre-liteblox'
    directory: str = '/var/cache/bind'

    def path(self, role):
        return self.named_conf if role == 'named.conf' else f'{self.config_dir}/{role}'


DEBIAN = Layout()


@dataclass
class NodeOptions:
    listen_on: Optional[list] = None
    listen_on_v6: Optional[list] = None
    allow_query: Optional[list] = None
    recursion: Optional[bool] = None
    allow_recursion: Optional[list] = None
    forwarders: Optional[list] = None
    forward: Optional[str] = None              # first | only
    dnssec_validation: Optional[str] = None    # auto | yes | no
    validate_except: Optional[list] = None
    extra: str = ''                            # statements with no field, inside options { }

    def to_json(self):
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text):
        data = json.loads(text) if text else {}
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class Acl:
    name: str
    items: list


@dataclass
class TsigKey:
    name: str
    algorithm: str
    secret: str


@dataclass
class ZoneDecl:
    name: str
    kind: str = 'primary'
    file: Optional[str] = None                 # None: the default path for the kind (file_for)
    dynamic: bool = False
    notify: Optional[str] = None
    also_notify: list = field(default_factory=list)
    allow_transfer: list = field(default_factory=list)
    allow_query: list = field(default_factory=list)
    primaries: list = field(default_factory=list)
    forwarders: list = field(default_factory=list)
    forward_mode: Optional[str] = None
    update_policy: list = field(default_factory=list)   # "grant KEY zonesub ANY" lines
    ixfr: bool = False          # a static primary with secondaries: journal its reloads so they get IXFRs

    def journal_for(self, layout=DEBIAN):
        return f'{layout.jnl_dir}/db.{self.name}.jnl' if self.ixfr and self.kind == 'primary' else None

    def file_for(self, layout=DEBIAN):
        if self.kind == 'forward':
            return None
        if self.file:
            return self.file
        folder = (layout.sec_dir if self.kind == 'secondary'
                  else layout.dyn_dir if self.dynamic else layout.config_dir)
        return f'{folder}/db.{self.name}'


@dataclass
class NodeConfig:
    options: NodeOptions = field(default_factory=NodeOptions)
    acls: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    zones: list = field(default_factory=list)
    top_extra: str = ''
    # the distro's built-in zone files, included as found (named.conf.root-hints on Debian 13)
    distro_includes: list = field(default_factory=list)


def zone_from_row(row):
    """A ZoneDecl for a zone row (static primary, or forwarding only). notify '' = not written (BIND's default)."""
    from ..dns.declare import parse_forwarders, parse_list
    keys = row.keys() if hasattr(row, 'keys') else row
    if 'kind' in keys and row['kind'] == 'forwarding':
        return ZoneDecl(name=row['name'], kind='forward', forwarders=parse_forwarders(row['forwarders']),
                        forward_mode=row['forward_mode'] or None)
    return ZoneDecl(name=row['name'], notify=row['notify'] or None,
                    file=row['node_file'] if 'node_file' in keys else None,
                    also_notify=parse_list(row['also_notify']), allow_transfer=parse_list(row['allow_transfer']),
                    allow_query=parse_list(row['allow_query'] if 'allow_query' in keys else ''))


def global_acls(conn):
    return [Acl(r['name'], json.loads(r['items'])) for r in conn.execute('SELECT * FROM acls ORDER BY name')]


def global_keys(conn):
    return [TsigKey(r['name'], r['algorithm'], r['secret'])
            for r in conn.execute('SELECT * FROM tsig_keys ORDER BY name')]


def node_address(node):
    """The IP address other nodes and LiteBlox reach the node's DNS on, or None when it isn't known."""
    keys = node.keys() if hasattr(node, 'keys') else node
    addr = (node['dns_address'] if 'dns_address' in keys else None) or node['host']
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return None


def zone_decl(zone, node, primary, serving, layout=DEBIAN):
    """How `node` declares `zone`, given the primary node (or None) and the nodes serving it."""
    decl = zone_from_row(zone)
    if decl.kind == 'forward':
        return decl             # every node serving it forwards the same way; roles don't apply
    if decl.file and not decl.file.startswith(layout.config_dir + '/'):
        decl.file = None        # e.g. a secondary copy's path, when the node now holds a primary copy
    if primary is not None and node['role'] == 'secondary':
        return ZoneDecl(zone['name'], kind='secondary', notify='no',
                        primaries=[f'{node_address(primary)} key {XFR_KEY}'],
                        allow_transfer=_with_key(decl.allow_transfer), allow_query=decl.allow_query)
    # a primary copy: the primary's, or (no primary picked, or not converted yet) the node's own
    keys = []
    if primary is not None and node['id'] == primary['id']:
        secondaries = [node_address(n) for n in serving if n['id'] != primary['id'] and n['role'] == 'secondary']
        if secondaries:
            decl.also_notify = decl.also_notify + [a for a in secondaries if a not in decl.also_notify]
            decl.allow_transfer = _with_key(decl.allow_transfer)
            if decl.notify in ('no', 'explicit'):
                decl.notify = 'explicit'        # LiteBlox's secondaries are always notified
            decl.ixfr = True
            keys.append(XFR_KEY)
    if _get(zone, 'dynamic'):
        # named owns the file and journals every update itself; LiteBlox reads and writes with its own key
        decl.dynamic, decl.ixfr = True, False
        decl.update_policy = [f'grant {UPDATE_KEY} zonesub ANY'] + list(_get(zone, '_grants') or [])
        decl.allow_transfer = _with_key(decl.allow_transfer, UPDATE_KEY)
        keys.append(UPDATE_KEY)
    if keys:
        # signed SOA refreshes (secondaries) and LiteBlox's reads get through a restricted allow-query
        restricted = decl.allow_query or _node_options(node).allow_query
        if restricted:
            for key in keys:
                restricted = _with_key(restricted, key)
            decl.allow_query = restricted
    return decl


def _get(row, key):
    keys = row.keys() if hasattr(row, 'keys') else row
    return row[key] if key in keys else None


def _node_options(node):
    keys = node.keys() if hasattr(node, 'keys') else node
    return NodeOptions.from_json(node['options'] if 'options' in keys else None)


def _with_key(items, name=XFR_KEY):
    key = f'key {name}'
    return [key] + [i for i in items if i != key]


def grant_lines(conn):
    """{zone id: ['grant KEY SCOPE [NAME] TYPES', ...]} from key_grants."""
    out = {}
    for g in conn.execute('SELECT g.*, k.name AS key FROM key_grants g JOIN tsig_keys k ON k.id = g.key_id '
                          'ORDER BY k.name, g.id'):
        name = f" {g['name'].rstrip('.')}." if g['scope'] != 'zonesub' else ''
        out.setdefault(g['zone_id'], []).append(f"grant {g['key']} {g['scope']}{name} {g['types']}")
    return out


def for_node(conn, node, zones=None, layout=DEBIAN, options=None, top_extra=None, acls=None):
    """The node's config from the DB. zones: zone rows to declare instead of the ones it serves now;
    a row's '_nodes' (node ids) stands in for zone_nodes when the change isn't saved yet.
    options / top_extra / acls: proposed values to render instead of the stored ones (previews)."""
    from ..dns.declare import managed_zones_for
    if zones is None:
        zones = managed_zones_for(conn, node['id'])
    all_nodes = {r['id']: dict(r) for r in conn.execute('SELECT * FROM nodes')}
    node = all_nodes.get(node['id'], dict(node))
    if options is not None:
        node['options'] = options.to_json()
    if top_extra is not None:
        node['top_extra'] = top_extra
    all_nodes[node['id']] = node
    primary = next((n for n in all_nodes.values() if n['role'] == 'primary'), None)
    grants = grant_lines(conn)
    decls = []
    for z in sorted(zones, key=lambda z: z['name']):
        z = dict(z)
        if 'id' in z:
            z['_grants'] = grants.get(z['id'], [])
        ids = z.get('_nodes') if isinstance(z, dict) else None
        if ids is None:
            ids = [r[0] for r in conn.execute('SELECT node_id FROM zone_nodes WHERE zone_id = ?', (z['id'],))]
        decls.append(zone_decl(z, node, primary, [all_nodes[i] for i in ids if i in all_nodes], layout))
    return NodeConfig(
        options=NodeOptions.from_json(node['options']),
        acls=global_acls(conn) if acls is None else acls,
        keys=global_keys(conn),
        zones=decls,
        top_extra=node['top_extra'] or '',
        distro_includes=distro_includes(node),
    )


def distro_includes(node):
    """The distro's include files kept at takeover that the node still has. An OS upgrade can drop one (Debian
    13's and Ubuntu 26.04's bind9 have no named.conf.default-zones: BIND 9.20 builds those zones in, and the stock
    named.conf includes named.conf.root-hints instead), so a missing default-zones gives way to root-hints when
    that's there. Until the agent reports what it has (distro_present NULL), the list as kept."""
    kept = json.loads(node['distro_includes'] or '[]')
    present = node['distro_present'] if 'distro_present' in node.keys() else None
    if present is None:
        return kept
    present = set(json.loads(present))
    out = []
    for path in kept:
        if path in present:
            out.append(path)
        elif path.endswith('/named.conf.default-zones'):
            hints = path[:-len('default-zones')] + 'root-hints'
            if hints in present:
                out.append(hints)
    return list(dict.fromkeys(out))
