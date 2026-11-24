"""What LiteBlox knows about one node's Kea config: the interfaces it serves, the global DHCPv4 and DHCPv6
settings, and the subnets on those interfaces."""

import json
from dataclasses import dataclass, field, replace
from typing import Optional

ROLES = ('kea-dhcp4.conf', 'kea-dhcp6.conf', 'kea-dhcp-ddns.conf')
DDNS_MODES = ('liteblox', 'external', 'off')   # where Kea registers clients: LiteBlox's primary, another server, nowhere
OPTION_FIELDS = ('routers', 'dns', 'domain', 'search', 'ntp')     # the options with a form field
LIFETIMES = ('valid_lifetime', 'renew_timer', 'rebind_timer')
LIFETIMES6 = ('preferred_lifetime', 'valid_lifetime', 'renew_timer', 'rebind_timer')
OPTION_FIELDS6 = ('dns', 'search', 'ntp')       # DHCPv6 has no routers option: router advertisements carry that


@dataclass
class KeaLayout:
    """Where Kea's files live on a node (the agent's config uses the same paths)."""
    config_dir: str = '/etc/kea'
    hooks_dir: str = '/usr/lib/x86_64-linux-gnu/kea/hooks'
    lease_file: str = '/var/lib/kea/kea-leases4.csv'
    lease_file6: str = '/var/lib/kea/kea-leases6.csv'
    dhcp4_socket: str = '/run/kea/kea4-ctrl-socket'
    dhcp6_socket: str = '/run/kea/kea6-ctrl-socket'
    d2_socket: str = '/run/kea/kea-ddns-ctrl-socket'
    d2_port: int = 53001
    kea_version: Optional[str] = None       # None: a current Kea (2.6 and later)

    def path(self, role):
        return f'{self.config_dir}/{role}'

    @property
    def before_2_5(self):
        import re
        m = re.match(r'\s*(\d+)\.(\d+)', self.kea_version or '')
        return bool(m) and (int(m.group(1)), int(m.group(2))) < (2, 5)

    @property
    def logger_output_key(self):
        """Kea 2.5 renamed a logger's output_options to output-options; 2.4 knows only the old name."""
        return 'output_options' if self.before_2_5 else 'output-options'


DEBIAN = KeaLayout()


@dataclass
class Dhcp4Settings:
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    options: dict = field(default_factory=dict)          # {routers: [..], dns: [..], domain: '', search: [..], ntp: [..]}
    extra_options: list = field(default_factory=list)
    authoritative: bool = False
    ddns_key_id: Optional[int] = None       # mode liteblox: the key from tsig_keys
    ddns_key: Optional[dict] = None         # {name, algorithm, secret} D2 signs with (the mode's key), or None
    ddns_mode: str = 'liteblox'
    ddns_server: str = ''                   # mode external: where updates go
    ddns_port: int = 53
    ddns_external_key: Optional[dict] = None

    @classmethod
    def from_row(cls, row):
        if row is None:
            return cls()
        keys = row.keys()
        own = ({'name': row['key_name'], 'algorithm': row['key_algorithm'], 'secret': row['key_secret']}
               if 'key_name' in keys and row['key_name'] else None)
        mode = row['ddns_mode'] if 'ddns_mode' in keys else ('liteblox' if own else 'off')
        external = json.loads(row['ddns_external_key']) if 'ddns_external_key' in keys and row['ddns_external_key'] \
            else None
        return cls(row['valid_lifetime'], row['renew_timer'], row['rebind_timer'], json.loads(row['options']),
                   json.loads(row['extra_options']), bool(row['authoritative']),
                   row['ddns_key_id'] if 'ddns_key_id' in keys else None,
                   own if mode == 'liteblox' else external if mode == 'external' else None, mode,
                   row['ddns_server'] if 'ddns_server' in keys else '',
                   row['ddns_port'] if 'ddns_port' in keys else 53, external)


@dataclass
class Reservation:
    id: Optional[int]
    subnet_id: Optional[int]
    hw_address: str
    ip_address: str
    hostname: str = ''
    options: dict = field(default_factory=dict)
    comment: str = ''

    @classmethod
    def from_row(cls, row):
        return cls(row['id'], row['subnet_id'], row['hw_address'], row['ip_address'], row['hostname'],
                   json.loads(row['options']), row['comment'])


@dataclass
class Subnet:
    id: Optional[int]
    prefix: str
    interface: str
    pools: list = field(default_factory=list)
    options: dict = field(default_factory=dict)
    extra_options: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    comment: str = ''
    ddns: bool = False                      # register clients in DNS (A + DHCID, and the PTR)
    ddns_zone_id: Optional[int] = None
    ddns_zone: Optional[str] = None         # that zone's name
    ddns_suffix: str = ''                   # '' : the zone itself; mode external: the domain (required)
    reservations: list = field(default_factory=list)
    ddns_reverse: str = ''                  # mode external: its reverse zones there; '': derived from the prefix
    ddns_mode: str = 'liteblox'             # the DHCP settings' mode, set when loaded (not a column)
    family = 4

    @property
    def url(self):
        return f'/dhcp/subnets/{self.id}'

    @property
    def ddns_domain(self):
        """The forward zone or domain its clients are registered in under the current mode, or None."""
        if self.ddns_mode == 'external':          # the zone at the other server; a LiteBlox zone's name till set
            return self.ddns_suffix or self.ddns_zone or None
        return self.ddns_zone if self.ddns_mode == 'liteblox' else None

    @property
    def registers(self):
        """Clients are registered in DNS: the subnet asks for it, and the mode gives it a place."""
        return bool(self.ddns and self.ddns_domain)

    @property
    def qualifying_suffix(self):
        return self.ddns_suffix or self.ddns_domain or ''

    @classmethod
    def from_row(cls, row):
        keys = row.keys()
        return cls(row['id'], row['prefix'], row['interface'], [p for p in row['pools'].splitlines() if p.strip()],
                   json.loads(row['options']), json.loads(row['extra_options']), json.loads(row['extra']),
                   row['valid_lifetime'], row['renew_timer'], row['rebind_timer'], row['comment'],
                   bool(row['ddns']) if 'ddns' in keys else False, row['ddns_zone_id'] if 'ddns_zone_id' in keys else None,
                   row['ddns_zone'] if 'ddns_zone' in keys else None, row['ddns_suffix'] if 'ddns_suffix' in keys else '',
                   ddns_reverse=row['ddns_reverse'] if 'ddns_reverse' in keys else '')


@dataclass
class Dhcp6Settings:
    preferred_lifetime: Optional[int] = None
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    options: dict = field(default_factory=dict)          # {dns: [..], search: [..], ntp: [..]}
    extra_options: list = field(default_factory=list)

    @classmethod
    def from_row(cls, row):
        if row is None:
            return cls()
        return cls(row['preferred_lifetime'], row['valid_lifetime'], row['renew_timer'], row['rebind_timer'],
                   json.loads(row['options']), json.loads(row['extra_options']))


@dataclass
class Reservation6:
    id: Optional[int]
    subnet_id: Optional[int]
    duid: str = ''                          # one of duid and hw_address identifies the client
    hw_address: str = ''
    ip_address: str = ''                    # '': none (a prefix only, or name only)
    prefix: str = ''                        # a delegated prefix, or ''
    hostname: str = ''
    options: dict = field(default_factory=dict)
    comment: str = ''

    @property
    def identifier(self):
        return ('duid', self.duid) if self.duid else ('hw-address', self.hw_address)

    @classmethod
    def from_row(cls, row):
        return cls(row['id'], row['subnet_id'], row['duid'], row['hw_address'], row['ip_address'], row['prefix'],
                   row['hostname'], json.loads(row['options']), row['comment'])


@dataclass
class Subnet6:
    id: Optional[int]
    prefix: str
    interface: str
    pools: list = field(default_factory=list)
    pd_pools: list = field(default_factory=list)        # [{prefix: 'p/len', delegated_len: n}]
    options: dict = field(default_factory=dict)
    extra_options: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    preferred_lifetime: Optional[int] = None
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    comment: str = ''
    ddns: bool = False
    ddns_zone_id: Optional[int] = None
    ddns_zone: Optional[str] = None
    ddns_suffix: str = ''
    ddns_reverse: str = ''
    ra: bool = False                        # router advertisements from the serving nodes
    ra_slaac: bool = False                  # ... with the A flag: clients may pick their own address too
    ra_since: Optional[str] = None
    reservations: list = field(default_factory=list)
    ddns_mode: str = 'liteblox'
    family = 6

    ddns_domain = Subnet.ddns_domain
    registers = Subnet.registers

    @property
    def url(self):
        return f'/dhcp/v6/subnets/{self.id}'

    qualifying_suffix = Subnet.qualifying_suffix

    @classmethod
    def from_row(cls, row):
        keys = row.keys()
        return cls(row['id'], row['prefix'], row['interface'], [p for p in row['pools'].splitlines() if p.strip()],
                   json.loads(row['pd_pools']), json.loads(row['options']), json.loads(row['extra_options']),
                   json.loads(row['extra']), row['preferred_lifetime'], row['valid_lifetime'], row['renew_timer'],
                   row['rebind_timer'], row['comment'], bool(row['ddns']), row['ddns_zone_id'],
                   row['ddns_zone'] if 'ddns_zone' in keys else None, row['ddns_suffix'], row['ddns_reverse'],
                   bool(row['ra']), bool(row['ra_slaac']), row['ra_since'])


@dataclass
class HaPair:
    primary_id: Optional[int] = None
    standby_id: Optional[int] = None
    primary_name: str = ''
    standby_name: str = ''
    primary_address: str = ''
    standby_address: str = ''
    port: int = 8001
    interface_map: dict = field(default_factory=dict)  # {primary's interface: the standby's}; missing = same name
    port6: int = 8002                                   # where kea-dhcp6 listens for its partner

    @property
    def active(self):
        return bool(self.primary_id and self.standby_id)

    def role_of(self, node_id):
        return 'primary' if node_id == self.primary_id else 'standby' if node_id == self.standby_id else None

    def partner_of(self, node_id):
        return self.standby_id if node_id == self.primary_id else self.primary_id if node_id == self.standby_id else None

    def standby_name_for(self, interface):
        """The standby's interface that serves what the primary serves on `interface`."""
        return self.interface_map.get(interface, interface)

    def interface_on(self, node_id, interface):
        """A subnet's interface (the primary's name) as `node_id` names it."""
        return self.standby_name_for(interface) if self.active and node_id == self.standby_id else interface


@dataclass
class KeaConfig:
    interfaces: list = field(default_factory=list)
    settings: Dhcp4Settings = field(default_factory=Dhcp4Settings)
    subnets: list = field(default_factory=list)
    primary: Optional[str] = None           # where D2 sends updates: the DNS primary, or the external server
    reverse_zones: list = field(default_factory=list)   # LiteBlox's dynamic reverse zones (names), for the PTRs
    ddns_port: int = 53
    ha: Optional[dict] = None               # {this, pair: HaPair, tls: {cert, key, ca}} when the node is in the pair
    dhcp6: bool = False                     # the node has kea-dhcp6 (6.0's Repair): kea-dhcp6.conf is written
    settings6: Dhcp6Settings = field(default_factory=Dhcp6Settings)
    subnets6: list = field(default_factory=list)
    interfaces6: list = field(default_factory=list)     # served interfaces with a DHCPv6 subnet
    ha6: Optional[dict] = None              # as ha, for kea-dhcp6: when both have it and the pair serves a v6 subnet
    shared_domains: list = field(default_factory=list)  # DDNS domains both families register in (dual-stack names)
    radvd: bool = False                     # the node has radvd set up: radvd.conf is written with Kea's files


def layout_for(node):
    """DEBIAN with the hooks directory the node's agent reported (it differs per architecture) and its Kea's
    version."""
    keys = node.keys() if hasattr(node, 'keys') else node
    hooks = node['kea_hooks_dir'] if 'kea_hooks_dir' in keys else None
    version = node['kea_version'] if 'kea_version' in keys else None
    return replace(DEBIAN, **({'hooks_dir': hooks} if hooks else {}), kea_version=version or None)


def settings(conn):
    return Dhcp4Settings.from_row(conn.execute(
        'SELECT s.*, k.name AS key_name, k.algorithm AS key_algorithm, k.secret AS key_secret FROM dhcp4_settings s '
        'LEFT JOIN tsig_keys k ON k.id = s.ddns_key_id WHERE s.id = 1').fetchone())


def ddns_mode(conn):
    row = conn.execute('SELECT ddns_mode FROM dhcp4_settings WHERE id = 1').fetchone()
    return row[0] if row else 'off'


def reservations(conn, subnet_id=None):
    sql = 'SELECT * FROM dhcp4_reservations' + (' WHERE subnet_id = ?' if subnet_id else '') + ' ORDER BY id'
    return [Reservation.from_row(r) for r in conn.execute(sql, (subnet_id,) if subnet_id else ())]


def subnets(conn):
    by_subnet = {}
    for r in reservations(conn):
        by_subnet.setdefault(r.subnet_id, []).append(r)
    out = [Subnet.from_row(r) for r in conn.execute(
        'SELECT s.*, z.name AS ddns_zone FROM dhcp4_subnets s LEFT JOIN zones z ON z.id = s.ddns_zone_id ORDER BY s.id')]
    mode = ddns_mode(conn)
    for s in out:
        s.reservations = by_subnet.get(s.id, [])
        s.ddns_mode = mode
    return out


def settings6(conn):
    return Dhcp6Settings.from_row(conn.execute('SELECT * FROM dhcp6_settings WHERE id = 1').fetchone())


def reservations6(conn, subnet_id=None):
    sql = 'SELECT * FROM dhcp6_reservations' + (' WHERE subnet_id = ?' if subnet_id else '') + ' ORDER BY id'
    return [Reservation6.from_row(r) for r in conn.execute(sql, (subnet_id,) if subnet_id else ())]


def subnets6(conn):
    by_subnet = {}
    for r in reservations6(conn):
        by_subnet.setdefault(r.subnet_id, []).append(r)
    out = [Subnet6.from_row(r) for r in conn.execute(
        'SELECT s.*, z.name AS ddns_zone FROM dhcp6_subnets s LEFT JOIN zones z ON z.id = s.ddns_zone_id ORDER BY s.id')]
    mode = ddns_mode(conn)
    for s in out:
        s.reservations = by_subnet.get(s.id, [])
        s.ddns_mode = mode
    return out


def ha_pair(conn):
    row = conn.execute('SELECT h.*, p.name AS primary_name, s.name AS standby_name FROM dhcp4_ha h '
                       'LEFT JOIN nodes p ON p.id = h.primary_node_id LEFT JOIN nodes s ON s.id = h.standby_node_id '
                       'WHERE h.id = 1').fetchone()
    if row is None:
        return HaPair()
    keys = row.keys()
    mapping = json.loads(row['interface_map'] or '{}') if 'interface_map' in keys else {}
    return HaPair(row['primary_node_id'], row['standby_node_id'], row['primary_name'] or '', row['standby_name'] or '',
                  row['primary_address'] or '', row['standby_address'] or '', row['port'], mapping,
                  row['port6'] if 'port6' in keys else 8002)


def dns_primary(conn):
    """The DNS primary's address (where dynamic updates go), or None."""
    from ..bindconf.model import node_address
    row = conn.execute("SELECT * FROM nodes WHERE role = 'primary'").fetchone()
    return node_address(row) if row else None


def dynamic_reverse_zones(conn):
    return [r['name'] for r in conn.execute("SELECT name FROM zones WHERE dynamic = 1 AND kind = 'primary' "
                                            "AND (name LIKE '%.in-addr.arpa' OR name LIKE '%.ip6.arpa') ORDER BY name")]


def shared_domains(v4, v6):
    """The DDNS domains registering subnets of both families use: a client there may hold an A and an AAAA."""
    return sorted({s.ddns_domain for s in v4 if s.registers} & {s.ddns_domain for s in v6 if s.registers})


def interfaces_of(node):
    keys = node.keys() if hasattr(node, 'keys') else node
    return json.loads(node['dhcp_interfaces'] or '[]') if 'dhcp_interfaces' in keys else []


def serves(pair, node, subnet):
    """Does `node` answer for `subnet` (whose interface is the primary's name)?"""
    return pair.interface_on(node['id'], subnet.interface) in interfaces_of(node)


def has_dhcp6(node):
    keys = node.keys() if hasattr(node, 'keys') else node
    return bool(node['dhcp6']) if 'dhcp6' in keys else False


def has_radvd(node):
    """Is radvd set up on the node (Repair with router advertisements ticked)?"""
    keys = node.keys() if hasattr(node, 'keys') else node
    return bool(node['radvd']) if 'radvd' in keys else False


def for_node(conn, node, interfaces=None, dhcp_settings=None, subnet_list=None, pair=None, dhcp6=None,
             dhcp6_settings=None, subnet6_list=None):
    """The node's Kea config from the DB; the keyword arguments stand in for unsaved changes (previews). dhcp6:
    whether to write kea-dhcp6.conf (default: the node has kea-dhcp6)."""
    dhcp6 = has_dhcp6(node) if dhcp6 is None else dhcp6
    if conn is None:
        return KeaConfig(dhcp6=dhcp6, radvd=dhcp6 and has_radvd(node))
    pair = ha_pair(conn) if pair is None else pair
    ha = None
    if pair.active and pair.role_of(node['id']):
        keys = node.keys() if hasattr(node, 'keys') else node
        tls = json.loads(node['kea_tls']) if 'kea_tls' in keys and node['kea_tls'] else None
        ha = {'this': node['name'], 'pair': pair, 'tls': tls}
        if interfaces is None and pair.role_of(node['id']) == 'standby':
            # the standby serves what the primary serves, so it can take over all of it
            primary = conn.execute('SELECT dhcp_interfaces FROM nodes WHERE id = ?', (pair.primary_id,)).fetchone()
            interfaces = json.loads(primary[0] or '[]') if primary else []
    served = interfaces_of(node) if interfaces is None else interfaces
    chosen = subnets(conn) if subnet_list is None else subnet_list
    chosen6 = (subnets6(conn) if subnet6_list is None else subnet6_list) if dhcp6 else []
    if pair.active and pair.role_of(node['id']) == 'standby':
        # subnets carry the primary's interface names (and `interfaces` is the primary's set): the standby's own
        # names come from the pair's map, matched by network
        chosen = [x for x in chosen if x.interface in served]
        chosen6 = [x for x in chosen6 if x.interface in served]
        served = [pair.standby_name_for(n) for n in served]
        chosen = [replace(x, interface=pair.standby_name_for(x.interface)) for x in chosen]
        chosen6 = [replace(x, interface=pair.standby_name_for(x.interface)) for x in chosen6]
    s = settings(conn) if dhcp_settings is None else dhcp_settings
    for sub in chosen:          # a preview of new settings registers by their mode
        sub.ddns_mode = s.ddns_mode
    target, port, reverse = None, 53, []
    if s.ddns_mode == 'liteblox':
        target, reverse = dns_primary(conn), dynamic_reverse_zones(conn)
    elif s.ddns_mode == 'external':
        target, port = s.ddns_server or None, s.ddns_port
    all6 = chosen6
    for sub in all6:
        sub.ddns_mode = s.ddns_mode
    chosen6 = [x for x in chosen6 if x.interface in served]
    ha6 = None
    if ha and chosen6:
        partner = conn.execute('SELECT * FROM nodes WHERE id = ?', (pair.partner_of(node['id']),)).fetchone()
        if partner is not None and has_dhcp6(partner):
            ha6 = ha
    shared = shared_domains(chosen, all6) if s.ddns_mode != 'off' else []
    return KeaConfig(interfaces=list(served), settings=s, subnets=[x for x in chosen if x.interface in served],
                     primary=target, reverse_zones=reverse, ddns_port=port, ha=ha, dhcp6=dhcp6,
                     settings6=(settings6(conn) if dhcp6_settings is None else dhcp6_settings) if dhcp6
                     else Dhcp6Settings(),
                     subnets6=chosen6, interfaces6=[n for n in served if any(x.interface == n for x in chosen6)],
                     ha6=ha6, shared_domains=shared, radvd=dhcp6 and has_radvd(node))
