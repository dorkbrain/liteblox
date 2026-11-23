"""The API's response shapes (they're what the Swagger page documents)."""

from typing import Literal, Optional, Union

from pydantic import BaseModel, Field


class TokenInfo(BaseModel):
    name: str
    scope: str
    expires_at: Optional[str] = None


class Me(BaseModel):
    username: str
    role: str
    token: TokenInfo


class NodeFlags(BaseModel):
    pending: Optional[str] = None
    drift: list[str] = []                   # generated BIND files changed on the node
    second_primary: list[str] = []          # zones it declares primary outside LiteBlox
    dhcp_drift: list[str] = []              # Kea files changed on the node
    dhcp_ha_state: Optional[str] = None
    clock_skew: Optional[float] = None      # seconds, the node's clock minus LiteBlox's
    clock_synced: Optional[bool] = None
    other_liteblox: bool = False            # a config from another LiteBlox: re-adopt it


class Node(BaseModel):
    name: str
    host: str
    dns_address: Optional[str] = None
    role: Optional[str] = None              # primary, secondary, or none picked
    bind: bool = True                       # runs BIND for LiteBlox (false: a scanner, or DHCP/Time only)
    managed: bool
    status: str
    status_detail: Optional[str] = None
    agent_version: Optional[str] = None
    named_version: Optional[str] = None
    last_seen_at: Optional[str] = None
    dhcp: bool
    dhcp_interfaces: list[str] = []
    time: Optional[dict] = None             # chrony's state when LiteBlox runs it: synced, reference, stratum, offset
    install_rev: Optional[int] = None       # the install layout Repair last put on it (the unit, the root installer)
    can_upgrade: bool = False               # its agent is older and can be upgraded over mTLS (POST …/upgrade-agent)
    flags: NodeFlags


class Problem(BaseModel):
    severity: str                           # error, warn, or info (info doesn't count towards the level)
    area: str                               # node, dns, dhcp, time
    what: str
    link: Optional[str] = None              # the page in LiteBlox that fixes it
    node: Optional[str] = None


class Tile(BaseModel):
    key: str                                # nodes, dns, dhcp, time, attention
    label: str
    level: str                              # ok, warn, error, or off (not set up)
    value: str
    sub: str


class Status(BaseModel):
    level: str                              # ok, warn, error: the worst problem that needs an admin
    attention: int                          # problems that need an admin (errors and warnings)
    checked_at: Optional[str] = None        # the health check's last answer from a node (UTC)
    problems: list[Problem]
    tiles: list[Tile]
    modules: list[str] = []                 # what this install runs: dns, dhcp, ntp, ipam (Settings → Modules)


class Zone(BaseModel):
    name: str
    kind: str                               # primary (forward/reverse) or forwarding
    dynamic: bool
    nodes: list[str]
    has_draft: bool


class ZoneSettings(BaseModel):
    notify: str = ''
    also_notify: list[str] = []
    allow_transfer: list[str] = []
    allow_query: list[str] = []
    forwarders: list[str] = []
    forward_mode: str = ''
    auto_ptr: bool
    sorted: bool                            # always true for a static zone since 3.3.1 (named orders a dynamic one)


class Grant(BaseModel):
    key: str
    scope: str
    name: str = ''
    types: str


class ZoneDetail(Zone):
    settings: ZoneSettings
    grants: list[Grant] = []
    published_serial: Optional[int] = None
    notes: str = ''                         # kept in LiteBlox only, never in the zone file


class NotesIn(BaseModel):
    notes: str


class Record(BaseModel):
    id: str                                 # by content: stays the same while the record is unchanged
    name: str                               # relative to the zone, '@' for its apex
    type: str
    ttl: Optional[int] = None
    data: str
    comment: Optional[str] = None
    rr: Optional[str] = None                # dynamic zones: the record and its RRset now, for If-Match


class Records(BaseModel):
    zone: str
    rev: str                                # also the ETag
    draft: bool                             # these are the draft's records (a static zone with changes)
    serial: Optional[int] = None
    records: list[Record]


class JobSummary(BaseModel):
    id: int
    kind: str
    status: str                             # running, ok, failed
    node: Optional[str] = None
    zone: Optional[str] = None
    username: Optional[str] = None
    created_at: str
    finished_at: Optional[str] = None


class Job(JobSummary):
    log: list[str]


# ── zone writes ────────────────────────────────────────────────────────────────

class RecordIn(BaseModel):
    name: str                               # relative to the zone ('www', '@'), or absolute with a final dot
    type: str
    data: str                               # as a zone file writes it: '10 mail.example.com.', TXT as "quoted strings"
    ttl: Optional[Union[int, str]] = None   # seconds or 1h/30m; none: the zone's default
    comment: Optional[str] = None
    ptr: Optional[bool] = None              # also add/change/remove the PTR; none: the zone's auto-PTR setting


class RecordPatch(BaseModel):
    """Only the fields sent change."""
    name: Optional[str] = None
    type: Optional[str] = None
    data: Optional[str] = None
    ttl: Optional[Union[int, str]] = None
    comment: Optional[str] = None
    ptr: Optional[bool] = None


class SoaIn(BaseModel):
    """The SOA's names and timers (seconds or 1h/30m); fields left out stay. The serial is LiteBlox's."""
    mname: Optional[str] = None
    rname: Optional[str] = None
    refresh: Optional[Union[int, str]] = None
    retry: Optional[Union[int, str]] = None
    expire: Optional[Union[int, str]] = None
    minimum: Optional[Union[int, str]] = None


class WriteResult(BaseModel):
    zone: str
    rev: str                                # the zone's version now (for the next If-Match)
    draft: bool                             # a static zone's change is in its draft until published
    record: Optional[Record] = None
    notes: list[str] = []                   # e.g. what happened to the PTR
    warnings: list[str] = []


class BatchOp(BaseModel):
    """add: name, type and data (ttl, comment optional). change: id plus only the fields to change.
    delete: id."""
    op: Literal['add', 'change', 'delete']
    id: Optional[str] = None                # change/delete: the record's id as GET …/records gave it
    name: Optional[str] = None
    type: Optional[str] = None
    data: Optional[str] = None
    ttl: Optional[Union[int, str]] = None
    comment: Optional[str] = None


class BatchIn(BaseModel):
    ops: list[BatchOp] = Field(min_length=1, max_length=2000)
    ptr: Optional[bool] = None              # PTRs follow A/AAAA changes; none: the zone's auto-PTR setting


class BatchResult(BaseModel):
    zone: str
    rev: str
    draft: bool
    records: list[Optional[Record]]         # one per op, in order: the record it became (none for a delete)
    notes: list[str] = []
    warnings: list[str] = []


class PublishIn(BaseModel):
    message: Optional[str] = None           # for the zone's History; none: "Publish <zone>"


class JobStarted(BaseModel):
    job: int                                # poll GET /api/v1/jobs/{job}


class Row(BaseModel):
    name: str
    type: str
    ttl: Optional[int] = None
    data: str


class Change(BaseModel):
    before: Row
    after: Row


class DraftSummary(BaseModel):
    added: list[Row] = []
    removed: list[Row] = []
    changed: list[Change] = []


class Check(BaseModel):
    ok: Optional[bool] = None               # None: named-checkzone isn't available
    output: str = ''


class Draft(BaseModel):
    zone: str
    draft: bool                             # false: nothing to publish (a publish then republishes as it is)
    rev: str
    stale: bool                             # the published copy changed after this draft was started
    summary: DraftSummary
    diff: str                               # unified, published → draft
    check: Optional[Check] = None
    linked: list[str] = []                  # reverse zones whose drafts publish together with this one


class Commit(BaseModel):
    sha: str
    author: str
    date: str
    message: str


class CommitText(Commit):
    text: str


# ── DHCP ───────────────────────────────────────────────────────────────────────

class DhcpServer(BaseModel):
    node: str
    does: str                               # failover primary, standby, serving, serves nothing
    interfaces: list[str] = []
    ha_state: Optional[str] = None          # as kea-dhcp4 last reported it (hot-standby when all is well)
    kea_config_changed: bool = False        # Kea's files were edited on the node
    config_behind: bool = False             # it missed a DHCP change; the health check writes it again


class DhcpPair(BaseModel):
    primary: str
    standby: str
    primary_address: str
    standby_address: str
    port: int


class DhcpSettings(BaseModel):
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    options: dict = {}
    extra_options: list = []
    authoritative: bool = False
    ddns_key: Optional[str] = None          # the TSIG key DHCP registers names with (its name only)
    ddns_mode: str = 'off'                  # liteblox (LiteBlox's DNS primary), external (another server), off
    ddns_server: Optional[str] = None       # external: where the updates go
    ddns_port: Optional[int] = None


class Dhcp(BaseModel):
    servers: list[DhcpServer]
    pair: Optional[DhcpPair] = None
    settings: DhcpSettings


class Reservation(BaseModel):
    id: int
    hw_address: str
    ip_address: str                         # '': name-only (a pool address, the name registered in DNS)
    hostname: str = ''
    options: dict = {}
    comment: str = ''


class Ddns(BaseModel):
    zone: str
    suffix: str                             # the names clients get: <hostname>.<suffix>


class Subnet(BaseModel):
    id: int                                 # Kea's subnet-id
    prefix: str
    interface: str
    pools: list[str]
    options: dict = {}
    extra_options: list = []
    extra: dict = {}
    valid_lifetime: Optional[int] = None
    renew_timer: Optional[int] = None
    rebind_timer: Optional[int] = None
    comment: str = ''
    ddns: Optional[Ddns] = None
    reservations: list[Reservation] = []


class Lease(BaseModel):
    ip: str
    mac: str
    hostname: str = ''
    subnet_id: Optional[int] = None
    state: str                              # active, declined, expired-reclaimed, released
    expires: str                            # ISO 8601, UTC
    expires_in: int                         # seconds (negative: past)
    registered: bool                        # its name is in DNS
    reserved: bool                          # it's on a reservation
    node: str                               # the server it was read from


class Leases(BaseModel):
    leases: list[Lease]
    read_from: Optional[str] = None         # a pair's leases come from its primary, or the standby when it's down
    errors: list[str] = []


class ReservationIn(BaseModel):
    hw_address: str                         # aa:bb:cc:dd:ee:ff (other separators are fine)
    ip_address: str = ''                    # '': name-only, in a subnet that registers clients (needs a hostname)
    hostname: str = ''                      # one label, e.g. printer; '': the client's own name
    options: dict = {}                      # {routers: [..], dns: [..], domain: '', ntp: [..]} for this client only
    comment: str = ''


class ReservationPatch(BaseModel):
    """Only the fields sent change."""
    hw_address: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    options: Optional[dict] = None
    comment: Optional[str] = None


class DhcpJob(BaseModel):
    job: int                                # poll GET /api/v1/jobs/{job}
    warnings: list[str] = []


class LeaseDeleted(BaseModel):
    ip: str
    node: str
    partner: Optional[str] = None           # the failover partner's copy was deleted too


# ── time ───────────────────────────────────────────────────────────────────────

class TimeServer(BaseModel):
    node: str
    serves: bool                            # answers other machines' time requests
    networks: list[str] = []
    keeps_serving: bool = False             # from its own clock when every source is unreachable (orphan)
    state: Optional[dict] = None            # synced, reference, stratum, offset, sources, reachable


class Time(BaseModel):
    sources: list[str]                      # as chrony.conf lines: "pool 2.debian.pool.ntp.org iburst"
    default: bool                           # Debian's pool, since none were set
    nodes: list[TimeServer]


class SearchRecord(BaseModel):
    zone: str
    name: str                               # relative to the zone, @ for the apex
    fqdn: str
    type: str
    data: str
    comment: Optional[str] = None
    draft: bool                             # from the zone's unpublished draft
    dynamic: bool
    as_of: Optional[str] = None             # a dynamic zone whose primary didn't answer: its history copy's time


class SearchReservation(BaseModel):
    subnet: str
    subnet_id: int
    id: int
    ip: str
    mac: str
    hostname: str = ''
    comment: str = ''


class SearchLease(BaseModel):
    ip: str
    mac: str
    hostname: str = ''
    state: str
    expires: str                            # ISO 8601, UTC
    subnet_id: Optional[int] = None
    node: Optional[str] = None              # the server it was read from


class SearchZone(BaseModel):
    name: str
    kind: str                               # primary, forwarding
    dynamic: bool


class SearchSubnet(BaseModel):
    id: int
    prefix: str
    comment: str = ''


class SearchCheck(BaseModel):
    level: str                              # warn, info
    text: str


class SearchIpamName(BaseModel):
    name: str
    mac: str = ''
    comment: str = ''


class SearchRdns(BaseModel):
    name: str = ''                          # '': the resolver has no PTR for it
    error: Optional[str] = None
    looked_up_at: int                       # unix seconds


class SearchAddress(BaseModel):
    ip: str
    names: list[str]                        # A records pointing at it
    ptr: list[str]                          # what its PTR records name
    reverse_zone: Optional[str] = None
    reservation: Optional[SearchReservation] = None
    lease: Optional[SearchLease] = None
    subnet: Optional[str] = None
    in_pool: bool = False
    ipam: Optional[SearchIpamName] = None   # its IPAM record (a name kept in IPAM only)
    rdns: Optional[SearchRdns] = None       # its PTR at the resolver set in Settings → IPAM
    checks: list[SearchCheck] = []


class SearchRecords(BaseModel):
    count: int                              # every match; items stops at the limit
    items: list[SearchRecord]


class SearchReservations(BaseModel):
    count: int
    items: list[SearchReservation]


class SearchLeases(BaseModel):
    count: int
    items: list[SearchLease]


class SearchZones(BaseModel):
    count: int
    items: list[SearchZone]


class SearchSubnets(BaseModel):
    count: int
    items: list[SearchSubnet]


class SearchDevice(BaseModel):
    mac: str
    label: str = ''
    comment: str = ''


class SearchDevices(BaseModel):
    count: int
    items: list[SearchDevice]


class SearchIpamRecord(BaseModel):
    ip: str
    name: str
    mac: str = ''
    comment: str = ''


class SearchIpamRecords(BaseModel):
    count: int
    items: list[SearchIpamRecord]


class Search(BaseModel):
    query: str
    kind: str                               # ip, network, mac, text
    records: SearchRecords
    reservations: SearchReservations
    leases: SearchLeases
    zones: SearchZones
    subnets: SearchSubnets
    devices: Optional[SearchDevices] = None  # IPAM devices whose label or comment matches (a text query)
    ipam: Optional[SearchIpamRecords] = None  # IPAM records (names kept in IPAM only) the query matches
    address: Optional[SearchAddress] = None  # an IP query: everything about that address
    skipped: list[str] = []                 # dynamic zones (and 'leases') a short query didn't read
    errors: list[str] = []


# ── IPAM ───────────────────────────────────────────────────────────────────────

class IpamRange(BaseModel):
    id: Optional[int] = None                # none: a DHCP pool (read-only, from the subnet)
    first: str
    last: str
    kind: str                               # static, infrastructure, reserved, other, dhcp
    name: str = ''
    comment: str = ''
    dhcp_subnet: Optional[int] = None


class IpamNetwork(BaseModel):
    id: int
    prefix: str
    name: str = ''
    comment: str = ''
    sweep: str = 'off'                      # off, hourly, daily
    swept_at: Optional[str] = None
    parent: Optional[int] = None            # the smallest network holding it (worked out, not stored)
    container: bool                         # it holds other networks, and no addresses of its own
    children: list[int] = []
    used: Optional[int] = None              # a leaf's used host addresses
    usable: int


class IpamNetworkDetail(IpamNetwork):
    ranges: list[IpamRange] = []


class IpamNetworkIn(BaseModel):
    prefix: str
    name: str = ''
    comment: str = ''
    sweep: str = 'off'


class IpamNetworkPatch(BaseModel):
    """Only the fields sent change; the prefix doesn't."""
    name: Optional[str] = None
    comment: Optional[str] = None
    sweep: Optional[str] = None


class IpamRangeIn(BaseModel):
    first: str
    last: str
    kind: str = 'static'                    # static, infrastructure, reserved, other
    name: str = ''
    comment: str = ''


class IpamRangePatch(BaseModel):
    first: Optional[str] = None
    last: Optional[str] = None
    kind: Optional[str] = None
    name: Optional[str] = None
    comment: Optional[str] = None


class IpamAddress(BaseModel):
    ip: str
    state: str                              # reserved, named, leased, dns, seen, free
    names: list[str] = []                   # A records pointing at it
    ipam_name: Optional[str] = None         # its IPAM record's name
    rdns: Optional[str] = None              # the name its PTR at the resolver gives (Settings → IPAM)
    ptr: list[str] = []
    mac: str = ''
    vendor: str = ''                        # with the device's label first, when it has one
    hostname: str = ''                      # the reservation's or lease's
    range: Optional[str] = None
    comment: str = ''
    comment_from: Optional[str] = None      # where the comment lives: dns, reservation, ipam, note
    last_seen: Optional[str] = None
    flapping: bool = False
    checks: list[SearchCheck] = []


class IpamAddresses(BaseModel):
    network: str
    page: int                               # one /24 per page, from 0
    pages: int
    items: list[IpamAddress]


class IpamSeen(BaseModel):
    ip: str
    mac: str
    vendor: str = ''
    first_seen: str
    last_seen: str
    node: Optional[str] = None
    source: str                             # neigh, sweep, probe
    repeater: bool = False                  # the MAC is marked as a Wi-Fi repeater's


class IpamFlapping(BaseModel):
    ip: str
    changes: int
    macs: list[str]
    last_at: str


class IpamDevice(BaseModel):
    mac: str
    label: str = ''
    comment: str = ''
    repeater: bool = False                  # a Wi-Fi repeater's MAC: it stands in for the devices behind it
    vendor: str = ''
    seen: list[IpamSeen] = []


class IpamDeviceIn(BaseModel):
    label: str = ''
    comment: str = ''
    repeater: Optional[bool] = None         # left out: as it was


class NextFreeIn(BaseModel):
    network: Optional[str] = None           # an IPAM network: its id or prefix
    range: Optional[int] = None             # an IPAM range's id
    subnet: Optional[str] = None            # a DHCP subnet (id or prefix): outside its pools, for a reservation
    count: int = 1                          # a block of contiguous addresses, 1 to 64
    align: bool = False                     # the block starts on a multiple of count
    hold: bool = True
    minutes: int = 10                       # how long the hold lasts
    note: str = ''


class NextFree(BaseModel):
    ips: list[str]
    checked: bool                           # probed on the network (false: no node is on it)
    node: Optional[str] = None
    probed: dict = {}                       # {ip: {replied, rtt_ms, state, mac, confirmed}}
    hold_id: Optional[str] = None
    hold_until: Optional[str] = None
    warnings: list[str] = []


class AssignIn(BaseModel):
    ip: Optional[str] = None
    ips: Optional[list[str]] = None         # a block: name needs {n} (counts from 1)
    name: str                               # host, host.zone, or k8s-{n}
    zone: Optional[str] = None              # default: the longest zone holding name
    mac: Optional[str] = None               # with a MAC (one per address in macs): a DHCP reservation
    macs: Optional[list[str]] = None
    comment: str = ''
    group: str = ''                         # a tag to unassign the lot by
    publish: bool = True                    # publish the zones changed (static records)
    target: Optional[str] = None            # dns (A records), or ipam: IPAM records, the default with DNS off


class Assigned(BaseModel):
    kind: str                               # static, reservation, ipam, or mixed (see kinds)
    kinds: list[str] = []                   # per address
    ips: list[str]
    names: list[str]
    jobs: list[int] = []
    notes: list[str] = []
    warnings: list[str] = []


class IpamName(BaseModel):
    ip: str
    name: str
    mac: str = ''
    comment: str = ''
    username: Optional[str] = None
    created_at: Optional[str] = None


class IpamNameIn(BaseModel):
    name: str                               # a host name, short or in full
    mac: str = ''                           # optional: the device that should be here
    comment: str = ''


class UnassignIn(BaseModel):
    ips: Optional[list[str]] = None
    range: Optional[str] = None             # 192.168.1.80-192.168.1.83
    group: Optional[str] = None
    publish: bool = True


class Unassigned(BaseModel):
    removed: list[str]
    skipped: list[str] = []                 # not made by assign: left alone
    jobs: list[int] = []
    notes: list[str] = []
    warnings: list[str] = []


class Released(BaseModel):
    released: list[str]
