"""Search: one query across every zone's records, the DHCP reservations and leases, the zones and subnets.

A query is read once as an IPv4 address, a network, a MAC (full or partial) or plain text, and each kind
matches what it can: an address matches A records and PTR owners exactly, text matches names, values and
comments as a substring. Static zones are searched as the grid shows them (the draft if there is one);
dynamic zones and leases are read live, falling back to the zone's history when its primary doesn't answer.

For one address, address() puts together everything about it (names, PTR, reservation, lease, subnet) and
says what doesn't add up: the seed of IPAM.
"""

import functools
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.name
import dns.query
import dns.reversename
import dns.zone

from .dhcp import leases as lease_mod
from .dhcp import model as dhcp_model
from .dns import dynamic, ptr
from .dns.drafts import Drafts
from .dns.repo import Repo
from .dns.zonefile import Zone, ZoneParseError
from .ipam.checks import address_checks

MIN_LENGTH = 2
LIVE_LENGTH = 3          # shorter queries skip Kea and the dynamic zones' transfers (the top bar box)
LIMIT = 200
TRANSFER_TIMEOUT = 5.0
NAME_TYPES = ('CNAME', 'DNAME', 'NS', 'PTR', 'MX', 'SRV')       # their last field is a name

_MAC = re.compile(r'(?i)^(?:[0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2})+|[0-9a-f]{4}(?:\.[0-9a-f]{4})+|[0-9a-f]{12})$')
KINDS = {'ip': 'an IP address', 'network': 'a network', 'mac': 'a MAC address', 'text': 'text'}


@dataclass
class Query:
    text: str
    kind: str                       # ip, network, mac, text
    ip: Optional[ipaddress.IPv4Address] = None
    network: Optional[ipaddress.IPv4Network] = None
    mac: str = ''                   # bare lowercase hex
    needle: str = ''                # lowercase, no trailing dot

    @property
    def label(self):
        return KINDS[self.kind]

    @property
    def live(self):
        return len(self.text) >= LIVE_LENGTH


def parse(q):
    """The query, or None when it's too short to search."""
    text = (q or '').strip()
    if len(text) < MIN_LENGTH:
        return None
    needle = text.lower().rstrip('.') or text.lower()
    if '/' in text:
        try:
            return Query(text, 'network', network=ipaddress.IPv4Network(text, strict=False), needle=needle)
        except ValueError:
            pass
    try:
        return Query(text, 'ip', ip=ipaddress.IPv4Address(text), needle=needle)
    except ValueError:
        pass
    # 'cafe' or 'beef' alone is a name more often than a MAC: a MAC has separators, or all 12 digits
    if _MAC.match(text) and (not text.isalnum() or len(text) == 12):
        return Query(text, 'mac', mac=bare_mac(text, partial=True), needle=needle)
    return Query(text, 'text', needle=needle)


def bare_mac(mac, partial=False):
    """'52:54:0:a:b:c' → '5254000a0b0c'. partial: a query still being typed, whose last part isn't padded."""
    mac = (mac or '').lower()
    if not re.search(r'[:-]', mac):
        return re.sub(r'[^0-9a-f]', '', mac)
    parts = [p for p in re.split(r'[:-]', mac) if p]
    return ''.join(p.zfill(2) if not partial or i < len(parts) - 1 else p for i, p in enumerate(parts))


# ── what a zone holds, indexed once per text ───────────────────────────────────

@dataclass(frozen=True)
class Rec:
    id: int
    name: str                       # relative to the zone, '@' for the apex
    fqdn: str                       # lowercase, no trailing dot
    rtype: str
    rdata: str
    comment: str
    address: Optional[ipaddress.IPv4Address]        # an A record's address, or a PTR owner's
    target: str                     # a name-valued record's target, absolute, lowercase, no trailing dot


@functools.lru_cache(maxsize=256)
def _index(text, origin):
    """(records, error) for a zone's text (cached: the same text is searched again and again)."""
    try:
        zone = Zone.parse(text, origin)
    except ZoneParseError as e:
        return (), str(e)
    out = []
    for r in zone.records():
        address = None
        if r.rtype == 'A':
            address = _v4(r.rdata)
        elif r.rtype == 'PTR':
            try:
                address = _v4(dns.reversename.to_address(r.name))
            except (dns.exception.DNSException, ValueError):
                pass
        target = ''
        if r.rtype in NAME_TYPES and r.rdata.split():
            try:
                target = dns.name.from_text(r.rdata.split()[-1], r.origin).to_text().rstrip('.').lower()
            except dns.exception.DNSException:
                pass
        out.append(Rec(r.id, r.relative_name(zone.origin), r.name.to_text().rstrip('.').lower(), r.rtype,
                       r.rdata, r.comment or '', address, target))
    return tuple(out), None


def _v4(text):
    try:
        a = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    return a if a.version == 4 else None


def _word(ip):
    """A pattern for an address inside text (an SPF record, a comment) that 10.0.0.1 doesn't match in 10.0.0.10."""
    return re.compile(r'(?<![\d.])' + re.escape(str(ip)) + r'(?![\d]|\.\d)')


def matches(query, rec):
    if query.kind == 'ip':
        return rec.address == query.ip or bool(_word(query.ip).search(rec.rdata + ' ' + rec.comment))
    if query.kind == 'network':
        return rec.address is not None and rec.address in query.network
    n = query.needle
    return (n in rec.fqdn or n in rec.rdata.lower() or (rec.target and n in rec.target)
            or n in rec.comment.lower())


# ── the search ─────────────────────────────────────────────────────────────────

@dataclass
class Group:
    hits: list = field(default_factory=list)
    count: int = 0

    def add(self, hit, limit):
        self.count += 1
        if len(self.hits) < limit:
            self.hits.append(hit)

    @property
    def cut(self):
        return self.count > len(self.hits)


@dataclass
class Results:
    query: Query
    records: Group = field(default_factory=Group)
    reservations: Group = field(default_factory=Group)
    leases: Group = field(default_factory=Group)
    zones: Group = field(default_factory=Group)
    subnets: Group = field(default_factory=Group)
    devices: Group = field(default_factory=Group)    # IPAM device labels and comments
    ipam: Group = field(default_factory=Group)       # IPAM records (names kept in IPAM only)
    errors: list = field(default_factory=list)
    stale: dict = field(default_factory=dict)       # dynamic zone → the time of the history copy searched
    skipped: list = field(default_factory=list)     # what a short query didn't search
    address: Optional[dict] = None
    limit: int = LIMIT

    @property
    def empty(self):
        return not any(g.count for g in (self.records, self.reservations, self.leases, self.zones, self.subnets,
                                         self.devices, self.ipam))


def search(conn, settings, q, limit=LIMIT, transfer=None):
    """Results for q, or None when q is too short. transfer: dynamic.axfr's, for tests."""
    query = parse(q)
    if query is None:
        return None
    res = Results(query, limit=limit)
    zones = conn.execute('SELECT * FROM zones ORDER BY name').fetchall()
    _records(conn, settings, res, zones, transfer)
    _zones(res, zones)
    subnets = dhcp_model.subnets(conn)
    _reservations(res, subnets)
    _subnets(res, subnets)
    from .modules import enabled
    ipam_on = enabled(conn)['ipam']
    if ipam_on and query.kind == 'text' and query.needle:
        from .ipam.devices import matching
        for d in matching(conn, query.needle):
            res.devices.add(d, res.limit)
    if ipam_on:
        from .ipam import names
        for r in names.matching(conn, query):
            res.ipam.add(r, res.limit)
    if query.live:
        found, errors = lease_mod.serving_leases(settings, conn)
        res.errors += [f"Leases: {e}" for e in errors]
        _leases(res, found, subnets)
        _named(res, subnets)
    elif lease_mod.serving(conn):
        res.skipped.append('leases')
    if query.kind == 'ip':
        res.address = address(res, subnets, [z['name'] for z in zones],
                              **(_learned(conn, settings, query.ip) if ipam_on else {}))
    return res


def _learned(conn, settings, ip):
    """What IPAM knows of an address beyond DNS and DHCP: what the nodes saw there, its MAC changes, whether it
    flaps, its network and range, its IPAM record and its PTR at the resolver (looked up again, in the background,
    when that's old)."""
    from .ipam import devices, model, names, ptr as rdns, seen
    found = seen.at_address(conn, ip)
    net = model.leaf_for(model.networks(conn), ip)
    ranges = model.ranges(conn, net.id) if net and not net.container else []
    rdns.refresh_later(settings, conn, [ip])
    return {'ipam': names.get(conn, ip), 'rdns': rdns.get(conn, ip), 'resolver': rdns.config(conn)[0],
            'seen': found, 'changes': seen.changes_at(conn, ip),
            'flapping': next((f for f in seen.flapping(conn) if f['ip'] == str(ip)), None),
            'expected': seen.expected(conn).get(str(ip)), 'network': net,
            'range': next((r for r in ranges if ip in r), None), 'repeaters': devices.repeaters(conn)}


def _records(conn, settings, res, zones, transfer):
    drafts = Drafts(settings)
    down = set()                # primaries that didn't answer: the rest of their zones come from history
    for z in zones:
        if z['kind'] == 'forwarding':
            continue
        draft = False
        if z['dynamic']:
            if not res.query.live:
                res.skipped.append(z['name'])
                continue
            text = _dynamic_text(conn, settings, res, z, down, transfer)
            if text is None:
                continue
        else:
            text, draft = drafts.load(z)
        recs, error = _index(text, z['name'] + '.')
        if error:
            res.errors.append(f"{z['name']} doesn't parse ({error}), so it wasn't searched")
        for r in recs:
            if matches(res.query, r):
                res.records.add({'zone': z['name'], 'rec': r, 'draft': draft, 'dynamic': bool(z['dynamic'])},
                                res.limit)


def _dynamic_text(conn, settings, res, z, down, transfer):
    try:
        host = dynamic.primary_host(conn, z)
    except dynamic.DynamicError:
        host = None
    if host and host not in down and not _known_down(conn, z):
        try:
            return dynamic.axfr(conn, z, transfer=transfer or _transfer)
        except dynamic.DynamicError:
            down.add(host)
    # the primary didn't answer: the newest copy in the zone's history (LiteBlox's own edits and a daily snapshot)
    repo = Repo(settings.repo_dir)
    text = repo.read(z['repo_file']) if z['repo_file'] else None
    if text is None:
        res.errors.append(f"{z['name']}: its primary didn't answer and it has no history yet, so it wasn't searched")
        return None
    log = repo.log(z['repo_file'], limit=1)
    res.stale[z['name']] = log[0]['date'] if log else ''
    return text


def _known_down(conn, z):
    """True when the health check already found the zone's primary unreachable (no point waiting for it)."""
    row = conn.execute("SELECT n.status FROM nodes n JOIN zone_nodes zn ON zn.node_id = n.id "
                       "WHERE zn.zone_id = ? AND n.role = 'primary'", (z['id'],)).fetchone()
    return row is not None and row['status'] == 'error'


def _transfer(host, name, keyring, algorithm):
    """dynamic.axfr's transfer, with a shorter wait than an edit can afford."""
    return dns.zone.from_xfr(dns.query.xfr(host, name, keyring=keyring, keyname=next(iter(keyring)),
                                           keyalgorithm=algorithm, lifetime=TRANSFER_TIMEOUT))


def _zones(res, zones):
    q = res.query
    for z in zones:
        net = reverse_network(z['name'])
        if q.kind == 'ip':
            hit = net is not None and q.ip in net
        elif q.kind == 'network':
            hit = net is not None and net.overlaps(q.network)
        else:
            hit = (q.needle in z['name'] or q.needle in (z['notes'] or '').lower()
                   or (z['kind'] == 'forwarding' and q.needle in (z['forwarders'] or '').lower()))
        if hit:
            res.zones.add({'zone': z, 'network': net}, res.limit)


def reverse_network(zone_name):
    """The IPv4 network a reverse zone covers (1.168.192.in-addr.arpa → 192.168.1.0/24), or None."""
    if not zone_name.endswith('.in-addr.arpa'):
        return None
    labels = zone_name[:-len('.in-addr.arpa')].split('.')
    if not 1 <= len(labels) <= 4 or not all(p.isdigit() and int(p) < 256 for p in labels):
        return None
    octets = list(reversed(labels))
    return ipaddress.IPv4Network('.'.join(octets + ['0'] * (4 - len(octets))) + f'/{8 * len(octets)}')


def _mac_hit(q, mac):
    if q.kind == 'mac':
        return q.mac in bare_mac(mac)
    return q.kind == 'text' and q.needle in (mac or '').lower()


def _reservations(res, subnets):
    q = res.query
    for s in subnets:
        for r in s.reservations:
            ip = _v4(r.ip_address)
            if q.kind == 'ip':
                hit = ip == q.ip
            elif q.kind == 'network':
                hit = ip is not None and ip in q.network
            else:
                hit = (_mac_hit(q, r.hw_address) or q.needle in r.ip_address
                       or q.needle in (r.hostname or '').lower() or q.needle in (r.comment or '').lower())
            if hit:
                res.reservations.add({'subnet': s, 'r': r}, res.limit)


def _named(res, subnets):
    """An address or network search also finds a name-only reservation through its client's active lease there."""
    if res.query.kind not in ('ip', 'network'):
        return
    named = {(s.id, r.hw_address.lower()): (s, r) for s in subnets for r in s.reservations if not r.ip_address}
    have = {id(h['r']) for h in res.reservations.hits}
    for h in res.leases.hits:
        x = h['lease']
        sr = named.get((x['subnet_id'], x['mac'].lower())) if x['state'] == 'active' else None
        if sr and id(sr[1]) not in have:
            have.add(id(sr[1]))
            res.reservations.add({'subnet': sr[0], 'r': sr[1]}, res.limit)


def _leases(res, found, subnets):
    q = res.query
    by_id = {s.id: s for s in subnets}
    full_mac = q.kind == 'mac' and len(q.mac) == 12
    for node, lease in found:
        ip = _v4(lease['ip'])
        if q.kind == 'ip':
            hit = ip == q.ip
        elif q.kind == 'network':
            hit = ip is not None and ip in q.network
        else:
            hit = (_mac_hit(q, lease['mac']) or q.needle in lease['ip']
                   or q.needle in (lease['hostname'] or '').lower())
        # expired and released leases linger in Kea: only an exact address or MAC shows them
        if hit and (lease['state'] == 'active' or q.kind == 'ip' or full_mac):
            res.leases.add({'node': node, 'lease': lease, 'subnet': by_id.get(lease['subnet_id'])}, res.limit)


def _subnets(res, subnets):
    q = res.query
    for s in subnets:
        try:
            net = ipaddress.IPv4Network(s.prefix, strict=False)
        except ValueError:
            continue
        if q.kind == 'ip':
            hit = q.ip in net
        elif q.kind == 'network':
            hit = net.overlaps(q.network)
        else:
            hit = q.needle in s.prefix or q.needle in (s.comment or '').lower()
        if hit:
            res.subnets.add({'subnet': s}, res.limit)


# ── one address, put together ──────────────────────────────────────────────────

def address(res, subnets, zone_names, seen=(), changes=(), flapping=None, network=None, range=None, expected=None,
            ipam=None, rdns=None, resolver='', repeaters=frozenset()):
    """Everything about res.query.ip, from the hits already found and what IPAM learned, plus what doesn't add
    up: {ip, names, ptrs, reverse_zone, reservations, lease, subnet, in_pool, seen, changes, flapping, network,
    range, ipam, rdns, resolver, checks: [(level, text, link)]}."""
    ip = res.query.ip
    hits = res.records.hits
    names = [h for h in hits if h['rec'].rtype == 'A' and h['rec'].address == ip]
    ptrs = [h for h in hits if h['rec'].rtype == 'PTR' and h['rec'].address == ip]
    rzone = ptr.reverse_zone_for(str(ip), [n for n in zone_names if n.endswith('.in-addr.arpa')])
    reservations = [h['r'] for h in res.reservations.hits]
    held = sorted(res.leases.hits, key=lambda h: h['lease']['state'] != 'active')
    lease = held[0]['lease'] if held else None
    active = lease if lease and lease['state'] == 'active' else None
    subnet = next((s for s in subnets if _contains(s.prefix, ip)), None)
    in_pool = bool(subnet) and any(first <= ip <= last for first, last in lease_mod.pool_ranges(subnet))
    r = reservations[0] if reservations else None
    used = names or reservations or active or ipam
    latest = seen[0] if seen else None
    checks = address_checks(ip, names, ptrs, rzone, r, active, subnet, in_pool, seen=latest,
                            static_range=range is not None and range.kind == 'static', ipam=ipam, rdns=rdns,
                            repeaters=repeaters)
    return {'ip': ip, 'names': names, 'ptrs': ptrs, 'reverse_zone': rzone, 'reservations': reservations,
            'lease': lease, 'lease_node': held[0]['node'] if held else None, 'subnet': subnet, 'in_pool': in_pool,
            'used': bool(used or seen), 'checks': checks, 'seen': list(seen), 'changes': list(changes),
            'flapping': flapping, 'expected': expected, 'network': network, 'range': range, 'ipam': ipam,
            'rdns': rdns, 'resolver': resolver}


def _contains(prefix, ip):
    try:
        return ip in ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return False


# ── for the page and the API ───────────────────────────────────────────────────

def mark(text, query):
    """text, escaped, with what the query matched in it wrapped in <mark>."""
    from markupsafe import Markup, escape
    text = str(text or '')
    if query.kind == 'ip':
        pattern = _word(query.ip)
    elif query.kind in ('text', 'mac') and query.needle:
        pattern = re.compile(re.escape(query.needle), re.I)
    else:
        return escape(text)
    out, at = [], 0
    for m in pattern.finditer(text):
        out += [escape(text[at:m.start()]), Markup('<mark>'), escape(m.group()), Markup('</mark>')]
        at = m.end()
    out.append(escape(text[at:]))
    return Markup('').join(out)


def record_link(hit):
    """The zone's grid filtered to the record's name (the apex: its value)."""
    from urllib.parse import quote
    rec = hit['rec']
    return f"/zones/{hit['zone']}?filter={quote(rec.rdata if rec.name == '@' else rec.name)}"


def to_dict(res):
    q = res.query

    def group(g, fn):
        return {'count': g.count, 'items': [fn(h) for h in g.hits]}

    def rec(h):
        r = h['rec']
        return {'zone': h['zone'], 'name': r.name, 'fqdn': r.fqdn, 'type': r.rtype, 'data': r.rdata,
                'comment': r.comment, 'draft': h['draft'], 'dynamic': h['dynamic'],
                'as_of': res.stale.get(h['zone'])}

    def reservation(h):
        r = h['r']
        return {'subnet': h['subnet'].prefix, 'subnet_id': h['subnet'].id, 'id': r.id, 'ip': r.ip_address,
                'mac': r.hw_address, 'hostname': r.hostname, 'comment': r.comment}

    def lease(h):
        x = h['lease']
        return {'ip': x['ip'], 'mac': x['mac'], 'hostname': x['hostname'], 'state': x['state'],
                'expires': datetime.fromtimestamp(x['expires'], timezone.utc).isoformat(timespec='seconds'),
                'subnet_id': x['subnet_id'], 'node': h['node']['name'] if h['node'] else None}

    out = {'query': q.text, 'kind': q.kind,
           'records': group(res.records, rec), 'reservations': group(res.reservations, reservation),
           'leases': group(res.leases, lease),
           'zones': group(res.zones, lambda h: {'name': h['zone']['name'], 'kind': h['zone']['kind'],
                                                'dynamic': bool(h['zone']['dynamic'])}),
           'subnets': group(res.subnets, lambda h: {'id': h['subnet'].id, 'prefix': h['subnet'].prefix,
                                                    'comment': h['subnet'].comment}),
           'devices': group(res.devices, lambda d: {'mac': d['mac'], 'label': d['label'], 'comment': d['comment']}),
           'ipam': group(res.ipam, lambda r: {'ip': r['ip'], 'name': r['name'], 'mac': r['mac'] or '',
                                               'comment': r['comment']}),
           'skipped': res.skipped, 'errors': res.errors, 'address': None}
    a = res.address
    if a:
        out['address'] = {
            'ip': str(a['ip']), 'names': [h['rec'].fqdn for h in a['names']],
            'ptr': [h['rec'].target for h in a['ptrs']], 'reverse_zone': a['reverse_zone'],
            'reservation': reservation({'subnet': a['subnet'], 'r': a['reservations'][0]})
            if a['reservations'] and a['subnet'] else None,
            'lease': lease({'lease': a['lease'], 'node': a['lease_node']}) if a['lease'] else None,
            'subnet': a['subnet'].prefix if a['subnet'] else None, 'in_pool': a['in_pool'],
            'seen': [{'mac': x['mac'], 'first_seen': x['first_seen'], 'last_seen': x['last_seen'], 'node': x['node']}
                     for x in a['seen']], 'flapping': a['flapping'] is not None,
            'network': a['network'].prefix if a['network'] else None,
            'ipam': {'name': a['ipam']['name'], 'mac': a['ipam']['mac'] or '', 'comment': a['ipam']['comment']}
            if a['ipam'] else None,
            'rdns': {'name': a['rdns']['name'], 'error': a['rdns']['error'], 'looked_up_at': a['rdns']['looked_up_at']}
            if a['rdns'] else None,
            'checks': [{'level': lvl, 'text': text} for lvl, text, _ in a['checks']]}
    return out
