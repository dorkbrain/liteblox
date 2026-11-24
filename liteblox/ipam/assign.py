"""Assign and unassign: put names on addresses from next free, and take exactly those away again.

With a MAC, an address in a DHCP subnet gets a reservation with the name as its hostname (one DHCP job for a
block). In a subnet that registers clients Kea puts the name in DNS; elsewhere LiteBlox adds the A record too.
Without a MAC, the address gets an A record (and its PTR, per the zone's setting) in the zone's draft, published
as a job unless publish is false. With the DNS module off, or target 'ipam', names go into IPAM records instead
(names.py: nothing in DNS; a MAC in a DHCP subnet still makes a reservation, one outside them stays on the
record). What assign made is kept in ipam_assignments, so unassign removes only that.
"""

import ipaddress
import time

from .free import FreeError


def _ips(values):
    out = []
    for v in values or []:
        try:
            ip = str(ipaddress.IPv4Address(str(v).strip()))
        except ValueError:
            if ':' in str(v):
                raise FreeError(f'{v}: assign takes IPv4 addresses. Name an IPv6 address with Add DNS (an AAAA '
                                'record), a DHCPv6 reservation, or an IPAM name')
            raise FreeError(f'{v} is not an IPv4 address')
        if ip in out:
            raise FreeError(f'{ip} is given twice')
        out.append(ip)
    if not out:
        raise FreeError('give an address')
    if len(out) > 64:
        raise FreeError('64 addresses at most')
    return out


def _names(template, count):
    template = (template or '').strip().rstrip('.').lower()
    if not template:
        raise FreeError('give a name')
    if count > 1 and '{n}' not in template:
        raise FreeError("a block needs {n} in its name, e.g. k8s-{n}: it counts from 1")
    return [template.replace('{n}', str(i + 1)) for i in range(count)]


def _fqdn(conn, name, zone):
    """(fqdn, zone) for a name: short + zone, or a full name in its longest-matching zone."""
    from ..dhcp.leases import dns_zone
    zone = (zone or '').strip().rstrip('.').lower() or None
    if zone and not conn.execute('SELECT 1 FROM zones WHERE name = ?', (zone,)).fetchone():
        raise FreeError(f'no zone {zone}', 404)
    if zone and not (name == zone or name.endswith('.' + zone)):
        name = f'{name}.{zone}'
    zone = zone or dns_zone(conn, name)
    if zone is None:
        raise FreeError(f'{name}: no zone in LiteBlox holds it (give zone, or a full name)')
    return name, zone


def _subnet_for(subnets, ip):
    a = ipaddress.IPv4Address(ip)
    return next((s for s in subnets if a in ipaddress.IPv4Network(s.prefix)), None)


def _publish(settings, conn, zones, username, via, message):
    """A publish job per static zone (each takes its linked reverse zones along). Returns (jobs, warnings)."""
    from .. import jobs
    from ..dns import publish as pub
    from ..nodes import roles
    out, warnings = [], []
    for z in sorted(zones):
        row = conn.execute('SELECT * FROM zones WHERE name = ?', (z,)).fetchone()
        if row is None or row['dynamic']:
            continue
        if pub.running(conn, row['id']) or roles.busy():
            warnings.append(f"{z}: a publish or role change is running, so it isn't published: publish it after")
            continue
        out.append(jobs.start(settings.db_path, 'publish',
                              lambda log, job_id, z=z: pub.publish(settings, z, username, log, job_id=job_id,
                                                                   linked=True, message=message),
                              username=username, zone_id=row['id']))
    return out, warnings


def _published(notes, zones):
    """The notes without "… is sent when you publish <zone>" for the zones just published."""
    return [n for n in notes if not any(n.endswith(f'when you publish {z}') for z in zones)]


def _add_records(settings, conn, items, comment, username, via):
    """A records (with their PTRs, per each zone's setting) into the drafts. Returns (zones, notes, warnings)."""
    from ..dns import editing, records
    zones, notes, warnings = set(), [], []
    for it in items:
        with editing.zone_lock(it['zone']):
            edit = editing.ZoneEdit(settings, conn, it['zone'])
            if edit.zone is None:
                raise FreeError(f"{it['zone']} doesn't parse; fix it on its Raw tab", 409)
            try:
                n, w, _ = editing.apply_row(edit, None, it['fqdn'] + '.', None, 'A', it['ip'], comment or None,
                                            bool(edit.row['auto_ptr']), None, username, via)
            except records.RecordError as e:
                raise FreeError(f"{it['fqdn']}: {'; '.join(f'{k}: {v}' for k, v in e.errors.items())}")
        zones.add(it['zone'])
        notes += n
        warnings += w
    return zones, notes, warnings


def _ipam_name(name, zone):
    from .model import IpamError
    from .names import clean_name
    if zone and not (name == zone or name.endswith('.' + zone)):
        name = f'{name}.{zone}'
    try:
        return clean_name(name)
    except IpamError as e:
        raise FreeError(str(e))


def assign(conn, settings, ips, name, zone=None, macs=None, comment='', group='', publish=True, username=None,
           via='', target=None):
    """{kind, kinds, ips, names, jobs, notes, warnings}. With macs (one per address), reservations; without, A
    records. target 'ipam' (the default with the DNS module off): IPAM records instead of A records."""
    from ..db import audit
    from ..dhcp import ops, validate
    from ..dhcp.model import Reservation, subnets as dhcp_subnets
    from ..dhcp.validate import normalize_mac
    from ..modules import enabled
    from .free import release
    dns_on = enabled(conn)['dns']
    if target not in (None, '', 'dns', 'ipam'):
        raise FreeError(f'target is dns or ipam, not {target}')
    if target == 'dns' and not dns_on:
        raise FreeError('the DNS module is off (Settings → Modules): leave out target, or give ipam', 404)
    to_ipam = target == 'ipam' or not dns_on
    zone = (zone or '').strip().rstrip('.').lower() or None
    ips = _ips(ips)
    names = _names(name, len(ips))
    macs = list(macs or [])
    if macs and len(macs) != len(ips):
        raise FreeError('give one MAC per address')
    held = [r['ip'] for r in conn.execute(f"SELECT ip FROM ipam_assignments WHERE ip IN ({','.join('?' * len(ips))})",
                                          ips)]
    if held:
        raise FreeError(f"already assigned: {', '.join(held)} (unassign first)", 409)
    group, comment = (group or '').strip()[:64], (comment or '').strip()[:200]
    subnets = dhcp_subnets(conn)
    items, adds, jobs, notes, warnings = [], [], [], [], []
    for i, ip in enumerate(ips):
        it = {'ip': ip, 'name': names[i], 'mac': None, 'subnet': None, 'zone': None, 'fqdn': None, 'kind': 'static'}
        s = _subnet_for(subnets, ip) if macs else None
        if macs and s is None and to_ipam:          # no DHCP here: the MAC stays on the IPAM record
            it['mac'] = normalize_mac(macs[i])
            if it['mac'] is None:
                raise FreeError(f'{ip}: {macs[i]} is not a MAC address')
            it['kind'], it['name'] = 'ipam', _ipam_name(names[i], zone)
        elif macs:
            if s is None:
                raise FreeError(f'{ip} is in no DHCP subnet, so it takes no reservation (leave out the MAC)')
            it['subnet'], it['mac'], it['kind'] = s, macs[i], 'reservation'
            if not s.registers and not to_ipam:    # Kea won't register it: LiteBlox adds the A record
                it['fqdn'], it['zone'] = _fqdn(conn, names[i], zone)
        elif to_ipam:
            it['kind'], it['name'] = 'ipam', _ipam_name(names[i], zone)
        else:
            it['fqdn'], it['zone'] = _fqdn(conn, names[i], zone)
        items.append(it)
    if any(it['subnet'] for it in items):
        served = ops.dhcp_interfaces(settings, conn)
        errors = {}
        for it in items:
            if it['subnet'] is None:
                continue
            s = it['subnet']
            r = Reservation(None, s.id, it['mac'], it['ip'], it['name'].split('.')[0], comment=comment)
            mine = [a for a in adds if a.subnet_id == s.id]
            s.reservations = list(s.reservations) + mine
            e, w = validate.check_reservation(r, s, served)
            s.reservations = [x for x in s.reservations if x not in mine]
            if e:
                errors[it['ip']] = '; '.join(f'{k}: {v}' for k, v in e.items())
            warnings += w
            it['mac'] = r.hw_address
            adds.append(r)
        if errors:
            raise FreeError('; '.join(f'{ip}: {e}' for ip, e in errors.items()))
    if adds and ops.busy(conn):          # before any record is added, so a refusal leaves nothing half done
        raise FreeError('another DHCP change is still running; try again when its job has finished', 409)
    statics = [it for it in items if it['fqdn']]
    zones, n, w = _add_records(settings, conn, statics, comment, username, via) if statics else (set(), [], [])
    notes, warnings = notes + n, warnings + w
    if adds:
        try:
            jobs.append(ops.start_reservations(settings, conn, add=adds, username=username,
                                               reason=f"assign {', '.join(ips)} ({', '.join(names)}){via}"))
        except ops.Busy as e:
            raise FreeError(str(e), 409)
    if zones and publish:
        j, w = _publish(settings, conn, zones, username, via, f"assign {', '.join(names)}")
        jobs, warnings, notes = jobs + j, warnings + w, _published(notes, zones)
    now = int(time.time())
    with conn:
        conn.executemany('INSERT INTO ipam_assignments (ip, grp, kind, name, zone, subnet_id, mac, comment, username, '
                         'created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                         [(it['ip'], group, it['kind'], it['fqdn'] or it['name'],
                           it['zone'], it['subnet'].id if it['subnet'] else None, it['mac'], comment, username, now)
                          for it in items])
        # one comment per address: an IPAM note there gives way to the record's
        conn.executemany('DELETE FROM ipam_notes WHERE ip = ?', [(it['ip'],) for it in items if it['kind'] == 'ipam'])
    for ip in ips:
        release(conn, ip=ip)
    audit(conn, username, 'ipam_assign', f"{', '.join(ips)}: {', '.join(names)}{' [' + group + ']' if group else ''}{via}")
    kinds = [it['kind'] for it in items]
    return {'kind': kinds[0] if len(set(kinds)) == 1 else 'mixed', 'kinds': kinds, 'ips': ips,
            'names': [it['fqdn'] or it['name'] for it in items], 'jobs': jobs, 'notes': notes, 'warnings': warnings}


def assignments(conn, ips=None, group=None):
    if group:
        return [dict(r) for r in conn.execute('SELECT * FROM ipam_assignments WHERE grp = ? ORDER BY ip', (group,))]
    rows = conn.execute(f"SELECT * FROM ipam_assignments WHERE ip IN ({','.join('?' * len(ips))})", ips).fetchall()
    return [dict(r) for r in rows]


def expand(text):
    """'192.0.2.10-192.0.2.13' (or '-13') → the addresses in it."""
    a, _, b = (text or '').partition('-')
    try:
        first = ipaddress.IPv4Address(a.strip())
        last = (ipaddress.IPv4Address(b.strip()) if '.' in b else
                ipaddress.IPv4Address(int(first) - int(first) % 256 + int(b.strip())))
    except ValueError:
        raise FreeError(f'{text} is not a range like 192.0.2.10-192.0.2.13')
    if last < first or int(last) - int(first) >= 256:
        raise FreeError(f'{text}: the last address comes after the first, 256 addresses at most')
    return [str(ipaddress.IPv4Address(n)) for n in range(int(first), int(last) + 1)]


def unassign(conn, settings, ips=None, group=None, publish=True, username=None, via=''):
    """Remove what assign made for these addresses (or this group): {removed, skipped, jobs, notes, warnings}.
    An address assign didn't make is skipped: records and reservations made elsewhere are never touched."""
    from ..db import audit
    from ..dhcp import ops
    from ..dhcp.model import subnets as dhcp_subnets
    from ..dns import editing
    from .free import release
    if group:
        rows = assignments(conn, group=group.strip())
        wanted = [r['ip'] for r in rows]
    else:
        wanted = _ips(ips)
        rows = assignments(conn, ips=wanted)
    if not rows:
        return {'removed': [], 'skipped': wanted, 'jobs': [], 'notes': [], 'warnings': []}
    found = {r['ip'] for r in rows}
    if any(r['kind'] == 'reservation' for r in rows) and ops.busy(conn):     # before any record is removed
        raise FreeError('another DHCP change is still running; try again when its job has finished', 409)
    notes, warnings, jobs, zones = [], [], [], set()
    for r in rows:
        if not r['zone']:
            continue
        with editing.zone_lock(r['zone']):
            try:
                edit = editing.ZoneEdit(settings, conn, r['zone'])
            except editing.NoSuchZone:
                notes.append(f"{r['ip']}: {r['zone']} is gone")
                continue
            rec = next((x for x in (edit.zone.records() if edit.zone else []) if x.rtype == 'A'
                        and x.name.to_text().rstrip('.').lower() == r['name'] and x.rdata.strip() == r['ip']), None)
            if rec is None:
                notes.append(f"{r['ip']}: {r['name']} wasn't in {r['zone']} any more")
                continue
            n, w = editing.delete_row(edit, rec, bool(edit.row['auto_ptr']), username, via)
            notes, warnings = notes + n, warnings + w
            zones.add(r['zone'])
    by_subnet = {s.id: s for s in dhcp_subnets(conn)}
    gone = []
    for r in rows:
        if r['kind'] != 'reservation':
            continue
        s = by_subnet.get(r['subnet_id'])
        res = next((x for x in (s.reservations if s else []) if x.hw_address == r['mac'] and x.ip_address == r['ip']),
                   None)
        if res is None:
            notes.append(f"{r['ip']}: its reservation for {r['mac']} wasn't there any more")
        else:
            gone.append(res)
    if gone:
        try:
            jobs.append(ops.start_reservations(settings, conn, delete=gone, username=username,
                                               reason=f"unassign {', '.join(r.ip_address for r in gone)}{via}"))
        except ops.Busy as e:
            raise FreeError(str(e), 409)
    if zones and publish:
        j, w = _publish(settings, conn, zones, username, via, f"unassign {', '.join(sorted(found))}")
        jobs, warnings, notes = jobs + j, warnings + w, _published(notes, zones)
    with conn:
        conn.executemany('DELETE FROM ipam_assignments WHERE ip = ?', [(ip,) for ip in found])
    for ip in found:
        release(conn, ip=ip)
    removed = sorted(found, key=ipaddress.IPv4Address)
    audit(conn, username, 'ipam_unassign', f"{', '.join(removed)}{' [' + group + ']' if group else ''}{via}")
    return {'removed': removed, 'skipped': [ip for ip in wanted if ip not in found], 'jobs': jobs, 'notes': notes,
            'warnings': warnings}
