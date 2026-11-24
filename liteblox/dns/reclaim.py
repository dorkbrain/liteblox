"""Stale DHCP names: the names Kea registered in a dynamic zone (an A or AAAA record with a DHCID beside it) whose
lease is long gone, and reclaiming them.

Kea removes a name when its lease expires and is reclaimed, but a name stays when that update was lost (the
primary was down, a promote happened, Kea's lease file was reset). Kea forgets expired leases after an hour, and
DNS records carry no expiry, so LiteBlox remembers per name the last lease expiry it saw (remember(), from the
health check's minutely lease read) or, failing that, when it first saw the name without a lease.

A name is stale when no live lease has its name or address, no reservation has either, and now > leaseexp +
grace (grace: the zone's "reclaim after", by default the longest lease time of the subnets registering into
it). With IPAM on and its keep_seen_names setting, a name whose address the nodes saw within the grace stays.
Names nobody gave a DHCID (typed in, ACME, another key's) are never stale.

Stale PTRs: a PTR Kea made (a DHCID beside it) in a LiteBlox dynamic reverse zone, pointing at a name in this zone
that has no A/AAAA for that address any more. Kea before 3.3.1 leaves the PTR when one family of a dual-stack name
goes, and a lost update can leave one too. One is stale when no live lease and no reservation has its address and
it has been that way longer than the zone's grace (a clock in ddns_names, keyed by the PTR's owner).

pass_due() runs from the scheduler for zones with reclamation on, at most hourly; it deletes nothing while DHCP
isn't healthy (a server down, the pair not in hot-standby, a lease read failing) or when too many names would go
at once (it says so in Needs attention instead).
"""

import ipaddress
import time

import dns.exception
import dns.name
import dns.reversename

from ..db import audit

KEA_VALID = 7200            # Kea's own default valid-lifetime
EVERY = 3600                # a zone's pass, at most this often
SHARE = 0.25                # more than this share of a zone's DHCP names going at once holds the pass back...
AT_LEAST = 4                # ...when that's at least this many names


def _fqdn(name):
    return str(name).rstrip('.').lower()


# ── what Kea's leases say ──────────────────────────────────────────────────────

def remember(conn, found):
    """From a lease read that had no errors: per hostname, its newest lease expiry and address."""
    best = {}
    for _, lease in found:
        name = _fqdn(lease.get('hostname') or '')
        if name and lease.get('expires') and lease['expires'] > best.get(name, (0, None))[0]:
            best[name] = (int(lease['expires']), lease['ip'])
    if not best:
        return
    with conn:
        conn.executemany(
            'INSERT INTO ddns_names (name, address, last_expiry) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET '
            'address = CASE WHEN excluded.last_expiry >= COALESCE(last_expiry, 0) THEN excluded.address ELSE address END, '
            'last_expiry = MAX(COALESCE(last_expiry, 0), excluded.last_expiry)',
            [(name, ip, exp) for name, (exp, ip) in best.items()])


def serves_v6(conn):
    """A DHCPv6 subnet exists and a serving node runs kea-dhcp6."""
    from ..dhcp import leases as lease_mod
    from ..dhcp.model import has_dhcp6
    return (conn.execute('SELECT 1 FROM dhcp6_subnets LIMIT 1').fetchone() is not None
            and any(has_dhcp6(n) for n in lease_mod.serving(conn)))


def all_leases(settings, conn):
    """([(node, lease)], [errors]) of both families: DHCPv6 addresses (not delegated prefixes) when v6 is served."""
    from ..dhcp import leases as lease_mod
    found, errors = lease_mod.serving_leases(settings, conn)
    found, errors = list(found), list(errors)
    if serves_v6(conn):
        found6, errors6 = lease_mod.serving_leases(settings, conn, family=6)
        found += [(n, x) for n, x in found6 if x.get('type', 'address') == 'address']
        errors += errors6
    return found, errors


def grace_default(conn, zone_row):
    """The longest lease time of the subnets registering into the zone (else the global one, else Kea's)."""
    from ..dhcp import model
    glob = model.settings(conn).valid_lifetime or KEA_VALID
    glob6 = model.settings6(conn).valid_lifetime or KEA_VALID
    times = [s.valid_lifetime or glob for s in model.subnets(conn) if s.ddns and s.ddns_zone == zone_row['name']]
    times += [s.valid_lifetime or glob6 for s in model.subnets6(conn) if s.ddns and s.ddns_zone == zone_row['name']]
    return max(times) if times else glob


def grace(conn, zone_row):
    return zone_row['reclaim_after'] or grace_default(conn, zone_row)


def dhcp_trouble(conn):
    """Why DHCP isn't healthy enough to judge names by its leases, or None."""
    from ..dhcp import model
    pair = model.ha_pair(conn)
    v6 = conn.execute('SELECT 1 FROM dhcp6_subnets LIMIT 1').fetchone() is not None
    for n in conn.execute('SELECT * FROM nodes WHERE dhcp = 1 ORDER BY name'):
        if n['status'] == 'error':
            return f"{n['name']} doesn't answer"
        if n['dhcp_sockets']:
            return f"{n['name']}: Kea isn't serving DHCP"
        if pair.active and n['dhcp_ha_state'] and n['dhcp_ha_state'] != 'hot-standby':
            return f"{n['name']}: DHCP failover is {n['dhcp_ha_state']}"
        if v6 and model.has_dhcp6(n):
            if n['dhcp6_sockets']:
                return f"{n['name']}: Kea isn't serving DHCPv6"
            if pair.active and n['dhcp6_ha_state'] and n['dhcp6_ha_state'] != 'hot-standby':
                return f"{n['name']}: DHCPv6 failover is {n['dhcp6_ha_state']}"
    return None


def _ip(text):
    """An address as one spelling (IPv6 compressed, lower case); text that isn't one as it is."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return text.strip()


# ── the rule ───────────────────────────────────────────────────────────────────

def kea_names(zone):
    """{owner Name: [its A and AAAA records]} for the owners with a DHCID record: the names Kea registered."""
    owners = {r.name for r in zone.records() if r.rtype == 'DHCID'}
    out = {}
    for r in zone.records():
        if r.rtype in ('A', 'AAAA') and r.name in owners:
            out.setdefault(r.name, []).append(r)
    return out


def _ago(seconds):
    from ..timefmt import duration
    seconds = max(0, int(seconds))
    if seconds < 60:
        return 'under a minute'
    return duration(seconds - seconds % 60 if seconds >= 120 else seconds)


def _live(leases, now):
    names, ips = set(), set()
    for _, lease in leases:
        if lease['state'] == 'active' and lease['expires'] > now:
            names.add(_fqdn(lease['hostname']))
            ips.add(_ip(lease['ip']))
    return names, ips


def _reserved(conn):
    from ..dhcp import model
    names, ips = set(), set()
    for r in list(model.reservations(conn)) + list(model.reservations6(conn)):
        if r.hostname:
            names.add(_fqdn(r.hostname))
        if r.ip_address:
            ips.add(_ip(r.ip_address))
    return names, ips


def _sorted_ips(addresses):
    return sorted(addresses, key=lambda a: (_ip_key(a), a))


def review(conn, settings, zone_row, zone, leases, now=None, notice=True):
    """Every DHCP name in the zone and its fate: [{name (Name), fqdn, addresses, stale (bool), why, since}],
    stale first. leases: [(node, lease)] of both families from a read without errors. notice: start the clock for
    a name seen without a lease for the first time (a pass does; the zone page only looks)."""
    from ..modules import enabled
    now = int(now or time.time())
    window = grace(conn, zone_row)
    live_names, live_ips = _live(leases, now)
    reserved_names, reserved_ips = _reserved(conn)
    origin = _fqdn(zone_row['name'])
    keep_seen = enabled(conn)['ipam'] and conn.execute(
        'SELECT keep_seen_names FROM ipam_settings WHERE id = 1').fetchone()[0]
    out = []
    for owner, recs in kea_names(zone).items():
        fqdn = _fqdn(owner.to_text())
        short = fqdn[:-len(origin) - 1] if fqdn.endswith('.' + origin) else fqdn
        addresses = _sorted_ips({_ip(r.rdata) for r in recs})
        item = {'name': owner, 'fqdn': fqdn, 'addresses': addresses, 'stale': False, 'why': '', 'since': None}
        out.append(item)
        if fqdn in live_names or live_ips.intersection(addresses):
            item['why'] = 'a live lease'
            continue
        if fqdn in reserved_names or short in reserved_names or reserved_ips.intersection(addresses):
            item['why'] = 'reserved'
            continue
        row = conn.execute('SELECT * FROM ddns_names WHERE name = ?', (fqdn,)).fetchone()
        since = row['last_expiry'] if row and row['last_expiry'] else row['noticed_at'] if row else None
        if since is None:
            since = now
            if not notice:
                item['why'] = 'no lease; its clock starts at the next check'
                continue
            else:
                with conn:
                    conn.execute('INSERT INTO ddns_names (name, address, noticed_at) VALUES (?, ?, ?) ON CONFLICT(name) '
                                 'DO UPDATE SET noticed_at = COALESCE(noticed_at, excluded.noticed_at)',
                                 (fqdn, addresses[0], now))
        item['since'] = since
        known = bool(row and row['last_expiry'])
        if now <= since + window:
            item['why'] = (f"{'its lease ended' if known else 'no lease since'} {_ago(now - since)} ago; "
                           f"stale in {_ago(since + window - now)}")
            continue
        if keep_seen:
            seen = conn.execute(f"SELECT MAX(last_seen) FROM ipam_seen WHERE ip IN ({','.join('?' * len(addresses))})",
                                addresses).fetchone()[0]
            if seen and seen >= now - window:
                item['why'] = f'no lease, still on the network (seen {_ago(now - seen)} ago)'
                continue
        item['stale'] = True
        item['why'] = (f"its lease ended {_ago(now - since)} ago" if known
                       else f"no lease for at least {_ago(now - since)}")
    out.sort(key=lambda i: (not i['stale'], i['fqdn']))
    return out


# ── stale PTRs ─────────────────────────────────────────────────────────────────

def _reverse_zones(conn):
    """{name: row} of the dynamic reverse zones LiteBlox holds (both families)."""
    return {r['name']: r for r in conn.execute(
        "SELECT * FROM zones WHERE kind = 'primary' AND dynamic = 1 AND "
        "(name LIKE '%.in-addr.arpa' OR name LIKE '%.ip6.arpa') ORDER BY name")}


def _home(target, zone_names):
    """The most specific of zone_names that target (a Name) is in, or None."""
    best = None
    for name in zone_names:
        zone = dns.name.from_text(name + '.')
        if target.is_subdomain(zone) and (best is None or len(zone) > len(best[1])):
            best = (name, zone)
    return best[0] if best else None


def kea_ptrs(settings, conn, zone_name):
    """[(reverse zone, owner Name, address, [PTR records], target Name)] for Kea's PTRs (a DHCID beside them) in
    LiteBlox's dynamic reverse zones whose target is in zone_name (its most specific zone in LiteBlox)."""
    from . import editing
    held = [r['name'] for r in conn.execute("SELECT name FROM zones WHERE kind != 'forwarding'")]
    out = []
    for rname in _reverse_zones(conn):
        try:
            zone = editing.ZoneEdit(settings, conn, rname).zone
        except Exception:           # a reverse zone that can't be read is left for the next pass
            continue
        if zone is None:
            continue
        owners = {r.name for r in zone.records() if r.rtype == 'DHCID'}
        ptrs = {}
        for r in zone.records():
            if r.rtype == 'PTR' and r.name in owners:
                ptrs.setdefault(r.name, []).append(r)
        for owner, recs in ptrs.items():
            try:
                address = _ip(dns.reversename.to_address(owner))
            except (dns.exception.DNSException, ValueError):
                continue            # not a whole address (classless delegation and the like)
            for target in {_target(r) for r in recs} - {None}:
                if _home(target, held) == zone_name:
                    out.append((rname, owner, address, [r for r in recs if _target(r) == target], target))
    return out


def review_ptrs(settings, conn, zone_row, zone, leases, now=None, notice=True):
    """Kea's PTRs pointing into the zone at a name that has no A/AAAA for that address:
    [{owner (reverse fqdn), rzone, address, target (fqdn), stale, why, since}], stale first. Also returns how many
    of Kea's PTRs point into the zone, for the pass's share check."""
    now = int(now or time.time())
    window = grace(conn, zone_row)
    forward = {(r.name, _ip(r.rdata)) for r in zone.records() if r.rtype in ('A', 'AAAA')}
    live_names, live_ips = _live(leases, now)
    _, reserved_ips = _reserved(conn)
    found = kea_ptrs(settings, conn, zone_row['name'])
    out = []
    for rname, owner, address, _, target in found:
        key = _fqdn(owner.to_text())
        if (target, address) in forward:
            if notice:              # it matches again: a later mismatch starts a new clock
                with conn:
                    conn.execute('DELETE FROM ddns_names WHERE name = ?', (key,))
            continue
        item = {'owner': key, 'rzone': rname, 'address': address, 'target': _fqdn(target.to_text()),
                'stale': False, 'why': '', 'since': None}
        out.append(item)
        if address in live_ips:
            item['why'] = 'a live lease has its address'
            continue
        if address in reserved_ips:
            item['why'] = 'its address is reserved'
            continue
        row = conn.execute('SELECT noticed_at FROM ddns_names WHERE name = ?', (key,)).fetchone()
        since = row['noticed_at'] if row and row['noticed_at'] else None
        if since is None:
            since = now
            if not notice:
                item['why'] = f"{item['target']} has no record for it; its clock starts at the next check"
                continue
            with conn:
                conn.execute('INSERT INTO ddns_names (name, address, noticed_at) VALUES (?, ?, ?) ON CONFLICT(name) '
                             'DO UPDATE SET noticed_at = COALESCE(noticed_at, excluded.noticed_at)', (key, address, now))
        item['since'] = since
        if now <= since + window:
            item['why'] = (f"{item['target']} has no record for it since {_ago(now - since)} ago; "
                           f"stale in {_ago(since + window - now)}")
            continue
        item['stale'] = True
        item['why'] = f"{item['target']} has had no record for it for at least {_ago(now - since)}"
    out.sort(key=lambda i: (not i['stale'], _ip_key(i['address'])))
    return out, len(found)


def _ip_key(a):
    try:
        ip = ipaddress.ip_address(a)
        return (ip.version, int(ip))
    except ValueError:
        return (9, 0)


# ── deleting ───────────────────────────────────────────────────────────────────

def delete(settings, conn, zone_name, fqdns, username, via=''):
    """Delete the names' A, AAAA and DHCID records (one update), and the PTR in a LiteBlox dynamic reverse zone
    that points at each (with that owner's DHCID when no other PTR is left there). Returns [lines] for a log."""
    from . import editing, ptr
    lines = []
    wanted = {_fqdn(f) for f in fqdns}
    with editing.zone_lock(zone_name):
        edit = editing.ZoneEdit(settings, conn, zone_name)
        owners = {o: recs for o, recs in kea_names(edit.zone).items() if _fqdn(o.to_text()) in wanted}
        doomed = [r for r in edit.zone.records() if r.name in owners and r.rtype in ('A', 'AAAA', 'DHCID')]
        if not doomed:
            return lines
        targets = {o: _sorted_ips({_ip(r.rdata) for r in recs}) for o, recs in owners.items()}
        editing.batch(edit, [editing.Op.removing(r) for r in doomed], False, username, via)
        for o, addresses in targets.items():
            lines.append(f"removed {_fqdn(o.to_text())} ({', '.join(addresses)}) from {zone_name}")
    reverse = list(_reverse_zones(conn))
    by_reverse = {}
    for owner, addresses in targets.items():
        for address in addresses:
            rname = ptr.reverse_zone_for(address, reverse)
            if rname:
                by_reverse.setdefault(rname, []).append((address, owner))
    for rname, items in sorted(by_reverse.items()):
        lines += [f'removed the PTR for {a} from {rname}' for a in _remove_ptrs(settings, conn, rname, items,
                                                                              username, via)]
    return lines


def delete_ptrs(settings, conn, zone_name, owners, username, via=''):
    """Delete the stale PTRs named by their owners (reverse fqdns), each with its DHCID when no other PTR is left
    there; only those that still point into zone_name at a name with no A/AAAA for the address. Returns [lines]."""
    from . import editing
    wanted = {_fqdn(o) for o in owners}
    with editing.zone_lock(zone_name):
        zone = editing.ZoneEdit(settings, conn, zone_name).zone
    if zone is None:
        return []
    forward = {(r.name, _ip(r.rdata)) for r in zone.records() if r.rtype in ('A', 'AAAA')}
    by_reverse = {}
    for rname, owner, address, _, target in kea_ptrs(settings, conn, zone_name):
        if _fqdn(owner.to_text()) in wanted and (target, address) not in forward:
            by_reverse.setdefault(rname, []).append((address, target))
    lines = []
    for rname, items in sorted(by_reverse.items()):
        gone = _remove_ptrs(settings, conn, rname, items, username, via)
        lines += [f'removed the stale PTR for {a} from {rname}' for a in gone]
        with conn:
            conn.executemany('DELETE FROM ddns_names WHERE name = ?',
                             [(_fqdn(dns.reversename.from_address(a).to_text()),) for a in gone])
    return lines


def _remove_ptrs(settings, conn, rname, items, username, via):
    """In one reverse zone, remove the PTR at each (address, target Name), and the owner's DHCID when no other
    PTR is left there. Returns the addresses whose PTR went."""
    from . import editing
    with editing.zone_lock(rname):
        redit = editing.ZoneEdit(settings, conn, rname)
        if redit.zone is None:
            return []
        ops, gone = [], []
        for address, target in items:
            at = dns.reversename.from_address(address)
            ptrs = [r for r in redit.zone.records() if r.name == at and r.rtype == 'PTR']
            mine = [r for r in ptrs if _target(r) == target]
            if not mine:
                continue
            ops += [editing.Op.removing(r) for r in mine]
            if len(mine) == len(ptrs):
                ops += [editing.Op.removing(r) for r in redit.zone.records() if r.name == at and r.rtype == 'DHCID']
            gone.append(address)
        if ops:
            editing.batch(redit, ops, False, username, via)
    return gone


def _target(rec):
    try:
        return dns.name.from_text(rec.rdata.strip(), rec.origin)
    except dns.exception.DNSException:
        return None


# ── the scheduled pass ─────────────────────────────────────────────────────────

def _note(conn, zone_id, note, now):
    with conn:
        conn.execute('UPDATE zones SET reclaim_checked_at = ?, reclaim_note = ? WHERE id = ?', (now, note, zone_id))


def check(settings, conn, zone_row, now=None):
    """One pass's verdict for a zone: ('skip', why) / ('hold', why) / ('ok', [stale items]): the stale names, then
    the stale PTRs (their items have 'owner')."""
    from ..dhcp import leases as lease_mod
    from . import editing
    trouble = dhcp_trouble(conn)
    if trouble:
        return 'skip', f'DHCP is not healthy ({trouble})'
    found, errors = all_leases(settings, conn)
    if errors:
        return 'skip', f"the leases couldn't be read ({errors[0]})"
    if not lease_mod.serving(conn):
        return 'skip', 'no DHCP server is serving'
    edit = editing.ZoneEdit(settings, conn, zone_row['name'])
    if edit.zone is None:
        return 'skip', f"{zone_row['name']} doesn't parse"
    items = review(conn, settings, zone_row, edit.zone, found, now=now)
    stale = [i for i in items if i['stale']]
    if len(stale) >= AT_LEAST and len(stale) > SHARE * len(items):
        return 'hold', (f'{len(stale)} of its {len(items)} DHCP names would go at once, more than '
                        f'{int(SHARE * 100)}%: nothing was reclaimed')
    ptrs, total = review_ptrs(settings, conn, zone_row, edit.zone, found, now=now)
    # a PTR a stale name takes with it isn't counted twice
    going = {a for i in stale for a in i['addresses']}
    ptrs = [p for p in ptrs if p['stale'] and p['address'] not in going]
    if len(ptrs) >= AT_LEAST and len(ptrs) > SHARE * total:
        return 'hold', (f"{len(ptrs)} of the {total} PTR records DHCP made for its names would go at once, more than "
                        f'{int(SHARE * 100)}%: nothing was reclaimed')
    return 'ok', stale + ptrs


def run_pass(settings, conn, zone_row, log=print, username='liteblox', now=None):
    """Check the zone and reclaim its stale names. Returns the names removed."""
    now = int(now or time.time())
    verdict, what = check(settings, conn, zone_row, now=now)
    if verdict != 'ok':
        log(f"{zone_row['name']}: {what}")
        _note(conn, zone_row['id'], f'{verdict}: {what}', now)
        return []
    if not what:
        log(f"{zone_row['name']}: no stale DHCP names")
        _note(conn, zone_row['id'], None, now)
        return []
    names = [i for i in what if 'owner' not in i]
    ptrs = [i for i in what if 'owner' in i]
    for item in names:
        log(f"  {item['fqdn']} ({', '.join(item['addresses'])}): {item['why']}")
    for item in ptrs:
        log(f"  the PTR for {item['address']} ({item['target']}): {item['why']}")
    lines = delete(settings, conn, zone_row['name'], [i['fqdn'] for i in names], username, ' (reclaimed)') if names else []
    if ptrs:
        lines += delete_ptrs(settings, conn, zone_row['name'], [i['owner'] for i in ptrs], username, ' (reclaimed)')
    for line in lines:
        log(f'  ✓ {line}')
    with conn:
        conn.executemany('DELETE FROM ddns_names WHERE name = ?', [(i['fqdn'],) for i in names])
    audit(conn, username, 'ddns_reclaim', f"{zone_row['name']}: " + ', '.join(
        [f"{i['fqdn']} {'/'.join(i['addresses'])}" for i in names]
        + [f"the PTR for {i['address']} ({i['target']})" for i in ptrs]))
    _note(conn, zone_row['id'], None, now)
    return [i['fqdn'] for i in names] + [i['owner'] for i in ptrs]


def due(conn, now=None):
    now = int(now or time.time())
    return conn.execute('SELECT * FROM zones WHERE dynamic = 1 AND reclaim = 1 AND '
                        '(reclaim_checked_at IS NULL OR reclaim_checked_at <= ?) ORDER BY name',
                        (now - EVERY + 60,)).fetchall()


def pass_due(settings, conn, now=None):
    """The scheduler's hourly work: each due zone is checked; a job runs only when something will be deleted.
    Returns the job ids started."""
    from .. import jobs
    started = []
    for z in due(conn, now):
        verdict, what = check(settings, conn, z, now=now)
        if verdict != 'ok' or not what:
            _note(conn, z['id'], None if verdict == 'ok' else f'{verdict}: {what}', int(now or time.time()))
            continue
        started.append(jobs.start(settings.db_path, 'reclaim', _job(settings, z), username='liteblox',
                                  zone_id=z['id']))
    return started


def _job(settings, zone_row):
    def work(log):
        from .. import db
        conn = db.connect(settings.db_path)
        try:
            run_pass(settings, conn, zone_row, log)
        finally:
            conn.close()
    return work
