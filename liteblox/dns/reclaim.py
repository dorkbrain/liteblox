"""Stale DHCP names: the names Kea registered in a dynamic zone (an A record with a DHCID beside it) whose lease
is long gone, and reclaiming them.

Kea removes a name when its lease expires and is reclaimed, but a name stays when that update was lost (the
primary was down, a promote happened, Kea's lease file was reset). Kea forgets expired leases after an hour, and
DNS records carry no expiry, so LiteBlox remembers per name the last lease expiry it saw (remember(), from the
health check's minutely lease read) or, failing that, when it first saw the name without a lease.

A name is stale when no live lease has its name or address, no reservation has either, and now > leaseexp +
grace (grace: the zone's "reclaim after", by default the longest lease time of the subnets registering into
it). With IPAM on and its keep_seen_names setting, a name whose address the nodes saw within the grace stays.
Names nobody gave a DHCID (typed in, ACME, another key's) are never stale.

pass_due() runs from the scheduler for zones with reclamation on, at most hourly; it deletes nothing while DHCP
isn't healthy (a server down, the pair not in hot-standby, a lease read failing) or when too many names would go
at once (it says so in Needs attention instead).
"""

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
            'address = excluded.address, last_expiry = MAX(COALESCE(last_expiry, 0), excluded.last_expiry)',
            [(name, ip, exp) for name, (exp, ip) in best.items()])


def grace_default(conn, zone_row):
    """The longest lease time of the subnets registering into the zone (else the global one, else Kea's)."""
    from ..dhcp import model
    glob = model.settings(conn).valid_lifetime or KEA_VALID
    times = [s.valid_lifetime or glob for s in model.subnets(conn) if s.ddns and s.ddns_zone == zone_row['name']]
    return max(times) if times else glob


def grace(conn, zone_row):
    return zone_row['reclaim_after'] or grace_default(conn, zone_row)


def dhcp_trouble(conn):
    """Why DHCP isn't healthy enough to judge names by its leases, or None."""
    from ..dhcp import model
    pair = model.ha_pair(conn)
    for n in conn.execute('SELECT * FROM nodes WHERE dhcp = 1 ORDER BY name'):
        if n['status'] == 'error':
            return f"{n['name']} doesn't answer"
        if n['dhcp_sockets']:
            return f"{n['name']}: Kea isn't serving DHCP"
        if pair.active and n['dhcp_ha_state'] and n['dhcp_ha_state'] != 'hot-standby':
            return f"{n['name']}: DHCP failover is {n['dhcp_ha_state']}"
    return None


# ── the rule ───────────────────────────────────────────────────────────────────

def kea_names(zone):
    """{owner Name: [its A records]} for the owners with a DHCID record: the names Kea registered."""
    owners = {r.name for r in zone.records() if r.rtype == 'DHCID'}
    out = {}
    for r in zone.records():
        if r.rtype == 'A' and r.name in owners:
            out.setdefault(r.name, []).append(r)
    return out


def _ago(seconds):
    from ..timefmt import duration
    seconds = max(0, int(seconds))
    if seconds < 60:
        return 'under a minute'
    return duration(seconds - seconds % 60 if seconds >= 120 else seconds)


def review(conn, settings, zone_row, zone, leases, now=None, notice=True):
    """Every DHCP name in the zone and its fate: [{name (Name), fqdn, addresses, stale (bool), why, since}],
    stale first. leases: [(node, lease)] from a read without errors. notice: start the clock for a name seen
    without a lease for the first time (a pass does; the zone page only looks)."""
    from ..dhcp import model
    from ..modules import enabled
    now = int(now or time.time())
    window = grace(conn, zone_row)
    live_names, live_ips = set(), set()
    for _, lease in leases:
        if lease['state'] == 'active' and lease['expires'] > now:
            live_names.add(_fqdn(lease['hostname']))
            live_ips.add(lease['ip'])
    reserved_names, reserved_ips = set(), set()
    for r in model.reservations(conn):
        if r.hostname:
            reserved_names.add(_fqdn(r.hostname))
        if r.ip_address:
            reserved_ips.add(r.ip_address)
    origin = _fqdn(zone_row['name'])
    keep_seen = enabled(conn)['ipam'] and conn.execute(
        'SELECT keep_seen_names FROM ipam_settings WHERE id = 1').fetchone()[0]
    out = []
    for owner, recs in kea_names(zone).items():
        fqdn = _fqdn(owner.to_text())
        short = fqdn[:-len(origin) - 1] if fqdn.endswith('.' + origin) else fqdn
        addresses = sorted({r.rdata.strip() for r in recs})
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


# ── deleting ───────────────────────────────────────────────────────────────────

def delete(settings, conn, zone_name, fqdns, username, via=''):
    """Delete the names' A and DHCID records (one update), and the PTR in a LiteBlox dynamic reverse zone that
    points at each (with that owner's DHCID when no other PTR is left there). Returns [lines] for a log."""
    from . import editing, ptr
    lines = []
    wanted = {_fqdn(f) for f in fqdns}
    with editing.zone_lock(zone_name):
        edit = editing.ZoneEdit(settings, conn, zone_name)
        owners = {o: recs for o, recs in kea_names(edit.zone).items() if _fqdn(o.to_text()) in wanted}
        doomed = [r for r in edit.zone.records() if r.name in owners and r.rtype in ('A', 'DHCID')]
        if not doomed:
            return lines
        targets = {o: sorted({r.rdata.strip() for r in recs}) for o, recs in owners.items()}
        editing.batch(edit, [editing.Op.removing(r) for r in doomed], False, username, via)
        for o, addresses in targets.items():
            lines.append(f"removed {_fqdn(o.to_text())} ({', '.join(addresses)}) from {zone_name}")
    held = {r['name']: r for r in conn.execute("SELECT * FROM zones WHERE kind = 'primary'")}
    by_reverse = {}
    for owner, addresses in targets.items():
        for address in addresses:
            rname = ptr.reverse_zone_for(address, [n for n in held if n.endswith('.in-addr.arpa')])
            if rname and held[rname]['dynamic']:
                by_reverse.setdefault(rname, []).append((address, owner))
    for rname, items in sorted(by_reverse.items()):
        with editing.zone_lock(rname):
            redit = editing.ZoneEdit(settings, conn, rname)
            ops, gone = [], []
            for address, owner in items:
                at = dns.reversename.from_address(address)
                ptrs = [r for r in redit.zone.records() if r.name == at and r.rtype == 'PTR']
                mine = [r for r in ptrs if _target(r) == owner]
                if not mine:
                    continue
                ops += [editing.Op.removing(r) for r in mine]
                if len(mine) == len(ptrs):
                    ops += [editing.Op.removing(r) for r in redit.zone.records() if r.name == at and r.rtype == 'DHCID']
                gone.append(address)
            if ops:
                editing.batch(redit, ops, False, username, via)
                lines += [f'removed the PTR for {a} from {rname}' for a in gone]
    return lines


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
    """One pass's verdict for a zone: ('skip', why) / ('hold', why) / ('ok', [stale items])."""
    from ..dhcp import leases as lease_mod
    from . import editing
    trouble = dhcp_trouble(conn)
    if trouble:
        return 'skip', f'DHCP is not healthy ({trouble})'
    found, errors = lease_mod.serving_leases(settings, conn)
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
    return 'ok', stale


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
    for item in what:
        log(f"  {item['fqdn']} ({', '.join(item['addresses'])}): {item['why']}")
    lines = delete(settings, conn, zone_row['name'], [i['fqdn'] for i in what], username, ' (reclaimed)')
    for line in lines:
        log(f'  ✓ {line}')
    names = [i['fqdn'] for i in what]
    with conn:
        conn.executemany('DELETE FROM ddns_names WHERE name = ?', [(n,) for n in names])
    audit(conn, username, 'ddns_reclaim', f"{zone_row['name']}: " + ', '.join(
        f"{i['fqdn']} {'/'.join(i['addresses'])}" for i in what))
    _note(conn, zone_row['id'], None, now)
    return names


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
