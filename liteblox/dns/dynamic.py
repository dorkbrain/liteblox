"""Dynamic zones: named owns the file; LiteBlox reads by AXFR and writes RFC 2136 updates.

Both go to the zone's primary, signed with LiteBlox's own key (UPDATE_KEY).
An edit becomes one update message: for each changed RRset, a prerequisite
that it is still exactly what the editor saw (or still absent), then the
replacement. If DHCP, ACME or anyone else changed it meanwhile, named refuses
the whole message and nothing is written. Each LiteBlox change, and a daily
pass for changes made by others, is committed to the zone's git history.
"""

import hashlib
import json

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.tsigkeyring
import dns.update
import dns.zone

from .. import db
from ..bindconf.model import UPDATE_KEY, node_address
from .repo import Repo

CONFLICT_RCODES = (dns.rcode.NXRRSET, dns.rcode.YXRRSET, dns.rcode.NXDOMAIN, dns.rcode.YXDOMAIN)


class DynamicError(RuntimeError):
    pass


class Conflict(DynamicError):
    """A prerequisite failed: the zone changed on the server since the editor loaded it."""


def _key(conn, name=UPDATE_KEY):
    row = conn.execute('SELECT * FROM tsig_keys WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise DynamicError(f"LiteBlox's key {name} doesn't exist yet: pick a primary first")
    return dns.tsigkeyring.from_text({name: row['secret']}), dns.name.from_text(row['algorithm'])


def primary_host(conn, zone_row):
    row = conn.execute("SELECT n.* FROM nodes n JOIN zone_nodes zn ON zn.node_id = n.id "
                       "WHERE zn.zone_id = ? AND n.role = 'primary'", (zone_row['id'],)).fetchone()
    if row is None or not node_address(row):
        raise DynamicError(f"{zone_row['name']} has no primary LiteBlox can reach for updates")
    return node_address(row)


def _origin(zone_row):
    return dns.name.from_text(zone_row['name'] + '.')


def to_text(zone):
    """A dnspython zone as zone-file text LiteBlox's parser and grid take (owners relative, sorted).

    named keeps no $TTL for a dynamic zone; without one a record added with no TTL would take the
    TTL of whichever line comes before it, so the SOA's TTL stands in as the default.
    """
    soa = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    return (f'$TTL {soa.ttl}\n' if soa else '') + zone.to_text(relativize=True, sorted=True)


def axfr(conn, zone_row, transfer=None):
    """The zone as named serves it now on its primary, as text."""
    return axfr_from(conn, zone_row, primary_host(conn, zone_row), transfer=transfer, where='its primary ')


def axfr_from(conn, zone_row, host, keys=(UPDATE_KEY,), transfer=None, where=''):
    """The zone as `host` serves it, as text. keys: LiteBlox's keys to try in turn (a primary allows
    its update key, a secondary its transfer key; a node mid-demotion may have either)."""
    error = None
    for key in keys:
        keyring, algorithm = _key(conn, key)
        try:
            if transfer:
                zone = transfer(host, zone_row['name'], keyring, algorithm)
            else:
                zone = dns.zone.from_xfr(dns.query.xfr(host, zone_row['name'], keyring=keyring, keyname=key,
                                                       keyalgorithm=algorithm, lifetime=15))
            return to_text(zone)
        except (dns.exception.DNSException, OSError, EOFError) as e:
            error = e
    raise DynamicError(f"can't read {zone_row['name']} from {where}{host}: {error or error.__class__.__name__}")


def _zone(text, origin):
    # dnspython reads a CR as part of the last token ("unknown unit ''"); a zone file saved with CRLF
    # (by a Windows editor or an older tool) has one on every line
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return dns.zone.from_text(text, origin, relativize=False, check_origin=False)


def serial(text, origin):
    return _zone(text, origin).get_rdataset(origin, 'SOA')[0].serial


def changes(old_text, new_text, origin):
    """[(name, rdtype, old rdataset or None, new rdataset or None)] for every RRset that differs.

    A changed SOA is sent with the serial one past the old one (named also bumps it on any update).
    """
    old, new = _zone(old_text, origin), _zone(new_text, origin)
    keys = set()
    for zone in (old, new):
        for name, node in zone.nodes.items():
            for rds in node.rdatasets:
                keys.add((name, rds.rdtype))
    out = []
    for name, rdtype in sorted(keys, key=lambda k: (k[0].to_text(), k[1])):
        before = old.get_rdataset(name, rdtype)
        after = new.get_rdataset(name, rdtype)
        if before is not None and after is not None and before == after and before.ttl == after.ttl:
            continue
        if rdtype == dns.rdatatype.SOA and after is not None and before is not None:
            soa = after[0].replace(serial=before[0].serial + 1)
            after = dns.rdataset.from_rdata(after.ttl, soa)
        out.append((name, rdtype, before, after))
    return out


def update(conn, zone_row, todo, send=None):
    """Send `todo` (from changes()) to the primary as one guarded update. Raises Conflict or DynamicError."""
    if not todo:
        return None
    keyring, algorithm = _key(conn)
    host = primary_host(conn, zone_row)
    message = dns.update.UpdateMessage(_origin(zone_row), keyring=keyring, keyname=UPDATE_KEY,
                                       keyalgorithm=algorithm)
    for name, rdtype, before, after in todo:
        if before is None:
            message.absent(name, rdtype)
        else:
            # RFC 2136 wants TTL 0 on a value-dependent prerequisite (named answers FORMERR otherwise)
            message.present(name, dns.rdataset.from_rdata_list(0, list(before)))
        if after is None:
            message.delete(name, rdtype)
        else:
            message.replace(name, after)
    try:
        response = send(message, host) if send else dns.query.tcp(message, host, timeout=15)
    except (dns.exception.DNSException, OSError) as e:
        raise DynamicError(f'the update to {host} got no answer: {e or e.__class__.__name__}')
    rcode = response.rcode()
    if rcode in CONFLICT_RCODES:
        raise Conflict(f"{zone_row['name']} changed on the server since you loaded it "
                       f'({dns.rcode.to_text(rcode)}); nothing was written')
    if rcode != dns.rcode.NOERROR:
        raise DynamicError(f"{host} refused the update to {zone_row['name']}: {dns.rcode.to_text(rcode)}")
    return rcode


def only_on(old_text, new_text, origin):
    """RRsets old_text holds that new_text lacks or holds differently (the SOA aside), as JSON-able
    [[name, type, ttl, [rdata, ...], [rdata now, ...] or None], ...] with names relative to the zone."""
    out = []
    for name, rdtype, before, after in changes(old_text, new_text, origin):
        if before is None or rdtype == dns.rdatatype.SOA:
            continue
        out.append([name.relativize(origin).to_text(), dns.rdatatype.to_text(rdtype), before.ttl,
                    sorted(rd.to_text() for rd in before),
                    sorted(rd.to_text() for rd in after) if after is not None else None])
    return out


def put_back(text, origin, rrsets):
    """text with each [name, type, ttl, rdatas, ...] from only_on() set as it was on the old copy."""
    zone = _zone(text, origin)
    for name, rdtype, ttl, rdatas, *_ in rrsets:
        owner = dns.name.from_text(name, origin)
        zone.replace_rdataset(owner, dns.rdataset.from_text_list('IN', rdtype, ttl, rdatas, origin=origin))
    return to_text(zone)


def raise_serial(conn, zone_row, above, transfer=None, send=None):
    """Move the primary's SOA serial past `above`, so a copy at that serial transfers again."""
    origin = _origin(zone_row)
    text = axfr(conn, zone_row, transfer)
    soa = _zone(text, origin).get_rdataset(origin, dns.rdatatype.SOA)
    if soa[0].serial > above:
        return soa[0].serial
    new = dns.rdataset.from_rdata(soa.ttl, soa[0].replace(serial=above + 1))
    update(conn, zone_row, [(origin, dns.rdatatype.SOA, soa, new)], send)
    return above + 1


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _rdata_key(rec):
    # named bumps the SOA serial with every update, so it says nothing about what an editor saw
    if rec.rtype == 'SOA':
        tokens = rec.rdata.split()
        return ' '.join(tokens[:2] + tokens[3:])
    return rec.rdata


def record_key(rec):
    """A record named by its content (owner, type, data), stable while it's unchanged; grid row ids are
    positions in a parse and shift. The API's record ids."""
    return sha(f'{rec.name} {rec.rtype} {_rdata_key(rec)}')[:16]


def rr_token(zone, rec):
    """'<record key>.<RRset digest>' for a grid row of a dynamic zone.

    Leases land while a page is open, which shifts record positions and the
    whole-zone rev; this names the record by content and pins only its RRset.
    """
    key = record_key(rec)
    rrset = sorted(f'{r.ttl} {_rdata_key(r)}' for r in zone.records() if r.name == rec.name and r.rtype == rec.rtype)
    return key + '.' + sha(f'{rec.name} {rec.rtype} ' + '\n'.join(rrset))[:16]


def find_token(zone, token):
    """The record rr_token() named, or None if it or its RRset changed since."""
    key = (token or '').split('.')[0]
    for rec in zone.records():
        if rr_token(zone, rec).split('.')[0] == key:
            return rec if rr_token(zone, rec) == token else None
    return None


def snapshot(settings, zone_row, text, author, message):
    """Commit `text` as the zone's newest version when it differs from the last one. Returns the commit or None."""
    repo = Repo(settings.repo_dir).ensure()
    if repo.read(zone_row['repo_file']) == text:
        return None
    return repo.write(zone_row['repo_file'], text, message, author)


def send_edit(settings, conn, zone_row, old_text, new_text, author, message, transfer=None, send=None):
    """Send new_text - old_text (old_text: what named served when the edit started) as one guarded update.

    Changes others made since the last version are committed first as their own snapshot, so the
    edit's version holds only this edit. Returns the zone's text after the update.
    """
    origin = _origin(zone_row)
    snapshot(settings, zone_row, old_text, 'liteblox', f'Snapshot (serial {serial(old_text, origin)})')
    update(conn, zone_row, changes(old_text, new_text, origin), send)
    text = axfr(conn, zone_row, transfer)
    snapshot(settings, zone_row, text, author, f'{message} (serial {serial(text, origin)})')
    return text


def snapshot_all(settings, log=print, transfer=None):
    """Commit every dynamic zone that changed by other means (DHCP, ACME, nsupdate) since its last version."""
    conn = db.connect(settings.db_path)
    try:
        for z in conn.execute('SELECT * FROM zones WHERE dynamic = 1 ORDER BY name').fetchall():
            try:
                text = axfr(conn, z, transfer)
                commit = snapshot(settings, z, text, 'liteblox', f"Snapshot (serial {serial(text, _origin(z))})")
                log(f"{z['name']}: {'committed ' + commit[:10] if commit else 'unchanged'}")
            except DynamicError as e:
                log(f"{z['name']}: {e}")
    finally:
        conn.close()


# ── PTR updates waiting for a static forward zone's publish ────────────────────

def queue_ptr(conn, forward_zone, reverse_zone, ops):
    """Keep ptr.changes() ops (kind, address, target Name) until forward_zone is published."""
    ops = [(kind, str(address), target.to_text() if hasattr(target, 'to_text') else str(target))
           for kind, address, target in ops]
    with conn:
        conn.execute('INSERT INTO ptr_queue (forward_zone_id, reverse_zone_id, ops) VALUES (?, ?, ?)',
                     (forward_zone['id'], reverse_zone['id'], json.dumps(ops)))


def queued_ptr(conn, forward_zone_id):
    """[(reverse zone name, [(kind, address, target)])] waiting for this forward zone's publish."""
    out = {}
    for r in conn.execute('SELECT q.*, z.name FROM ptr_queue q JOIN zones z ON z.id = q.reverse_zone_id '
                          'WHERE q.forward_zone_id = ? ORDER BY q.id', (forward_zone_id,)):
        out.setdefault(r['name'], []).extend(tuple(op) for op in json.loads(r['ops']))
    return list(out.items())


def failed_ptr(conn, forward_zone_id):
    """[(reverse zone name, [(kind, address, target)], failed_at, error)]: queued PTR changes whose send
    failed after the forward zone was published; they wait for Retry (or the next publish)."""
    out = {}
    for r in conn.execute('SELECT q.*, z.name FROM ptr_queue q JOIN zones z ON z.id = q.reverse_zone_id '
                          'WHERE q.forward_zone_id = ? AND q.failed_at IS NOT NULL ORDER BY q.id', (forward_zone_id,)):
        entry = out.setdefault(r['name'], [r['name'], [], r['failed_at'], r['error']])
        entry[1].extend(tuple(op) for op in json.loads(r['ops']))
        entry[2], entry[3] = r['failed_at'], r['error']
    return [tuple(e) for e in out.values()]


def drop_ptr_queue(conn, forward_zone_id, failed=False):
    """Drop the queued PTR changes waiting for a publish (a discarded draft), or with failed=True the ones
    whose send failed (the admin gave up on them)."""
    with conn:
        conn.execute('DELETE FROM ptr_queue WHERE forward_zone_id = ? AND failed_at IS '
                     + ('NOT NULL' if failed else 'NULL'), (forward_zone_id,))


def flush_ptr_queue(settings, conn, forward_zone, username, log, transfer=None, send=None):
    """Send the queued PTR changes as updates to their dynamic reverse zones (after the forward zone's publish).

    Returns the reverse zones whose changes didn't go out; those stay queued, marked failed.
    """
    from . import ptr
    from .zonefile import Zone
    failed = []
    for rname, ops in queued_ptr(conn, forward_zone['id']):
        rzone = conn.execute('SELECT * FROM zones WHERE name = ?', (rname,)).fetchone()
        try:
            text = axfr(conn, rzone, transfer)
            zone = Zone.parse(text, rname + '.')
            for kind, address, target in ops:
                changed, message = ptr.apply(zone, kind, address, dns.name.from_text(target))
                if message:
                    log(f'  {message}')
            send_edit(settings, conn, rzone, text, zone.render(), username,
                      f"PTR changes from {forward_zone['name']}", transfer, send)
            log(f"  ✓ {rname}: PTR changes sent as updates")
        except DynamicError as e:
            log(f"  ⚠ {rname}: PTR changes not sent ({e}); they stay queued (Retry on {forward_zone['name']}'s page)")
            failed.append(rname)
            with conn:
                conn.execute("UPDATE ptr_queue SET failed_at = datetime('now'), error = ? "
                             'WHERE forward_zone_id = ? AND reverse_zone_id = ?',
                             (str(e), forward_zone['id'], rzone['id']))
            continue
        with conn:
            conn.execute('DELETE FROM ptr_queue WHERE forward_zone_id = ? AND reverse_zone_id = ?',
                         (forward_zone['id'], rzone['id']))
    return failed
