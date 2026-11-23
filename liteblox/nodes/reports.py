"""Demote reports: record sets a node's copy held that the primary's didn't, kept when the node was
brought in line (an old primary demoted, a secondary that had been down), so they can be put back."""

import json
from datetime import datetime, timezone

import dns.name

from .. import db
from ..dns import dynamic
from ..dns.drafts import Drafts
from ..dns.zonefile import Zone


class ReportError(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def open_reports(conn, node_id=None):
    sql = ('SELECT r.*, z.name AS zone, z.dynamic, n.name AS node FROM demote_reports r '
           'JOIN zones z ON z.id = r.zone_id JOIN nodes n ON n.id = r.node_id WHERE r.resolved_at IS NULL')
    args = ()
    if node_id is not None:
        sql, args = sql + ' AND r.node_id = ?', (node_id,)
    return [dict(r, rrsets=json.loads(r['rrsets'])) for r in conn.execute(sql + ' ORDER BY r.id', args)]


def get(conn, report_id):
    r = conn.execute('SELECT r.*, z.name AS zone, z.dynamic, n.name AS node FROM demote_reports r '
                     'JOIN zones z ON z.id = r.zone_id JOIN nodes n ON n.id = r.node_id WHERE r.id = ?',
                     (report_id,)).fetchone()
    return dict(r, rrsets=json.loads(r['rrsets'])) if r else None


def _resolve(conn, report_id, rrsets, username):
    with conn:
        conn.execute('UPDATE demote_reports SET rrsets = ?, resolved_at = ?, resolved_by = ? WHERE id = ?',
                     (json.dumps(rrsets), None if rrsets else _now(), None if rrsets else username, report_id))


def reapply(settings, conn, report_id, picks, username, transfer=None, send=None):
    """Put the picked record sets (indexes into the report's list) back: a dynamic zone by a guarded
    update to the primary, a static zone into its draft. Returns a line saying what happened."""
    report = get(conn, report_id)
    if report is None or report['resolved_at']:
        raise ReportError('that report is already done')
    chosen = [report['rrsets'][i] for i in sorted(set(picks)) if 0 <= i < len(report['rrsets'])]
    if not chosen:
        raise ReportError('pick at least one record set to put back')
    zone = conn.execute('SELECT * FROM zones WHERE id = ?', (report['zone_id'],)).fetchone()
    source = f"{report['node']}'s old copy"
    if zone['dynamic']:
        origin = dns.name.from_text(zone['name'] + '.')
        current = dynamic.axfr(conn, zone, transfer)
        dynamic.send_edit(settings, conn, zone, current, dynamic.put_back(current, origin, chosen), username,
                          f'Put back from {source}', transfer, send)
        done = f"sent to {zone['name']}'s primary"
    else:
        drafts = Drafts(settings)
        text, _ = drafts.load(zone)
        z = Zone.parse(text, zone['name'] + '.')
        for name, rtype, ttl, rdatas, *_ in chosen:
            owner = z.name_from_text(name)
            for rec in [r for r in z.records() if r.name == owner and r.rtype == rtype]:
                z.delete(rec)
            for rdata in rdatas:
                z.add(name, rtype, rdata, ttl)
        drafts.save(zone, z.render(), username)
        done = f"added to {zone['name']}'s draft: review and publish it"
    left = [r for r in report['rrsets'] if r not in chosen]
    _resolve(conn, report_id, left, username)
    db.audit(conn, username, 'demote_reapply', f"{zone['name']} from {report['node']}: {len(chosen)} record set(s)")
    return f'{len(chosen)} record set(s) {done}'


def dismiss(conn, report_id, username):
    report = get(conn, report_id)
    if report is None:
        raise ReportError('no such report')
    with conn:
        conn.execute('UPDATE demote_reports SET resolved_at = ?, resolved_by = ? WHERE id = ?',
                     (_now(), username, report_id))
    db.audit(conn, username, 'demote_dismiss', f"{report['zone']} from {report['node']}")
