"""What needs an admin, from the DB alone (the health check keeps it current every minute).

problems() feeds the Dashboard's attention list and tiles, the top bar's dot and
GET /api/v1/status. Each problem links to the page that fixes it.
"""

import json
import threading
import time
from datetime import datetime, timedelta, timezone

from . import db, timefmt

SEEN_WITHIN = timedelta(minutes=3)      # three health checks
CERT_WARN = timedelta(days=30)
SKEW_WARN, SKEW_ERROR = 30, 120          # seconds; signed updates fail at 300
RANK = {'error': 0, 'warn': 1, 'info': 2}

HA_STATES = {'partner-down': 'the other DHCP server is down: this one serves alone',
             'terminated': 'DHCP failover stopped (usually the two clocks are over 60 s apart)'}


def _when(text):
    dt = datetime.fromisoformat(str(text).replace(' ', 'T', 1))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _node_problems(conn, settings, n, now):
    from .backups import service as backups
    from .bindconf import apply as bind_apply
    from .dhcp import apply as dhcp_apply
    name, page = n['name'], f"/nodes/{n['id']}"
    out = []

    def add(severity, area, what, link=page):
        out.append({'severity': severity, 'area': area, 'what': what, 'link': link, 'node': name})

    if n['status'] == 'new':
        add('warn', 'node', f'{name} is not set up yet', f"/nodes/{n['id']}/bootstrap")
        return out
    if n['status'] == 'error':
        detail = (n['status_detail'] or '').splitlines()[0] if n['status_detail'] else ''
        add('error', 'node', f"{name} doesn't answer" + (f': {detail}' if detail else ''))
    elif n['last_seen_at'] and now - _when(n['last_seen_at']) > SEEN_WITHIN:
        add('warn', 'node', f"{name} hasn't been checked since {timefmt.local(n['last_seen_at'])} (is the health check running?)")
    if n['pending']:
        add('warn', 'dns', f"{name} missed a role change while unreachable; its "
                    f"{'demotion' if n['pending'] == 'demote' else 'update'} runs when it answers")
    if n['second_primary']:
        add('error', 'dns', f"{name} declares {', '.join(json.loads(n['second_primary']))} as primary outside LiteBlox",
            f"/nodes/{n['id']}/drift")
    elif n['drift']:
        add('warn', 'dns', f"{name}'s BIND config was changed outside LiteBlox ({', '.join(json.loads(n['drift']))})",
            f"/nodes/{n['id']}/drift")
    elif bind_apply.stale(conn, n):
        add('info', 'dns', f"{name}'s BIND config is behind; the health check writes it again")
    if n['dhcp']:
        state = n['dhcp_ha_state']
        if state and state != 'hot-standby':
            add('error' if state == 'terminated' else 'warn', 'dhcp',
                f'{name}: DHCP failover is {state}' + (f' ({HA_STATES[state]})' if state in HA_STATES else ''), '/dhcp')
        sockets = json.loads(n['dhcp_sockets']) if n['dhcp_sockets'] and n['status'] != 'error' else None
        if sockets:
            why = '; '.join(sockets['errors'])
            if sockets['status'] == 'retrying':
                add('warn', 'dhcp', f"{name}: Kea can't listen for DHCP yet and keeps trying ({why})", f'{page}#dhcp')
            else:
                add('error', 'dhcp', f"{name}: Kea isn't serving DHCP ({why})" + (
                    ('; Rewrite DHCP config makes it try again' if n['dhcp_drift'] else
                     '; LiteBlox reloads it once its interfaces are up') if sockets['status'] == 'failed' else ''), f'{page}#dhcp')
        if n['dhcp_drift']:
            add('warn', 'dhcp', f"{name}'s Kea config was changed outside LiteBlox", f'{page}#dhcp')
        elif dhcp_apply.stale(conn, n):
            add('info', 'dhcp', f"{name}'s DHCP config is behind; the health check writes it again", f'{page}#dhcp')
    if n['ntp']:
        state = json.loads(n['ntp_state']) if n['ntp_state'] else None
        if n['ntp_drift']:
            add('warn', 'time', f"{name}'s chrony config was changed outside LiteBlox", f'{page}#time')
        elif state is None and n['status'] == 'ready':
            add('error', 'time', f"{name}: chrony isn't running", f'{page}#time')
        elif state and not state.get('synced'):
            add('warn', 'time', f'{name}: chrony has no usable time source', f'{page}#time')
    skew = n['clock_skew']
    if isinstance(skew, (int, float)) and abs(skew) >= SKEW_WARN:
        add('error' if abs(skew) >= SKEW_ERROR else 'warn', 'time',
            f"{name}'s clock is {skew:+.0f} s from LiteBlox's (signed updates fail at 300 s)")
    elif n['clock_synced'] == 0 and not n['ntp']:
        add('warn', 'time', f"{name}'s clock isn't synchronized (timedatectl)")
    if backups.is_stale(conn, settings, n['id']):
        add('warn', 'node', f'{name} has had no successful backup in {backups.STALE_HOURS} hours', f"{page}/backups")
    if n['cert_not_after']:
        left = _when(n['cert_not_after']) - now
        if left < CERT_WARN:
            add('error' if left.total_seconds() <= 0 else 'warn', 'node',
                f"{name}'s agent certificate {'expired' if left.total_seconds() <= 0 else 'expires'} "
                f"{timefmt.local(n['cert_not_after'])[:10]}; Repair / upgrade agent issues a new one", f"/nodes/{n['id']}/bootstrap")
    reports = conn.execute('SELECT COUNT(*) FROM demote_reports WHERE node_id = ? AND resolved_at IS NULL',
                           (n['id'],)).fetchone()[0]
    if reports:
        add('warn', 'dns', f"{name} kept {reports} record report{'' if reports == 1 else 's'} when it was demoted")
    return out


def _zone_problems(conn, settings):
    from .dns.canonical import why_unsorted
    from .dns.drafts import Drafts
    out = []
    rows = conn.execute("SELECT * FROM zones WHERE kind = 'primary' ORDER BY name").fetchall()
    drafts = Drafts(settings)
    for z in rows:
        last = conn.execute('SELECT status, error FROM deploys WHERE zone_id = ? ORDER BY id DESC LIMIT 1',
                            (z['id'],)).fetchone()
        if last and last['status'] in ('failed', 'partial'):
            out.append({'severity': 'error' if last['status'] == 'failed' else 'warn', 'area': 'dns', 'node': None,
                        'what': f"the last publish of {z['name']} {'failed' if last['status'] == 'failed' else 'reached only some nodes'}",
                        'link': f"/zones/{z['name']}/history"})
        if drafts.has_draft(z['name']):
            out.append({'severity': 'info', 'area': 'dns', 'node': None, 'what': f"{z['name']} has unpublished changes",
                        'link': f"/zones/{z['name']}/review"})
        if z['dynamic'] and z['reclaim'] and (z['reclaim_note'] or '').startswith('hold: '):
            out.append({'severity': 'warn', 'area': 'dns', 'node': None, 'link': f"/zones/{z['name']}?stale=1#stale",
                        'what': f"{z['name']}: stale DHCP names held back: {z['reclaim_note'][len('hold: '):]}"})
        why = None if z['dynamic'] else why_unsorted(drafts.load(z)[0], z['name'] + '.')
        if why:
            out.append({'severity': 'info', 'area': 'dns', 'node': None, 'link': f"/zones/{z['name']}/raw",
                        'what': f"{z['name']} can't be kept sorted, so it keeps its own order ({why})"})
    return out


def _dhcp_problems(conn):
    from .dhcp.model import subnets
    from .dhcp.routes import ddns_summary
    out = []
    if not conn.execute('SELECT 1 FROM nodes WHERE dhcp = 1').fetchone():
        return out
    for s in subnets(conn):
        summary = ddns_summary(conn, s)
        if summary and summary['grants']:
            out.append({'severity': 'warn', 'area': 'dhcp', 'node': None, 'link': f'/dhcp/subnets/{s.id}',
                        'what': f"{s.prefix}: the DNS registration key isn't granted everything its names need"})
    return out


def _ipam_problems(conn, now):
    """Two devices on one address: its MAC keeps changing (seen.flapping), until an admin acknowledges it."""
    from .ipam import seen
    cfg = seen.settings(conn)
    return [{'severity': 'warn', 'area': 'ipam', 'node': None, 'link': f"/search?q={f['ip']}#address",
             'what': f"{f['ip']}: {len(f['macs'])} different MACs in {cfg.flap_minutes} minutes (an address conflict?)"}
            for f in seen.flapping(conn, int(now.timestamp()))]


def problems(conn, settings, now=None):
    """[{severity: error|warn|info, area: node|dns|dhcp|time|ipam|web, what, link, node}], the worst first."""
    now = now or datetime.now(timezone.utc)
    out = []
    for n in conn.execute('SELECT * FROM nodes ORDER BY name').fetchall():
        out += _node_problems(conn, settings, n, now)
    managed = conn.execute('SELECT COUNT(*) FROM nodes WHERE managed = 1').fetchone()[0]
    if managed and not conn.execute("SELECT 1 FROM nodes WHERE role = 'primary'").fetchone():
        out.append({'severity': 'warn', 'area': 'dns', 'node': None, 'link': '/nodes',
                    'what': 'no primary yet: make one node the primary (Nodes)'})
    out += _zone_problems(conn, settings) + _dhcp_problems(conn) + _ipam_problems(conn, now)
    from .web_tls import problems as https_problems
    out += https_problems(conn, settings)
    # a module that's off has nothing to say (the clock checks stay: they're about the nodes)
    from .modules import enabled
    on = enabled(conn)
    out = [p for p in out if on.get(p['area'], True)]
    return sorted(out, key=lambda p: RANK[p['severity']])


def level(found):
    """The worst severity that needs an admin: 'error', 'warn' or 'ok' (info doesn't count)."""
    worst = min((RANK[p['severity']] for p in found), default=RANK['info'])
    return {0: 'error', 1: 'warn'}.get(worst, 'ok')


# The top bar shows the level on every page: one evaluation is shared for a few seconds.
_cache, _cache_lock = {}, threading.Lock()
CACHE_FOR = 15


def cached_level(settings):
    with _cache_lock:
        hit = _cache.get(settings.db_path)
        if hit and time.monotonic() - hit[0] < CACHE_FOR:
            return hit[1]
    conn = db.connect(settings.db_path)
    try:
        found = problems(conn, settings)
    finally:
        conn.close()
    result = (level(found), sum(1 for p in found if p['severity'] != 'info'))
    with _cache_lock:
        _cache[settings.db_path] = (time.monotonic(), result)
    return result
