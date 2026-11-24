"""The health check, every minute: ask each node's agent how it is, notice config changed outside
LiteBlox (drift, a second primary made by hand), and run the pending change for a node that
missed a role change (an old primary to demote) once it answers again."""

import json
from datetime import datetime, timedelta, timezone

from .. import db, jobs, stats
from . import drift, roles
from . import service as nodes
from .client import AgentError

RETRY_AFTER = timedelta(minutes=10)      # a failed pending change isn't retried every minute


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def _tried_recently(conn, node_id):
    since = (datetime.now(timezone.utc) - RETRY_AFTER).strftime('%Y-%m-%d %H:%M:%S')
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'reconcile' AND node_id = ? AND created_at > ?",
                        (node_id, since)).fetchone() is not None


def _job_tried_recently(conn, kind, node_id):
    since = (datetime.now(timezone.utc) - RETRY_AFTER).strftime('%Y-%m-%d %H:%M:%S')
    return conn.execute('SELECT 1 FROM jobs WHERE kind = ? AND node_id = ? AND created_at > ?',
                        (kind, node_id, since)).fetchone() is not None


def _time(settings, conn, node, status, background):
    """chrony's state, drift on chrony.conf, and a missed change written again (at most every 10 minutes)."""
    from ..ntp import apply as ntp_apply
    expected = json.loads(node['ntp_files'] or '{}')
    actual = (((status or {}).get('time') or {}).get('files')) or {}
    changed = [role for role, sha in sorted(expected.items()) if actual.get(role) != sha]
    state = ntp_apply.state_of(status)
    with conn:
        conn.execute('UPDATE nodes SET ntp_drift = ?, ntp_state = ? WHERE id = ?',
                     (json.dumps(changed) if changed else None, json.dumps(state) if state else None, node['id']))
    note = f"; chrony config changed outside LiteBlox" if changed else ''
    if state is None:
        note += '; chrony is not running'
    elif not state['synced']:
        note += '; time: no usable source'
    if not changed and not roles.busy() and ntp_apply.stale(conn, nodes.get_node(conn, node['id'])) \
            and not _job_tried_recently(conn, 'time config', node['id']):
        ntp_apply.start_rewrite(settings, node['id'], 'liteblox', 'time sync catches up', background=background)
        note += '; its time config is behind: rewriting it'
    return note


def _bind_behind(settings, conn, node, background):
    """A config LiteBlox renders differently now (written by an older LiteBlox): write it again, at most
    every 10 minutes, and never beside another running job that could be writing it too."""
    from ..bindconf import apply as bind_apply
    node = nodes.get_node(conn, node['id'])
    if roles.busy() or not bind_apply.stale(conn, node) or _job_tried_recently(conn, 'bind config', node['id']):
        return False
    if conn.execute("SELECT 1 FROM jobs WHERE status = 'running'").fetchone():
        return False
    bind_apply.start_rewrite(settings, node['id'], 'liteblox', 'BIND config catches up', background=background)
    return True


def _sample(settings, conn, node):
    """The node's figures for the Dashboard's graphs (an agent older than 3.3 has none)."""
    try:
        with nodes.agent_client(settings, node, timeout=10.0) as c:
            stats.sample_node(conn, node['id'], c.stats())
    except AgentError:
        pass


def _neighbours(settings, conn, node):
    """What the node sees on its networks, for IPAM (an agent older than 3.4 has no /neigh: nothing to read)."""
    from ..ipam import seen
    v6 = any(':' in n for n in json.loads(node['networks'] or '[]'))     # an IPv6 network of its own: NDP too
    try:
        with nodes.agent_client(settings, node, timeout=10.0) as c:
            entries = c.neigh()
            if v6:
                # an agent before 6.0 ignores the family and answers with its IPv4 table again: keep only IPv6
                entries += [e for e in c.neigh(family=6) if ':' in (e.get('ip') or '')]
    except AgentError:
        return
    seen.record(conn, node['id'], entries)


def _sample_leases(settings, conn):
    from ..dhcp import leases
    if not leases.serving(conn):
        return
    found, errors = leases.serving_leases(settings, conn)
    if found or not errors:         # no server answered: no figures rather than a false 0
        stats.sample_leases(conn, leases.pool_use(conn, found))
    if not errors:                  # each name's newest lease expiry, for stale DHCP names
        from ..dns import reclaim
        reclaim.remember(conn, found)
    from ..dhcp.model import has_dhcp6
    if conn.execute('SELECT 1 FROM dhcp6_subnets LIMIT 1').fetchone() and any(has_dhcp6(n) for n in leases.serving(conn)):
        found6, errors6 = leases.serving_leases(settings, conn, family=6)
        if found6 or not errors6:
            stats.sample_leases6(conn, leases.pool_use6(conn, found6))
        if not errors6:
            from ..dns import reclaim
            reclaim.remember(conn, [(n, x) for n, x in found6 if x.get('type') == 'address'])


def _dhcp_tried_recently(conn, node_id):
    since = (datetime.now(timezone.utc) - RETRY_AFTER).strftime('%Y-%m-%d %H:%M:%S')
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'dhcp config' AND node_id = ? AND created_at > ?",
                        (node_id, since)).fetchone() is not None


def _interfaces_down(conn, node, status):
    """The interfaces Kea serves on node that its agent reports down (or doesn't have)."""
    from ..dhcp.model import for_node
    up = {i['name'] for i in (status or {}).get('interfaces') or [] if i.get('up')}
    if not (status or {}).get('interfaces'):
        return []                   # an agent that doesn't say: try the reload
    config = for_node(conn, nodes.get_node(conn, node['id']))
    return [i for i in dict.fromkeys(config.interfaces + config.interfaces6) if i not in up]


def start_reconcile(settings, node, background=True):
    """The node's pending change as a job (the health check's own user 'liteblox')."""
    return jobs.start(settings.db_path, 'reconcile',
                      lambda log: roles.reconcile(settings, node['id'], 'liteblox', log),
                      node_id=node['id'], username='liteblox', background=background)


def listening(dhcp4, daemon='kea-dhcp4'):
    """None when kea-dhcp4 (or kea-dhcp6) answers and listens on all its interfaces; else {status, errors}: 'down'
    (it doesn't answer), or status-get's 'retrying' / 'failed' (an interface it can't open, e.g. not up yet at
    boot)."""
    if not dhcp4:
        return None
    if not dhcp4.get('running'):
        return {'status': 'down', 'errors': [dhcp4.get('error') or f"{daemon} doesn't answer"]}
    sockets = dhcp4.get('sockets') or {}
    if sockets.get('status', 'ready') == 'ready':     # Kea before 2.0 doesn't report it
        return None
    return {'status': sockets['status'], 'errors': [str(e) for e in sockets.get('errors') or []] or ['no details']}


def check_node(settings, conn, node, background=True):
    """One node: status, drift, pending change. Returns a short line for the log."""
    if not node['agent_version'] and node['status'] == 'new':
        return f"{node['name']}: not set up yet"
    status, error = nodes.refresh(conn, settings, node)
    if error:
        return f"{node['name']}: unreachable ({error})"
    _sample(settings, conn, node)
    _neighbours(settings, conn, node)
    if node['pending']:
        # its config is from before a role change, so it differs; that's the pending change, not drift
        if roles.busy() or _tried_recently(conn, node['id']):
            return f"{node['name']}: back, its pending change waits"
        start_reconcile(settings, node, background)
        return f"{node['name']}: back, running its pending change"
    kea = drift.dhcp_changed(node, status)
    kea_note = f"; Kea config changed outside LiteBlox: {', '.join(kea)}" if kea else ''
    if node['dhcp']:
        services = ((status or {}).get('kea') or {}).get('services') or {}
        dhcp4, dhcp6 = services.get('dhcp4') or {}, services.get('dhcp6') or {}
        ha_state = ((dhcp4.get('ha') or {}).get('local') or {}).get('state')
        ha6_state = ((dhcp6.get('ha') or {}).get('local') or {}).get('state')
        sockets, sockets6 = listening(dhcp4), listening(dhcp6, 'kea-dhcp6')
        with conn:
            conn.execute('UPDATE nodes SET dhcp_drift = ?, dhcp_ha_state = ?, dhcp_ha_checked_at = ?, dhcp_sockets = ?, '
                         'dhcp6_ha_state = ?, dhcp6_ha_checked_at = ?, dhcp6_sockets = ? WHERE id = ?',
                         (json.dumps(kea) if kea else None, ha_state, _now() if ha_state else None,
                          json.dumps(sockets) if sockets else None, ha6_state, _now() if ha6_state else None,
                          json.dumps(sockets6) if sockets6 else None, node['id']))
        ra = (status or {}).get('ra') or {}
        if ra.get('ready') and not ra.get('in_place'):
            kea_note += "; radvd's config isn't in place"
        elif ra.get('ready') and ra.get('interfaces') and not ra.get('active'):
            kea_note += '; radvd is not running'
        if ha_state and ha_state != 'hot-standby':
            kea_note += f'; DHCP failover: {ha_state}'
        if ha6_state and ha6_state != 'hot-standby':
            kea_note += f'; DHCPv6 failover: {ha6_state}'
        if sockets:
            kea_note += f"; Kea DHCP {sockets['status']}: {'; '.join(sockets['errors'])}"
        if sockets6:
            kea_note += f"; Kea DHCPv6 {sockets6['status']}: {'; '.join(sockets6['errors'])}"
            if not sockets or sockets6['status'] == 'failed':
                sockets = sockets6          # the reload below starts kea-dhcp6's retries over as well
        from ..dhcp import apply as dhcp_apply
        # a DHCP change it missed (down during a promote, say): write it now, at most every 10 minutes
        if not kea and not roles.busy() and dhcp_apply.stale(conn, nodes.get_node(conn, node['id'])) \
                and not _dhcp_tried_recently(conn, node['id']):
            dhcp_apply.start_rewrite(settings, node['id'], 'liteblox', 'DHCP catches up', background=background)
            kea_note += '; its DHCP config is behind: rewriting it'
        # Kea gave up opening its sockets (an interface that came up after its retries ran out) and never tries
        # again by itself; a reload starts its retries over, once its interfaces are up (a reload before that
        # fails and rolls back). Not over a hand edit, which a rewrite would undo.
        elif sockets and sockets['status'] == 'failed' and not kea and not roles.busy() \
                and not _dhcp_tried_recently(conn, node['id']):
            down = _interfaces_down(conn, node, status)
            if down:
                kea_note += f": waits for {', '.join(down)} to come up"
            else:
                dhcp_apply.start_rewrite(settings, node['id'], 'liteblox', "Kea wasn't listening: reload",
                                         background=background)
                kea_note += ': reloading it'
    if node['ntp']:
        kea_note += _time(settings, conn, node, status, background)
    if not node['managed']:
        return f"{node['name']}: ok{kea_note}"
    changed = drift.changed_roles(conn, node, status)
    second = []
    if 'zones.conf' in changed:
        try:
            with nodes.agent_client(settings, node) as c:
                second = drift.second_primaries(conn, node, c.config()['zones'])
        except AgentError:
            pass
    with conn:
        conn.execute('UPDATE nodes SET drift = ?, second_primary = ?, drift_checked_at = ? WHERE id = ?',
                     (json.dumps(changed) if changed else None, json.dumps(second) if second else None,
                      _now(), node['id']))
    if second:
        return f"{node['name']}: declares {', '.join(second)} as primary outside LiteBlox{kea_note}"
    if not changed and _bind_behind(settings, conn, node, background):
        kea_note += '; its BIND config is behind: rewriting it'
    return f"{node['name']}: " + (f"changed outside LiteBlox: {', '.join(changed)}" if changed else 'ok') + kea_note


def check_all(settings, log=print, background=True):
    conn = db.connect(settings.db_path)
    try:
        for node in nodes.list_nodes(conn):
            try:
                log(check_node(settings, conn, node, background))
            except Exception as e:      # one node's trouble mustn't stop the others' checks
                log(f"{node['name']}: health check failed: {e}")
        try:
            from ..dhcp import ra
            line = ra.backstop(settings, conn, background)
            if line:
                log(line)
        except Exception as e:
            log(f'router advertisement backstop failed: {e}')
        try:
            _sample_leases(settings, conn)
            stats.prune(conn)
        except Exception as e:
            log(f'graph samples failed: {e}')
        try:
            from ..ipam import seen
            seen.prune(conn)
        except Exception as e:
            log(f'IPAM prune failed: {e}')
    finally:
        conn.close()
