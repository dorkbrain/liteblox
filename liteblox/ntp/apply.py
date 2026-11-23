"""Write chrony's config to nodes, one at a time, with a check after each and all-or-nothing rollback.

Like dhcp.apply for Kea: back the node up, stage (the agent runs chronyd -p on the candidate), commit
(systemd restarts chrony through LiteBlox's path unit; the agent puts the old file back if chrony doesn't
come up), then read chrony's state. A source that isn't reachable yet is only reported: a pool's names
take a moment to resolve, and a source may come and go.
"""

import difflib
import json

from .. import db, jobs
from ..nodes import service as nodes
from ..nodes.client import AgentError
from .model import for_node, ntp_nodes
from .render import file_hashes, render


class NtpError(RuntimeError):
    pass


def files_for(conn, node, **overrides):
    return render(for_node(conn, node, **overrides))


def record_commit(conn, node_id, files):
    with conn:
        conn.execute('UPDATE nodes SET ntp_files = ?, ntp_drift = NULL WHERE id = ?',
                     (json.dumps(file_hashes(files)), node_id))


def state_of(status):
    """{synced, reference, stratum, offset, sources} from the agent's /status.time, or None."""
    time = (status or {}).get('time') or {}
    tracking = time.get('tracking')
    if time.get('daemon') != 'chrony':
        return None
    sources = time.get('sources') or []
    synced = bool(tracking) and tracking.get('leap') != 'Not synchronised' and any(s['state'] == '*' for s in sources)
    return {'synced': synced, 'reference': (tracking or {}).get('reference'), 'stratum': (tracking or {}).get('stratum'),
            'offset': (tracking or {}).get('offset'), 'sources': len(sources),
            'reachable': sum(1 for s in sources if s.get('reach'))}


def describe(state):
    if not state:
        return 'chrony is not answering'
    if state['synced']:
        return f"syncing from {state['reference']} (stratum {state['stratum']}, offset {state['offset']:+.6f}s)"
    return f"not synchronised yet: {state['reachable']} of {state['sources']} sources reachable"


def preview(conn, settings, node, **overrides):
    """What a change would write on one node: {node, diff, problems}."""
    old = files_for(conn, nodes.get_node(conn, node['id']))
    new = files_for(conn, node, **overrides)
    diff = ''.join(''.join(difflib.unified_diff(old[r].splitlines(True), new[r].splitlines(True),
                                                f'{node["name"]} {r} now', f'{node["name"]} {r} after'))
                   for r in new)
    problems = []
    if diff:
        try:
            with nodes.agent_client(settings, node, timeout=30.0) as c:
                c.check_ntp(new)
        except AgentError as e:
            problems.append(f"{node['name']}: {e.message}" + (f"\n{e.details['output']}" if e.details.get('output') else ''))
    return {'node': node, 'diff': diff, 'problems': problems}


def apply_ntp(settings, conn, node_ids, reason, username, log, change=None, undo=None):
    """Write each node's chrony config as the DB says (after change(conn)); all or nothing. Returns the names."""
    from ..backups import service as backups
    rows = [nodes.get_node(conn, int(i)) for i in node_ids]
    missing = [n['name'] for n in rows if not n['ntp']]
    if missing:
        raise NtpError(f"time sync isn't set up on {', '.join(missing)} (its page → Set up time sync)")
    if change:
        change(conn)
    done = []

    def give_up(message):
        for n in reversed(done):
            try:
                with nodes.agent_client(settings, n, timeout=60.0) as c:
                    c.rollback_ntp()
                log(f"  ✓ {n['name']}: rolled back")
            except AgentError as e:
                log(f"  ✗ {n['name']}: rollback failed: {e.message}")
        if undo:
            undo(conn)
        with conn:
            for n in done:
                conn.execute('UPDATE nodes SET ntp_files = ? WHERE id = ?', (n['ntp_files'], n['id']))
        raise NtpError(message)

    for node in sorted(rows, key=lambda n: n['name']):
        node = nodes.get_node(conn, node['id'])
        log(f"{node['name']}:")
        files = files_for(conn, node)
        try:
            backups.snapshot_before_change(conn, settings, node, reason, username)
        except backups.BackupError as e:
            give_up(f"{node['name']}: {e}")
        try:
            with nodes.agent_client(settings, node, timeout=90.0) as c:
                c.commit_ntp(c.stage_ntp(files)['stage_id'])
                state = state_of(c.status())
        except AgentError as e:
            detail = e.details.get('output')
            log(f"  ✗ refused: {e.message}" + (f'\n{detail}' if detail else ''))
            give_up(f"{node['name']}: {e.message}")
        done.append(node)
        log('  ✓ backed up, committed (chrony restarted on the new config)')
        log(f'  {describe(state)}')
        record_commit(conn, node['id'], files)
        with conn:
            conn.execute('UPDATE nodes SET ntp_state = ? WHERE id = ?', (json.dumps(state) if state else None, node['id']))
    return [n['name'] for n in rows]


def stale(conn, node):
    """Has the DB moved on since this node was last given its chrony config?"""
    if not node['ntp'] or not node['ntp_files']:
        return False
    return file_hashes(files_for(conn, node)) != json.loads(node['ntp_files'])


def busy(conn):
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'time config' AND status = 'running'").fetchone() is not None


def start(settings, node_ids, reason, username, change=None, undo=None, done=None, background=True, node_id=None):
    """apply_ntp as a job ('time config')."""
    def run(log):
        conn = db.connect(settings.db_path)
        try:
            names = apply_ntp(settings, conn, node_ids, reason, username, log, change, undo)
            db.audit(conn, username, 'ntp_apply', f"{reason}: {', '.join(names)}")
            log(done or f"✓ {', '.join(names)}: chrony runs the new config")
        finally:
            conn.close()
    return jobs.start(settings.db_path, 'time config', run, node_id=node_id, username=username, background=background)


def start_rewrite(settings, node_id, username, reason='rewrite time config', background=True):
    return start(settings, [node_id], reason, username, background=background, node_id=node_id,
                 done="✓ the chrony config is LiteBlox's")
