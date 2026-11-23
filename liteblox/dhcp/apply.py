"""Write Kea's config to nodes, one at a time, with a check after each and all-or-nothing rollback.

Like bindconf.apply for BIND: back the node up, stage (the agent runs kea-dhcp4 -t),
commit (config-reload; the agent puts the old files back itself if Kea refuses), then
check that both Kea services still answer and that kea-dhcp4 opened its interface
sockets. A node that fails rolls back every node this job already changed, and the
DB change that started it is undone.
"""

import difflib
import json
import time

from .. import db, jobs
from ..nodes import service as nodes
from ..nodes.client import AgentError
from . import validate
from .model import for_node, ha_pair, layout_for
from .render import file_hashes, render


class DhcpError(RuntimeError):
    pass


def files_for(conn, node, **overrides):
    return render(for_node(conn, node, **overrides), layout_for(node))


def dhcp_nodes(conn):
    return [n for n in nodes.list_nodes(conn) if n['dhcp']]


def running(c):
    """{service: running} from the node's Kea control sockets; dhcp4 also needs its sockets open."""
    out = {}
    for service in ('dhcp4', 'd2'):
        try:
            answer = c.dhcp_command(service, 'status-get')
            ok = answer.get('result') == 0
            if service == 'dhcp4' and ok:
                sockets = ((answer.get('arguments') or {}).get('sockets') or {}).get('status', 'ready')
                ok = sockets == 'ready'
            out[service] = ok
        except AgentError:
            out[service] = False
    return out


def ha_state(c):
    """kea-dhcp4's own HA state (hot-standby, partner-down, waiting...), or None outside a pair."""
    try:
        answer = c.dhcp_command('dhcp4', 'status-get')
    except AgentError:
        return None
    ha = ((answer.get('arguments') or {}).get('high-availability') or [{}])[0]
    return ((ha.get('ha-servers') or {}).get('local') or {}).get('state')


def _ordered(rows, pair):
    """The standby first and the primary last, so the node serving clients changes after its partner."""
    rank = {pair.standby_id: 0, pair.primary_id: 2} if pair.active else {}
    return sorted(rows, key=lambda n: (rank.get(n['id'], 1), n['name']))


def record_commit(conn, node_id, files):
    with conn:
        conn.execute('UPDATE nodes SET dhcp_files = ?, dhcp_drift = NULL WHERE id = ?',
                     (json.dumps(file_hashes(files)), node_id))


def live_interfaces(settings, node):
    with nodes.agent_client(settings, node, timeout=15.0) as c:
        return c.status().get('interfaces') or []


def _guard(node, files, interfaces):
    """The development safeguard, once more right before the files leave LiteBlox."""
    validate.guard_rendered(files)
    served = json.loads(files['kea-dhcp4.conf'])['Dhcp4']['interfaces-config']['interfaces']
    errors = validate.check_interfaces(node, served, interfaces, [])
    if errors:
        raise validate.Invalid(errors)


def preview(conn, settings, node, **overrides):
    """What a change would write on one node: {node, diff, problems}."""
    old = files_for(conn, nodes.get_node(conn, node['id']))
    new = files_for(conn, node, **overrides)

    def shown(files, role):       # the review never shows a private key or a TSIG secret
        text = files.get(role, '')
        return f'(a private key, {len(text)} bytes)\n' if role == 'tls/ha.key' and text else nodes.mask_secrets(text)
    diff = ''.join(''.join(difflib.unified_diff(shown(old, r).splitlines(True), shown(new, r).splitlines(True),
                                                f'{node["name"]} {r} now', f'{node["name"]} {r} after'))
                   for r in dict.fromkeys(list(old) + list(new)))
    problems = []
    try:
        _guard(node, new, live_interfaces(settings, node))
        if diff:
            with nodes.agent_client(settings, node, timeout=30.0) as c:
                c.check_dhcp(new)
    except validate.Invalid as e:
        problems += list(e.errors.values())
    except AgentError as e:
        problems.append(f"{node['name']}: {e.message}" + (f'\n{kea_errors(e.details.get("output"))}'
                                                          if e.details.get('output') else ''))
    return {'node': node, 'diff': diff, 'problems': problems}


def kea_errors(output):
    """The lines of Kea's -t output that say what's wrong (it logs a lot around them)."""
    lines = [l for l in output.splitlines() if 'ERROR' in l or 'failed' in l.lower() or 'error' in l.lower()]
    return '\n'.join(lines or output.splitlines()[-3:])


def apply_dhcp(settings, conn, node_ids, reason, username, log, change=None, undo=None, settle=8, ha_wait=90,
               skip_unchanged=False):
    """Write each node's Kea config as the DB says (after change(conn)); all or nothing. Returns the names of
    the nodes written. skip_unchanged: leave a node alone when its config wouldn't change (a subnet that isn't
    served yet), so Kea isn't reloaded and the pair doesn't resync for nothing."""
    from ..backups import service as backups
    rows = [nodes.get_node(conn, int(i)) for i in node_ids]
    missing = [n['name'] for n in rows if not n['dhcp']]
    if missing:
        raise DhcpError(f"Kea isn't set up on {', '.join(missing)} (its page → Set up DHCP)")
    if change:
        change(conn)
    pair = ha_pair(conn)
    rows = _ordered(rows, pair)
    done = []

    def give_up(message):
        for n in reversed(done):
            try:
                with nodes.agent_client(settings, n, timeout=60.0) as c:
                    c.rollback_dhcp()
                log(f"  ✓ {n['name']}: rolled back")
            except AgentError as e:
                log(f"  ✗ {n['name']}: rollback failed: {e.message}")
        if undo:
            undo(conn)
        with conn:
            for n in done:
                conn.execute('UPDATE nodes SET dhcp_files = ? WHERE id = ?', (n['dhcp_files'], n['id']))
        raise DhcpError(message)

    for node in rows:
        node = nodes.get_node(conn, node['id'])
        log(f"{node['name']}:")
        files = files_for(conn, node)
        if skip_unchanged and not node['dhcp_drift'] and node['dhcp_files'] \
                and file_hashes(files) == json.loads(node['dhcp_files']):
            log('  unchanged: nothing written')
            continue
        try:
            _guard(node, files, live_interfaces(settings, node))
        except validate.Invalid as e:
            log(f'  ✗ {e}')
            give_up(f"{node['name']}: {e}")
        except AgentError as e:
            give_up(f"{node['name']} is unreachable: {e.message}")
        served = json.loads(files['kea-dhcp4.conf'])['Dhcp4']['interfaces-config']['interfaces']
        log(f"  serves on: {', '.join(served) or 'no interface'}")
        try:
            backups.snapshot_before_change(conn, settings, node, reason, username)
        except backups.BackupError as e:
            give_up(f"{node['name']}: {e}")
        try:
            with nodes.agent_client(settings, node, timeout=60.0) as c:
                c.commit_dhcp(c.stage_dhcp(files)['stage_id'])
        except AgentError as e:
            detail = e.details.get('output')
            log(f"  ✗ refused: {e.message}" + (f'\n{detail}' if detail else ''))
            give_up(f"{node['name']} refused the Kea config: {e.message}")
        done.append(node)
        log('  ✓ backed up, committed (Kea reloaded its config)')
        state = {}
        for _ in range(settle):
            with nodes.agent_client(settings, node, timeout=30.0) as c:
                state = running(c)
            if all(state.values()):
                break
            time.sleep(1)
        if not all(state.values()):
            down = ', '.join(s for s, ok in state.items() if not ok)
            log(f'  ✗ after the change: {down} not answering, or its sockets not open')
            give_up(f"{node['name']}: Kea stopped working after the change ({down}); every node this change "
                    'touched was rolled back')
        log('  ✓ kea-dhcp4 (sockets open) and D2 answer')
        record_commit(conn, node['id'], files)
    ids = {n['id'] for n in done}
    if pair.active and ids & {pair.primary_id, pair.standby_id} and {pair.primary_id, pair.standby_id} <= \
            {n['id'] for n in rows}:
        # the pair has to find each other (TLS, the link addresses, clocks) before this counts as done
        log('Failover pair: waiting for both servers to reach hot-standby (this can take a minute or two)')
        states = {}
        for _ in range(ha_wait // 3):
            for n in rows:
                if n['id'] in (pair.primary_id, pair.standby_id):
                    with nodes.agent_client(settings, n, timeout=15.0) as c:
                        states[n['name']] = ha_state(c)
            if all(s == 'hot-standby' for s in states.values()):
                break
            time.sleep(3)
        if not all(s == 'hot-standby' for s in states.values()):
            seen = ', '.join(f'{k}: {v or "no answer"}' for k, v in states.items())
            log(f'  ✗ the pair did not reach hot-standby within {ha_wait}s ({seen})')
            give_up(f'the failover pair did not start ({seen}); every node this change touched was rolled back')
        log(f"  ✓ {pair.primary_name} serves, {pair.standby_name} stands by (hot-standby)")
    return [n['name'] for n in done]


def stale(conn, node):
    """Has the DB moved on since this DHCP node was last given its config (a new primary, a rotated key...)?"""
    if not node['dhcp'] or not node['dhcp_files']:
        return False
    return file_hashes(files_for(conn, node)) != json.loads(node['dhcp_files'])


def follow_primary(settings, conn, log, username='liteblox'):
    """Rewrite Kea's config on every DHCP node it changed for (D2 sends DNS updates to the primary).

    Best effort: a node that can't be changed now keeps its old config and the health check
    tries again; one with Kea config changed by hand is left for its Overwrite.
    """
    for node in dhcp_nodes(conn):
        if not stale(conn, node):
            continue
        if node['dhcp_drift']:
            log(f"  ⚠ {node['name']}: its Kea config was changed outside LiteBlox; DHCP's DNS updates follow once "
                'you overwrite it (its page)')
            continue
        try:
            apply_dhcp(settings, conn, [node['id']], 'DHCP follows the DNS primary', username, lambda line: log('  ' + line))
            log(f"  ✓ {node['name']}: DHCP sends its DNS updates to {for_node(conn, node).primary}")
        except (DhcpError, AgentError) as e:
            log(f"  ⚠ {node['name']}: Kea's config not updated yet ({e}); the health check tries again")


def start(settings, node_ids, reason, username, change=None, undo=None, done=None, background=True, node_id=None,
          skip_unchanged=True):
    """apply_dhcp as a job ('dhcp config'); nodes whose config doesn't change are left alone unless
    skip_unchanged=False (a rewrite)."""
    def run(log):
        conn = db.connect(settings.db_path)
        try:
            names = apply_dhcp(settings, conn, node_ids, reason, username, log, change, undo,
                               skip_unchanged=skip_unchanged)
            db.audit(conn, username, 'dhcp_apply', f"{reason}: {', '.join(names) or 'no node changed'}")
            if not names:
                log("✓ Saved; no node's Kea config changed")
                return
            log(done or f"✓ {', '.join(names)}: Kea runs the new config")
        finally:
            conn.close()
    return jobs.start(settings.db_path, 'dhcp config', run, node_id=node_id, username=username, background=background)


def start_rewrite(settings, node_id, username, reason='rewrite Kea config', background=True):
    """One node's Kea config written again (Rewrite DHCP config, and Overwrite after drift)."""
    return start(settings, [node_id], reason, username, background=background, node_id=node_id,
                 done='✓ the Kea config is LiteBlox\'s', skip_unchanged=False)
