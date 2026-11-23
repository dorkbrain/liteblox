"""Publish a zone: bump the serial, check it, commit it, deploy it to the nodes holding a primary copy.

With a primary picked that is the primary alone; its secondaries follow by
NOTIFY and IXFR, and LiteBlox waits for them to reach the new serial. Before a
primary is picked (one node, or a dual-master pair) every node serving the zone
holds a primary copy, and the deploy is two-phase across them: every node
stages the new file and checks it with its own named-checkzone; only when all
of them have staged does any node switch over. A node whose file changed
outside LiteBlox (drift) or that can't be reached stops the publish before
anything is written. After the switch every node is asked over DNS which
serial it serves.
"""

import contextlib
import hashlib
import time

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from .. import db
from ..nodes import service as nodes
from ..nodes.client import AgentError
from . import serial as serial_mod
from .drafts import Drafts, rev as rev_of
from .repo import Repo
from .validate import ToolMissing, named_checkzone
from .zonefile import Zone, ZoneParseError


SECONDARY_ATTEMPTS = 20     # seconds a secondary gets to reach a new serial (NOTIFY usually takes one)


class PublishError(RuntimeError):
    pass


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def linked_nodes(conn, zone_id):
    return conn.execute('SELECT n.*, zn.node_file, zn.deployed_sha256 FROM zone_nodes zn '
                        'JOIN nodes n ON n.id = zn.node_id WHERE zn.zone_id = ? ORDER BY n.name',
                        (zone_id,)).fetchall()


def is_secondary(node):
    return node['role'] == 'secondary'


def address(node):
    from ..bindconf.model import node_address
    return node_address(node) or node['host']


def _file_serial(content, name):
    try:
        return Zone.parse(content, name + '.').serial
    except (ZoneParseError, LookupError, ValueError):
        return None


def node_states(conn, settings, zone_row):
    """Live state of every node serving the zone.

    state: 'in-sync' (has the published copy), 'behind' (unchanged since LiteBlox's
    last write but older than the published copy), 'drift' (changed on the node),
    'unreachable'.
    """
    published = Drafts(settings).published(zone_row)
    out = []
    for n in linked_nodes(conn, zone_row['id']):
        live = bool(zone_row['dynamic'])
        entry = {'node': n, 'content': None, 'sha256': None, 'loaded_serial': None, 'error': None,
                 'secondary': is_secondary(n) or live}
        if entry['secondary']:
            # a secondary's copy is whatever it last transferred, and a dynamic zone's file is named's own:
            # compare what it serves
            seen = served_serial(address(n), zone_row['name'])
            entry['loaded_serial'] = seen
            want = None if live else _file_serial(published, zone_row['name'])
            if seen is None:
                entry.update(state='unreachable', error='does not answer for the zone over DNS')
            else:
                entry['state'] = 'in-sync' if want is None or seen >= want else 'behind'
            out.append(entry)
            continue
        try:
            with nodes.agent_client(settings, n, timeout=10.0) as c:
                z = c.get_zone(zone_row['name'])
            entry.update(content=z['content'], sha256=z['sha256'], loaded_serial=z.get('loaded_serial'))
            entry['file_serial'] = _file_serial(z['content'], zone_row['name'])
            if z['sha256'] == sha(published):
                entry['state'] = 'in-sync'
                if z['sha256'] != n['deployed_sha256']:
                    _adopt_matching(conn, zone_row['id'], n['id'], z['sha256'])
            elif z['sha256'] != n['deployed_sha256']:
                entry['state'] = 'drift'
            else:
                entry['state'] = 'behind'
        except AgentError as e:
            entry.update(state='unreachable', error=e.message)
        out.append(entry)
    return out


def _adopt_matching(conn, zone_id, node_id, file_sha):
    """A node file changed outside LiteBlox but now equals the published copy: nothing to resolve."""
    with conn:
        conn.execute('UPDATE zone_nodes SET deployed_sha256 = ? WHERE zone_id = ? AND node_id = ?',
                     (file_sha, zone_id, node_id))


def served_serial(host, zone_name, timeout=2.0):
    """SOA serial the server at host answers with, or None."""
    query = dns.message.make_query(zone_name.rstrip('.') + '.', dns.rdatatype.SOA)
    try:
        response = dns.query.udp(query, host, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, host, timeout=timeout)
    except (dns.exception.DNSException, OSError):
        return None
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.SOA:
            return rrset[0].serial
    return None


def wait_for_serial(host, zone_name, expected, attempts=6, delay=1.0):
    """Poll until host serves `expected` (or a later serial). Returns the last serial seen."""
    seen = None
    for i in range(attempts):
        seen = served_serial(host, zone_name)
        if seen is not None and seen >= expected:
            return seen
        if i < attempts - 1:
            time.sleep(delay)
    return seen


def running(conn, zone_id):
    return conn.execute("SELECT id FROM deploys WHERE zone_id = ? AND status = 'running'",
                        (zone_id,)).fetchone() is not None


def _node_result(conn, deploy_id, node_id, status, error=None, served=None):
    with conn:
        conn.execute('INSERT INTO deploy_nodes (deploy_id, node_id, status, error, served_serial) VALUES (?, ?, ?, ?, ?) '
                     'ON CONFLICT (deploy_id, node_id) DO UPDATE SET status = excluded.status, '
                     'error = excluded.error, served_serial = COALESCE(excluded.served_serial, served_serial)',
                     (deploy_id, node_id, status, error, served))


def _finish(conn, deploy_id, status, error=None, **fields):
    sets = ', '.join(f'{k} = ?' for k in fields)
    with conn:
        conn.execute(f"UPDATE deploys SET status = ?, error = ?, finished_at = datetime('now')"
                     f"{', ' + sets if sets else ''} WHERE id = ?",
                     (status, error, *fields.values(), deploy_id))


class _Item:
    """One zone in a publish job."""

    def __init__(self, row, deploy_id):
        self.row, self.deploy_id, self.name = row, deploy_id, row['name']


def publish(settings, zone_name, username, log, rev=None, job_id=None, verify=wait_for_serial,
            linked=False, revs=None, message=None):
    """Publish a zone's draft (or republish its published copy). Returns zone_name's deploy id.

    linked=True also publishes drafts linked to it (PTR changes an edit here made in a
    reverse zone, and so on); every node stages every zone before any node switches over.
    rev / revs: the revisions the user reviewed (zone_name's, and {zone: rev} for the rest).
    message: the user's commit message for every zone in this publish (the serial is added);
    None keeps the default "Publish <zone>".
    """
    from ..nodes import roles
    if roles.busy():
        raise PublishError('a role change (promote, demote) is running; publish when it has finished')
    conn = db.connect(settings.db_path)
    try:
        names = [zone_name] + (sorted(Drafts(settings).linked(zone_name)) if linked else [])
        revs = dict(revs or {})
        if rev is not None:
            revs[zone_name] = rev
        rows = []
        for name in names:
            row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
            if row is None:
                raise PublishError(f'no such zone {name}')
            if row['kind'] == 'forwarding':
                raise PublishError(f'{name} forwards queries elsewhere: it has no records to publish')
            if row['dynamic']:
                raise PublishError(f'{name} is dynamic: its edits are sent as updates, there is nothing to publish')
            if running(conn, row['id']):
                raise PublishError(f'a publish of {name} is already running')
            rows.append(row)
        items = []
        with conn:
            for row in rows:
                items.append(_Item(row, conn.execute(
                    'INSERT INTO deploys (zone_id, job_id, username, message) VALUES (?, ?, ?, ?)',
                    (row['id'], job_id, username, message)).lastrowid))
        try:
            _publish(conn, settings, items, username, log, revs, verify, message)
            return items[0].deploy_id
        except Exception as e:
            for it in items:
                if conn.execute('SELECT status FROM deploys WHERE id = ?', (it.deploy_id,)).fetchone()[0] == 'running':
                    _finish(conn, it.deploy_id, 'failed', str(e))
            raise
    finally:
        conn.close()


def _publish(conn, settings, items, username, log, revs, verify, message=None):
    drafts = Drafts(settings)
    repo = Repo(settings.repo_dir).ensure()
    multi = len(items) > 1
    label = (lambda it, n: f"{n['name']} {it.name}") if multi else (lambda it, n: n['name'])

    for it in items:
        it.text, it.is_draft = drafts.load(it.row)
        if it.name in revs and rev_of(it.text) != revs[it.name]:
            raise PublishError(f'{it.name} changed since you reviewed it; review it again'
                               if multi else 'the zone changed since you reviewed it; review it again')
        if it.is_draft and drafts.is_stale(it.row):
            raise PublishError(f'the published copy of {it.name} changed after this draft was started; '
                               'review the diff, discard the draft and redo the change')
        serving = linked_nodes(conn, it.row['id'])
        waiting = [n['name'] for n in serving if not n['managed']]
        if waiting:
            raise PublishError(f"{', '.join(waiting)} {'is' if len(waiting) == 1 else 'are'} not taken over yet: "
                               "take over first (the node's page → Take over)")
        it.targets = [n for n in serving if not is_secondary(n)]
        it.secondaries = [n for n in serving if is_secondary(n)]
        if not it.targets:
            raise PublishError(f'no node holds a primary copy of {it.name}')
        it.published_sha = sha(drafts.published(it.row))
        log(f"{'Publishing draft of' if it.is_draft else 'Republishing'} {it.name} to "
            f"{', '.join(n['name'] for n in it.targets)} (deploy #{it.deploy_id})"
            + (f"; {', '.join(n['name'] for n in it.secondaries)} will transfer it" if it.secondaries else ''))
        for n in it.secondaries:
            _node_result(conn, it.deploy_id, n['id'], 'pending')

    all_nodes = {n['id']: n for it in items for n in it.targets}
    with contextlib.ExitStack() as stack:
        clients = {i: stack.enter_context(nodes.agent_client(settings, n, timeout=30.0)) for i, n in all_nodes.items()}

        # 1. preflight: every node reachable and unchanged since LiteBlox last wrote it
        problems = []
        for it in items:
            it.current, it.live = {}, []
            for n in it.targets:
                try:
                    z = clients[n['id']].get_zone(it.name)
                except AgentError as e:
                    _node_result(conn, it.deploy_id, n['id'], 'unreachable', e.message)
                    problems.append(f"{label(it, n)}: unreachable ({e.message})")
                    continue
                it.current[n['id']] = z['sha256']
                it.live += [s for s in (z.get('loaded_serial'), _file_serial(z['content'], it.name)) if s]
                if z['sha256'] != n['deployed_sha256'] and z['sha256'] == it.published_sha:
                    _adopt_matching(conn, it.row['id'], n['id'], z['sha256'])
                    _node_result(conn, it.deploy_id, n['id'], 'pending')
                elif z['sha256'] != n['deployed_sha256']:
                    _node_result(conn, it.deploy_id, n['id'], 'drift', 'zone file changed on the node outside LiteBlox')
                    problems.append(f"{label(it, n)}: {n['node_file']} was changed on the node since LiteBlox last wrote it")
                else:
                    _node_result(conn, it.deploy_id, n['id'], 'pending')
        if problems:
            for p in problems:
                log(f'  ✗ {p}')
            raise PublishError('nothing was changed: ' + '; '.join(problems)
                               + ". Resolve it on the zone's Review page.")
        log('  ✓ all nodes reachable and unchanged since the last publish')

        # 2. new serials, local check
        for it in items:
            try:
                zone = Zone.parse(it.text, it.name + '.')
            except ZoneParseError as e:
                raise PublishError(f'{it.name} does not parse: {e}')
            old, it.serial = serial_mod.bump(zone, live=it.live)
            it.text = zone.render()
            log(f"  {it.name + ' ' if multi else ''}serial {old} → {it.serial}")
            try:
                ok, out = named_checkzone(it.name, it.text)
                if not ok:
                    raise PublishError(f'named-checkzone rejected {it.name}:\n{out}')
                log(f"  ✓ named-checkzone (LiteBlox){' ' + it.name if multi else ''}")
            except ToolMissing:
                log("  named-checkzone is not installed here; relying on each node's check")

        # 3. stage every zone on every node; any failure aborts all of them
        staged = []
        for it in items:
            for n in it.targets:
                try:
                    st = clients[n['id']].stage_zone(it.name, it.text, it.current[n['id']])
                except AgentError as e:
                    detail = f"\n{e.details.get('output')}" if e.details.get('output') else ''
                    _node_result(conn, it.deploy_id, n['id'], 'failed', e.message + detail)
                    log(f"  ✗ {label(it, n)}: staging failed: {e.message}")
                    for other, m, sid in staged:
                        with contextlib.suppress(AgentError):
                            clients[m['id']].abort_zone(other.name, sid)
                        _node_result(conn, other.deploy_id, m['id'], 'aborted')
                    raise PublishError(f"staging failed on {label(it, n)}; no node was changed")
                staged.append((it, n, st['stage_id']))
                _node_result(conn, it.deploy_id, n['id'], 'staged')
                log(f"  ✓ {label(it, n)}: staged and checked by its named-checkzone")

        # 4. record the new versions, then switch every node over
        for it in items:
            it.commit = repo.write(it.row['repo_file'], it.text,
                                   f"{message or f'Publish {it.name}'} (serial {it.serial})", username)
            if it.is_draft:
                moved = (drafts.meta(it.name) or {}).get('moved_comments')
                with conn:          # comment lines sorting took out of the file join the zone's notes
                    conn.execute("UPDATE zones SET notes = CASE WHEN ? = '' THEN notes "
                                 "WHEN notes = '' THEN ? ELSE notes || char(10) || ? END WHERE id = ?",
                                 ('\n'.join(moved or []),) * 3 + (it.row['id'],))
                drafts.discard(it.name)
            it.committed = []
            log(f"  ✓ committed {it.commit[:10] if it.commit else '(no file change)'} to the zone history"
                + (f' ({it.name})' if multi else ''))
        for it, n, sid in staged:
            try:
                clients[n['id']].commit_zone(it.name, sid)
            except AgentError as e:
                _node_result(conn, it.deploy_id, n['id'], 'failed', e.message)
                log(f"  ✗ {label(it, n)}: {e.message} (the node kept its previous file)")
                continue
            with conn:
                conn.execute('UPDATE zone_nodes SET deployed_sha256 = ? WHERE zone_id = ? AND node_id = ?',
                             (sha(it.text), it.row['id'], n['id']))
            _node_result(conn, it.deploy_id, n['id'], 'committed')
            it.committed.append(n)
            log(f"  ✓ {label(it, n)}: switched to the new file and reloaded")

    # 5. ask each node over DNS what it serves; secondaries get time for NOTIFY + transfer
    incomplete = []
    for it in items:
        ok = len(it.committed) == len(it.targets)
        for n in it.committed + (it.secondaries if it.committed else []):
            secondary = is_secondary(n)
            seen = (verify(address(n), it.name, it.serial, attempts=SECONDARY_ATTEMPTS) if secondary
                    else verify(address(n), it.name, it.serial))
            if seen is not None and seen >= it.serial:
                _node_result(conn, it.deploy_id, n['id'], 'verified', served=seen)
                log(f"  ✓ {label(it, n)}: serving serial {seen}" + (' (transferred)' if secondary else ''))
            else:
                ok = False
                error = (f"hasn't transferred serial {it.serial} yet (serves {seen})" if secondary
                         else f'serves serial {seen}, expected {it.serial}')
                _node_result(conn, it.deploy_id, n['id'], 'failed', error, served=seen)
                log(f"  ✗ {label(it, n)}: {error}")
        _finish(conn, it.deploy_id, 'ok' if ok else 'partial',
                None if ok else 'not every node is serving the new serial', commit_sha=it.commit, serial=it.serial)
        if not ok:
            incomplete.append(f'{it.name} (serial {it.serial})')
    # PTR changes for dynamic reverse zones were waiting for these forward zones to go live
    from . import dynamic
    for it in items:
        if it.committed and dynamic.queued_ptr(conn, it.row['id']):
            dynamic.flush_ptr_queue(settings, conn, it.row, username, log)
    if incomplete:
        raise PublishError(f"published {', '.join(incomplete)}, but not every node is serving it; "
                           'fix the node and publish again')


def accept_node_file(conn, zone_row, node_id, expected_sha):
    """Treat the node's current (drifted) file as LiteBlox's base: the next publish overwrites it."""
    with conn:
        cur = conn.execute('UPDATE zone_nodes SET deployed_sha256 = ? WHERE zone_id = ? AND node_id = ?',
                           (expected_sha, zone_row['id'], node_id))
    return cur.rowcount == 1


def recent_deploys(conn, zone_id, limit=10):
    return conn.execute('SELECT * FROM deploys WHERE zone_id = ? ORDER BY id DESC LIMIT ?', (zone_id, limit)).fetchall()


def deploy_nodes(conn, deploy_id):
    return conn.execute('SELECT dn.*, n.name FROM deploy_nodes dn JOIN nodes n ON n.id = dn.node_id '
                        'WHERE dn.deploy_id = ? ORDER BY n.name', (deploy_id,)).fetchall()

