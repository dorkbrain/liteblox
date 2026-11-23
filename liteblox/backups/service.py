"""Node config backups: fetch from the agent, skip unchanged ones, prune to the retention window.

Archives are written to <backups>/<node>/<node>-YYYYmmdd-HHMMSS[-kind].tgz and
restore with `tar zxf FILE -C /` (the agent stores paths without the leading /).
"""

import io
import json
import tarfile
from datetime import datetime, timedelta, timezone

from ..nodes import agent_module
from ..nodes.client import AgentError
from ..nodes.service import agent_client

KINDS = ('scheduled', 'manual', 'pre-change', 'pre-bootstrap')
SNAPSHOT_KINDS = ('pre-change', 'pre-bootstrap')
SNAPSHOT_DAYS = 90
RECENT_HOURS = 24
STALE_HOURS = 48
MAX_VIEW_BYTES = 512 * 1024


class BackupError(RuntimeError):
    pass


def _utcnow():
    return datetime.now(timezone.utc)


def _parse(ts):
    return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)


def _fmt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def meta_member(name):
    return f'{agent_module().BACKUP_META}/{name}'


def read_manifest(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        return json.load(tar.extractfile(meta_member('manifest.json')))


def _write(settings, node_name, kind, data):
    folder = settings.backups_dir / node_name
    folder.mkdir(parents=True, exist_ok=True)
    suffix = '' if kind == 'scheduled' else f'-{kind}'
    name = f"{node_name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}{suffix}.tgz"
    path = folder / name
    n = 1
    while path.exists():                    # two backups in the same second
        path = folder / name.replace('.tgz', f'-{n}.tgz')
        n += 1
    path.touch(mode=0o600)
    path.write_bytes(data)
    return f'{node_name}/{path.name}'


def last_ok(conn, node_id):
    return conn.execute("SELECT * FROM backups WHERE node_id = ? AND status = 'ok' "
                        'ORDER BY created_at DESC, id DESC LIMIT 1', (node_id,)).fetchone()


def backup_node(conn, settings, node, kind='manual', reason=None, username=None):
    """Back up one node. Returns {'action': 'written'|'unchanged'|'failed', 'id', 'error'}.

    Scheduled runs skip writing when the file list and hashes match the last
    backup; manual and pre-change backups always write a file.
    """
    if kind not in KINDS:
        raise ValueError(f'bad backup kind {kind}')
    keys = bool(node['backup_keys'])
    try:
        with agent_client(settings, node, timeout=120.0) as c:
            data, manifest_hash = c.backup(include_keys=keys)
        manifest = read_manifest(data)
    except (AgentError, tarfile.TarError, KeyError, ValueError) as e:
        message = getattr(e, 'message', None) or str(e)
        with conn:
            row_id = conn.execute(
                "INSERT INTO backups (node_id, kind, status, reason, username, error) VALUES (?, ?, 'failed', ?, ?, ?)",
                (node['id'], kind, reason, username, message)).lastrowid
        return {'action': 'failed', 'id': row_id, 'error': message}

    previous = last_ok(conn, node['id'])
    if (kind == 'scheduled' and previous and previous['manifest_sha256'] == manifest_hash
            and bool(previous['keys_included']) == keys):
        with conn:
            conn.execute("UPDATE backups SET checked_at = datetime('now') WHERE id = ?", (previous['id'],))
        return {'action': 'unchanged', 'id': previous['id'], 'error': None}

    file = _write(settings, node['name'], kind, data)
    with conn:
        row_id = conn.execute(
            'INSERT INTO backups (node_id, kind, status, file, size, file_count, keys_included, '
            "manifest_sha256, manifest, reason, username) VALUES (?, ?, 'ok', ?, ?, ?, ?, ?, ?, ?, ?)",
            (node['id'], kind, file, len(data), len(manifest['files']), int(keys), manifest_hash,
             json.dumps(manifest), reason, username)).lastrowid
    return {'action': 'written', 'id': row_id, 'error': None}


def record_file(conn, settings, node_id, path, kind, reason=None, username=None):
    """Register an archive made elsewhere (bootstrap's SSH snapshot of /etc/bind)."""
    rel = path.relative_to(settings.backups_dir).as_posix()
    with conn:
        return conn.execute(
            "INSERT INTO backups (node_id, kind, status, file, size, reason, username) VALUES (?, ?, 'ok', ?, ?, ?, ?)",
            (node_id, kind, rel, path.stat().st_size, reason, username)).lastrowid


def snapshot_before_change(conn, settings, node, reason, username):
    """Back up a node before LiteBlox changes its config; refuses the change if the backup fails."""
    result = backup_node(conn, settings, node, 'pre-change', reason, username)
    if result['action'] == 'failed':
        raise BackupError(f"backup before {reason} failed, change not made: {result['error']}")
    return result


def prune(conn, settings, node_id, now=None):
    """Delete backups outside retention. Returns the deleted rows' files.

    Kept: the newest backup always; everything from the last 24 hours; the newest
    scheduled/manual backup of each of the last keep_daily days and keep_weekly
    ISO weeks; pre-change/pre-bootstrap snapshots for 90 days. Failed attempts
    are dropped after 90 days.
    """
    now = now or _utcnow()
    cfg = settings.backups
    rows = conn.execute('SELECT * FROM backups WHERE node_id = ? ORDER BY created_at DESC, id DESC',
                        (node_id,)).fetchall()
    ok = [r for r in rows if r['status'] == 'ok']
    keep = {ok[0]['id']} if ok else set()

    days, weeks = {}, {}
    for r in ok:
        created = _parse(r['created_at'])
        if now - created <= timedelta(hours=RECENT_HOURS):
            keep.add(r['id'])
        if r['kind'] in SNAPSHOT_KINDS:
            if now - created <= timedelta(days=SNAPSHOT_DAYS):
                keep.add(r['id'])
            continue
        day = created.date()
        week = created.isocalendar()[:2]
        if day not in days and len(days) < cfg.keep_daily:
            days[day] = r['id']
        if week not in weeks and len(weeks) < cfg.keep_weekly:
            weeks[week] = r['id']
    keep |= set(days.values()) | set(weeks.values())

    deleted = []
    for r in rows:
        if r['id'] in keep:
            continue
        if r['status'] == 'failed' and now - _parse(r['created_at']) <= timedelta(days=SNAPSHOT_DAYS):
            continue
        if r['file']:
            (settings.backups_dir / r['file']).unlink(missing_ok=True)
            deleted.append(r['file'])
        with conn:
            conn.execute('DELETE FROM backups WHERE id = ?', (r['id'],))
    return deleted


def is_stale(conn, settings, node_id, now=None):
    """True when scheduled backups are on and the node hasn't had a good one in 48 hours (a scanner has nothing
    to back up)."""
    if not settings.backups.backup_at:
        return False
    node = conn.execute('SELECT bind, dhcp, ntp FROM nodes WHERE id = ?', (node_id,)).fetchone()
    if node is not None and not (node['bind'] or node['dhcp'] or node['ntp']):
        return False
    row = last_ok(conn, node_id)
    if row is None:
        return True
    seen = max(_parse(row['created_at']), _parse(row['checked_at']) if row['checked_at'] else _parse(row['created_at']))
    return (now or _utcnow()) - seen > timedelta(hours=STALE_HOURS)


def manifest_changes(old, new):
    """File-level differences between two manifests: added, removed, changed paths."""
    old_files = (old or {}).get('files', {})
    new_files = (new or {}).get('files', {})
    return {
        'added': sorted(set(new_files) - set(old_files)),
        'removed': sorted(set(old_files) - set(new_files)),
        'changed': sorted(p for p in set(old_files) & set(new_files)
                          if old_files[p]['sha256'] != new_files[p]['sha256']),
    }


def previous_ok(conn, row):
    return conn.execute("SELECT * FROM backups WHERE node_id = ? AND status = 'ok' AND manifest IS NOT NULL "
                        'AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT 1',
                        (row['node_id'], row['created_at'], row['created_at'], row['id'])).fetchone()


def read_file(settings, row, path):
    """Contents of one file from an archive, as text (None if it isn't in the archive)."""
    member = path.lstrip('/')
    with tarfile.open(settings.backups_dir / row['file'], mode='r:gz') as tar:
        try:
            info = tar.getmember(member)
        except KeyError:
            return None
        if not info.isfile():
            return None
        data = tar.extractfile(info).read(MAX_VIEW_BYTES + 1)
    text = data[:MAX_VIEW_BYTES].decode('utf-8', errors='replace')
    return text + ('\n… (truncated)' if len(data) > MAX_VIEW_BYTES else '')


def ready_nodes(conn):
    """Set-up nodes with something to back up: BIND, Kea or chrony (not scanners)."""
    return conn.execute("SELECT * FROM nodes WHERE status != 'new' AND (bind = 1 OR dhcp = 1 OR ntp = 1) "
                        'ORDER BY name').fetchall()


def backup_all(settings, kind='scheduled', username=None, log=print):
    """Back up and prune every set-up node. Used by the scheduler and `liteblox backup run --all`."""
    from .. import db
    conn = db.connect(settings.db_path)
    try:
        results = {}
        for node in ready_nodes(conn):
            result = backup_node(conn, settings, node, kind, username=username)
            pruned = prune(conn, settings, node['id'])
            results[node['name']] = dict(result, pruned=pruned)
            log(f"{node['name']}: {result['action']}"
                + (f" ({result['error']})" if result['error'] else '')
                + (f', pruned {len(pruned)}' if pruned else ''))
        return results
    finally:
        conn.close()
