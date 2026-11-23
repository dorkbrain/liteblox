import hashlib
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone

import pytest

from liteblox import jobs, scheduler
from liteblox.backups import service as backups
from liteblox.nodes import agent_module
from liteblox.nodes import service as nodes
from liteblox.nodes.client import AgentError

from conftest import csrf_from
from test_nodes import FP, HOST_KEY

FILES = {'/etc/bind/named.conf': b'include "/etc/bind/named.conf.local";\n',
         '/etc/bind/db.example.com': b'@ IN SOA ns1 root 1 1 1 1 1\n',
         '/etc/bind/rndc.key': b'key "rndc-key" { secret "x"; };\n'}


def make_archive(files, keys=True):
    """An archive shaped like the agent's /backup output; returns (bytes, manifest hash)."""
    meta = agent_module().BACKUP_META
    included = {p: d for p, d in files.items() if keys or not p.endswith('.key')}
    manifest = {'node': 'test', 'named_version': 'BIND 9.20.30', 'keys_included': keys,
                'files': {p: {'sha256': hashlib.sha256(d).hexdigest(), 'size': len(d), 'mode': '0o644'}
                          for p, d in included.items()},
                'skipped': {} if keys else {'/etc/bind/rndc.key': 'key excluded'}}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for name, data in [(p.lstrip('/'), d) for p, d in included.items()] + [
                (f'{meta}/manifest.json', json.dumps(manifest).encode())]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue(), hashlib.sha256(json.dumps(manifest['files'], sort_keys=True).encode()).hexdigest()


class BackupAgent:
    files = dict(FILES)
    fail = None

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def backup(self, include_keys=True):
        if self.fail:
            raise AgentError(None, self.fail)
        return make_archive(self.files, include_keys)


@pytest.fixture
def agent(monkeypatch):
    BackupAgent.files, BackupAgent.fail = dict(FILES), None
    monkeypatch.setattr(backups, 'agent_client', lambda settings, node, timeout=10.0: BackupAgent())
    return BackupAgent


@pytest.fixture
def node(conn):
    node_id = nodes.add_node(conn, 'ns1', '192.0.2.53', 22, 8530, HOST_KEY, FP)
    with conn:
        conn.execute("UPDATE nodes SET status = 'ready' WHERE id = ?", (node_id,))
    return nodes.get_node(conn, node_id)


def rows(conn):
    return conn.execute('SELECT * FROM backups ORDER BY id').fetchall()


# ── taking backups ─────────────────────────────────────────────────────────────

def test_manual_backup_writes_private_archive(conn, settings, node, agent):
    result = backups.backup_node(conn, settings, node, 'manual', username='admin')
    assert result['action'] == 'written'
    row = rows(conn)[0]
    path = settings.backups_dir / row['file']
    assert row['file'].startswith('ns1/ns1-') and row['file'].endswith('-manual.tgz')
    assert path.stat().st_mode & 0o777 == 0o600
    assert (row['status'], row['file_count'], row['keys_included'], row['username']) == ('ok', 3, 1, 'admin')
    with tarfile.open(path) as tar:
        names = tar.getnames()
    assert 'etc/bind/named.conf' in names
    assert all(n.startswith(('etc/', 'var/lib/liteblox-agent/')) for n in names)   # tar zxf -C / is safe


def test_scheduled_backup_skips_unchanged(conn, settings, node, agent):
    assert backups.backup_node(conn, settings, node, 'scheduled')['action'] == 'written'
    assert backups.backup_node(conn, settings, node, 'scheduled')['action'] == 'unchanged'
    assert len(rows(conn)) == 1 and rows(conn)[0]['checked_at']
    assert len(list((settings.backups_dir / 'ns1').iterdir())) == 1

    agent.files['/etc/bind/db.example.com'] = b'@ IN SOA ns1 root 2 1 1 1 1\n'
    assert backups.backup_node(conn, settings, node, 'scheduled')['action'] == 'written'
    assert backups.backup_node(conn, settings, node, 'manual')['action'] == 'written'   # manual always writes
    assert len(rows(conn)) == 3


def test_keys_setting(conn, settings, node, agent):
    backups.backup_node(conn, settings, node, 'scheduled')
    with conn:
        conn.execute('UPDATE nodes SET backup_keys = 0')
    node = nodes.get_node(conn, 'ns1')
    assert backups.backup_node(conn, settings, node, 'scheduled')['action'] == 'written'
    row = rows(conn)[-1]
    assert row['keys_included'] == 0 and '/etc/bind/rndc.key' not in json.loads(row['manifest'])['files']


def test_failed_backup_is_recorded_and_blocks_changes(conn, settings, node, agent):
    agent.fail = 'cannot reach agent'
    assert backups.backup_node(conn, settings, node)['action'] == 'failed'
    assert rows(conn)[0]['status'] == 'failed' and rows(conn)[0]['error'] == 'cannot reach agent'
    with pytest.raises(backups.BackupError, match='change not made'):
        backups.snapshot_before_change(conn, settings, node, 'adopt example.com', 'admin')


def test_backup_all_covers_set_up_nodes(conn, settings, node, agent):
    nodes.add_node(conn, 'fresh', '192.0.2.99', 22, 8530, HOST_KEY, FP)      # status 'new': skipped
    lines = []
    results = backups.backup_all(settings, 'scheduled', log=lines.append)
    assert list(results) == ['ns1'] and lines == ['ns1: written']


# ── retention ──────────────────────────────────────────────────────────────────

def _insert(conn, settings, node_id, created, kind='scheduled', status='ok'):
    file = None
    if status == 'ok':
        file = f"ns1/ns1-{created.strftime('%Y%m%d-%H%M%S')}-{kind}.tgz"
        path = settings.backups_dir / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'x')
    with conn:
        return conn.execute('INSERT INTO backups (node_id, kind, status, file, created_at) VALUES (?, ?, ?, ?, ?)',
                            (node_id, kind, status, file, created.strftime('%Y-%m-%d %H:%M:%S'))).lastrowid


def test_prune_keeps_daily_weekly_and_recent_snapshots(conn, settings, node):
    settings.backups.keep_daily, settings.backups.keep_weekly = 3, 2
    now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    ids = {}
    for d in range(30):                                  # one scheduled backup a day, plus a manual on day 0
        ids[d] = _insert(conn, settings, node['id'], now - timedelta(days=d, hours=1))
    ids['manual-today'] = _insert(conn, settings, node['id'], now - timedelta(hours=2), 'manual')
    ids['snap-new'] = _insert(conn, settings, node['id'], now - timedelta(days=10), 'pre-change')
    ids['snap-old'] = _insert(conn, settings, node['id'], now - timedelta(days=120), 'pre-bootstrap')
    ids['fail-new'] = _insert(conn, settings, node['id'], now - timedelta(days=5), status='failed')
    ids['fail-old'] = _insert(conn, settings, node['id'], now - timedelta(days=100), status='failed')

    deleted = backups.prune(conn, settings, node['id'], now=now)
    kept = {r['id'] for r in rows(conn)}

    # newest per day for the last 3 days (day 0's newest is the 1h-old scheduled one)
    assert {ids[0], ids[1], ids[2]} <= kept
    assert ids['manual-today'] in kept                   # under 24 hours old: always kept
    # newest per ISO week for 2 weeks: day 0's week is already covered; the previous week's newest is kept
    prev_week = next(d for d in range(30) if (now - timedelta(days=d, hours=1)).isocalendar()[1]
                     != now.isocalendar()[1])
    assert ids[prev_week] in kept
    assert ids['snap-new'] in kept and ids['snap-old'] not in kept
    assert ids['fail-new'] in kept and ids['fail-old'] not in kept
    assert len(kept) == 7
    assert all(not (settings.backups_dir / f).exists() for f in deleted)


def test_prune_never_deletes_the_only_backup(conn, settings, node):
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    only = _insert(conn, settings, node['id'], old, 'pre-bootstrap')
    backups.prune(conn, settings, node['id'], now=datetime(2026, 10, 24, tzinfo=timezone.utc))
    assert [r['id'] for r in rows(conn)] == [only]


# ── staleness, changes, scheduler ──────────────────────────────────────────────

def test_is_stale(conn, settings, node):
    now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
    assert backups.is_stale(conn, settings, node['id'], now)
    row_id = _insert(conn, settings, node['id'], now - timedelta(hours=60))
    assert backups.is_stale(conn, settings, node['id'], now)
    with conn:
        conn.execute("UPDATE backups SET checked_at = ? WHERE id = ?",
                     ((now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'), row_id))
    assert not backups.is_stale(conn, settings, node['id'], now)
    settings.backups.backup_at = ''
    assert not backups.is_stale(conn, settings, node['id'], now - timedelta(days=30))


def test_manifest_changes():
    old = {'files': {'a': {'sha256': '1'}, 'b': {'sha256': '2'}, 'c': {'sha256': '3'}}}
    new = {'files': {'a': {'sha256': '1'}, 'b': {'sha256': 'X'}, 'd': {'sha256': '4'}}}
    assert backups.manifest_changes(old, new) == {'added': ['d'], 'removed': ['c'], 'changed': ['b']}


@pytest.mark.parametrize('now, expected', [
    (datetime(2026, 10, 24, 3, 0), 15 * 60),
    (datetime(2026, 10, 24, 3, 15), 24 * 3600),
    (datetime(2026, 10, 24, 23, 0), (4 * 60 + 15) * 60),
])
def test_seconds_until(now, expected):
    assert scheduler.seconds_until('03:15', now) == expected


def test_bootstrap_snapshot_is_recorded(conn, settings, node, monkeypatch):
    def fake_bootstrap(n, *args, **kw):
        path = settings.backups_dir / 'ns1' / 'ns1-20261024-120000-prebootstrap.tgz'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'snapshot')
        n['prebootstrap_backup'] = path
        raise RuntimeError('ssh failed after the snapshot')
    monkeypatch.setattr(nodes, 'bootstrap', fake_bootstrap)
    nodes.start_bootstrap(settings, node['id'], None, None, 'admin', background=False)
    row = rows(conn)[0]
    assert (row['kind'], row['file'], row['size']) == ('pre-bootstrap', 'ns1/ns1-20261024-120000-prebootstrap.tgz', 8)
    assert nodes.get_node(conn, 'ns1')['status'] == 'error'


# ── pages ──────────────────────────────────────────────────────────────────────

def test_backup_pages(client, make_user, login, conn, settings, node, agent):
    login(*make_user('admin', 'admin-password', 'admin'))
    t = csrf_from(client.get('/nodes/1/backups').text)
    r = client.post('/nodes/1/backups', data={'csrf_token': t}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/backups/1'

    agent.files['/etc/bind/db.example.com'] = b'@ IN SOA ns1 root 2 1 1 1 1\n'
    client.post('/nodes/1/backups', data={'csrf_token': t})
    detail = client.get('/backups/2').text
    assert 'changed' in detail and '/etc/bind/db.example.com' in detail and 'tar zxf' in detail

    listing = client.get('/nodes/1/backups').text
    assert listing.count('manual') >= 2 and '1 file' in listing
    with conn:
        conn.execute("UPDATE backups SET kind = 'pre-change' WHERE id = 1")
    listing = client.get('/nodes/1/backups').text
    assert 'All <span class="count">2</span>' in listing and 'Pre-change <span class="count">1</span>' in listing
    assert 'kind=pre-bootstrap' not in listing                                  # no backups of that kind
    manual = client.get('/nodes/1/backups?kind=manual').text
    assert '/backups/2"' in manual and '/backups/1"' not in manual and '1 file' in manual   # changes vs. any kind
    assert 'No backups of this kind' in client.get('/nodes/1/backups?kind=scheduled').text

    dl = client.get('/backups/2/download')
    assert dl.status_code == 200 and dl.headers['content-type'] == 'application/gzip'
    view = client.get('/backups/2/view', params={'path': '/etc/bind/db.example.com'})
    assert 'SOA ns1 root 2' in view.text
    assert client.get('/backups/2/view', params={'path': '/etc/passwd'}).status_code == 404

    r = client.post('/nodes/1/backups/settings', data={'csrf_token': t}, follow_redirects=False)
    assert r.status_code == 303 and nodes.get_node(conn, 'ns1')['backup_keys'] == 0


def test_readonly_can_list_but_not_download(client, make_user, login, conn, settings, node, agent):
    backups.backup_node(conn, settings, node)
    login(*make_user('viewer', 'viewer-pass', 'readonly'))
    page = client.get('/nodes/1/backups')
    assert page.status_code == 200 and 'Download' not in page.text and 'Back up now' not in page.text
    assert client.get('/backups/1').status_code == 200
    assert client.get('/backups/1/download').status_code == 403
    assert client.get('/backups/1/view', params={'path': '/etc/bind/rndc.key'}).status_code == 403
    t = csrf_from(page.text)
    assert client.post('/nodes/1/backups', data={'csrf_token': t}).status_code == 403


def test_stale_shows_on_nodes_page(client, make_user, login, node):
    login(*make_user('admin', 'admin-password', 'admin'))
    assert 'backup stale' in client.get('/nodes').text
    assert 'no successful backup in 48 hours' in client.get('/').text
