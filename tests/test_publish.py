import hashlib
import re
from pathlib import Path

import pytest

from liteblox import jobs
from liteblox.dns import publish as pub
from liteblox.dns.drafts import Drafts, rev
from liteblox.dns.repo import Repo, zone_file
from liteblox.dns.zonefile import Zone
from liteblox.nodes import service as nodes
from liteblox.nodes.client import AgentError

from conftest import csrf_from
from test_nodes import FP, HOST_KEY

EXAMPLE = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class FakeNode:
    """One node's agent: a zone file, the serial it serves, and failure switches."""

    def __init__(self, content):
        self.content = content
        self.served = Zone.parse(content, 'example.com.').serial
        self.staged = {}
        self.fail_stage = self.fail_commit = self.down = False
        self.calls = []

    def get_zone(self, name):
        self._check()
        return {'content': self.content, 'sha256': sha(self.content), 'loaded_serial': self.served}

    def stage_zone(self, name, content, base):
        self._check()
        self.calls.append('stage')
        if base != sha(self.content):
            raise AgentError(409, 'drift')
        if self.fail_stage:
            raise AgentError(422, 'named-checkzone rejected the zone', {'output': 'bad record'})
        self.staged['s1'] = content
        return {'stage_id': 's1', 'output': 'OK', 'sha256': sha(content)}

    def commit_zone(self, name, stage_id):
        self.calls.append('commit')
        if self.fail_commit:
            raise AgentError(500, 'rndc reload failed; rolled back')
        self.content = self.staged.pop(stage_id)
        self.served = Zone.parse(self.content, 'example.com.').serial
        return {'loaded_serial': self.served}

    def abort_zone(self, name, stage_id):
        self.calls.append('abort')
        self.staged.pop(stage_id, None)

    def _check(self):
        if self.down:
            raise AgentError(None, 'cannot reach agent')


class Client:
    def __init__(self, fake):
        self.fake = fake

    def __enter__(self):
        return self.fake

    def __exit__(self, *exc):
        pass


@pytest.fixture
def setup(conn, settings, monkeypatch):
    """example.com published and served by ns1 + ns2 (fake agents)."""
    Repo(settings.repo_dir).ensure().write(zone_file('example.com'), EXAMPLE, 'Import example.com', 'test')
    with conn:
        conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES ('example.com', 'local', ?)",
                     (zone_file('example.com'),))
    fakes = {}
    for i, host in enumerate(('192.0.2.1', '192.0.2.2'), 1):
        node_id = nodes.add_node(conn, f'ns{i}', host, 22, 8530, HOST_KEY, FP)
        with conn:
            conn.execute("UPDATE nodes SET status = 'ready', managed = 1 WHERE id = ?", (node_id,))
            conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (1, ?, ?, ?)',
                         (node_id, '/etc/bind/db.example.com', sha(EXAMPLE)))
        fakes[host] = FakeNode(EXAMPLE)
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['host']]))
    zone_row = conn.execute('SELECT * FROM zones').fetchone()
    return fakes, zone_row


def verify_with(fakes):
    return lambda host, zone, expected, **kw: fakes[host].served


def edit_draft(settings, zone_row, old='192.0.2.53', new='192.0.2.54'):
    Drafts(settings).save(zone_row, EXAMPLE.replace(old, new), 'admin')


def run(settings, fakes, log=None, **kw):
    return pub.publish(settings, 'example.com', 'admin', log or (lambda line: None),
                       verify=verify_with(fakes), **kw)


def deploy(conn, deploy_id=None):
    row = conn.execute('SELECT * FROM deploys ORDER BY id DESC LIMIT 1').fetchone()
    return row, {r['name']: r['status'] for r in pub.deploy_nodes(conn, row['id'])}


# ── the happy path ─────────────────────────────────────────────────────────────

def test_publish_draft_to_all_nodes(conn, settings, setup):
    fakes, zone_row = setup
    edit_draft(settings, zone_row)
    lines = []
    run(settings, fakes, lines.append)

    published = Repo(settings.repo_dir).read(zone_file('example.com'))
    assert '192.0.2.54' in published and Zone.parse(published, 'example.com.').serial > 2026010101
    assert all(f.content == published for f in fakes.values())
    assert Drafts(settings).load(zone_row) == (published, False)                  # draft cleared
    assert {r['deployed_sha256'] for r in conn.execute('SELECT * FROM zone_nodes')} == {sha(published)}
    row, per_node = deploy(conn)
    assert row['status'] == 'ok' and per_node == {'ns1': 'verified', 'ns2': 'verified'}
    assert row['commit_sha'] and row['serial'] == Zone.parse(published, 'example.com.').serial
    assert any('serving serial' in l for l in lines)
    # stage everywhere before committing anywhere
    assert fakes['192.0.2.1'].calls == ['stage', 'commit'] and fakes['192.0.2.2'].calls == ['stage', 'commit']


def test_serial_beats_what_nodes_serve(conn, settings, setup):
    fakes, zone_row = setup
    fakes['192.0.2.2'].served = 2099010100
    edit_draft(settings, zone_row)
    run(settings, fakes)
    assert deploy(conn)[0]['serial'] == 2099010101


def test_republish_without_draft(conn, settings, setup):
    fakes, zone_row = setup
    run(settings, fakes)
    assert deploy(conn)[0]['status'] == 'ok'
    assert all(f.served == deploy(conn)[0]['serial'] for f in fakes.values())


# ── refusals before anything changes ───────────────────────────────────────────

def _nothing_changed(settings, fakes, zone_row, draft=True):
    assert Repo(settings.repo_dir).read(zone_file('example.com')) == EXAMPLE
    assert all(f.content == EXAMPLE and not f.staged for f in fakes.values())
    assert Drafts(settings).load(zone_row)[1] is draft


def test_drift_blocks_publish(conn, settings, setup):
    fakes, zone_row = setup
    fakes['192.0.2.2'].content = EXAMPLE + '; edited on the node\n'
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='changed on the node'):
        run(settings, fakes)
    assert fakes['192.0.2.1'].calls == [] and fakes['192.0.2.2'].calls == []
    assert Repo(settings.repo_dir).read(zone_file('example.com')) == EXAMPLE
    row, per_node = deploy(conn)
    assert row['status'] == 'failed' and per_node == {'ns1': 'pending', 'ns2': 'drift'}

    states = {s['node']['name']: s['state'] for s in pub.node_states(conn, settings, zone_row)}
    assert states == {'ns1': 'in-sync', 'ns2': 'drift'}
    assert pub.accept_node_file(conn, zone_row, 2, sha(fakes['192.0.2.2'].content))
    run(settings, fakes)                                                    # now overwrites ns2's edit
    assert '; edited on the node' not in fakes['192.0.2.2'].content


def test_node_file_matching_published_copy_is_not_drift(conn, settings, setup):
    fakes, zone_row = setup
    with conn:     # LiteBlox lost track (e.g. the node's edit was imported) but the file is identical
        conn.execute("UPDATE zone_nodes SET deployed_sha256 = 'stale' WHERE node_id = 2")
    assert {s['node']['name']: s['state'] for s in pub.node_states(conn, settings, zone_row)} == \
        {'ns1': 'in-sync', 'ns2': 'in-sync'}
    with conn:
        conn.execute("UPDATE zone_nodes SET deployed_sha256 = 'stale' WHERE node_id = 2")
    edit_draft(settings, zone_row)
    run(settings, fakes)
    assert deploy(conn)[0]['status'] == 'ok'


def test_unreachable_node_blocks_publish(conn, settings, setup):
    fakes, zone_row = setup
    fakes['192.0.2.1'].down = True
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='unreachable'):
        run(settings, fakes)
    fakes['192.0.2.1'].down = False
    _nothing_changed(settings, fakes, zone_row)


def test_stage_failure_aborts_everywhere(conn, settings, setup):
    fakes, zone_row = setup
    fakes['192.0.2.2'].fail_stage = True
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='no node was changed'):
        run(settings, fakes)
    _nothing_changed(settings, fakes, zone_row)
    assert fakes['192.0.2.1'].calls == ['stage', 'abort']
    assert deploy(conn)[1] == {'ns1': 'aborted', 'ns2': 'failed'}


def test_reviewed_revision_must_match(conn, settings, setup):
    fakes, zone_row = setup
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='changed since you reviewed'):
        run(settings, fakes, rev='0000000000000000')
    run(settings, fakes, rev=rev(EXAMPLE.replace('192.0.2.53', '192.0.2.54')))


def test_stale_draft_is_refused(conn, settings, setup):
    fakes, zone_row = setup
    edit_draft(settings, zone_row)
    Repo(settings.repo_dir).write(zone_file('example.com'), EXAMPLE + '; reimported\n', 'reimport', 'x')
    with pytest.raises(pub.PublishError, match='draft was started'):
        run(settings, fakes)


def test_only_one_publish_at_a_time(conn, settings, setup):
    fakes, zone_row = setup
    with conn:
        conn.execute("INSERT INTO deploys (zone_id, status) VALUES (1, 'running')")
    with pytest.raises(pub.PublishError, match='already running'):
        run(settings, fakes)


# ── partial failure and recovery ───────────────────────────────────────────────

def test_commit_failure_is_partial_then_republish_fixes(conn, settings, setup):
    fakes, zone_row = setup
    fakes['192.0.2.2'].fail_commit = True
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='not every node'):
        run(settings, fakes)
    row, per_node = deploy(conn)
    assert row['status'] == 'partial' and per_node == {'ns1': 'verified', 'ns2': 'failed'}
    published = Repo(settings.repo_dir).read(zone_file('example.com'))
    assert fakes['192.0.2.1'].content == published and fakes['192.0.2.2'].content == EXAMPLE
    states = {s['node']['name']: s['state'] for s in pub.node_states(conn, settings, zone_row)}
    assert states == {'ns1': 'in-sync', 'ns2': 'behind'}

    fakes['192.0.2.2'].fail_commit = False
    run(settings, fakes)
    assert deploy(conn)[0]['status'] == 'ok'
    assert fakes['192.0.2.1'].content == fakes['192.0.2.2'].content


def test_verify_mismatch_is_partial(conn, settings, setup):
    fakes, zone_row = setup
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='not every node'):
        pub.publish(settings, 'example.com', 'admin', lambda l: None, verify=lambda h, z, e: e - 1)
    row, per_node = deploy(conn)
    assert row['status'] == 'partial' and set(per_node.values()) == {'failed'}


# ── pages ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def test_review_publish_and_drift_actions(admin, conn, settings, setup, monkeypatch):
    fakes, zone_row = setup
    real_publish, real_start = pub.publish, jobs.start
    monkeypatch.setattr(pub, 'publish', lambda *a, **k: real_publish(*a, **{**k, 'verify': verify_with(fakes)}))
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    edit_draft(settings, zone_row)

    review = admin.get('/zones/example.com/review').text
    assert 'has the published copy' in review and 'Publish to 2 nodes' in review
    t = csrf_from(review)
    reviewed = re.search(r'name="rev" value="([0-9a-f]+)"', review).group(1)

    r = admin.post('/zones/example.com/publish', data={'csrf_token': t, 'rev': reviewed}, follow_redirects=False)
    job_id = int(r.headers['location'].rsplit('/', 1)[1])
    job = jobs.get(conn, job_id)
    assert job['status'] == 'ok', job['log']
    assert job['zone_id'] == 1 and 'serving serial' in job['log']
    page = admin.get(f'/jobs/{job_id}').text
    assert '/zones/example.com' in page

    zone_page = admin.get('/zones/example.com').text
    assert 'ns1 ✓' in zone_page and 'last publish <a href="/zones/example.com/deploys/1">#1</a>' in zone_page
    assert 'href="/zones/example.com/deploys/1">#1</a>' in admin.get('/zones/example.com/history').text
    assert 'published copy' in admin.get('/zones/example.com/settings').text
    assert admin.get('/zones/example.com/deploys/1').status_code == 200

    # drift on ns2 -> review shows it with both choices; import keeps the node's edit
    edited = fakes['192.0.2.2'].content + '; hand edit\n'
    fakes['192.0.2.2'].content = edited
    review = admin.get('/zones/example.com/review').text
    assert 'changed on the node' in review, review[review.find('<h2>Nodes'):][:1500]
    assert '+; hand edit' in review and 'Republish' not in review
    admin.post('/zones/example.com/nodes/2/import', data={'csrf_token': t, 'sha256': sha(edited)})
    assert Repo(settings.repo_dir).read(zone_file('example.com')) == edited
    states = {s['node']['name']: s['state'] for s in pub.node_states(conn, settings, zone_row)}
    assert states == {'ns1': 'behind', 'ns2': 'in-sync'}



# ── with a primary picked ──────────────────────────────────────────────────────

@pytest.fixture
def primary_setup(conn, settings, setup, monkeypatch):
    """ns1 the primary, ns2 its secondary (which serves whatever it last transferred)."""
    fakes, zone_row = setup
    with conn:
        conn.execute("UPDATE nodes SET role = 'primary' WHERE name = 'ns1'")
        conn.execute("UPDATE nodes SET role = 'secondary' WHERE name = 'ns2'")
        conn.execute("UPDATE zone_nodes SET node_file = '/var/lib/bind/liteblox/sec/db.example.com', "
                     "deployed_sha256 = NULL WHERE node_id = 2")
    secondary = fakes['192.0.2.2']
    secondary.get_zone = lambda name: pytest.fail('a secondary copy is never read through the agent')
    secondary.transfers = True
    monkeypatch.setattr(pub, 'served_serial', lambda host, zone, timeout=2.0: fakes[host].served)
    return fakes, zone_row


def follow(fakes):
    """verify that lets the secondary 'transfer' from the primary when asked (if it's allowed to)."""
    def verify(host, zone, expected, **kw):
        primary, secondary = fakes['192.0.2.1'], fakes['192.0.2.2']
        if host == '192.0.2.2':
            secondary.asked = kw
            if secondary.transfers:
                secondary.served = primary.served
        return fakes[host].served
    return verify


def test_publish_goes_to_the_primary_and_waits_for_the_secondary(conn, settings, primary_setup):
    fakes, zone_row = primary_setup
    edit_draft(settings, zone_row)
    lines = []
    deploy_id = pub.publish(settings, 'example.com', 'admin', lines.append, verify=follow(fakes))
    assert fakes['192.0.2.1'].calls == ['stage', 'commit'] and fakes['192.0.2.2'].calls == []
    assert fakes['192.0.2.2'].asked == {'attempts': pub.SECONDARY_ATTEMPTS}
    d, rows = deploy(conn, deploy_id)
    assert d['status'] == 'ok' and rows == {'ns1': 'verified', 'ns2': 'verified'}
    assert any('ns2 will transfer it' in line for line in lines)
    assert any('ns2: serving serial' in line and 'transferred' in line for line in lines)
    states = {s['node']['name']: s for s in pub.node_states(conn, settings, zone_row)}
    assert states['ns2']['secondary'] and states['ns2']['state'] == 'in-sync'


def test_review_names_the_primary_and_its_secondaries(client, make_user, login, conn, settings, primary_setup):
    fakes, zone_row = primary_setup
    edit_draft(settings, zone_row)
    login(*make_user('admin', 'admin-password', 'admin'))
    assert 'to ns1 (ns2 will transfer it)</button>' in client.get('/zones/example.com/review').text


def test_a_secondary_that_lags_makes_it_partial(conn, settings, primary_setup):
    fakes, zone_row = primary_setup
    fakes['192.0.2.2'].transfers = False
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='not every node is serving it'):
        pub.publish(settings, 'example.com', 'admin', print, verify=follow(fakes))
    d, rows = deploy(conn)
    assert d['status'] == 'partial' and rows == {'ns1': 'verified', 'ns2': 'failed'}
    error = conn.execute("SELECT error FROM deploy_nodes WHERE status = 'failed'").fetchone()[0]
    assert "hasn't transferred serial" in error
    states = {s['node']['name']: s['state'] for s in pub.node_states(conn, settings, zone_row)}
    assert states['ns2'] == 'behind'


def test_publish_refuses_a_node_not_taken_over(conn, settings, setup):
    fakes, zone_row = setup
    with conn:
        conn.execute("UPDATE nodes SET managed = 0 WHERE name = 'ns2'")
    edit_draft(settings, zone_row)
    with pytest.raises(pub.PublishError, match='ns2 is not taken over yet'):
        run(settings, fakes)
    assert fakes['192.0.2.1'].calls == []


def test_publishing_a_sorted_draft_moves_its_comments_to_the_notes(conn, settings, setup):
    fakes, zone_row = setup
    drafts = Drafts(settings)
    drafts.save(zone_row, ''.join(line for line in EXAMPLE.splitlines(keepends=True)
                                  if not line.startswith('$GENERATE')), 'admin')        # sortable without it
    moved = drafts.meta('example.com')['moved_comments']
    assert moved and all(not line.startswith(';') for line in moved)
    text, _ = drafts.load(zone_row)
    drafts.save(zone_row, text.replace('192.0.2.53', '192.0.2.54'), 'admin')            # a later edit adds none
    assert drafts.meta('example.com')['moved_comments'] == moved
    run(settings, fakes)
    assert conn.execute('SELECT notes FROM zones').fetchone()[0] == '\n'.join(moved)
    edit_draft(settings, zone_row, '192.0.2.54', '192.0.2.55')
    run(settings, fakes)
    assert conn.execute('SELECT notes FROM zones').fetchone()[0] == '\n'.join(moved)        # not again
