"""Agent upgrades over mutual TLS (4.5): which nodes can, the job, the buttons, the API, the v39 column."""

import pytest

from conftest import csrf_from
from liteblox import db, jobs
from liteblox.nodes import agent_sha256, service
from liteblox.nodes.bootstrap import INSTALL_REV
from liteblox.nodes.client import AgentError
from test_api import bearer, make, people  # noqa: F401 (fixture)

NEW = agent_sha256()


@pytest.fixture
def node(conn):
    with conn:
        node_id = conn.execute(
            "INSERT INTO nodes (name, host, host_key, host_key_fp, status, agent_version, agent_sha256, "
            "cert_fingerprint, install_rev) VALUES ('ns1', '192.0.2.53', 'k', 'f', 'ready', '4.4.0', ?, 'fp', ?)",
            ('ab' * 32, INSTALL_REV)).lastrowid
    return node_id


def row(conn, node_id):
    return conn.execute('SELECT * FROM nodes WHERE id = ?', (node_id,)).fetchone()


def set_node(conn, node_id, **fields):
    with conn:
        conn.execute(f"UPDATE nodes SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                     (*fields.values(), node_id))


def status(sha, version='4.5.0', last=None):
    return {'agent_version': version, 'agent_sha256': sha, 'install_rev': INSTALL_REV, 'named_version': 'BIND 9.20',
            'interfaces': [], 'last_upgrade': last, 'taken_over': False}


class Agent:
    """A node's agent: answers /status from a script of answers, one per call."""

    def __init__(self, answers, refuse=None):
        self.answers, self.refuse, self.staged = list(answers), refuse, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def status(self):
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, AgentError):
            raise answer
        return answer

    def upgrade_agent(self, version, digest, source):
        if self.refuse:
            raise AgentError(409, self.refuse)
        self.staged.append((version, digest, len(source)))
        return {'staged': True}


@pytest.fixture
def fake(monkeypatch):
    def install(agent):
        monkeypatch.setattr(service, 'agent_client', lambda s, n, timeout=10.0: agent)
        return agent
    return install


def run(settings, ids, clock_step=3):
    t = [0.0]

    def clock():
        return t[0]

    def sleep(s):
        t[0] += clock_step
    return service.start_agent_upgrade(settings, ids, 'alice', background=False, sleep=sleep, clock=clock,
                                       via=' (test)')


def job(conn, job_id):
    return jobs.get(conn, job_id)


# ── which nodes ────────────────────────────────────────────────────────────────

def test_v39_adds_the_column(conn):
    assert len(db.MIGRATIONS) >= 39
    assert 'install_rev' in {r['name'] for r in conn.execute('PRAGMA table_info(nodes)')}


def test_can_upgrade(conn, node):
    assert service.can_upgrade(row(conn, node))
    set_node(conn, node, install_rev=INSTALL_REV - 1)
    assert not service.can_upgrade(row(conn, node))         # needs Repair for the installer
    set_node(conn, node, install_rev=None)
    assert not service.can_upgrade(row(conn, node))
    set_node(conn, node, install_rev=INSTALL_REV, agent_sha256=NEW)
    assert not service.can_upgrade(row(conn, node))         # already current
    set_node(conn, node, agent_sha256='ab' * 32, cert_fingerprint=None)
    assert not service.can_upgrade(row(conn, node))         # needs Repair (certificate)
    set_node(conn, node, cert_fingerprint='fp', status='error')
    assert not service.can_upgrade(row(conn, node))         # unreachable


def test_record_status_keeps_install_rev(conn, node):
    service.record_status(conn, node, status('ab' * 32) | {'install_rev': 7})
    assert row(conn, node)['install_rev'] == 7
    service.record_status(conn, node, status('ab' * 32) | {'install_rev': None})
    assert row(conn, node)['install_rev'] == 0             # an agent from before 4.5


# ── the job ────────────────────────────────────────────────────────────────────

def test_the_happy_path(conn, settings, node, fake):
    before = {'at': 1, 'result': 'running', 'version': '4.4.0'}
    agent = fake(Agent([status('ab' * 32, '4.4.0', before), AgentError(None, 'restarting'),
                        status(NEW, '4.5.0', {'at': 2, 'result': 'installed'})]))
    j = job(conn, run(settings, [node]))
    assert j['status'] == 'ok', j['log']
    assert agent.staged and agent.staged[0][1] == NEW
    assert row(conn, node)['agent_sha256'] == NEW and row(conn, node)['agent_version'] == '4.5.0'
    assert 'ns1: ✓ running agent 4.5.0' in j['log'] and j['kind'] == 'agent upgrade' and j['node_id'] == node
    assert conn.execute("SELECT username, detail FROM audit WHERE action = 'node_agent_upgrade'").fetchone()[:] == (
        'alice', f'ns1 {service.__version__} (test)')


def test_a_rollback_is_reported(conn, settings, node, fake):
    before = {'at': 1, 'result': 'running'}
    rolled = {'at': 1, 'result': 'rolled back', 'detail': 'the new agent did not start 2 times'}
    fake(Agent([status('ab' * 32, '4.4.0', before), status('ab' * 32, '4.4.0', before),
                status('ab' * 32, '4.4.0', rolled)]))
    j = job(conn, run(settings, [node]))
    assert j['status'] == 'failed'
    assert 'ns1: rolled back: the new agent did not start 2 times' in j['log']
    assert 'not upgraded: ns1' in j['log']
    assert not conn.execute("SELECT 1 FROM audit WHERE action = 'node_agent_upgrade'").fetchone()


def test_an_old_refusal_isnt_taken_for_this_one(conn, settings, node, fake):
    old = {'at': 1, 'result': 'refused', 'detail': 'from last time'}
    fake(Agent([status('ab' * 32, '4.4.0', old), status('ab' * 32, '4.4.0', old),
                status(NEW, '4.5.0', {'at': 1, 'result': 'installed'})]))
    assert job(conn, run(settings, [node]))['status'] == 'ok'


def test_a_timeout(conn, settings, node, fake):
    fake(Agent([status('ab' * 32, '4.4.0'), AgentError(None, 'connection refused')]))
    j = job(conn, run(settings, [node], clock_step=30))
    assert j['status'] == 'failed'
    assert "didn't come back on the new code" in j['log'] and 'connection refused' in j['log']


def test_the_agent_refuses(conn, settings, node, fake):
    fake(Agent([status('ab' * 32, '4.4.0')], refuse='this node has no installer yet'))
    j = job(conn, run(settings, [node]))
    assert j['status'] == 'failed' and 'the agent refused the upgrade: this node has no installer yet' in j['log']


def test_nodes_that_cant_are_skipped(conn, settings, node, fake):
    set_node(conn, node, install_rev=0)
    agent = fake(Agent([status('ab' * 32, '4.4.0')]))
    j = job(conn, run(settings, [node]))
    assert j['status'] == 'ok' and 'it needs Repair / upgrade agent over SSH' in j['log'] and not agent.staged


def test_refused_while_a_job_runs_on_the_node(conn, settings, node):
    with conn:
        conn.execute("INSERT INTO jobs (kind, node_id, status) VALUES ('publish', ?, 'running')", (node,))
    with pytest.raises(service.NodeError, match='a job is still running on ns1'):
        run(settings, [node])


# ── the pages ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('alice', 'correct-horse', 'admin'))
    return client


@pytest.fixture
def viewer(client, make_user, login):
    login(*make_user('bob', 'correct-horse', 'readonly'))
    return client


@pytest.fixture
def started(monkeypatch):
    calls = []

    def start(settings, ids, username, **kw):
        calls.append((ids, username))
        return 42
    monkeypatch.setattr(service, 'start_agent_upgrade', start)
    return calls


def post(client, path):
    token = csrf_from(client.get('/nodes').text)
    return client.post(path, data={'csrf_token': token}, follow_redirects=False)


def test_the_buttons(admin, conn, node, started):
    assert 'Upgrade agent</button>' in admin.get('/nodes').text
    assert 'action="/nodes/upgrade-agents"' in admin.get('/nodes').text
    assert f'action="/nodes/{node}/upgrade-agent"' in admin.get(f'/nodes/{node}').text
    r = post(admin, f'/nodes/{node}/upgrade-agent')
    assert r.status_code == 303 and r.headers['location'] == '/jobs/42' and started == [([node], 'alice')]
    r = post(admin, '/nodes/upgrade-agents')
    assert r.headers['location'] == '/jobs/42' and started[-1] == ([node], 'alice')


def test_no_button_when_it_needs_repair(admin, conn, node, started):
    set_node(conn, node, install_rev=0)
    assert 'action="/nodes/upgrade-agents"' not in admin.get('/nodes').text
    page = admin.get(f'/nodes/{node}').text
    assert f'action="/nodes/{node}/upgrade-agent"' not in page and '/help/install#upgrading-an-agent' in page
    r = post(admin, f'/nodes/{node}/upgrade-agent')
    assert r.status_code == 303 and 'error=' in r.headers['location'] and started == []


def test_read_only_users_cant(viewer, conn, node, started):
    assert 'upgrade-agent' not in viewer.get(f'/nodes/{node}').text
    assert 'upgrade-agents' not in viewer.get('/nodes').text
    assert post(viewer, f'/nodes/{node}/upgrade-agent').status_code == 403
    assert post(viewer, '/nodes/upgrade-agents').status_code == 403
    assert started == []


def test_csrf_is_needed(admin, node, started):
    r = admin.post(f'/nodes/{node}/upgrade-agent', follow_redirects=False)
    assert r.status_code in (400, 403) and started == []


# ── the API ────────────────────────────────────────────────────────────────────

def test_the_api(client, people, conn, node, started):  # noqa: F811
    full = bearer(make(people, 'alice', 'full'))
    got = client.get('/api/v1/nodes/ns1', headers=full).json()
    assert got['install_rev'] == INSTALL_REV and got['can_upgrade'] is True
    r = client.post('/api/v1/nodes/ns1/upgrade-agent', headers=full)
    assert r.status_code == 202 and r.json() == {'job': 42} and r.headers['location'] == '/api/v1/jobs/42'
    assert started == [([node], 'alice')]
    assert client.post('/api/v1/nodes/nope/upgrade-agent', headers=full).status_code == 404
    read = bearer(make(people, 'alice', 'read'))
    assert client.post('/api/v1/nodes/ns1/upgrade-agent', headers=read).status_code == 403
    set_node(conn, node, agent_sha256=NEW)
    r = client.post('/api/v1/nodes/ns1/upgrade-agent', headers=full)
    assert r.status_code == 409 and 'already current' in r.json()['detail']
    assert client.get('/api/v1/nodes', headers=full).json()[0]['can_upgrade'] is False
