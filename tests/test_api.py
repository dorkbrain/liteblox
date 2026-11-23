"""The API (3.1 milestone 1): tokens, bearer-only auth, the spec and docs page, the read endpoints."""

import re

import pytest
from fastapi import Depends

from liteblox import auth, jobs
from liteblox.api import tokens
from liteblox.api.deps import api_writer
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file

from conftest import csrf_from
from test_managed import EXAMPLE, lab  # noqa: F401 (fixture)


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def people(conn):
    auth.create_user(conn, 'alice', 'correct-horse', 'admin')
    auth.create_user(conn, 'bob', 'correct-horse', 'readonly')
    return conn


def make(conn, user='alice', scope='full', **kw):
    return tokens.create(conn, user, kw.pop('name', f'{user}-{scope}'), scope, 'test', **kw)[1]


# ── tokens ─────────────────────────────────────────────────────────────────────

def test_a_token_is_kept_only_as_a_hash(people):
    token_id, secret = tokens.create(people, 'alice', 'ci', 'read', 'alice')
    assert secret.startswith('lbx_') and len(secret) > 40
    dump = '\n'.join(str(tuple(r)) for r in people.execute('SELECT * FROM api_tokens'))
    assert secret not in dump and secret[:10] in dump          # the prefix, to tell tokens apart
    user = tokens.authenticate(people, secret, '192.0.2.9')
    assert (user.username, user.role, user.scope, user.can_write) == ('alice', 'admin', 'read', False)
    assert tokens.authenticate(people, secret[:-1] + 'x') is None and tokens.authenticate(people, 'nope') is None
    with pytest.raises(tokens.TokenError, match='already'):
        tokens.create(people, 'alice', 'ci', 'read', 'alice')
    with pytest.raises(tokens.TokenError, match='name it'):
        tokens.create(people, 'alice', '', 'read', 'alice')
    tokens.revoke(people, token_id)
    assert tokens.authenticate(people, secret) is None


def test_expiry_last_use_and_the_user_behind_it(people):
    secret = make(people, expires_days=1)
    with people:
        people.execute("UPDATE api_tokens SET expires_at = '2000-01-01 00:00:00'")
    assert tokens.authenticate(people, secret) is None
    secret = make(people, name='second')
    tokens.authenticate(people, secret, '192.0.2.9')
    first = people.execute("SELECT last_used_at FROM api_tokens WHERE name = 'second'").fetchone()[0]
    with people:
        people.execute("UPDATE api_tokens SET last_used_at = '2001-01-01 00:00:00' WHERE name = 'second'")
    tokens.authenticate(people, secret, '192.0.2.9')         # older than a minute: written again
    assert people.execute("SELECT last_used_at FROM api_tokens WHERE name = 'second'").fetchone()[0] >= first
    auth.create_user(people, 'carol', 'correct-horse', 'admin')
    carol = make(people, 'carol')
    auth.set_role(people, 'carol', 'readonly')
    assert tokens.authenticate(people, carol).can_write is False           # the role is read every call
    auth.set_password(people, 'carol', 'another-horse')
    assert tokens.authenticate(people, carol) is not None                  # a password change keeps tokens
    auth.delete_user(people, 'carol')
    assert tokens.authenticate(people, carol) is None


# ── auth on the API ────────────────────────────────────────────────────────────

def test_only_a_bearer_token_gets_in(app, client, people, login):
    token = make(people, scope='read')
    assert client.get('/api/v1/me').status_code == 401
    login('alice', 'correct-horse')
    r = client.get('/api/v1/me')
    assert r.status_code == 401 and r.headers['www-authenticate'] == 'Bearer'    # a session isn't enough
    me = client.get('/api/v1/me', headers=bearer(token)).json()
    assert me == {'username': 'alice', 'role': 'admin', 'token': {'name': 'alice-read', 'scope': 'read',
                                                                    'expires_at': None}}


def test_a_token_logs_nobody_into_the_pages(client, people):
    r = client.get('/nodes', headers=bearer(make(people)), follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/login'


def test_writes_need_a_full_token_of_an_admin_and_no_csrf(app, client, people):
    @app.post('/api/v1/_probe')
    def probe(user=Depends(api_writer)):
        return {'ok': user.username}
    assert client.post('/api/v1/_probe', headers=bearer(make(people))).json() == {'ok': 'alice'}
    r = client.post('/api/v1/_probe', headers=bearer(make(people, scope='read')))
    assert (r.status_code, r.json()['detail']) == (403, 'this token is read-only')
    r = client.post('/api/v1/_probe', headers=bearer(make(people, 'bob')))
    assert (r.status_code, r.json()['detail']) == (403, 'admin role required')
    assert client.post('/nodes/new', data={}).status_code == 403              # the pages still check CSRF


def test_the_spec_and_the_docs_page(client, people, login):
    assert client.get('/api/v1/openapi.json').status_code == 401
    assert client.get('/api/docs', follow_redirects=False).headers['location'] == '/login'
    spec = client.get('/api/v1/openapi.json', headers=bearer(make(people, 'bob', 'read'))).json()
    assert spec['paths'] and all(p.startswith('/api/v1/') for p in spec['paths'])
    assert '/api/v1/openapi.json' not in spec['paths'] and spec['components']['securitySchemes']['token']['scheme'] == 'bearer'
    login('bob', 'correct-horse')
    assert client.get('/api/v1/openapi.json').status_code == 200
    page = client.get('/api/docs').text
    assert 'vendor/swagger-ui-bundle.js' in page and 'api-docs.js' in page
    assert client.get('/static/vendor/swagger-ui-bundle.js').status_code == 200


# ── read endpoints ─────────────────────────────────────────────────────────────

@pytest.fixture
def zone(conn, settings, lab):  # noqa: F811
    Repo(settings.repo_dir).ensure().write(zone_file('example.com'), EXAMPLE, 'Import', 'test')
    with conn:
        conn.execute("INSERT INTO zones (name, mode, repo_file, also_notify) VALUES ('example.com', 'managed', ?, "
                     "'192.0.2.200')", (zone_file('example.com'),))
        for node_id in (1, 2):
            conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (1, ?, ?)",
                         (node_id, '/etc/bind/liteblox/db.example.com'))
        conn.execute("UPDATE nodes SET role = 'primary', drift = '[\"options.conf\"]', clock_skew = 3.5 WHERE id = 1")
    return conn.execute("SELECT * FROM zones WHERE name = 'example.com'").fetchone()


def test_nodes_and_zones(client, people, zone):
    h = bearer(make(people, 'bob', 'read'))
    nodes = client.get('/api/v1/nodes', headers=h).json()
    assert [n['name'] for n in nodes] == ['ns1', 'ns2']
    assert nodes[0]['role'] == 'primary' and nodes[0]['flags']['drift'] == ['options.conf']
    assert nodes[0]['flags']['clock_skew'] == 3.5 and nodes[1]['managed'] is True
    assert client.get('/api/v1/nodes/ns9', headers=h).status_code == 404
    assert client.get('/api/v1/zones', headers=h).json() == [
        {'name': 'example.com', 'kind': 'primary', 'dynamic': False, 'nodes': ['ns1', 'ns2'], 'has_draft': False}]
    detail = client.get('/api/v1/zones/example.com', headers=h).json()
    assert detail['settings']['also_notify'] == ['192.0.2.200'] and detail['published_serial']


def test_records_their_ids_and_the_draft(client, people, settings, zone):
    h = bearer(make(people, 'bob', 'read'))
    r = client.get('/api/v1/zones/example.com/records', headers=h)
    body = r.json()
    assert r.headers['etag'] == f'"{body["rev"]}"' and body['draft'] is False
    soa = next(x for x in body['records'] if x['type'] == 'SOA')
    assert soa['name'] == '@' and body['serial'] == int(soa['data'].split()[2])
    ids = {(x['name'], x['type'], x['data']): x['id'] for x in body['records']}
    # a draft with a record added at the top: every other record keeps its id
    Drafts(settings).save(zone, 'added 300 IN A 192.0.2.99\n' + EXAMPLE, 'alice')
    draft = client.get('/api/v1/zones/example.com/records', headers=h).json()
    assert draft['draft'] is True and draft['rev'] != body['rev']
    again = {(x['name'], x['type'], x['data']): x['id'] for x in draft['records']}
    assert all(again[k] == v for k, v in ids.items()) and ('added', 'A', '192.0.2.99') in again
    published = client.get('/api/v1/zones/example.com/records?published=true', headers=h).json()
    assert published['rev'] == body['rev'] and published['draft'] is False
    assert client.get('/api/v1/zones/nope.lab/records', headers=h).status_code == 404


def test_jobs(client, people, settings):
    h = bearer(make(people, 'bob', 'read'))
    job_id = jobs.start(settings.db_path, 'publish', lambda log: log('hello'), background=False, username='alice')
    listed = client.get('/api/v1/jobs', headers=h).json()
    assert listed[0]['id'] == job_id and listed[0]['status'] == 'ok'
    job = client.get(f'/api/v1/jobs/{job_id}', headers=h).json()
    assert job['kind'] == 'publish' and any('hello' in line for line in job['log'])
    assert client.get('/api/v1/jobs?status=failed', headers=h).json() == []
    assert client.get('/api/v1/jobs/999', headers=h).status_code == 404


# ── the token pages and the CLI ────────────────────────────────────────────────

def test_admins_make_tokens_for_anyone_users_for_themselves(client, people, login):
    login('alice', 'correct-horse')
    page = client.get('/users').text
    r = client.post('/tokens', data={'csrf_token': csrf_from(page), 'username': 'bob', 'name': 'monitoring',
                                     'scope': 'read', 'back': 'users'}, follow_redirects=True)
    secret = re.search(r'lbx_[A-Za-z0-9_-]+', r.text).group(0)
    assert 'only time LiteBlox shows this token' in r.text and tokens.authenticate(people, secret).username == 'bob'
    reveal = r.url.path
    r = client.post(reveal + '/done', data={'csrf_token': csrf_from(r.text)}, follow_redirects=True)
    assert r.url.path == '/users' and 'monitoring' in r.text and secret not in r.text
    assert client.get(reveal).status_code == 404                  # shown once
    client.post('/logout', data={'csrf_token': csrf_from(r.text)})

    login('bob', 'correct-horse')
    page = client.get('/account').text
    assert 'monitoring' in page
    client.post('/tokens', data={'csrf_token': csrf_from(page), 'username': 'alice', 'name': 'mine', 'scope': 'full'})
    owners = dict(people.execute('SELECT t.name, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id'))
    assert owners['mine'] == 'bob'                              # not alice's: only admins choose the user
    alice = make(people, name='alices')
    alice_id = people.execute("SELECT id FROM api_tokens WHERE name = 'alices'").fetchone()[0]
    r = client.post(f'/tokens/{alice_id}/revoke', data={'csrf_token': csrf_from(page)})
    assert r.status_code == 404 and tokens.authenticate(people, alice)
    mine = people.execute("SELECT id FROM api_tokens WHERE name = 'mine'").fetchone()[0]
    client.post(f'/tokens/{mine}/revoke', data={'csrf_token': csrf_from(page)})
    assert not people.execute("SELECT 1 FROM api_tokens WHERE name = 'mine'").fetchone()
    assert [r[0] for r in people.execute("SELECT action FROM audit WHERE action LIKE 'token%' ORDER BY id")] == [
        'token_add', 'token_add', 'token_revoke']


def test_cli(people, settings, monkeypatch, capsys):
    from liteblox import cli
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    assert cli.main(['token', 'add', 'bob', 'ci', '--read-only', '--expires', '30']) in (0, None)
    secret = capsys.readouterr().out.split()[-1]
    assert tokens.authenticate(people, secret).scope == 'read'
    assert cli.main(['token', 'list']) in (0, None)
    out = capsys.readouterr().out
    assert 'bob' in out and 'ci' in out and secret not in out
    token_id = people.execute('SELECT id FROM api_tokens').fetchone()[0]
    assert cli.main(['token', 'revoke', str(token_id)]) in (0, None)
    assert tokens.authenticate(people, secret) is None
    assert cli.main(['token', 'add', 'nobody', 'x']) == 1
