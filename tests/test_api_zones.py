"""The API (3.1 milestone 2): changing zones, their drafts and publishes, through tokens."""

import pytest

from liteblox import auth, jobs
from liteblox.api import tokens
from liteblox.dns import publish as pub

from test_dynamic import dyn, server  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)
from test_ptr import REV, draft, served, serves, zones  # noqa: F401 (fixtures)


@pytest.fixture
def api(client, conn):
    """A client with a full token of an admin; `api.read` / `api.viewer`: a read token, a readonly user's full one."""
    auth.create_user(conn, 'alice', 'correct-horse', 'admin')
    auth.create_user(conn, 'bob', 'correct-horse', 'readonly')
    client.headers['Authorization'] = 'Bearer ' + tokens.create(conn, 'alice', 'ci', 'full', 'test')[1]
    client.read = {'Authorization': 'Bearer ' + tokens.create(conn, 'alice', 'look', 'read', 'test')[1]}
    client.viewer = {'Authorization': 'Bearer ' + tokens.create(conn, 'bob', 'full', 'full', 'test')[1]}
    return client


def ids(api, zone='example.com'):
    return {(r['name'], r['type'], r['data']): r['id'] for r in api.get(f'/api/v1/zones/{zone}/records').json()['records']}


def add(api, name, data, rtype='A', zone='example.com', headers=None, **kw):
    return api.post(f'/api/v1/zones/{zone}/records', json={'name': name, 'type': rtype, 'data': data, **kw},
                    headers=headers)


# ── a static zone ──────────────────────────────────────────────────────────────

def test_add_edit_delete_in_the_draft(api, conn, settings, served):  # noqa: F811
    before = ids(api)
    r = add(api, 'web', '192.0.2.77')
    assert r.status_code == 201, r.text
    body = r.json()
    assert body['draft'] is True and body['record']['name'] == 'web' and body['record']['data'] == '192.0.2.77'
    assert '77\tIN\tPTR\tweb.example.com.' in draft(settings, REV)              # the PTR, as in the grid
    after = ids(api)
    assert all(after[k] == v for k, v in before.items())                        # nobody else's id moved
    d = api.get('/api/v1/zones/example.com/draft').json()
    assert d['draft'] and d['summary']['added'] == [{'name': 'web', 'type': 'A', 'ttl': None, 'data': '192.0.2.77'}]
    assert d['linked'] == [REV] and '+web' in d['diff'].replace('\t', '') and d['check']['ok'] in (True, None)

    r = api.patch(f"/api/v1/zones/example.com/records/{body['record']['id']}", json={'data': '192.0.2.78'})
    assert r.status_code == 200, r.text
    moved = r.json()['record']
    assert moved['data'] == '192.0.2.78' and moved['id'] != body['record']['id']
    assert api.patch(f"/api/v1/zones/example.com/records/{body['record']['id']}", json={'ttl': 60}).status_code == 404
    assert '78\tIN\tPTR\tweb.example.com.' in draft(settings, REV) and '77\tIN\tPTR' not in draft(settings, REV)

    r = api.delete(f"/api/v1/zones/example.com/records/{moved['id']}")
    assert r.status_code == 200 and ('web', 'A', '192.0.2.78') not in ids(api)
    assert 'web.example.com' not in (draft(settings, REV) or '')
    audit = [row[0] for row in conn.execute("SELECT detail FROM audit WHERE action LIKE 'record_%' ORDER BY id")]
    assert audit and all(d.endswith('(token ci)') for d in audit)


def test_if_match_and_validation(api, served):  # noqa: F811
    rev = api.get('/api/v1/zones/example.com/records').json()['rev']
    assert add(api, 'a1', '192.0.2.70', headers={'If-Match': f'"{rev}"'}).status_code == 201
    r = add(api, 'a2', '192.0.2.71', headers={'If-Match': f'"{rev}"'})        # the zone moved on since
    assert r.status_code == 412
    r = add(api, 'bad', 'not-an-address')
    assert r.status_code == 422 and r.json()['errors']['value']
    assert add(api, '@', 'elsewhere.example.net.', rtype='CNAME').json()['errors']['type']
    assert api.post('/api/v1/zones/nope.lab/records', json={'name': 'x', 'type': 'A', 'data': '192.0.2.1'}).status_code == 404
    assert api.post('/api/v1/zones/example.com/records', json={'name': 'x'}).status_code == 422     # fields missing


def test_soa(api, served):  # noqa: F811
    r = api.put('/api/v1/zones/example.com/soa', json={'refresh': '2h', 'rname': 'dns.example.com.'})
    assert r.status_code == 200, r.text
    tokens_ = r.json()['record']['data'].split()
    assert tokens_[1] == 'dns.example.com.' and tokens_[3] == '7200'
    assert api.put('/api/v1/zones/example.com/soa', json={'retry': 'soon'}).status_code == 422
    soa = next(r for r in api.get('/api/v1/zones/example.com/records').json()['records'] if r['type'] == 'SOA')
    assert api.delete(f"/api/v1/zones/example.com/records/{soa['id']}").status_code == 409


def test_discard(api, settings, served):  # noqa: F811
    add(api, 'web', '192.0.2.77')
    assert api.delete('/api/v1/zones/example.com/draft').status_code == 204
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None
    assert api.get('/api/v1/zones/example.com/draft').json()['draft'] is False


def test_publish_as_a_job(api, conn, settings, served, monkeypatch):  # noqa: F811
    real_start, real_publish = jobs.start, pub.publish
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'publish', lambda *a, **k: real_publish(*a, **{**k, 'verify': serves(served)}))
    rev = add(api, 'web', '192.0.2.77').json()['rev']
    r = api.post('/api/v1/zones/example.com/publish', json={'message': 'Add web'}, headers={'If-Match': f'"{rev}"'})
    assert r.status_code == 202 and r.headers['location'] == f"/api/v1/jobs/{r.json()['job']}"
    job = api.get(f"/api/v1/jobs/{r.json()['job']}").json()
    assert job['status'] == 'ok', job['log']
    for f in served.values():
        assert '192.0.2.77' in f.files['example.com'] and '77\tIN\tPTR\tweb.example.com.' in f.files[REV]
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None
    history = api.get('/api/v1/zones/example.com/history').json()
    assert history[0]['message'].startswith('Add web')
    assert '192.0.2.77' in api.get(f"/api/v1/zones/example.com/history/{history[0]['sha']}").json()['text']
    assert api.get('/api/v1/zones/example.com/history/0000').status_code == 404
    # a stale If-Match: the job refuses it
    add(api, 'web2', '192.0.2.79')
    r = api.post('/api/v1/zones/example.com/publish', headers={'If-Match': f'"{rev}"'})
    assert api.get(f"/api/v1/jobs/{r.json()['job']}").json()['status'] == 'failed'


def test_text(api, served):  # noqa: F811
    add(api, 'web', '192.0.2.77')
    assert '192.0.2.77' in api.get('/api/v1/zones/example.com/text').text
    assert '192.0.2.77' not in api.get('/api/v1/zones/example.com/text?published=true').text


def test_every_write_needs_a_full_admin_token(api, served):  # noqa: F811
    rec = next(iter(ids(api).values()))
    calls = [('post', '/api/v1/zones/example.com/records', {'name': 'x', 'type': 'A', 'data': '192.0.2.1'}),
             ('patch', f'/api/v1/zones/example.com/records/{rec}', {'ttl': 60}),
             ('delete', f'/api/v1/zones/example.com/records/{rec}', None),
             ('put', '/api/v1/zones/example.com/soa', {'refresh': 60}),
             ('delete', '/api/v1/zones/example.com/draft', None),
             ('post', '/api/v1/zones/example.com/publish', {})]
    for headers in (api.read, api.viewer):
        for method, url, body in calls:
            kw = {'json': body} if body is not None else {}
            assert api.request(method, url, headers=headers, **kw).status_code == 403, (method, url)
    assert api.get('/api/v1/zones/example.com/draft', headers=api.read).status_code == 200


# ── a dynamic zone ─────────────────────────────────────────────────────────────

def test_a_dynamic_zone_changes_at_once(api, conn, settings, dyn):  # noqa: F811
    fakes, server = dyn
    r = add(api, 'pc2', '192.168.0.60', zone='dyn.lab')
    assert r.status_code == 201 and r.json()['draft'] is False and 'pc2' in server.text('dyn.lab')
    listed = api.get('/api/v1/zones/dyn.lab/records').json()['records']
    pc2 = next(x for x in listed if x['name'] == 'pc2')
    assert pc2['rr']
    # DHCP adds a lease meanwhile: the zone's rev moves, the record's rr doesn't
    server.load('dyn.lab', server.text('dyn.lab') + 'lease 300 IN A 192.168.0.99\n')
    r = api.patch(f"/api/v1/zones/dyn.lab/records/{pc2['id']}", json={'data': '192.168.0.61'},
                  headers={'If-Match': f"\"{pc2['rr']}\""})
    assert r.status_code == 200, r.text
    assert '192.168.0.61' in server.text('dyn.lab') and 'lease' in server.text('dyn.lab')
    # pc2's own RRset changed since: its old rr is refused
    r = api.delete(f"/api/v1/zones/dyn.lab/records/{r.json()['record']['id']}", headers={'If-Match': f"\"{pc2['rr']}\""})
    assert r.status_code == 412
    assert api.get('/api/v1/zones/dyn.lab/draft').status_code == 409
    assert api.post('/api/v1/zones/dyn.lab/publish').status_code == 409


def test_a_dynamic_conflict_is_409(api, dyn):  # noqa: F811
    import dns.rcode
    fakes, server = dyn
    server.refuse = dns.rcode.NXRRSET                  # changed between this request's AXFR and its update
    r = add(api, 'pc4', '192.168.0.62', zone='dyn.lab')
    assert r.status_code == 409 and 'changed on the server' in r.json()['detail']


def test_notes(api, conn, served):  # noqa: F811
    assert api.get('/api/v1/zones/example.com').json()['notes'] == ''
    assert api.put('/api/v1/zones/example.com/notes', json={'notes': 'lab names\r\n'}).status_code == 204
    zone = api.get('/api/v1/zones/example.com', headers=api.read).json()
    assert zone['notes'] == 'lab names' and zone['settings']['sorted'] is True
    assert api.put('/api/v1/zones/example.com/notes', json={'notes': 'x'}, headers=api.read).status_code == 403
    assert api.put('/api/v1/zones/example.com/notes', json={'notes': 'x'}, headers=api.viewer).status_code == 403
    assert conn.execute("SELECT detail FROM audit WHERE action = 'zone_notes'").fetchone()[0].startswith('example.com')
