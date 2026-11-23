"""The API batch (4.1 M3): many record changes in one call, all or nothing."""

from test_api_zones import api, ids  # noqa: F401 (fixture)
from test_dynamic import dyn, server  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)
from test_ptr import REV, draft, served, serves, zones  # noqa: F401 (fixtures)

URL = '/api/v1/zones/example.com/records/batch'


def test_a_batch_goes_into_the_draft_with_ptrs(api, conn, settings, served):  # noqa: F811
    before = ids(api)
    mail = before[('mail', 'A', '192.0.2.25')]
    sip = before[('sip', 'A', '192.0.2.60')]
    r = api.post(URL, json={'ops': [
        {'op': 'add', 'name': 'web1', 'type': 'a', 'data': '192.0.2.71', 'comment': 'first'},
        {'op': 'add', 'name': 'web2', 'type': 'A', 'data': '192.0.2.72', 'ttl': '10m'},
        {'op': 'change', 'id': mail, 'ttl': 600},
        {'op': 'delete', 'id': sip}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body['draft'] is True and len(body['records']) == 4 and body['records'][3] is None
    assert [(x['name'], x['data'], x['ttl']) for x in body['records'][:3]] == [
        ('web1', '192.0.2.71', 3600), ('web2', '192.0.2.72', 600), ('mail', '192.0.2.25', 600)]
    assert body['records'][0]['comment'] == 'first'
    after = ids(api)
    assert after[('web1', 'A', '192.0.2.71')] == body['records'][0]['id'] and ('sip', 'A', '192.0.2.60') not in after
    rtext = draft(settings, REV)
    assert '71\tIN\tPTR\tweb1.example.com.' in rtext and '72\tIN\tPTR\tweb2.example.com.' in rtext
    assert '60\tIN\tPTR' not in rtext
    assert api.get('/api/v1/zones/example.com/draft').json()['linked'] == [REV]
    assert [d for (d,) in conn.execute("SELECT detail FROM audit WHERE action = 'record_batch'")] == [
        'example.com: 2 added, 1 changed, 1 deleted (token ci)']


def test_one_bad_op_changes_nothing(api, settings, served):  # noqa: F811
    mail = ids(api)[('mail', 'A', '192.0.2.25')]
    r = api.post(URL, json={'ops': [
        {'op': 'add', 'name': 'ok', 'type': 'A', 'data': '192.0.2.80'},
        {'op': 'add', 'name': 'bad', 'type': 'A', 'data': 'nope'},
        {'op': 'add', 'name': 'half'},
        {'op': 'change', 'id': 'gone'},
        {'op': 'delete', 'id': mail},
        {'op': 'change', 'id': mail, 'ttl': 60},
        {'op': 'add', 'name': '@', 'type': 'CNAME', 'data': 'elsewhere.example.net.'}]})
    assert r.status_code == 422, r.text
    errors = {e['index']: e['errors'] for e in r.json()['errors']}
    assert sorted(errors) == [1, 2, 3, 5, 6] and 'nothing was changed' in r.json()['detail']
    assert errors[1]['value'] and set(errors[2]) == {'type', 'data'} and 'no such record' in errors[3]['id']
    assert 'earlier op' in errors[5]['id'] and errors[6]['type']
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None


def test_ops_see_the_ones_before_them(api, settings, served):  # noqa: F811
    # a CNAME to a name the batch adds, then a second name on the same address
    r = api.post(URL, json={'ops': [{'op': 'add', 'name': 'box', 'type': 'A', 'data': '192.0.2.90'},
                                    {'op': 'add', 'name': 'alias', 'type': 'CNAME', 'data': 'box'},
                                    {'op': 'add', 'name': 'alias', 'type': 'A', 'data': '192.0.2.91'}]})
    assert r.status_code == 422 and [e['index'] for e in r.json()['errors']] == [2]     # CNAME and other data
    assert draft(settings, 'example.com') is None


def test_if_match_and_limits(api, served):  # noqa: F811
    rev = api.get('/api/v1/zones/example.com/records').json()['rev']
    one = {'ops': [{'op': 'add', 'name': 'm1', 'type': 'A', 'data': '192.0.2.81'}]}
    assert api.post(URL, json=one, headers={'If-Match': f'"{rev}"'}).status_code == 200
    assert api.post(URL, json=one, headers={'If-Match': f'"{rev}"'}).status_code == 412
    assert api.post(URL, json={'ops': []}).status_code == 422
    assert api.post(URL, json={'ops': [{'op': 'rename'}]}).status_code == 422
    assert api.post(URL, json=one, headers=api.read).status_code == 403
    assert api.post(URL, json=one, headers=api.viewer).status_code == 403
    assert api.post('/api/v1/zones/nope.lab/records/batch', json=one).status_code == 404
    soa = next(r['id'] for r in api.get('/api/v1/zones/example.com/records').json()['records'] if r['type'] == 'SOA')
    r = api.post(URL, json={'ops': [{'op': 'delete', 'id': soa}]})
    assert r.status_code == 422 and 'PUT' in r.json()['errors'][0]['errors']['id']


def test_ptr_false_leaves_the_reverse_zone(api, settings, served):  # noqa: F811
    r = api.post(URL, json={'ptr': False, 'ops': [{'op': 'add', 'name': 'np', 'type': 'A', 'data': '192.0.2.84'}]})
    assert r.status_code == 200 and draft(settings, REV) is None


def test_a_dynamic_zone_gets_one_update(api, dyn):  # noqa: F811
    fakes, server = dyn
    pc1 = next(x for x in api.get('/api/v1/zones/dyn.lab/records').json()['records'] if x['name'] == 'pc1')
    server.load('dyn.lab', server.text('dyn.lab') + 'lease 300 IN A 192.168.0.99\n')   # DHCP meanwhile
    sent = len(server.updates)
    r = api.post('/api/v1/zones/dyn.lab/records/batch', headers={'If-Match': f"\"{pc1['rr']}\""}, json={'ops': [
        {'op': 'add', 'name': 'pc7', 'type': 'A', 'data': '192.168.0.70'},
        {'op': 'add', 'name': 'pc8', 'type': 'A', 'data': '192.168.0.71'},
        {'op': 'delete', 'id': pc1['id']}]})
    assert r.status_code == 200, r.text
    text = server.text('dyn.lab')
    assert r.json()['draft'] is False and 'pc7' in text and 'pc8' in text and 'lease' in text
    assert '192.168.0.51' not in text and len(server.updates) == sent + 1
    # a stale rr refuses the batch whole
    r = api.post('/api/v1/zones/dyn.lab/records/batch', headers={'If-Match': f"\"{pc1['rr']}\""}, json={'ops': [
        {'op': 'add', 'name': 'pc9', 'type': 'A', 'data': '192.168.0.72'}]})
    assert r.status_code == 412 and 'pc9' not in server.text('dyn.lab')
