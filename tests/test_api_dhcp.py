"""The API (3.1 milestone 3): DHCP servers, subnets, leases, reservations (as jobs) and lease deletes."""

import pytest

from liteblox import jobs
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation
from liteblox.pki import PKI

from conftest import csrf_from
from test_api_zones import api  # noqa: F401 (fixture)
from test_dhcp_ha import both_dhcp, paired_lab  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)


def lease(ip, mac='aa:bb:cc:dd:ee:01', subnet_id=1):
    return {'ip-address': ip, 'hw-address': mac, 'subnet-id': subnet_id, 'state': 0, 'cltt': 1_000_000_000,
            'valid-lft': 3600, 'hostname': 'pc1.lab.', 'fqdn-fwd': True}


@pytest.fixture
def pair(conn, settings, paired_lab, monkeypatch):  # noqa: F811
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001)
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:dd:ee:50', '198.51.100.50', 'printer'))
    for f in paired_lab.values():
        f.kea_ha_state = 'hot-standby'
    with conn:
        conn.execute("UPDATE nodes SET dhcp_ha_state = 'hot-standby'")
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    return paired_lab


def job(api, r):
    assert r.status_code == 202, r.text
    return api.get(f"/api/v1/jobs/{r.json()['job']}").json()


def test_servers_settings_and_subnets(api, pair):
    d = api.get('/api/v1/dhcp').json()
    assert [(s['node'], s['does'], s['interfaces'], s['ha_state']) for s in d['servers']] == [
        ('ns1', 'failover primary', ['ens19'], 'hot-standby'), ('ns2', 'standby', ['ens19'], 'hot-standby')]
    assert d['pair'] == {'primary': 'ns1', 'standby': 'ns2', 'primary_address': '198.51.100.53',
                         'standby_address': '198.51.100.54', 'port': 8001}
    assert 'secret' not in str(d['settings'])
    subnets = api.get('/api/v1/dhcp/subnets').json()
    assert subnets[0]['prefix'] == '198.51.100.0/24' and subnets[0]['reservations'][0]['hostname'] == 'printer'
    assert api.get('/api/v1/dhcp/subnets/1').json()['pools'] == ['198.51.100.100 - 198.51.100.199']
    assert api.get('/api/v1/dhcp/subnets/9').status_code == 404


def test_leases_from_the_primary_or_the_standby(api, pair):
    pair[1].kea_leases = [lease('198.51.100.120'), lease('198.51.100.50', 'aa:bb:cc:dd:ee:50')]
    pair[2].kea_leases = [lease('198.51.100.120')]
    got = api.get('/api/v1/dhcp/leases').json()
    assert got['read_from'] == 'ns1' and [x['ip'] for x in got['leases']] == ['198.51.100.50', '198.51.100.120']
    printer = got['leases'][0]
    assert printer['reserved'] is True and printer['registered'] is True and printer['expires'].endswith('+00:00')
    assert api.get('/api/v1/dhcp/leases?subnet=2').json()['leases'] == []
    pair[1].kea_running['dhcp4'] = False
    got = api.get('/api/v1/dhcp/leases').json()
    assert got['read_from'] == 'ns2' and len(got['leases']) == 1 and 'ns1' in got['errors'][0]


def test_reservations_are_jobs_standby_first(api, conn, pair):
    pair[1].kea_leases = [lease('198.51.100.9', 'aa:bb:cc:dd:ee:77')]
    r = api.post('/api/v1/dhcp/subnets/1/reservations',
                 json={'hw_address': 'AA-BB-CC-00-00-99', 'ip_address': '198.51.100.9', 'hostname': 'Scanner'})
    assert any('has a lease on 198.51.100.9' in w for w in r.json()['warnings'])
    done = job(api, r)
    assert done['status'] == 'ok', done['log']
    assert [n for n, what in pair[1].all_calls if what == 'commit dhcp'] == ['ns2', 'ns1']
    for f in pair.values():
        assert 'aa:bb:cc:00:00:99' in f.kea_files['kea-dhcp4.conf']
    added = next(x for x in api.get('/api/v1/dhcp/subnets/1').json()['reservations'] if x['ip_address'] == '198.51.100.9')
    assert (added['hw_address'], added['hostname']) == ('aa:bb:cc:00:00:99', 'scanner')
    audit = conn.execute("SELECT detail FROM audit WHERE action = 'dhcp_apply' ORDER BY id DESC").fetchone()[0]
    assert '(token ci)' in audit

    r = api.patch(f"/api/v1/dhcp/subnets/1/reservations/{added['id']}", json={'hostname': 'scanner2'})
    assert job(api, r)['status'] == 'ok'
    changed = next(x for x in api.get('/api/v1/dhcp/subnets/1').json()['reservations'] if x['id'] == added['id'])
    assert changed['hostname'] == 'scanner2' and changed['ip_address'] == '198.51.100.9'
    assert job(api, api.delete(f"/api/v1/dhcp/subnets/1/reservations/{added['id']}"))['status'] == 'ok'
    assert '198.51.100.9' not in str(api.get('/api/v1/dhcp/subnets/1').json()['reservations'])
    assert api.delete('/api/v1/dhcp/subnets/1/reservations/999').status_code == 404


def test_reservation_errors(api, pair):
    r = api.post('/api/v1/dhcp/subnets/1/reservations', json={'hw_address': 'nope', 'ip_address': '192.0.2.9',
                                                                'options': {'routers': ['x']}})
    errors = r.json()['errors']
    assert r.status_code == 422 and errors['hw_address'] and errors['ip_address'] and errors['options.routers']
    r = api.post('/api/v1/dhcp/subnets/1/reservations', json={'hw_address': 'aa:bb:cc:dd:ee:51',
                                                                'ip_address': '198.51.100.50'})
    assert 'already reserved' in r.json()['errors']['ip_address']


def test_one_dhcp_change_at_a_time(api, client, conn, settings, pair, make_user, login):
    with conn:
        conn.execute("INSERT INTO jobs (kind, status, username) VALUES ('dhcp config', 'running', 'someone')")
    r = api.post('/api/v1/dhcp/subnets/1/reservations', json={'hw_address': 'aa:bb:cc:00:00:98',
                                                                'ip_address': '198.51.100.8'})
    assert r.status_code == 409 and 'still running' in r.json()['detail']
    # the page says so too
    del client.headers['Authorization']
    login('alice', 'correct-horse')
    page = client.get('/dhcp/subnets/1/reservations/new').text
    r = client.post('/dhcp/subnets/1/reservations', data={'csrf_token': csrf_from(page), 'hw_address': 'aa:bb:cc:00:00:98',
                                                          'ip_address': '198.51.100.8'}, follow_redirects=True)
    assert 'still running' in r.text


def test_lease_delete_on_both(api, conn, pair):
    pair[1].kea_leases = [lease('198.51.100.120')]
    pair[2].kea_leases = [lease('198.51.100.120')]
    r = api.delete('/api/v1/dhcp/leases/198.51.100.120')
    assert r.json() == {'ip': '198.51.100.120', 'node': 'ns1', 'partner': 'ns2'}
    assert ('lease4-del', {'ip-address': '198.51.100.120', 'update-ddns': True}) in pair[1].kea_commands
    assert ('lease4-del', {'ip-address': '198.51.100.120', 'update-ddns': False}) in pair[2].kea_commands
    assert pair[1].kea_leases == [] and pair[2].kea_leases == []
    assert api.delete('/api/v1/dhcp/leases/198.51.100.121').status_code == 404
    assert conn.execute("SELECT detail FROM audit WHERE action = 'dhcp_lease_delete'").fetchone()[0].endswith('(token ci)')


def test_writes_need_a_full_admin_token(api, pair):
    pair[1].kea_leases = [lease('198.51.100.120')]
    calls = [('post', '/api/v1/dhcp/subnets/1/reservations', {'hw_address': 'aa:bb:cc:00:00:97', 'ip_address': '198.51.100.7'}),
             ('patch', '/api/v1/dhcp/subnets/1/reservations/1', {'hostname': 'x'}),
             ('delete', '/api/v1/dhcp/subnets/1/reservations/1', None),
             ('delete', '/api/v1/dhcp/leases/198.51.100.120', None)]
    for headers in (api.read, api.viewer):
        for method, url, body in calls:
            kw = {'json': body} if body is not None else {}
            assert api.request(method, url, headers=headers, **kw).status_code == 403, (method, url)
    assert pair[1].kea_leases and api.get('/api/v1/dhcp/leases', headers=api.read).status_code == 200
