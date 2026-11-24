"""The DHCPv6 pages (6.0): the subnet form, review, save and delete; reservations; the settings; the DHCP page."""

import json

import pytest

from liteblox import jobs
from liteblox.dhcp import store
from liteblox.dhcp.model import Subnet6, settings6, subnets6

from conftest import csrf_from
from test_managed import FakeNode, lab  # noqa: F401 (fixtures)

LAB = 'fd00:1:2:100::/64'
IFACES = [{'name': 'ens18', 'up': True, 'addresses': ['192.0.2.53/24', 'fe80::1/64']},
          {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24', 'fe80::2/64', 'fd00:1:2:100::213/64']}]


@pytest.fixture
def admin(client, make_user, login, monkeypatch, conn, lab):  # noqa: F811
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    real_status = FakeNode.status
    monkeypatch.setattr(FakeNode, 'status', lambda self: dict(real_status(self), interfaces=IFACES))
    fakes, _ = lab
    for f in fakes.values():
        f.kea_running['dhcp6'] = True
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp6 = 1, kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks', "
                     "dhcp_interfaces = '[\"ens19\"]' WHERE id = 1")
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def job_of(conn, r):
    return jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))


def test_subnet_form_review_save_and_delete(admin, conn, lab):  # noqa: F811
    fakes, _ = lab
    page = admin.get('/dhcp/v6/subnets/new').text
    assert 'Add IPv6 subnet' in page and 'Delegated prefixes' in page and 'DNS registration' in page
    t = csrf_from(page)
    form = {'csrf_token': t, 'prefix': LAB, 'pools': 'fd00:1:2:100::1000 - fd00:1:2:100::1fff',
            'pd_pools': 'fd00:1:2:f000::/52 60', 'dns': 'fd00:1:2:100::213', 'search': 'ddns.lab'}
    review = admin.post('/dhcp/v6/subnets/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'kea-dhcp6.conf' in review and 'kea-dhcp6 -t' in review and 'fd00:1:2:100::/64' in review
    bad = admin.post('/dhcp/v6/subnets/preview', data={**form, 'pd_pools': 'nonsense'}, headers={'X-CSRF-Token': t})
    assert 'delegated-prefix pool' in bad.text
    r = admin.post('/dhcp/v6/subnets', data=form, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    (s,) = subnets6(conn)
    assert s.interface == 'ens19' and s.pd_pools == [{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}]
    (written,) = json.loads(fakes[1].kea_files['kea-dhcp6.conf'])['Dhcp6']['subnet6']
    assert written['pd-pools'] == [{'prefix': 'fd00:1:2:f000::', 'prefix-len': 52, 'delegated-len': 60}]
    assert json.loads(fakes[1].kea_files['kea-dhcp6.conf'])['Dhcp6']['interfaces-config']['interfaces'] == ['ens19']

    # the DHCP page lists it, the tabs work, the form shows what's saved
    dhcp = admin.get('/dhcp').text
    assert 'IPv6 subnets' in dhcp and f'/dhcp/v6/subnets/{s.id}' in dhcp and '/60s from' in dhcp
    assert 'Delegated prefixes' in admin.get(f'/dhcp/v6/subnets/{s.id}').text
    assert 'No leases or reservations yet' in admin.get(f'/dhcp/v6/subnets/{s.id}/addresses').text
    settings_page = admin.get(f'/dhcp/v6/subnets/{s.id}/settings').text
    assert 'Served on <code>ens19</code>' in settings_page and 'fd00:1:2:f000::/52 60' in settings_page

    # a bad form comes back marked; delete needs the prefix typed
    r = admin.post('/dhcp/v6/subnets', data={**form, 'id': str(s.id), 'preferred_lifetime': '9000',
                                             'valid_lifetime': '7200'})
    assert r.status_code == 422 and 'stops being preferred' in r.text
    r = admin.post(f'/dhcp/v6/subnets/{s.id}/delete', data={'csrf_token': t, 'confirm': 'nope'}, follow_redirects=False)
    assert 'error=' in r.headers['location'] and subnets6(conn)
    r = admin.post(f'/dhcp/v6/subnets/{s.id}/delete', data={'csrf_token': t, 'confirm': LAB}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok' and subnets6(conn) == []
    assert json.loads(fakes[1].kea_files['kea-dhcp6.conf'])['Dhcp6']['subnet6'] == []


def test_a_node_without_kea_dhcp6_is_named(admin, conn):
    with conn:
        conn.execute('UPDATE nodes SET dhcp6 = 0 WHERE id = 1')
    page = admin.get('/dhcp/v6/subnets/new').text
    assert 'run kea-dhcp6 yet' in page
    t = csrf_from(page)
    review = admin.post('/dhcp/v6/subnets/preview', data={'csrf_token': t, 'prefix': LAB,
                                                          'pools': 'fd00:1:2:100::1000 - fd00:1:2:100::1fff'},
                        headers={'X-CSRF-Token': t}).text
    assert "kea-dhcp6 yet: Repair" in review and 'kea-dhcp6.conf' not in review


def test_reservations(admin, conn, lab):  # noqa: F811
    fakes, _ = lab
    s = store.next_subnet6_id(conn)
    from liteblox.dhcp.model import Subnet6
    store.save_subnet6(conn, Subnet6(s, LAB, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'],
                                     pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}]))
    page = admin.get(f'/dhcp/v6/subnets/{s}/reservations/new?duid=00:01:00:01:aa:bb&ip=fd00:1:2:100::1005').text
    assert 'value="00:01:00:01:aa:bb"' in page and 'value="fd00:1:2:100::1005"' in page
    t = csrf_from(page)
    form = {'csrf_token': t, 'duid': '00-01-00-01-AA-BB', 'ip_address': 'fd00:1:2:100::50',
            'prefix': 'fd00:1:2:f010::/60', 'hostname': 'router2'}
    review = admin.post(f'/dhcp/v6/subnets/{s}/reservations/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert '00:01:00:01:aa:bb' in review and 'fd00:1:2:f010::/60' in review
    bad = admin.post(f'/dhcp/v6/subnets/{s}/reservations/preview', data={**form, 'ip_address': '10.0.0.1'},
                     headers={'X-CSRF-Token': t}).text
    assert 'not an IPv6 address' in bad
    r = admin.post(f'/dhcp/v6/subnets/{s}/reservations', data=form, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    (sub,) = json.loads(fakes[1].kea_files['kea-dhcp6.conf'])['Dhcp6']['subnet6']
    assert sub['reservations'] == [{'duid': '00:01:00:01:aa:bb', 'ip-addresses': ['fd00:1:2:100::50'],
                                    'prefixes': ['fd00:1:2:f010::/60'], 'hostname': 'router2'}]
    (rid,) = [r.id for r in subnets6(conn)[0].reservations]
    rows = admin.get(f'/dhcp/v6/subnets/{s}/addresses').text
    assert 'reserved, offline' in rows and f'/dhcp/v6/subnets/{s}/reservations/{rid}' in rows
    assert 'router2' in admin.get(f'/dhcp/v6/subnets/{s}/reservations/{rid}').text
    r = admin.post(f'/dhcp/v6/subnets/{s}/reservations/{rid}/delete', data={'csrf_token': t}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok' and subnets6(conn)[0].reservations == []
    assert store.get_reservation6(conn, rid) is None


def test_settings6(admin, conn):
    page = admin.get('/dhcp/v6/settings').text
    assert 'DHCPv6 settings' in page and 'sntp-servers' in page
    t = csrf_from(page)
    r = admin.post('/dhcp/v6/settings', data={'csrf_token': t, 'dns': 'fd00:1:2:100::213', 'preferred_lifetime': '3000',
                                              'valid_lifetime': '4000'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    s = settings6(conn)
    assert s.options == {'dns': ['fd00:1:2:100::213']} and s.preferred_lifetime == 3000
    r = admin.post('/dhcp/v6/settings', data={'csrf_token': t, 'dns': '192.0.2.1'})
    assert r.status_code == 422 and 'not an IPv6 address' in r.text


def test_viewers_read_only(client, conn, lab, make_user, login):  # noqa: F811
    login(*make_user('viewer', 'viewer-password', 'readonly'))
    page = client.get('/dhcp').text
    assert 'Add IPv6 subnet' not in page
    t = csrf_from(page)
    assert client.post('/dhcp/v6/settings', data={'csrf_token': t}).status_code == 403
    assert client.get('/dhcp/v6/subnets/new').status_code == 403


def test_pair_port6(admin, conn):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp6 = 1 WHERE id = 2")
    page = admin.get('/dhcp').text
    from liteblox.dhcp import validate
    node = {'id': 1, 'name': 'ns1', 'dhcp': 1}
    other = {'id': 2, 'name': 'ns2', 'dhcp': 1}
    live = {1: IFACES, 2: [{'name': 'ens19', 'up': True, 'addresses': ['198.51.100.54/24']}]}
    errors = validate.check_pair(node, other, '198.51.100.53', '198.51.100.54', 8001, live, ['ens19'], 8001)
    assert 'a port of its own' in errors['port6']
    assert validate.check_pair(node, other, '198.51.100.53', '198.51.100.54', 8001, live, ['ens19'], 8002) == {}
    assert 'name="port6" value="8002"' in page


def test_ra_switch(admin, conn, lab):  # noqa: F811
    fakes, _ = lab
    page = admin.get('/dhcp/v6/subnets/new').text
    assert 'Router advertisements' in page and 'name="ra_slaac"' in page
    t = csrf_from(page)
    form = {'csrf_token': t, 'prefix': LAB, 'pools': 'fd00:1:2:100::1000 - fd00:1:2:100::1fff', 'ra': '1'}
    # ns1 serves it but has no radvd: refused, and the form says how to get it
    r = admin.post('/dhcp/v6/subnets', data=form)
    assert r.status_code == 422 and "ns1 can&#39;t send router advertisements" in r.text
    with conn:
        conn.execute('UPDATE nodes SET radvd = 1 WHERE id = 1')
    review = admin.post('/dhcp/v6/subnets/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'radvd.conf' in review and 'AdvDefaultLifetime 0' in review
    r = admin.post('/dhcp/v6/subnets', data={**form, 'ra_slaac': '1'}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok', job_of(conn, r)['log']
    assert 'router advertisements on' in job_of(conn, r)['log'] or 'router advertisements on' in \
        conn.execute("SELECT detail FROM audit WHERE action = 'dhcp_apply'").fetchone()[0]
    (s,) = subnets6(conn)
    assert s.ra and s.ra_slaac and s.ra_since
    assert 'AdvAutonomous on;' in fakes[1].kea_files['radvd.conf']
    settings_page = admin.get(f'/dhcp/v6/subnets/{s.id}/settings').text
    assert f'On since {s.ra_since} UTC' in settings_page

    # off again: radvd.conf back to the header alone, and the time it was on is forgotten
    r = admin.post('/dhcp/v6/subnets', data={**form, 'id': str(s.id), 'ra': ''}, follow_redirects=False)
    assert job_of(conn, r)['status'] == 'ok'
    (s,) = subnets6(conn)
    assert not s.ra and s.ra_since is None and 'interface' not in fakes[1].kea_files['radvd.conf']


def test_the_form_suggests_dns_and_time_servers(admin, conn):
    with conn:
        conn.execute("UPDATE nodes SET addresses = ?", (json.dumps(['198.51.100.53', 'fd00:1:2:100::213']),))
    store.save_subnet6(conn, Subnet6(1, LAB, 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff']))
    page = admin.get('/dhcp/v6/subnets/1/settings').text
    assert "LiteBlox's DNS nodes in this subnet: <code>fd00:1:2:100::213</code>" in page
    assert "LiteBlox's time servers" not in page
    with conn:
        conn.execute("UPDATE nodes SET ntp = 1, ntp_serve = 1, ntp_allow = ? WHERE id = 1", (json.dumps([LAB]),))
    page = admin.get('/dhcp/v6/subnets/1/settings').text
    assert "LiteBlox's time servers in this subnet: <code>fd00:1:2:100::213</code>" in page
    # BIND told not to listen on IPv6: not suggested for DNS
    with conn:
        conn.execute("""UPDATE nodes SET options = '{"listen_on_v6": ["none"]}'""")
    assert "LiteBlox's DNS nodes in this subnet" not in admin.get('/dhcp/v6/subnets/1/settings').text
