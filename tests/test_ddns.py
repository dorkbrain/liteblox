"""DDNS: Kea registering clients in dynamic zones, following the primary, guards, and node clocks."""

import json
import re

import pytest

from liteblox import jobs, keys
from liteblox.dhcp import apply as dhcp_apply, store, validate
from liteblox.dhcp.model import Dhcp4Settings, KeaConfig, Subnet, settings as load_settings
from liteblox.dhcp.render import render, reverse_zones_for
from liteblox.dns import declare
from liteblox.nodes import health, roles, service as nodes

from conftest import csrf_from
from test_dynamic import FORWARD, REVERSE, dyn, server, zone_row  # noqa: F401 (fixtures)
from test_managed import lab, ok_verify  # noqa: F401 (fixtures)
from test_promote import NS1, NS2, kw, pair  # noqa: F401 (fixtures)

KEY = {'name': 'dhcp', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0c2VjcmV0'}
NET = '198.51.100.0/24'


def ddns_subnet(**kw):
    return Subnet(**{'id': 1, 'prefix': NET, 'interface': 'ens19', 'pools': ['198.51.100.100 - 198.51.100.199'],
                     'ddns': True, 'ddns_zone': 'dyn.lab', **kw})


# ── rendering ──────────────────────────────────────────────────────────────────

def test_ddns_renders_for_registering_subnets():
    config = KeaConfig(['ens19'], Dhcp4Settings(ddns_key=KEY), [ddns_subnet(), ddns_subnet(id=2, prefix='203.0.113.0/24',
                       pools=['203.0.113.10 - 203.0.113.20'], ddns=False)],
                       primary='192.0.2.54', reverse_zones=['100.51.198.in-addr.arpa', '0.168.192.in-addr.arpa'])
    files = render(config)
    d4 = json.loads(files['kea-dhcp4.conf'])['Dhcp4']
    assert d4['dhcp-ddns'] == {'enable-updates': True, 'server-ip': '127.0.0.1', 'server-port': 53001}
    assert d4['ddns-send-updates'] is False
    first, second = d4['subnet4']
    assert first['ddns-send-updates'] is True and first['ddns-qualifying-suffix'] == 'dyn.lab.'
    assert first['ddns-update-on-renew'] is True            # or a client moved to its reservation keeps its old A
    assert first['ddns-override-client-update'] is True     # or a Windows client (S=0) gets a PTR but no A
    assert 'ddns-send-updates' not in second and 'ddns-override-client-update' not in second
    d2 = json.loads(files['kea-dhcp-ddns.conf'])['DhcpDdns']
    server = [{'ip-address': '192.0.2.54', 'port': 53}]
    assert d2['tsig-keys'] == [KEY]
    assert d2['forward-ddns']['ddns-domains'] == [{'name': 'dyn.lab.', 'key-name': 'dhcp', 'dns-servers': server}]
    assert d2['reverse-ddns']['ddns-domains'] == [{'name': '100.51.198.in-addr.arpa.', 'key-name': 'dhcp',
                                                   'dns-servers': server}]


def test_extra_settings_cannot_undo_what_registration_needs():
    # 3.3.3's workaround on prod put the override in Extra subnet settings: LiteBlox's own value wins,
    # so the file is the same with or without it there
    subnet = lambda extra: ddns_subnet(extra=extra)
    render_with = lambda extra: render(KeaConfig(['ens19'], Dhcp4Settings(ddns_key=KEY), [subnet(extra)],
                                                 primary='192.0.2.54'))['kea-dhcp4.conf']
    assert render_with({'ddns-override-client-update': True}) == render_with({})
    assert json.loads(render_with({'ddns-override-client-update': False}))['Dhcp4']['subnet4'][0][
        'ddns-override-client-update'] is True


@pytest.mark.parametrize('settings_kw, primary', [({}, '192.0.2.54'), ({'ddns_key': KEY}, None)])
def test_no_ddns_without_a_key_or_a_primary(settings_kw, primary):
    files = render(KeaConfig(['ens19'], Dhcp4Settings(**settings_kw), [ddns_subnet()], primary=primary))
    assert 'dhcp-ddns' not in json.loads(files['kea-dhcp4.conf'])['Dhcp4']
    d2 = json.loads(files['kea-dhcp-ddns.conf'])['DhcpDdns']
    assert d2['forward-ddns'] == {'ddns-domains': []} and d2['tsig-keys'] == []


def test_suffix_and_reverse_zone_pick():
    files = render(KeaConfig(['ens19'], Dhcp4Settings(ddns_key=KEY), [ddns_subnet(ddns_suffix='dhcp.dyn.lab')],
                             primary='192.0.2.54'))
    assert json.loads(files['kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]['ddns-qualifying-suffix'] == 'dhcp.dyn.lab.'
    assert reverse_zones_for('192.168.0.0/23', ['0.168.192.in-addr.arpa', '1.168.192.in-addr.arpa',
                                                '2.168.192.in-addr.arpa', '10.in-addr.arpa']) == [
        '0.168.192.in-addr.arpa', '1.168.192.in-addr.arpa']


# ── validation and grants ──────────────────────────────────────────────────────

def make_key(conn):
    with conn:
        key_id = conn.execute("INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES ('dhcp', 'hmac-sha256', "
                              "'c2VjcmV0c2VjcmV0', 'user')").lastrowid
        conn.execute("UPDATE dhcp4_settings SET ddns_key_id = ?, ddns_mode = 'liteblox' WHERE id = 1", (key_id,))
    return key_id


def grant(conn, zone, scope, name, types):
    with conn:
        conn.execute("INSERT INTO key_grants (key_id, zone_id, scope, name, types) SELECT k.id, z.id, ?, ?, ? "
                     "FROM tsig_keys k, zones z WHERE k.name = 'dhcp' AND z.name = ?", (scope, name, types, zone))


def test_check_ddns(conn, settings, dyn):  # noqa: F811
    s = Subnet(1, NET, 'ens19', ddns=True, ddns_zone_id=zone_row(conn, 'dyn.lab')['id'])
    assert 'DNS registration is off' in validate.check_ddns(conn, s, load_settings(conn))['ddns']
    make_key(conn)
    assert validate.check_ddns(conn, s, load_settings(conn)) == {} and s.ddns_zone == 'dyn.lab'
    s.ddns_suffix = 'dhcp.dyn.lab.'
    assert validate.check_ddns(conn, s, load_settings(conn)) == {} and s.ddns_suffix == 'dhcp.dyn.lab'
    s.ddns_suffix = 'elsewhere.example'
    assert 'a name inside it' in validate.check_ddns(conn, s, load_settings(conn))['ddns_suffix']
    declare.create_zone(settings, 'static.lab', ['1', '2'], FORWARD.replace('dyn.lab', 'static.lab'), 'admin', print,
                        verify=ok_verify)
    s = Subnet(1, NET, 'ens19', ddns=True, ddns_zone_id=zone_row(conn, 'static.lab')['id'])
    assert 'dynamic forward zone' in validate.check_ddns(conn, s, load_settings(conn))['ddns_zone_id']


def test_missing_grants(conn, settings, dyn, server):  # noqa: F811
    declare.create_zone(settings, '100.51.198.in-addr.arpa', ['1', '2'], REVERSE, 'admin', print, verify=ok_verify)
    make_key(conn)
    s = ddns_subnet()
    rev = ['100.51.198.in-addr.arpa']
    assert validate.missing_grants(conn, 'dhcp', s, rev) == [('dyn.lab', 'zonesub', '', 'A AAAA DHCID'),
                                                             ('100.51.198.in-addr.arpa', 'zonesub', '', 'PTR DHCID')]
    grant(conn, 'dyn.lab', 'zonesub', '', 'A AAAA')                     # no DHCID yet
    grant(conn, '100.51.198.in-addr.arpa', 'zonesub', '', 'ANY')
    assert validate.missing_grants(conn, 'dhcp', s, rev) == [('dyn.lab', 'zonesub', '', 'A AAAA DHCID')]
    grant(conn, 'dyn.lab', 'zonesub', '', 'DHCID')
    assert validate.missing_grants(conn, 'dhcp', s, rev) == []
    # a suffix inside the zone: a subdomain grant covers it, a name grant for another name doesn't
    s = ddns_subnet(id=2, ddns_suffix='dhcp.dyn.lab')
    with conn:
        conn.execute("DELETE FROM key_grants WHERE zone_id = ?", (zone_row(conn, 'dyn.lab')['id'],))
    grant(conn, 'dyn.lab', 'name', 'other.dyn.lab', 'ANY')
    assert validate.missing_grants(conn, 'dhcp', s, []) == [('dyn.lab', 'subdomain', 'dhcp.dyn.lab', 'A AAAA DHCID')]
    grant(conn, 'dyn.lab', 'subdomain', 'dhcp.dyn.lab', 'A DHCID')
    assert validate.missing_grants(conn, 'dhcp', s, []) == []


# ── the DHCP tab ───────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def serve(conn):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp_interfaces = '[\"ens19\"]', "
                     "kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks' WHERE id = 1")


def test_review_lists_missing_grants_and_adds_them(admin, conn, settings, dyn, monkeypatch):  # noqa: F811
    fakes, _ = dyn
    serve(conn)
    make_key(conn)
    t = csrf_from(admin.get('/dhcp/subnets/new').text)
    form = {'csrf_token': t, 'prefix': NET, 'pools': '198.51.100.100 - 198.51.100.199', 'ddns': '1',
            'ddns_zone_id': str(zone_row(conn, 'dyn.lab')['id'])}
    review = admin.post('/dhcp/subnets/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'may not register these names yet' in review and 'Add the missing grants' in review
    assert 'Clients become <code>host.dyn.lab</code>' in review and '>Apply</button>' not in review
    r = admin.post('/dhcp/subnets', data=form)
    assert r.status_code == 422 and 'Add the missing grants' in r.text
    r = admin.post('/dhcp/grants', data={'grants': json.dumps([['dyn.lab', 'zonesub', '', 'A AAAA DHCID']])},
                   headers={'X-CSRF-Token': t})
    # in place: the job's log under the button, polled, not a trip to the job page
    assert 'HX-Redirect' not in r.headers
    job_id = int(re.search(r'hx-get="/dhcp/grants/(\d+)" hx-trigger="every 1s"', r.text).group(1))
    job = jobs.get(conn, job_id)
    assert job['status'] == 'ok', job['log']
    assert 'grant dhcp zonesub A AAAA DHCID' in fakes[1].zones_conf
    poll = admin.get(f'/dhcp/grants/{job_id}')
    assert poll.status_code == 286 and 'every 1s' not in poll.text            # done: polling stops
    assert 'hx-post="/dhcp/subnets/preview"' in poll.text and f'"granted": "{job_id}"' in poll.text
    review = admin.post('/dhcp/subnets/preview', data={**form, 'granted': str(job_id)}, headers={'X-CSRF-Token': t}).text
    assert 'may not register' not in review and '>Apply</button>' in review
    assert f'may now register these names (<a href="/jobs/{job_id}">job #{job_id}</a>)' in review
    r = admin.post('/dhcp/subnets', data=form, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    d2 = json.loads(fakes[1].kea_files['kea-dhcp-ddns.conf'])['DhcpDdns']
    assert d2['forward-ddns']['ddns-domains'][0]['dns-servers'] == [{'ip-address': NS1, 'port': 53}]


def test_a_failed_grant_job_does_not_review_again(admin, conn, settings, dyn):  # noqa: F811
    job_id = jobs.start(settings.db_path, 'grant', lambda log: 1 / 0, background=False)
    poll = admin.get(f'/dhcp/grants/{job_id}')
    assert poll.status_code == 286 and 'subnets/preview' not in poll.text and "weren't all added" in poll.text
    other = jobs.start(settings.db_path, 'bind config', lambda log: None, background=False)
    assert admin.get(f'/dhcp/grants/{other}').status_code == 404


def test_settings_key_must_be_a_client_key(admin, conn, settings, lab):  # noqa: F811
    roles.ensure_keys(conn)
    internal = conn.execute("SELECT id FROM tsig_keys WHERE name = 'liteblox'").fetchone()[0]
    t = csrf_from(admin.get('/dhcp/settings').text)
    r = admin.post('/dhcp/settings', data={'csrf_token': t, 'ddns_key_id': str(internal)})
    assert r.status_code == 422 and 'not a client key' in r.text


# ── following the primary ──────────────────────────────────────────────────────

def registering(conn):
    serve(conn)
    make_key(conn)
    grant(conn, 'dyn.lab', 'zonesub', '', 'ANY')
    store.save_subnet(conn, ddns_subnet(ddns_zone_id=zone_row(conn, 'dyn.lab')['id']))


def d2_server(fake):
    return json.loads(fake.kea_files['kea-dhcp-ddns.conf'])['DhcpDdns']['forward-ddns']['ddns-domains'][0][
        'dns-servers'][0]['ip-address']


def test_promote_points_dhcp_at_the_new_primary(conn, settings, pair):  # noqa: F811
    fakes, server, copies, transfer = pair
    registering(conn)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'set up', 'admin', print)
    assert d2_server(fakes[1]) == NS1
    lines = []
    roles.promote(settings, 2, 'admin', lines.append, **kw(transfer))
    assert d2_server(fakes[1]) == NS2
    assert any(f'DHCP sends its DNS updates to {NS2}' in line for line in lines)


def test_a_dhcp_node_down_at_the_promote_catches_up_on_the_health_check(conn, settings, pair, monkeypatch):  # noqa: F811
    fakes, server, copies, transfer = pair
    registering(conn)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'set up', 'admin', print)
    fakes[1].kea_running['d2'] = False                     # D2 not answering: the rewrite fails and rolls back
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    lines = []
    roles.promote(settings, 2, 'admin', lines.append, **kw(transfer))
    assert any("Kea's config not updated yet" in line for line in lines) and d2_server(fakes[1]) == NS1
    fakes[1].kea_running['d2'] = True
    with conn:
        conn.execute("DELETE FROM jobs WHERE kind = 'dhcp config'")
    line = health.check_node(settings, conn, nodes.get_node(conn, 1), background=False)
    assert 'its DHCP config is behind: rewriting it' in line and d2_server(fakes[1]) == NS2
    assert not dhcp_apply.stale(conn, nodes.get_node(conn, 1))


# ── guards ─────────────────────────────────────────────────────────────────────

def test_a_registering_zone_and_its_key_are_protected(conn, settings, dyn):  # noqa: F811
    registering(conn)
    assert 'DHCP (its DNS registration key)' in keys.references(conn, 'dhcp')
    with pytest.raises(keys.KeyProblem, match='still used by DHCP'):
        keys.delete(settings, 'dhcp', 'admin', print)
    with pytest.raises(declare.DeclareError, match='registers its clients in dyn.lab'):
        declare.set_dynamic(settings, 'dyn.lab', False, 'admin', print, verify=ok_verify)
    with pytest.raises(declare.DeclareError, match='registers its clients in dyn.lab'):
        declare.delete_zone(settings, 'dyn.lab', 'admin', print, verify=ok_verify)


def test_rotating_the_key_updates_kea(conn, settings, dyn):  # noqa: F811
    fakes, _ = dyn
    registering(conn)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'set up', 'admin', print)
    keys.rotate(settings, 'dhcp', 'bmV3c2VjcmV0bmV3c2VjcmV0', 'admin', print)
    assert json.loads(fakes[1].kea_files['kea-dhcp-ddns.conf'])['DhcpDdns']['tsig-keys'][0]['secret'] == \
        'bmV3c2VjcmV0bmV3c2VjcmV0'


# ── clocks ─────────────────────────────────────────────────────────────────────

def test_clock_fields_and_states():
    assert nodes.clock_fields({'clock': {'time': 1000.0, 'synchronized': True}}, 958.0)['clock_skew'] == 42.0
    assert nodes.clock_fields({}, 1.0) == {}
    node = {'name': 'ns1', 'clock_skew': 1.5, 'clock_synced': 1}
    assert nodes.clock_state(node) == (None, None)
    assert nodes.clock_state({**node, 'clock_skew': -45})[0] == 'warn'
    level, message = nodes.clock_state({**node, 'clock_skew': 200})
    assert level == 'error' and '200s ahead' in message and '300s' in message
    assert nodes.clock_state({**node, 'clock_synced': 0})[0] == 'warn'


def test_clock_skew_on_the_pages(conn, lab, client, make_user, login):  # noqa: F811
    with conn:
        conn.execute("UPDATE nodes SET clock_skew = 150, clock_synced = 1 WHERE id = 1")
        conn.execute("UPDATE nodes SET clock_skew = 0.4, clock_synced = 0 WHERE id = 2")
    login(*make_user('admin', 'admin-password', 'admin'))
    page = client.get('/nodes').text
    assert 'clock +150s' in page and 'clock not synced' in page
    assert "ns1&#39;s clock is 150s ahead" in client.get('/nodes/1').text
