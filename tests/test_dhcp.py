"""Kea on a node: rendering, apply with rollback, drift, the DHCP card and the node's Danger zone."""

import json

import pytest

from liteblox import jobs
from liteblox.dhcp import apply as dhcp_apply
from liteblox.dhcp.model import DEBIAN, KeaConfig, KeaLayout, layout_for
from liteblox.dhcp.render import file_hashes, render
from liteblox.nodes import health, service as nodes

from conftest import csrf_from
from test_managed import Client, FakeNode, lab  # noqa: F401 (fixtures)


def with_dhcp(conn, *node_ids):
    with conn:
        for i in node_ids:
            conn.execute("UPDATE nodes SET dhcp = 1, kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks' "
                         'WHERE id = ?', (i,))


def test_the_rendered_config_serves_nothing():
    files = render(KeaConfig())
    dhcp4 = json.loads(files['kea-dhcp4.conf'])['Dhcp4']
    assert dhcp4['interfaces-config']['interfaces'] == [] and dhcp4['subnet4'] == []
    # it keeps trying an interface that isn't up yet (at boot) instead of listening on nothing for good
    assert dhcp4['interfaces-config']['service-sockets-max-retries'] > 0
    assert dhcp4['lease-database'] == {'type': 'memfile', 'name': '/var/lib/kea/kea-leases4.csv', 'persist': True,
                                       'lfc-interval': 3600}
    assert dhcp4['control-socket'] == {'socket-type': 'unix', 'socket-name': '/run/kea/kea4-ctrl-socket'}
    d2 = json.loads(files['kea-dhcp-ddns.conf'])['DhcpDdns']
    assert d2['ip-address'] == '127.0.0.1' and d2['tsig-keys'] == []
    assert render(KeaConfig()) == files                        # stable, so the drift hashes are too


def test_layout_follows_the_nodes_hooks_dir():
    assert layout_for({'kea_hooks_dir': '/usr/lib/aarch64-linux-gnu/kea/hooks'}).hooks_dir.startswith('/usr/lib/aarch64')
    assert layout_for({'kea_hooks_dir': None}) is DEBIAN
    files = render(KeaConfig(), KeaLayout(hooks_dir='/usr/lib/aarch64-linux-gnu/kea/hooks'))
    assert 'aarch64' in files['kea-dhcp4.conf']


def test_apply_writes_and_records(conn, settings, lab):  # noqa: F811
    fakes, snapshots = lab
    with_dhcp(conn, 1)
    lines = []
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', lines.append)
    assert fakes[1].kea_files == render(KeaConfig())
    assert json.loads(nodes.get_node(conn, 1)['dhcp_files']) == file_hashes(render(KeaConfig()))
    assert snapshots == [('ns1', 'test')] and any('kea-dhcp4 (sockets open) and D2 answer' in line for line in lines)


def test_apply_refuses_a_node_without_kea(conn, settings, lab):  # noqa: F811
    with pytest.raises(dhcp_apply.DhcpError, match="isn't set up on ns2"):
        dhcp_apply.apply_dhcp(settings, conn, [2], 'test', 'admin', print)


def test_apply_rolls_back_every_node_when_kea_stops_answering(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1, 2)
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    fakes[1].kea_files = {'kea-dhcp4.conf': 'old', 'kea-dhcp-ddns.conf': 'old d2'}
    fakes[2].kea_running['d2'] = False
    with pytest.raises(dhcp_apply.DhcpError, match='ns2: Kea stopped working'):
        dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'test', 'admin', print)
    assert fakes[1].kea_files == {'kea-dhcp4.conf': 'old', 'kea-dhcp-ddns.conf': 'old d2'}
    assert 'rollback dhcp' in fakes[1].calls and 'rollback dhcp' in fakes[2].calls


def test_a_refused_stage_changes_nothing(conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    fakes[1].fail_kea_stage = True
    with pytest.raises(dhcp_apply.DhcpError, match='refused the Kea config'):
        dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    assert fakes[1].kea_files == {} and nodes.get_node(conn, 1)['dhcp_files'] is None


def test_health_check_flags_kea_drift_and_rewrite_clears_it(conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    fakes[1].kea_files['kea-dhcp4.conf'] = fakes[1].kea_files['kea-dhcp4.conf'].replace('INFO', 'DEBUG')
    line = health.check_node(settings, conn, nodes.get_node(conn, 1))
    assert 'Kea config changed outside LiteBlox: kea-dhcp4.conf' in line
    assert json.loads(nodes.get_node(conn, 1)['dhcp_drift']) == ['kea-dhcp4.conf']
    job_id = dhcp_apply.start_rewrite(settings, 1, 'admin', background=False)
    assert jobs.get(conn, job_id)['status'] == 'ok'
    assert nodes.get_node(conn, 1)['dhcp_drift'] is None and 'DEBUG' not in fakes[1].kea_files['kea-dhcp4.conf']


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def test_the_dhcp_card(admin, conn, settings, lab):  # noqa: F811
    fakes, _ = lab
    card = admin.get('/nodes/1/dhcp').text
    assert "LiteBlox didn't set it up here" in card and '/nodes/1/bootstrap?dhcp=1' in card
    assert 'name="dhcp" value="true" x-model="dhcp" checked' in admin.get('/nodes/1/bootstrap?dhcp=1').text
    with_dhcp(conn, 1)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    card = admin.get('/nodes/1/dhcp').text
    assert '2.6.3' in card and 'pid 7' in card and 'nothing answers DHCP' in card
    assert '<code>ens19</code> 198.51.100.53/24' in card
    assert card.count('management (LiteBlox reaches the node here)') == 1          # ens18 carries 192.0.2.53
    assert 'Rewrite DHCP config' in card
    fakes[1].kea_files['kea-dhcp4.conf'] = fakes[1].kea_files['kea-dhcp4.conf'].replace('INFO', 'DEBUG')
    health.check_node(settings, conn, nodes.get_node(conn, 1))
    card = admin.get('/nodes/1/dhcp').text
    assert 'changed outside LiteBlox' in card and 'Overwrite the changes' in card
    assert '+' in card and 'DEBUG' in card and 'kea-dhcp4.conf as LiteBlox wrote it' in card


def test_rewrite_route(admin, conn, settings, lab, monkeypatch):  # noqa: F811
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    t = csrf_from(admin.get('/nodes/1').text)
    r = admin.post('/nodes/1/dhcp/rewrite', data={'csrf_token': t}, follow_redirects=False)
    assert 'not+set+up' in r.headers['location'] or 'not%20set%20up' in r.headers['location']
    with_dhcp(conn, 1)
    r = admin.post('/nodes/1/dhcp/rewrite', data={'csrf_token': t}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok' and job['kind'] == 'dhcp config', job['log']


def test_the_node_page_has_a_danger_zone(admin, conn, lab, client, make_user, login):  # noqa: F811
    page = admin.get('/nodes/1').text
    assert 'Danger zone' in page and 'href="/nodes/1/remove"' in page and 'Remove ns1…' in page
    assert '>Remove node</a>' not in page
    assert 'hx-get="/nodes/1/dhcp"' in page
    login(*make_user('viewer', 'viewer-password', 'readonly'))
    assert 'Danger zone' not in client.get('/nodes/1').text


@pytest.fixture
def rewrites(monkeypatch):
    started = []
    monkeypatch.setattr(dhcp_apply, 'start_rewrite', lambda settings, node_id, username, reason='', background=True:
                        started.append((node_id, reason)) or jobs.start(settings.db_path, 'dhcp config', lambda log: None,
                                                                        node_id=node_id, username=username, background=False))
    return started


def test_kea_that_gave_up_on_its_sockets_is_reloaded_once(conn, settings, lab, rewrites):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    fakes[1].kea_sockets = 'failed'
    line = health.check_node(settings, conn, nodes.get_node(conn, 1))
    assert rewrites == [(1, "Kea wasn't listening: reload")] and line.endswith(': reloading it')
    health.check_node(settings, conn, nodes.get_node(conn, 1))          # within 10 minutes: no second one
    assert len(rewrites) == 1


def test_kea_waits_for_its_interface_before_a_reload(conn, settings, lab, rewrites):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    with conn:
        conn.execute('UPDATE nodes SET dhcp_interfaces = \'["ens19"]\' WHERE id = 1')
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    fakes[1].kea_sockets = 'failed'
    real = fakes[1].status
    fakes[1].status = lambda: {**real(), 'interfaces': [{'name': 'ens19', 'up': False, 'addresses': []}]}
    line = health.check_node(settings, conn, nodes.get_node(conn, 1))
    assert rewrites == [] and line.endswith(': waits for ens19 to come up')
    fakes[1].status = real                                               # ens19 is up again
    health.check_node(settings, conn, nodes.get_node(conn, 1))
    assert rewrites == [(1, "Kea wasn't listening: reload")]


@pytest.mark.parametrize('state', ['retrying', 'down', 'failed with drift', 'failed while busy'])
def test_kea_is_left_alone(conn, settings, lab, rewrites, monkeypatch, state):  # noqa: F811
    fakes, _ = lab
    with_dhcp(conn, 1)
    dhcp_apply.apply_dhcp(settings, conn, [1], 'test', 'admin', print)
    fakes[1].kea_sockets = state.split()[0]
    if state == 'down':
        fakes[1].kea_sockets = 'ready'
        monkeypatch.setattr(health, 'listening', lambda dhcp4: {'status': 'down', 'errors': ['x']})
    if state == 'failed with drift':          # a rewrite would undo someone's hand edit
        fakes[1].kea_files['kea-dhcp4.conf'] = fakes[1].kea_files['kea-dhcp4.conf'].replace('INFO', 'DEBUG')
    if state == 'failed while busy':
        monkeypatch.setattr(health.roles, 'busy', lambda: True)
    health.check_node(settings, conn, nodes.get_node(conn, 1))
    assert rewrites == []
