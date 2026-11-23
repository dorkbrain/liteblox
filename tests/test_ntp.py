"""Time (3.2): chrony on the nodes, written by LiteBlox: the agent's side, rendering, Settings → Time, health."""

import json
import re
import sys
import threading
from pathlib import Path

import pytest

from liteblox import jobs
from liteblox.nodes import bootstrap as bootstrap_mod
from liteblox.nodes import health
from liteblox.nodes import service as nodes
from liteblox.nodes.client import AgentClient, AgentError
from liteblox.ntp import apply as ntp_apply
from liteblox.ntp import validate
from liteblox.ntp.model import NtpConfig, Source
from liteblox.ntp.render import chrony_conf, render
from liteblox.pki import PKI

from conftest import csrf_from
from test_agent import agent_mod, fake_root, pki  # noqa: F401 (fixtures)
from test_agent import agent_config as bind_agent_config  # noqa: F401 (fixture)
from test_managed import lab  # noqa: F401 (fixture)
from test_nodes import FP, HOST_KEY, FakeAgent, FakeRemote

HERE = Path(__file__).parent


# ── the agent ──────────────────────────────────────────────────────────────────

@pytest.fixture
def chrony_client(fake_root, bind_agent_config, pki, monkeypatch):  # noqa: F811
    (fake_root / 'etc/chrony').mkdir(parents=True)
    conf = fake_root / 'etc/chrony/chrony.conf'
    conf.write_text(chrony_conf(NtpConfig()))
    monkeypatch.setenv('FAKE_CHRONY_CONF', str(conf))
    tools = {}
    for tool in ('chronyd', 'chronyc', 'systemctl'):
        script = fake_root / 'bin' / tool
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fakechrony.py"}" {tool} "$@"\n')
        script.chmod(0o755)
        tools[tool] = str(script)
    cfg = dict(bind_agent_config, chrony_dir=str(fake_root / 'etc/chrony'), chrony_conf=str(conf), chrony_restart_wait=2,
               tools=dict(bind_agent_config['tools'], **tools))
    srv = agent_mod.make_server(cfg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with AgentClient('127.0.0.1', pki, port=srv.server_address[1]) as c:
        yield c, conf
    srv.shutdown()
    srv.server_close()


def test_the_rendered_config_passes_the_allow_list():
    cfg = NtpConfig([Source('pool', '2.debian.pool.ntp.org'), Source('server', '192.0.2.1', prefer=True, minpoll=4)],
                    serve=True, allow=['192.168.0.0/24', 'fd00::/64'], local=10)
    agent_mod.validate_chrony(chrony_conf(cfg))


@pytest.mark.parametrize('line, message', [
    ('include /etc/passwd', 'not allowed'),
    ('confdir /etc/chrony/conf.d', 'not allowed'),
    ('refclock SHM 0', 'not allowed'),
    ('keyfile /tmp/keys', 'must be /etc/chrony/chrony.keys'),
    ('allow 0.0.0.0/0', 'every address'),
    ('allow lan', 'not a network'),
    ('server bad_host! iburst', 'host name or address'),
    ('pool 2.debian.pool.ntp.org offline', "'offline' not allowed"),
    ('local stratum 99', 'stratum N'),
])
def test_refused_chrony_lines(line, message):
    with pytest.raises(agent_mod.ConfError, match=re.escape(message)):
        agent_mod.validate_chrony(chrony_conf(NtpConfig()) + line + '\n')


def test_a_config_needs_the_header_and_a_source():
    with pytest.raises(agent_mod.ConfError, match='header'):
        agent_mod.validate_chrony('pool 2.debian.pool.ntp.org iburst\n')
    with pytest.raises(agent_mod.ConfError, match='no server or pool'):
        agent_mod.validate_chrony(chrony_conf(NtpConfig()).replace('pool 2.debian.pool.ntp.org iburst\n', ''))


def test_stage_commit_restart_and_rollback(chrony_client):
    c, conf = chrony_client
    old = conf.read_text()
    new = chrony_conf(NtpConfig([Source('server', '192.168.1.1')]))
    assert c.check_ntp({'chrony.conf': new})['ok']
    c.commit_ntp(c.stage_ntp({'chrony.conf': new})['stage_id'])
    assert conf.read_text() == new
    time = c.status()['time']
    assert time['daemon'] == 'chrony' and time['managed'] and time['tracking']['reference'] == '192.168.1.1'
    assert time['sources'][0] == {'address': '192.168.1.1', 'state': '*', 'stratum': 2, 'reach': 255,
                                  'offset': -0.00170674}
    assert c.ntp_files()['chrony.conf'] == new
    c.rollback_ntp()
    assert conf.read_text() == old


def test_chronyd_rejects_at_check_and_stage(chrony_client):
    c, conf = chrony_client
    bad = chrony_conf(NtpConfig()) + '# reject-me\n'
    for call in (c.check_ntp, c.stage_ntp):
        with pytest.raises(AgentError, match='chronyd rejected'):
            call({'chrony.conf': bad})
    assert not list(conf.parent.glob('*liteblox*'))          # no candidate left behind


def test_chrony_not_coming_back_puts_the_old_file_back(chrony_client):
    c, conf = chrony_client
    old = conf.read_text()
    with pytest.raises(AgentError, match='not running after the change'):
        c.commit_ntp(c.stage_ntp({'chrony.conf': chrony_conf(NtpConfig()) + '# breaks-chrony\n'})['stage_id'])
    assert conf.read_text() == old


# ── LiteBlox: sources, rendering ───────────────────────────────────────────────

def test_parse_sources():
    parsed, errors = validate.parse_sources('pool 2.debian.pool.ntp.org\nserver 192.168.1.1 prefer noiburst\n'
                                            '192.0.2.5  # a bare address is a server\nserver time.example.com nts maxpoll 10\n')
    assert not errors
    assert [s.line() for s in parsed] == ['pool 2.debian.pool.ntp.org iburst', 'server 192.168.1.1 prefer',
                                          'server 192.0.2.5 iburst', 'server time.example.com iburst nts maxpoll 10']
    assert validate.parse_sources('')[1] == ['list at least one server or pool']
    errors = validate.parse_sources('pool bad_name!\nserver 192.0.2.1 offline\nserver 192.0.2.1\n')[1]
    assert len(errors) == 3 and 'listed twice' in errors[2]


def test_render():
    text = chrony_conf(NtpConfig([Source('server', '192.168.1.1')], serve=True, allow=['192.168.0.0/24'], local=10))
    assert text.startswith('# Generated by LiteBlox.') and 'server 192.168.1.1 iburst\n' in text
    assert 'allow 192.168.0.0/24\nlocal stratum 10 orphan\n' in text and 'sourcedir' not in text and 'confdir' not in text
    assert 'allow' not in chrony_conf(NtpConfig(serve=False, allow=['192.168.0.0/24']))


# ── Settings → Time, the apply, the card, health ───────────────────────────────

@pytest.fixture
def timed(conn, lab, monkeypatch):  # noqa: F811
    """Both lab nodes set up for time sync, as bootstrap leaves them."""
    fakes, _ = lab
    with conn:
        conn.execute('UPDATE nodes SET ntp = 1')
    for node_id, f in fakes.items():
        f.chrony_files = render(NtpConfig())
        ntp_apply.record_commit(conn, node_id, f.chrony_files)
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    return fakes


@pytest.fixture
def admin(client, make_user, login):
    make_user()
    login('alice', 'correct-horse')
    return client


def test_settings_page_review_and_apply(admin, conn, timed):
    page = admin.get('/settings/time').text
    assert 'pool 2.debian.pool.ntp.org iburst' in page and "Debian's default pool" in page
    t = csrf_from(page)
    review = admin.post('/settings/time/preview', data={'sources': 'server 192.168.1.1\n'}, headers={'X-CSRF-Token': t}).text
    assert '+server 192.168.1.1 iburst' in review and '-pool 2.debian.pool.ntp.org iburst' in review
    assert 'chronyd -p' in review and 'Apply to every time server' in review
    bad = admin.post('/settings/time/preview', data={'sources': 'server bad_name!\n'}, headers={'X-CSRF-Token': t}).text
    assert 'needs a host name' in bad
    r = admin.post('/settings/time', data={'csrf_token': t, 'sources': 'server 192.168.1.1\n'}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    for f in timed.values():
        assert 'server 192.168.1.1 iburst' in f.chrony_files['chrony.conf']
    assert 'syncing from 192.0.2.1' in job['log']
    assert 'server 192.168.1.1 iburst' in admin.get('/settings/time').text


def test_a_node_that_refuses_rolls_everything_back(conn, settings, timed):
    timed[2].fail_ntp = True
    before = {i: dict(f.chrony_files) for i, f in timed.items()}
    with pytest.raises(ntp_apply.NtpError, match='chronyd rejected'):
        ntp_apply.apply_ntp(settings, conn, [1, 2], 'test', 'admin', print,
                            change=lambda c: c.execute("UPDATE ntp_settings SET sources = '[{\"kind\": \"server\", "
                                                       "\"address\": \"192.0.2.9\"}]'"),
                            undo=lambda c: c.execute("UPDATE ntp_settings SET sources = '[]'"))
    assert 'rollback ntp' in timed[1].calls and {i: f.chrony_files for i, f in timed.items()} == before
    assert conn.execute('SELECT sources FROM ntp_settings').fetchone()[0] == '[]'


def test_without_nodes_the_sources_are_just_saved(admin, conn, lab):  # noqa: F811
    t = csrf_from(admin.get('/settings/time').text)
    r = admin.post('/settings/time', data={'csrf_token': t, 'sources': 'pool pool.ntp.org\n'}, follow_redirects=True)
    assert 'Saved' in r.text and 'pool pool.ntp.org iburst' in r.text


def test_viewers_cannot_change_time(client, make_user, login, timed):
    make_user('viewer', 'correct-horse', 'readonly')
    login('viewer', 'correct-horse')
    assert client.get('/settings/time').status_code == 403
    assert 'Time (chrony)' in client.get('/nodes/1/time').text


def test_the_node_card(admin, conn, timed):
    card = admin.get('/nodes/1/time').text
    assert 'running' in card and '<code>192.0.2.1</code>, stratum 3' in card and 'Rewrite time config' in card
    with conn:
        conn.execute('UPDATE nodes SET ntp = 0 WHERE id = 2')
    timed[2].chrony_files = {}
    card = admin.get('/nodes/2/time').text
    assert 'Kept by <strong>timesyncd</strong>' in card and 'href="/nodes/2/bootstrap?ntp=1"' in card
    assert 'name="ntp" value="true" x-model="ntp" checked' in admin.get('/nodes/2/bootstrap?ntp=1').text


def test_health_drift_state_and_catching_up(admin, conn, settings, timed):
    timed[1].chrony_files['chrony.conf'] += '# hand edit\n'
    timed[2].ntp_synced = False
    for n in nodes.list_nodes(conn):
        health.check_node(settings, conn, n, background=False)
    n1, n2 = nodes.get_node(conn, 1), nodes.get_node(conn, 2)
    assert json.loads(n1['ntp_drift']) == ['chrony.conf'] and json.loads(n2['ntp_state'])['synced'] is False
    page = admin.get('/nodes').text
    assert 'time config changed' in page and 'time: no source' in page
    card = admin.get('/nodes/1/time').text
    assert '+# hand edit' in card and 'Overwrite the changes' in card
    t = csrf_from(card if 'csrf_token' in card else admin.get('/nodes/1').text)
    r = admin.post('/nodes/1/time/rewrite', data={'csrf_token': t}, follow_redirects=False)
    assert jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))['status'] == 'ok'
    health.check_node(settings, conn, nodes.get_node(conn, 1), background=False)
    assert nodes.get_node(conn, 1)['ntp_drift'] is None
    # a node that missed a change is written again by the health check
    with conn:
        conn.execute("UPDATE ntp_settings SET sources = '[{\"kind\": \"server\", \"address\": \"192.0.2.7\"}]'")
    timed[2].ntp_synced = True
    note = health.check_node(settings, conn, nodes.get_node(conn, 2), background=False)
    assert 'rewriting it' in note and 'server 192.0.2.7 iburst' in timed[2].chrony_files['chrony.conf']


# ── bootstrap ──────────────────────────────────────────────────────────────────

def test_bootstrap_sets_chrony_up(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', lambda s: None)
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530, 'host_key': HOST_KEY,
            'host_key_fp': FP, 'ntp_conf': chrony_conf(NtpConfig())}
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(ntp=True),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', print, connect=FakeRemote)
    joined = '\n'.join(FakeRemote.last.commands)
    assert 'install -y chrony' in joined and 'enable --now liteblox-chrony.path' in joined
    assert 'chgrp liteblox-agent /etc/chrony /etc/chrony/chrony.conf && chmod 2775 /etc/chrony' in joined
    assert 'pre-liteblox' in joined
    chrony_files = next(u for u in FakeRemote.last.uploads if 'liteblox-chrony.path' in u)
    assert b'PathChanged=/etc/chrony/chrony.conf' in chrony_files['liteblox-chrony.path']
    assert chrony_files['chrony.conf'].decode() == node['ntp_conf']
    unit = FakeRemote.last.uploaded['liteblox-agent.service'].decode()
    assert re.search(r'^ReadWritePaths=.* /etc/chrony$', unit, re.M)
    assert node['ntp_setup']['ntp'] == 1 and 'chrony.conf' in json.loads(node['ntp_setup']['ntp_files'])


# ── serving time (milestone 2) ─────────────────────────────────────────────────

def serve_form(t, **extra):
    return {'csrf_token': t, 'sources': 'pool 2.debian.pool.ntp.org\n', **extra}


def test_serving_through_settings(admin, conn, timed):
    t = csrf_from(admin.get('/settings/time').text)
    review = admin.post('/settings/time/preview', headers={'X-CSRF-Token': t},
                        data=serve_form(t, serve_1='1', allow_1='198.51.100.0/24', local_1='1')).text
    assert '+allow 198.51.100.0/24' in review and '+local stratum 10 orphan' in review
    assert 'No change on ns2' in review
    r = admin.post('/settings/time', data=serve_form(t, serve_1='1', allow_1='198.51.100.0/24\n198.51.100.0/24',
                                                     local_1='1'), follow_redirects=False)
    assert jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))['status'] == 'ok'
    assert 'allow 198.51.100.0/24\nlocal stratum 10 orphan\n' in timed[1].chrony_files['chrony.conf']
    assert 'allow' not in timed[2].chrony_files['chrony.conf']
    n1 = nodes.get_node(conn, 1)
    assert (n1['ntp_serve'], json.loads(n1['ntp_allow']), n1['ntp_local']) == (1, ['198.51.100.0/24'], 10)
    page = admin.get('/settings/time').text
    assert 'name="serve_1" value="1" aria-label="ns1 serves time" checked' in page
    assert 'to 198.51.100.0/24; keeps serving' in admin.get('/nodes/1/time').text


@pytest.mark.parametrize('extra, message', [
    ({'serve_1': '1', 'allow_1': ''}, 'name the networks it serves time to'),
    ({'serve_1': '1', 'allow_1': '0.0.0.0/0'}, 'every address is not allowed'),
    ({'serve_1': '1', 'allow_1': 'lan'}, 'is not a network'),
])
def test_serving_errors(admin, timed, extra, message):
    t = csrf_from(admin.get('/settings/time').text)
    r = admin.post('/settings/time', data=serve_form(t, **extra))
    assert r.status_code == 422 and message in r.text


def test_the_dev_guard_on_served_networks(admin, timed, monkeypatch):
    monkeypatch.setenv('LITEBLOX_DEV_NTP_SERVE_ONLY', '198.51.100.0/24')
    t = csrf_from(admin.get('/settings/time').text)
    r = admin.post('/settings/time', data=serve_form(t, serve_1='1', allow_1='192.0.2.0/24'))
    assert r.status_code == 422 and 'outside LITEBLOX_DEV_NTP_SERVE_ONLY' in r.text
    ok = admin.post('/settings/time/preview', headers={'X-CSRF-Token': t},
                    data=serve_form(t, serve_1='1', allow_1='198.51.100.0/25')).text
    assert 'outside' not in ok


def test_review_notes_a_network_the_node_isnt_on(admin, timed):
    t = csrf_from(admin.get('/settings/time').text)
    review = admin.post('/settings/time/preview', headers={'X-CSRF-Token': t},
                        data=serve_form(t, serve_1='1', allow_1='203.0.113.0/24')).text
    assert 'ns1 has no address in 203.0.113.0/24' in review


def test_dhcp_suggests_the_time_servers(admin, conn, timed):
    from liteblox.dhcp import store
    from liteblox.dhcp.model import Subnet
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp_interfaces = '[\"ens19\"]' WHERE id = 1")
    store.save_subnet(conn, Subnet(1, '198.51.100.0/24', 'ens19', ['198.51.100.100 - 198.51.100.199']))
    assert "LiteBlox's time servers" not in admin.get('/dhcp/subnets/1/settings').text
    with conn:
        conn.execute("UPDATE nodes SET ntp_serve = 1, ntp_allow = '[\"198.51.100.0/24\"]' WHERE id = 1")
    page = admin.get('/dhcp/subnets/1/settings').text
    assert "LiteBlox's time servers in this subnet: <code>198.51.100.53</code>" in page


def test_api_time(conn, client, timed):
    from liteblox import auth
    from liteblox.api import tokens
    auth.create_user(conn, 'bob', 'correct-horse', 'readonly')
    h = {'Authorization': 'Bearer ' + tokens.create(conn, 'bob', 'look', 'read', 'test')[1]}
    with conn:
        conn.execute("UPDATE nodes SET ntp_serve = 1, ntp_allow = '[\"198.51.100.0/24\"]', ntp_local = 10, "
                     "ntp_state = '{\"synced\": true, \"reference\": \"192.0.2.1\", \"stratum\": 3, \"offset\": 0.0}' WHERE id = 1")
    got = client.get('/api/v1/ntp', headers=h).json()
    assert got['sources'] == ['pool 2.debian.pool.ntp.org iburst'] and got['default'] is True
    assert got['nodes'][0] == {'node': 'ns1', 'serves': True, 'networks': ['198.51.100.0/24'], 'keeps_serving': True,
                               'state': {'synced': True, 'reference': '192.0.2.1', 'stratum': 3, 'offset': 0.0}}
    assert client.get('/api/v1/nodes/ns1', headers=h).json()['time']['reference'] == '192.0.2.1'
