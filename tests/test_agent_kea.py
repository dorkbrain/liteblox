"""The agent's Kea side: validators, /dhcp stage/commit/rollback, control commands, status."""

import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from liteblox.dhcp.model import KeaConfig, KeaLayout
from liteblox.dhcp.render import render
from liteblox.nodes.client import AgentClient, AgentError

from fakekea import FakeKeaSocket
from test_agent import agent_mod, fake_root, pki  # noqa: F401 (fixtures)
from test_agent import agent_config as bind_agent_config  # noqa: F401 (fixture)

HERE = Path(__file__).parent


@pytest.fixture
def kea_root(fake_root):  # noqa: F811
    """fake_root plus /etc/kea, a hooks dir, a lease dir, fake Kea tools and two fake control sockets."""
    for d in ('etc/kea', 'hooks', 'var/lib/kea', 'var/log/kea'):
        (fake_root / d).mkdir(parents=True)
    for tool in ('kea-dhcp4', 'kea-dhcp-ddns', 'ip', 'timedatectl'):
        script = fake_root / 'bin' / tool
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fakekea.py"}" {tool} "$@"\n')
        script.chmod(0o755)
    run = Path(tempfile.mkdtemp(prefix='kea'))      # AF_UNIX paths must stay short
    sockets = {'dhcp4': FakeKeaSocket(str(run / 'k4')), 'd2': FakeKeaSocket(str(run / 'kd'), 'd2')}
    yield fake_root, sockets
    for s in sockets.values():
        s.close()
    shutil.rmtree(run, ignore_errors=True)


@pytest.fixture
def layout(kea_root):
    root, _ = kea_root
    return KeaLayout(config_dir=str(root / 'etc/kea'), hooks_dir=str(root / 'hooks'),
                     lease_file=str(root / 'var/lib/kea/kea-leases4.csv'),
                     dhcp4_socket='/run/kea/kea4-ctrl-socket', d2_socket='/run/kea/kea-ddns-ctrl-socket')


@pytest.fixture
def kea_client(kea_root, bind_agent_config, pki):  # noqa: F811
    root, sockets = kea_root
    cfg = dict(bind_agent_config, kea_dir=str(root / 'etc/kea'), kea_hooks_dir=str(root / 'hooks'),
               kea_lease_dir=str(root / 'var/lib/kea'), kea_log_dir=str(root / 'var/log/kea'),
               kea_access={s: sock.path for s, sock in sockets.items()},
               tools=dict(bind_agent_config['tools'], **{t.replace('-', '_'): str(root / 'bin' / t)
                                                         for t in ('kea-dhcp4', 'kea-dhcp-ddns', 'ip', 'timedatectl')}))
    srv = agent_mod.make_server(cfg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with AgentClient('127.0.0.1', pki, port=srv.server_address[1]) as c:
        yield c, cfg
    srv.shutdown()
    srv.server_close()


def test_rendered_config_passes_the_allow_lists(kea_client, layout):
    _, cfg = kea_client
    files = render(KeaConfig(), layout)
    for role, text in files.items():
        agent_mod.validate_kea(role, text, cfg)
    assert json.loads(files['kea-dhcp4.conf'])['Dhcp4']['interfaces-config']['interfaces'] == []


@pytest.mark.parametrize('role, change, message', [
    ('kea-dhcp4.conf', lambda d: d['Dhcp4'].update({'config-control': {}}), 'config-control not allowed'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4'].update({'hosts-databases': []}), 'hosts-databases not allowed'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4']['lease-database'].update({'type': 'mysql'}), 'lease-database must be memfile'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4']['lease-database'].update({'name': '/etc/shadow'}), 'lease-database'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4']['hooks-libraries'].append({'library': '/tmp/evil.so'}), 'hooks library'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4'].update({'control-socket': {'socket-type': 'unix', 'socket-name': '/tmp/x'}}),
     'control-socket must be'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4']['loggers'][0]['output-options'][0].update({'output': '/etc/cron.d/x'}),
     'logger output'),
    ('kea-dhcp4.conf', lambda d: d['Dhcp4']['loggers'][0].update({'output_options': [{'output': '/etc/cron.d/x'}]}),
     'logger output'),           # Kea 2.4's spelling is checked too
    ('kea-dhcp4.conf', lambda d: d['Dhcp4'].update({'dhcp-ddns': {'server-ip': '192.0.2.1'}}), 'loopback'),
    ('kea-dhcp-ddns.conf', lambda d: d['DhcpDdns'].update({'ip-address': '0.0.0.0'}), 'loopback'),
    ('kea-dhcp-ddns.conf', lambda d: d['DhcpDdns'].update({'tsig-keys': [{'name': 'k', 'secret-file': '/x'}]}),
     'secret-file'),
])
def test_refused_kea_configs(kea_client, layout, role, change, message):
    client, cfg = kea_client
    data = json.loads(render(KeaConfig(), layout)[role])
    change(data)
    with pytest.raises(agent_mod.ConfError, match=message):
        agent_mod.validate_kea(role, json.dumps(data), cfg)
    with pytest.raises(AgentError) as e:
        client.stage_dhcp({role: json.dumps(data)})
    assert e.value.status == 422
    assert not [p for p in os.listdir(cfg['kea_dir']) if 'liteblox' in p]


def test_include_and_non_json_are_refused(kea_client):
    _, cfg = kea_client
    with pytest.raises(agent_mod.ConfError, match='include'):
        agent_mod.validate_kea('kea-dhcp4.conf', '<?include "/etc/passwd"?>', cfg)
    with pytest.raises(agent_mod.ConfError, match='strict JSON'):
        agent_mod.validate_kea('kea-dhcp4.conf', '{"Dhcp4": {} // comment\n}', cfg)
    with pytest.raises(agent_mod.ConfError, match='nothing else'):
        agent_mod.validate_kea('kea-dhcp4.conf', '{"Dhcp4": {}, "Dhcp6": {}}', cfg)


def test_stage_commit_reloads_and_rolls_back(kea_client, kea_root, layout):
    client, cfg = kea_client
    _, sockets = kea_root
    files = render(KeaConfig(), layout)
    assert client.check_dhcp(files)['ok']
    assert not [p for p in os.listdir(cfg['kea_dir']) if 'liteblox' in p]     # check leaves nothing behind
    result = client.commit_dhcp(client.stage_dhcp(files)['stage_id'])
    live = Path(cfg['kea_dir'])
    assert (live / 'kea-dhcp4.conf').read_text() == files['kea-dhcp4.conf']
    assert (live / 'kea-dhcp-ddns.conf').stat().st_mode & 0o777 == 0o640
    assert {'kea-dhcp4.conf', 'kea-dhcp-ddns.conf'} <= set(result['files'])
    assert [c['command'] for c in sockets['dhcp4'].commands] == ['config-reload']
    assert [c['command'] for c in sockets['d2'].commands] == ['config-reload']

    # a second change, then rollback: the first files are back and reloaded
    second = dict(files, **{'kea-dhcp4.conf': files['kea-dhcp4.conf'].replace('"INFO"', '"DEBUG"')})
    client.commit_dhcp(client.stage_dhcp({'kea-dhcp4.conf': second['kea-dhcp4.conf']})['stage_id'])
    assert '"DEBUG"' in (live / 'kea-dhcp4.conf').read_text()
    client.rollback_dhcp()
    assert (live / 'kea-dhcp4.conf').read_text() == files['kea-dhcp4.conf']
    assert sockets['dhcp4'].commands[-1]['command'] == 'config-reload'


def test_a_reload_failure_puts_the_old_files_back(kea_client, kea_root, layout):
    client, cfg = kea_client
    _, sockets = kea_root
    files = render(KeaConfig(), layout)
    client.commit_dhcp(client.stage_dhcp(files)['stage_id'])
    # the live file's group as Kea needs it (a group of the test user's other than its primary, if any)
    live = Path(cfg['kea_dir']) / 'kea-dhcp4.conf'
    gid = next((g for g in os.getgroups() if g != os.getgid()), os.getgid())
    os.chown(live, -1, gid)
    sockets['dhcp4'].fail_reload = True
    changed = files['kea-dhcp4.conf'].replace('"INFO"', '"DEBUG"')
    with pytest.raises(AgentError) as e:
        client.commit_dhcp(client.stage_dhcp({'kea-dhcp4.conf': changed})['stage_id'])
    assert e.value.status == 500 and 'rolled back' in e.value.message
    restored = Path(cfg['kea_dir']) / 'kea-dhcp4.conf'
    assert restored.read_text() == files['kea-dhcp4.conf']
    assert restored.stat().st_gid == gid                    # Kea reads it through its group



def test_a_reload_that_misses_a_new_interface_is_retried(kea_client, kea_root, layout):
    # Kea started before the interface existed (a VLAN made later): config-reload refuses a subnet on it until Kea
    # looks again, which config-set without the subnets' interface names makes it do
    client, cfg = kea_client
    _, sockets = kea_root
    data = json.loads(render(KeaConfig(), layout)['kea-dhcp4.conf'])
    data['Dhcp4']['interfaces-config']['interfaces'] = ['ens19']
    data['Dhcp4']['subnet4'] = [{'id': 1, 'subnet': '192.0.2.0/24', 'interface': 'ens19'}]
    text = json.dumps(data, indent=2)
    sockets['dhcp4'].unknown_interface = 'ens19'
    client.commit_dhcp(client.stage_dhcp({'kea-dhcp4.conf': text})['stage_id'])
    commands = [c['command'] for c in sockets['dhcp4'].commands]
    assert commands == ['config-reload', 'config-set', 'config-reload']
    sent = sockets['dhcp4'].commands[1]['arguments']['Dhcp4']
    assert 'interface' not in sent['subnet4'][0] and sent['interfaces-config']['interfaces'] == ['ens19']
    assert (Path(cfg['kea_dir']) / 'kea-dhcp4.conf').read_text() == text          # the real file stays


def test_kea_rejects_at_stage(kea_client, layout):
    client, cfg = kea_client
    data = json.loads(render(KeaConfig(), layout)['kea-dhcp4.conf'])
    data['Dhcp4']['user-context'] = {'note': 'BROKEN'}
    with pytest.raises(AgentError) as e:
        client.stage_dhcp({'kea-dhcp4.conf': json.dumps(data)})
    assert e.value.status == 422 and 'Kea rejected' in e.value.message and 'fake failure' in e.value.details['output']
    assert not [p for p in os.listdir(cfg['kea_dir']) if 'liteblox' in p]


def test_commands_are_allow_listed(kea_client, kea_root):
    client, _ = kea_client
    _, sockets = kea_root
    assert client.dhcp_command('dhcp4', 'status-get')['arguments']['pid'] == 4242
    for service, command in (('dhcp4', 'config-set'), ('dhcp4', 'shutdown'), ('d2', 'config-get'), ('x', 'status-get')):
        with pytest.raises(AgentError) as e:
            client.dhcp_command(service, command)
        assert e.value.status == 403
    assert [c['command'] for c in sockets['dhcp4'].commands] == ['status-get']


def test_status_reports_kea_and_interfaces(kea_client, kea_root, layout):
    client, cfg = kea_client
    client.commit_dhcp(client.stage_dhcp(render(KeaConfig(), layout))['stage_id'])
    status = client.status()
    kea = status['kea']
    assert kea['installed'] and kea['version'] == '2.6.3' and kea['hooks_dir'] == cfg['kea_hooks_dir']
    assert kea['services']['dhcp4'] == {'running': True, 'pid': 4242, 'uptime': 60, 'reload': 30}
    assert kea['files']['kea-dhcp4.conf'] and kea['files']['kea-dhcp-ddns.conf']
    assert status['interfaces'] == [{'name': 'ens18', 'up': True, 'addresses': ['192.0.2.53/24']},
                                    {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24', 'fd00:1:2:100::53/64',
                                                                                'fe80::53/64']}]
    kea_root[1]['d2'].close()
    assert client.status()['kea']['services']['d2']['running'] is False


def test_without_kea(kea_client, kea_root):
    client, cfg = kea_client
    os.unlink(cfg['tools']['kea_dhcp4'])
    assert client.status()['kea'] == {'installed': False}
    with pytest.raises(AgentError) as e:
        client.stage_dhcp({'kea-dhcp4.conf': '{}'})
    assert e.value.status == 409 and 'not set up' in e.value.message


def test_find_kea_hooks_falls_back():
    assert agent_mod.find_kea_hooks().endswith('/kea/hooks')


def test_status_reports_the_clock(kea_client):
    import time
    client, _ = kea_client
    before = time.time()
    clock = client.status()['clock']
    assert before - 1 <= clock['time'] <= time.time() + 1 and clock['synchronized'] is True


def test_status_and_files_for_readopt(kea_client, layout):
    """kea status says whether a LiteBlox wrote the config and how many subnets it serves; secrets=1 shows D2's key."""
    from liteblox.dhcp.model import Dhcp4Settings, Subnet
    client, cfg = kea_client
    key = {'name': 'kea-home', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0c2VjcmV0'}
    sub = Subnet(1, '198.51.100.0/24', 'ens19', ['198.51.100.10 - 198.51.100.20'], ddns=True,
                 ddns_suffix='dhcp.home.lan', ddns_mode='external')
    files = render(KeaConfig(['ens19'], Dhcp4Settings(ddns_mode='external', ddns_key=key), [sub],
                             primary='192.0.2.99'), layout)
    for role, text in files.items():
        Path(cfg['kea_dir'], role).write_text(text)
    kea = client.status()['kea']
    assert kea['liteblox'] is True and kea['subnets'] == 1
    assert key['secret'] not in json.dumps(client.dhcp_files())
    assert client.dhcp_files(secrets=True)['kea-dhcp-ddns.conf'] == files['kea-dhcp-ddns.conf']
    Path(cfg['kea_dir'], 'kea-dhcp4.conf').write_text('{"Dhcp4": {}}')
    assert client.status()['kea']['liteblox'] is False


def test_kea_before_2_5_gets_its_own_logger_spelling(kea_client, layout):
    from liteblox.dhcp.model import DEBIAN, layout_for
    assert layout_for({'kea_hooks_dir': None, 'kea_version': '2.4.1'}).logger_output_key == 'output_options'
    for version in ('2.6.3', None, ''):
        assert layout_for({'kea_hooks_dir': None, 'kea_version': version}).logger_output_key == 'output-options'
    old = layout_for({'kea_hooks_dir': '/usr/lib/aarch64-linux-gnu/kea/hooks', 'kea_version': '2.4.1'})
    assert old.hooks_dir.startswith('/usr/lib/aarch64') and DEBIAN.kea_version is None
    for role in ('kea-dhcp4.conf', 'kea-dhcp-ddns.conf'):
        text = render(KeaConfig(), old)[role]
        assert '"output_options"' in text and '"output-options"' not in text
    from dataclasses import replace
    client, cfg = kea_client
    agent_mod.validate_kea('kea-dhcp4.conf', render(KeaConfig(), replace(layout, kea_version='2.4.1'))['kea-dhcp4.conf'],
                           cfg)
