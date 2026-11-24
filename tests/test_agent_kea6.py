"""The agent's kea-dhcp6 side (6.0): its config file beside DHCPv4's, the allow-list, reloads, status, and a node
from before 6.0 that has no kea-dhcp6 yet."""

import json
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from liteblox.dhcp.model import KeaConfig, KeaLayout, Subnet6
from liteblox.dhcp.render import render
from liteblox.nodes.client import AgentClient, AgentError

from fakekea import FakeKeaSocket
from test_agent import agent_mod, fake_root, pki  # noqa: F401 (fixtures)
from test_agent import agent_config as bind_agent_config  # noqa: F401 (fixture)

HERE = Path(__file__).parent
TOOLS = ('kea-dhcp4', 'kea-dhcp6', 'kea-dhcp-ddns', 'ip', 'timedatectl')


@pytest.fixture
def kea6_root(fake_root):  # noqa: F811
    for d in ('etc/kea', 'hooks', 'var/lib/kea', 'var/log/kea'):
        (fake_root / d).mkdir(parents=True)
    for tool in TOOLS:
        script = fake_root / 'bin' / tool
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fakekea.py"}" {tool} "$@"\n')
        script.chmod(0o755)
    run = Path(tempfile.mkdtemp(prefix='kea'))
    sockets = {'dhcp4': FakeKeaSocket(str(run / 'k4')), 'dhcp6': FakeKeaSocket(str(run / 'k6'), 'dhcp6'),
               'd2': FakeKeaSocket(str(run / 'kd'), 'd2')}
    yield fake_root, sockets
    for s in sockets.values():
        s.close()
    shutil.rmtree(run, ignore_errors=True)


@pytest.fixture
def layout(kea6_root):
    root, _ = kea6_root
    return KeaLayout(config_dir=str(root / 'etc/kea'), hooks_dir=str(root / 'hooks'),
                     lease_file=str(root / 'var/lib/kea/kea-leases4.csv'),
                     lease_file6=str(root / 'var/lib/kea/kea-leases6.csv'))


@pytest.fixture
def client6(kea6_root, bind_agent_config, pki):  # noqa: F811
    root, sockets = kea6_root
    cfg = dict(bind_agent_config, kea_dir=str(root / 'etc/kea'), kea_hooks_dir=str(root / 'hooks'),
               kea_lease_dir=str(root / 'var/lib/kea'), kea_log_dir=str(root / 'var/log/kea'),
               kea_access={s: sock.path for s, sock in sockets.items()},
               tools=dict(bind_agent_config['tools'], **{t.replace('-', '_'): str(root / 'bin' / t) for t in TOOLS}))
    srv = agent_mod.make_server(cfg)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with AgentClient('127.0.0.1', pki, port=srv.server_address[1]) as c:
        yield c, cfg
    srv.shutdown()
    srv.server_close()


def a_subnet():
    return Subnet6(7, 'fd00:1:2:100::/64', 'ens19', pools=['fd00:1:2:100::1000 - fd00:1:2:100::1fff'],
                   pd_pools=[{'prefix': 'fd00:1:2:f000::/52', 'delegated_len': 60}],
                   options={'dns': ['fd00:1:2:100::213']})


def test_rendered_dhcp6_passes_the_allow_list(client6, layout):
    _, cfg = client6
    files = render(KeaConfig(dhcp6=True, subnets6=[a_subnet()], interfaces6=['ens19']), layout)
    assert set(files) == {'kea-dhcp4.conf', 'kea-dhcp6.conf', 'kea-dhcp-ddns.conf'}
    for role, text in files.items():
        agent_mod.validate_kea(role, text, cfg)


@pytest.mark.parametrize('change, message', [
    (lambda d: d['Dhcp6'].update({'config-control': {}}), 'config-control not allowed'),
    (lambda d: d['Dhcp6'].update({'data-directory': '/tmp'}), 'data-directory not allowed'),
    (lambda d: d['Dhcp6'].update({'subnet4': []}), 'subnet4 not allowed'),
    (lambda d: d['Dhcp6']['lease-database'].update({'name': '/etc/shadow'}), 'lease-database'),
    (lambda d: d['Dhcp6']['hooks-libraries'].append({'library': '/tmp/evil.so'}), 'hooks library'),
    (lambda d: d['Dhcp6'].update({'control-socket': {'socket-type': 'unix', 'socket-name': '/tmp/x'}}),
     'control-socket must be'),
    (lambda d: d['Dhcp6'].update({'server-id': {'type': 'LLT', 'data-directory': '/tmp'}}), 'server-id takes'),
    (lambda d: d['Dhcp6']['loggers'][0]['output-options'].append({'output': '/etc/cron.d/x'}), 'logger output'),
])
def test_refused_dhcp6_configs(client6, layout, change, message):
    _, cfg = client6
    data = json.loads(render(KeaConfig(dhcp6=True), layout)['kea-dhcp6.conf'])
    change(data)
    with pytest.raises(agent_mod.ConfError, match=message):
        agent_mod.validate_kea('kea-dhcp6.conf', json.dumps(data), cfg)


def test_stage_commit_reloads_kea_dhcp6(client6, kea6_root, layout):
    client, cfg = client6
    _, sockets = kea6_root
    files = render(KeaConfig(dhcp6=True, subnets6=[a_subnet()], interfaces6=['ens19']), layout)
    assert client.check_dhcp(files)['ok']
    result = client.commit_dhcp(client.stage_dhcp(files)['stage_id'])
    assert (Path(cfg['kea_dir']) / 'kea-dhcp6.conf').read_text() == files['kea-dhcp6.conf']
    assert (Path(cfg['kea_dir']) / 'kea-dhcp6.conf').stat().st_mode & 0o777 == 0o640
    assert result['files']['kea-dhcp6.conf']
    assert [c['command'] for c in sockets['dhcp6'].commands] == ['config-reload']

    # only DHCPv6 changed: only kea-dhcp6 reloads, and a rollback reloads it again
    changed = files['kea-dhcp6.conf'].replace('"INFO"', '"DEBUG"')
    client.commit_dhcp(client.stage_dhcp({'kea-dhcp6.conf': changed})['stage_id'])
    assert [c['command'] for c in sockets['dhcp4'].commands] == ['config-reload']
    client.rollback_dhcp()
    assert (Path(cfg['kea_dir']) / 'kea-dhcp6.conf').read_text() == files['kea-dhcp6.conf']
    assert [c['command'] for c in sockets['dhcp6'].commands] == ['config-reload'] * 3


def test_a_dhcp6_reload_failure_rolls_back(client6, kea6_root, layout):
    client, cfg = client6
    _, sockets = kea6_root
    files = render(KeaConfig(dhcp6=True), layout)
    client.commit_dhcp(client.stage_dhcp(files)['stage_id'])
    sockets['dhcp6'].fail_reload = True
    with pytest.raises(AgentError) as e:
        client.commit_dhcp(client.stage_dhcp({'kea-dhcp6.conf': files['kea-dhcp6.conf'].replace('"INFO"', '"DEBUG"')})
                           ['stage_id'])
    assert e.value.status == 500 and 'dhcp6: fake reload failure' in e.value.details['output']
    assert (Path(cfg['kea_dir']) / 'kea-dhcp6.conf').read_text() == files['kea-dhcp6.conf']


def test_a_new_interface_is_retried_for_dhcp6(client6, kea6_root, layout):
    client, cfg = client6
    _, sockets = kea6_root
    text = render(KeaConfig(dhcp6=True, subnets6=[a_subnet()], interfaces6=['ens19']), layout)['kea-dhcp6.conf']
    sockets['dhcp6'].unknown_interface = 'ens19'
    client.commit_dhcp(client.stage_dhcp({'kea-dhcp6.conf': text})['stage_id'])
    assert [c['command'] for c in sockets['dhcp6'].commands] == ['config-reload', 'config-set', 'config-reload']
    sent = sockets['dhcp6'].commands[1]['arguments']['Dhcp6']
    assert 'interface' not in sent['subnet6'][0] and sent['interfaces-config']['interfaces'] == ['ens19']
    assert sockets['dhcp4'].commands == []


def test_dhcp6_commands_and_status(client6, kea6_root, layout):
    client, _ = client6
    _, sockets = kea6_root
    client.commit_dhcp(client.stage_dhcp(render(KeaConfig(dhcp6=True, subnets6=[a_subnet()],
                                                          interfaces6=['ens19']), layout))['stage_id'])
    assert client.dhcp_command('dhcp6', 'status-get')['arguments']['pid'] == 4242
    for command in ('config-set', 'lease4-get', 'shutdown'):
        with pytest.raises(AgentError) as e:
            client.dhcp_command('dhcp6', command)
        assert e.value.status == 403
    kea = client.status()['kea']
    assert kea['dhcp6'] is True and kea['services']['dhcp6']['running'] is True
    assert kea['files']['kea-dhcp6.conf'] and kea['subnets6'] == 1


def test_a_node_without_kea_dhcp6(client6, kea6_root, layout):
    # a node from before 6.0's Repair: its DHCPv4 keeps working, kea-dhcp6.conf is refused, and nothing asks
    # kea-dhcp6 how it is
    client, cfg = client6
    _, sockets = kea6_root
    os.unlink(cfg['tools']['kea_dhcp6'])
    files = render(KeaConfig(dhcp6=True), layout)
    with pytest.raises(AgentError) as e:
        client.stage_dhcp(files)
    assert e.value.status == 409 and 'kea-dhcp6 is not installed' in e.value.message
    v4 = {r: t for r, t in files.items() if r != 'kea-dhcp6.conf'}
    client.commit_dhcp(client.stage_dhcp(v4)['stage_id'])
    kea = client.status()['kea']
    assert kea['dhcp6'] is False and 'dhcp6' not in kea['services'] and 'subnets6' not in kea
    assert sockets['dhcp6'].commands == []
    assert client.dhcp_files()['kea-dhcp6.conf'] in (None, '')
