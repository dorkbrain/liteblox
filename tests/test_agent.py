import importlib.util
import io
import json
import os
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

from liteblox.bindconf.model import Layout, NodeConfig, NodeOptions, ZoneDecl
from liteblox.bindconf.render import render
from liteblox.nodes import agent_dir, agent_sha256
from liteblox.nodes.client import AgentClient, AgentError
from liteblox.pki import PKI

from cryptography.x509.oid import ExtendedKeyUsageOID

HERE = Path(__file__).parent
EXAMPLE = (HERE / 'fixtures' / 'zones' / 'example.com.zone').read_text()

_spec = importlib.util.spec_from_file_location('liteblox_agent', agent_dir() / 'liteblox_agent.py')
agent_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent_mod)


# ── fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """A fake node filesystem with BIND config, zones and stand-in tools."""
    root = tmp_path / 'node'
    bind = root / 'etc/bind'
    cache = root / 'var/cache/bind'
    for d in (bind, cache, root / 'bin', root / 'state'):
        d.mkdir(parents=True)
    monkeypatch.setenv('FAKEBIND_ROOT', str(root))

    (bind / 'named.conf').write_text(
        f'// main config\n'
        f'options {{ directory "{cache}"; }};\n'
        f'include "{bind}/rndc.key";\n'
        f'include "{bind}/named.conf.local";\n'
        f'include "{bind}/named.conf.default-zones";\n'
        f'include "{bind}/named.conf.liteblox";\n')
    (bind / 'rndc.key').write_text('key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };\n')
    (bind / 'named.conf.local').write_text(
        f'zone "example.com" {{ type master; file "{bind}/db.example.com"; }};\n'
        f'zone "rel.example" {{ type primary; file "db.rel"; }};   # relative to directory\n'
        f'zone "sec.example" {{ type slave; masters {{ 192.0.2.1; }}; file "sec.example"; }};\n'
        f'view "internal" {{ zone "viewed.example" {{ type master; file "{bind}/db.viewed"; }}; }};\n')
    (bind / 'named.conf.default-zones').write_text(
        f'zone "localhost" {{ type master; file "{bind}/db.local"; }};\n')
    (bind / 'db.example.com').write_text(EXAMPLE)
    (bind / 'db.example.com').chmod(0o644)
    (bind / 'db.local').write_text('@ IN SOA localhost. root.localhost. 1 1 1 1 1\n')
    (bind / 'db.viewed').write_text('@ IN SOA ns. root. 5 1 1 1 1\n')
    (cache / 'db.rel').write_text('@ IN SOA ns1.rel.example. root.rel.example. 2026010105 1 1 1 1\n')
    (cache / 'sec.example.jnl').write_text('journal')

    for tool in ('named', 'named-checkconf', 'named-checkzone', 'rndc'):
        script = root / 'bin' / tool
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fakebind.py"}" {tool} "$@"\n')
        script.chmod(0o755)
    os.system(f'"{root / "bin/rndc"}" reload >/dev/null')     # "named" loads the zones at start
    (root / 'rndc.log').unlink()
    return root


@pytest.fixture
def pki(tmp_path):
    return PKI(tmp_path / 'pki').ensure()


@pytest.fixture
def agent_config(fake_root, pki, tmp_path):
    certs = tmp_path / 'agent-certs'
    certs.mkdir()
    key, cert = pki.issue_server_cert('test-node', ['127.0.0.1'])
    (certs / 'agent.key').write_bytes(key)
    (certs / 'agent.crt').write_bytes(cert)
    (certs / 'ca.crt').write_bytes(pki.ca_pem())
    bind = fake_root / 'etc/bind'
    tools = {t.replace('-', '_'): str(fake_root / 'bin' / t)
             for t in ('named', 'named-checkconf', 'named-checkzone', 'rndc')}
    cfg = dict(agent_mod.DEFAULT_CONFIG, listen='127.0.0.1', port=0, version='test',
               cert=str(certs / 'agent.crt'), key=str(certs / 'agent.key'), ca=str(certs / 'ca.crt'),
               state_dir=str(fake_root / 'state'), named_conf=str(bind / 'named.conf'),
               managed_dir=str(bind / 'liteblox'), jnl_dir=str(fake_root / 'var/lib/bind/liteblox/jnl'),
               dyn_dir=str(fake_root / 'var/lib/bind/liteblox/dyn'),
               sec_dir=str(fake_root / 'var/lib/bind/liteblox/sec'), pre_dir=str(bind / 'pre-liteblox'),
               directory=str(fake_root / 'var/cache/bind'),
               distro_includes=[str(bind / 'named.conf.default-zones')],
               backup_paths=[str(bind)], tools=tools, agent_lib=str(tmp_path / 'agent-lib'))
    return cfg


@pytest.fixture
def server(agent_config):
    srv = agent_mod.make_server(agent_config)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def client(server, pki):
    with AgentClient('127.0.0.1', pki, port=server.server_address[1]) as c:
        yield c


def rndc_log(root):
    log = root / 'rndc.log'
    return log.read_text().splitlines() if log.exists() else []


# ── named.conf parsing ─────────────────────────────────────────────────────────

def test_parse_conf_and_find_zones():
    text = '''
    options { directory "/var/cache/bind"; listen-on { 127.0.0.1; }; };  /* block comment */
    zone "Example.COM." IN { type master; file "/etc/bind/db.example.com"; };
    zone "rel.example" { type primary; file "db.rel"; };   // trailing comment
    view "lan" { match-clients { any; }; zone "v.example" { type master; file "/x"; }; };
    zone "0.in-addr.arpa" { type master; file "/etc/bind/db.0"; };
    '''
    zones = {z['name']: z for z in agent_mod.zones_from_conf(agent_mod.parse_conf(text))}
    assert zones['example.com']['type'] == 'primary'
    assert zones['rel.example']['file'] == '/var/cache/bind/db.rel'
    assert zones['v.example']['view'] == 'lan'
    assert zones['0.in-addr.arpa']['builtin']


@pytest.mark.parametrize('text', ['zone "x" { type master; ', 'options { a; }; }', 'zone "x" { type master }'])
def test_parse_conf_errors(text):
    with pytest.raises(agent_mod.ConfError):
        agent_mod.parse_conf(text)


# ── status / config / read ─────────────────────────────────────────────────────

def test_status(client):
    s = client.status()
    assert s['named_version'].startswith('BIND 9.20.99-fake')
    assert s['rndc_ok'] and s['checkconf_ok']
    assert s['zones_writable'] == {'example.com': True, 'rel.example': True}
    assert s['agent_version'] == 'test'
    assert s['agent_sha256'] == agent_sha256()


def test_config_discovers_zones(client, fake_root):
    cfg = client.config()
    zones = {z['name']: z for z in cfg['zones']}
    bind = fake_root / 'etc/bind'
    assert zones['example.com']['declared_in'] == str(bind / 'named.conf.local')
    assert zones['example.com']['loaded_serial'] == 2026010101
    assert zones['rel.example']['file'] == str(fake_root / 'var/cache/bind/db.rel')
    assert zones['sec.example']['type'] == 'secondary'
    assert zones['viewed.example']['view'] == 'internal'
    assert zones['localhost']['builtin'] and zones['localhost']['declared_in'].endswith('default-zones')
    assert 'rndc-key' in cfg['checkconf'] and 'c2VjcmV0' not in cfg['checkconf']   # -px masks secrets


def test_config_reports_a_secondarys_serial(client, fake_root):
    # the serial a secondary serves is the copy it transferred (the Zones list shows it per node)
    state = json.loads((fake_root / 'loaded.json').read_text())
    (fake_root / 'loaded.json').write_text(json.dumps(dict(state, **{'sec.example': 2026010107})))
    zones = {z['name']: z for z in client.config()['zones']}
    assert zones['sec.example']['loaded_serial'] == 2026010107
    assert zones['localhost']['loaded_serial'] is None


class _StatsChannel(BaseHTTPRequestHandler):
    """BIND's statistics channel, the parts the agent reads."""
    body = {'boot-time': '2026-11-01T08:00:00.000Z', 'config-time': '2026-11-01T08:00:00.000Z',
            'opcodes': {'QUERY': 1234, 'NOTIFY': 3},
            'rcodes': {'NOERROR': 1200, 'NXDOMAIN': 30, 'SERVFAIL': 4, 'REFUSED': 0},
            'nsstats': {'QryRecursion': 50, 'UpdateDone': 7, 'XfrReqDone': 2}}

    def do_GET(self):
        data = json.dumps(self.body).encode()
        self.send_response(200 if self.path == '/json/v1/server' else 404)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _fake_proc(root):
    proc = root / 'proc'
    proc.mkdir()
    (proc / 'loadavg').write_text('0.25 0.10 0.05 1/123 4567\n')
    (proc / 'meminfo').write_text('MemTotal:        2000000 kB\nMemFree:          100000 kB\n'
                                  'MemAvailable:    1500000 kB\n')
    (proc / 'uptime').write_text('3600.50 7000.00\n')
    return proc


def test_stats(server, client, fake_root):
    channel = HTTPServer(('127.0.0.1', 0), _StatsChannel)
    threading.Thread(target=channel.serve_forever, daemon=True).start()
    try:
        server.agent.cfg.update(proc_dir=str(_fake_proc(fake_root)), stats_disks=[str(fake_root), '/nonexistent'],
                                bind_stats_url=f'http://127.0.0.1:{channel.server_address[1]}/json/v1/server')
        s = client.stats()
    finally:
        channel.shutdown()
        channel.server_close()
    assert s['errors'] == {}
    assert s['system']['load'] == [0.25, 0.10, 0.05]
    assert s['system']['mem_total'] == 2000000 * 1024 and s['system']['mem_available'] == 1500000 * 1024
    assert s['system']['uptime'] == 3600.5
    assert list(s['system']['disks']) == [str(fake_root)]       # one it can't stat is left out
    assert s['system']['disks'][str(fake_root)]['total'] > 0
    assert s['bind'] == {'boot_time': '2026-11-01T08:00:00.000Z', 'config_time': '2026-11-01T08:00:00.000Z',
                         'queries': 1234, 'noerror': 1200, 'nxdomain': 30, 'servfail': 4, 'refused': 0,
                         'recursive': 50, 'updates': 7, 'xfr_out': 2}


def test_stats_parts_fail_on_their_own(server, client, fake_root):
    # no statistics channel (a node not rewritten yet), and no /proc files: both reported, nothing raised
    server.agent.cfg.update(proc_dir=str(fake_root / 'no-proc'), bind_stats_url='http://127.0.0.1:9/json/v1/server')
    s = client.stats()
    assert s['system'] is None and s['bind'] is None
    assert 'loadavg' in s['errors']['system']
    assert s['errors']['bind'].startswith("BIND's statistics channel:")


def test_get_zone(client):
    z = client.get_zone('example.com.')
    assert z['content'] == EXAMPLE
    assert z['sha256'] == agent_mod.sha256(EXAMPLE.encode())


@pytest.mark.parametrize('zone, status', [
    ('nope.example', 404), ('sec.example', 409), ('viewed.example', 409), ('localhost', 409),
])
def test_zone_refusals(client, zone, status):
    with pytest.raises(AgentError) as e:
        client.get_zone(zone)
    assert e.value.status == status


# ── stage / commit / abort ─────────────────────────────────────────────────────

def test_stage_and_commit(client, fake_root):
    live = fake_root / 'etc/bind/db.example.com'
    base = client.get_zone('example.com')['sha256']
    new = EXAMPLE.replace('2026010101', '2026010102')

    staged = client.stage_zone('example.com', new, base)
    assert 'loaded serial 2026010102' in staged['output']
    assert (fake_root / 'etc/bind/db.example.com.liteblox-new').exists()
    assert live.read_text() == EXAMPLE            # nothing live yet

    result = client.commit_zone('example.com', staged['stage_id'])
    assert live.read_text() == new
    assert live.stat().st_mode & 0o777 == 0o644
    assert result['loaded_serial'] == 2026010102
    assert 'reload example.com' in rndc_log(fake_root)
    assert not (fake_root / 'etc/bind/db.example.com.liteblox-new').exists()
    backups = list((fake_root / 'state/backups/example.com').iterdir())
    assert len(backups) == 1 and backups[0].read_text() == EXAMPLE


def test_stage_rejects_drift(client):
    with pytest.raises(AgentError) as e:
        client.stage_zone('example.com', EXAMPLE, 'not-the-current-hash')
    assert e.value.status == 409
    assert e.value.details['current_sha256'] == agent_mod.sha256(EXAMPLE.encode())


def test_stage_rejects_bad_zone(client, fake_root):
    base = client.get_zone('example.com')['sha256']
    with pytest.raises(AgentError) as e:
        client.stage_zone('example.com', EXAMPLE + 'BADZONE\n', base)
    assert e.value.status == 422 and 'not loaded' in e.value.details['output']
    assert not (fake_root / 'etc/bind/db.example.com.liteblox-new').exists()


def test_commit_rejects_change_after_stage(client, fake_root):
    base = client.get_zone('example.com')['sha256']
    staged = client.stage_zone('example.com', EXAMPLE.replace('192.0.2.1', '192.0.2.2'), base)
    (fake_root / 'etc/bind/db.example.com').write_text(EXAMPLE + '; hand edit\n')
    with pytest.raises(AgentError) as e:
        client.commit_zone('example.com', staged['stage_id'])
    assert e.value.status == 409
    assert (fake_root / 'etc/bind/db.example.com').read_text().endswith('; hand edit\n')


def test_commit_rolls_back_when_reload_fails(client, fake_root):
    base = client.get_zone('example.com')['sha256']
    staged = client.stage_zone('example.com', EXAMPLE.replace('2026010101', '2026010103'), base)
    (fake_root / 'rndc-fail').touch()
    with pytest.raises(AgentError) as e:
        client.commit_zone('example.com', staged['stage_id'])
    assert e.value.status == 500 and 'rolled back' in e.value.message
    assert (fake_root / 'etc/bind/db.example.com').read_text() == EXAMPLE


def test_abort_and_stale_stage_ids(client, fake_root):
    base = client.get_zone('example.com')['sha256']
    staged = client.stage_zone('example.com', EXAMPLE, base)
    client.abort_zone('example.com', staged['stage_id'])
    assert not (fake_root / 'etc/bind/db.example.com.liteblox-new').exists()
    with pytest.raises(AgentError) as e:
        client.commit_zone('example.com', staged['stage_id'])
    assert e.value.status == 404

    staged = client.stage_zone('example.com', EXAMPLE, base)
    with pytest.raises(AgentError) as e:       # a stage id only works for its own zone
        client.commit_zone('rel.example', staged['stage_id'])
    assert e.value.status == 404


# ── managed include ────────────────────────────────────────────────────────────

NEW_ZONE = '@ IN SOA ns1.new.example. root.new.example. 2026010101 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.53\n'


# ── generated config (/config/*) ───────────────────────────────────────────────

def fake_layout(root):
    bind = root / 'etc/bind'
    return Layout(named_conf=str(bind / 'named.conf'), config_dir=str(bind / 'liteblox'),
                  dyn_dir=str(root / 'var/lib/bind/liteblox/dyn'), sec_dir=str(root / 'var/lib/bind/liteblox/sec'),
                  pre_dir=str(bind / 'pre-liteblox'), directory=str(root / 'var/cache/bind'),
                  jnl_dir=str(root / 'var/lib/bind/liteblox/jnl'))


@pytest.fixture
def stock_root(fake_root):
    """The fake node as the bind9 package leaves it: options + empty local + distro zones."""
    bind = fake_root / 'etc/bind'
    (bind / 'named.conf').write_text(f'include "{bind}/named.conf.options";\n'
                                     f'include "{bind}/named.conf.local";\n'
                                     f'include "{bind}/named.conf.default-zones";\n')
    (bind / 'named.conf.options').write_text(f'options {{ directory "{fake_root}/var/cache/bind"; }};\n')
    (bind / 'named.conf.local').write_text('// Do any local configuration here\n')
    return fake_root


def generated(root, zones=(), **options):
    bind = root / 'etc/bind'
    return render(NodeConfig(options=NodeOptions(**options), zones=list(zones),
                             distro_includes=[str(bind / 'named.conf.default-zones')]), fake_layout(root))


def take_over(client, root, zones=(), zone_files=None):
    bind = root / 'etc/bind'
    staged = client.stage_config(generated(root, zones), zone_files, takeover=True,
                                 retire=[str(bind / 'named.conf.options'), str(bind / 'named.conf.local')])
    return client.commit_config(staged['stage_id'])


def test_status_v2_fields(client, stock_root):
    (stock_root / 'etc/bind/named.conf.options.dpkg-dist').write_text('new package version\n')
    s = client.status()
    assert s['client_address'] == '127.0.0.1'
    assert s['taken_over'] is False
    assert s['dpkg_leftovers'] == [str(stock_root / 'etc/bind/named.conf.options.dpkg-dist')]
    assert s['config_files']['zones.conf'] is None and s['config_files']['named.conf']


def test_config_secrets_only_on_request(client):
    assert 'c2VjcmV0' not in client.config()['checkconf']
    assert 'secret "c2VjcmV0"' in client.config(secrets=True)['checkconf']


def test_check_config_runs_named_checkconf_on_the_candidate(client, stock_root):
    before = (stock_root / 'etc/bind/named.conf').read_text()
    out = client.check_config(generated(stock_root, recursion=False))
    assert out['ok'] and 'recursion no;' in out['checkconf']
    assert (stock_root / 'etc/bind/named.conf').read_text() == before
    assert not (stock_root / 'etc/bind/liteblox').exists()
    with pytest.raises(AgentError) as e:
        client.check_config(generated(stock_root, extra='BROKEN yes;'))
    assert e.value.status == 422 and 'BROKEN' in e.value.details['output']
    assert [p.name for p in (stock_root / 'state').iterdir()] == ['backups']


def test_takeover_commit_and_rollback(client, stock_root):
    bind = stock_root / 'etc/bind'
    original = (bind / 'named.conf').read_text()
    result = take_over(client, stock_root, [ZoneDecl('new.example')], {'new.example': NEW_ZONE})

    pre = Path(result['preserved'])
    assert pre.parent == bind / 'pre-liteblox'
    assert sorted(p.name for p in pre.iterdir()) == ['named.conf', 'named.conf.local', 'named.conf.options']
    assert (pre / 'named.conf').read_text() == original
    assert not (bind / 'named.conf.options').exists() and not (bind / 'named.conf.local').exists()
    assert (bind / 'named.conf').read_text().startswith('// Generated by LiteBlox')
    assert (bind / 'liteblox/db.new.example').read_text() == NEW_ZONE
    assert oct((bind / 'liteblox/keys.conf').stat().st_mode & 0o777) == '0o640'
    assert 'reconfig' in rndc_log(stock_root)
    s = client.status()
    assert s['taken_over'] is True
    assert s['config_files'] == result['config_files'] and all(s['config_files'].values())
    assert client.get_zone('new.example')['content'] == NEW_ZONE

    rolled = client.rollback_config()
    assert rolled['takeover'] is True
    assert (bind / 'named.conf').read_text() == original
    assert (bind / 'named.conf.options').exists() and (bind / 'named.conf.local').exists()
    assert not (bind / 'liteblox/zones.conf').exists() and not (bind / 'liteblox/db.new.example').exists()
    assert not pre.exists()
    assert client.status()['taken_over'] is False
    with pytest.raises(AgentError) as e:
        client.rollback_config()
    assert e.value.status == 404


def test_partial_set_after_takeover(client, stock_root):
    take_over(client, stock_root)
    files = generated(stock_root, [ZoneDecl('new.example')])
    staged = client.stage_config({'zones.conf': files['zones.conf']}, {'new.example': NEW_ZONE})
    client.commit_config(staged['stage_id'])
    assert 'new.example' in {z['name'] for z in client.config()['zones']}
    # a declared zone's file only changes through /zones
    with pytest.raises(AgentError) as e:
        client.stage_config({'zones.conf': files['zones.conf']}, {'new.example': NEW_ZONE})
    assert e.value.status == 409
    # undo only the last change: the zone goes, the takeover stays
    client.rollback_config()
    assert 'new.example' not in {z['name'] for z in client.config()['zones']}
    assert client.status()['taken_over'] is True


def test_commit_rolls_back_when_reconfig_fails(client, stock_root):
    bind = stock_root / 'etc/bind'
    original = (bind / 'named.conf').read_text()
    (stock_root / 'rndc-fail').write_text('')
    with pytest.raises(AgentError) as e:
        take_over(client, stock_root)
    assert e.value.status == 500 and 'rolled back' in e.value.message
    assert (bind / 'named.conf').read_text() == original
    assert (bind / 'named.conf.options').exists()
    assert not (bind / 'liteblox/options.conf').exists()
    assert not list((bind / 'pre-liteblox').iterdir())
    (stock_root / 'rndc-fail').unlink()
    with pytest.raises(AgentError) as e:
        client.rollback_config()            # the failed commit left nothing to undo
    assert e.value.status == 404


def test_commit_rolls_back_when_checkconf_fails(client, stock_root):
    bind = stock_root / 'etc/bind'
    staged = client.stage_config(generated(stock_root), takeover=True)
    (bind / 'named.conf.default-zones').write_text('# BROKEN\n')       # not part of the set
    with pytest.raises(AgentError) as e:
        client.commit_config(staged['stage_id'])
    assert e.value.status == 422
    assert not (bind / 'named.conf').read_text().startswith('// Generated')
    assert 'reconfig' not in rndc_log(stock_root)


def test_commit_refuses_a_file_changed_after_stage(client, stock_root):
    staged = client.stage_config(generated(stock_root), takeover=True)
    (stock_root / 'etc/bind/named.conf').write_text('// edited by hand\n')
    with pytest.raises(AgentError) as e:
        client.commit_config(staged['stage_id'])
    assert e.value.status == 409
    assert (stock_root / 'etc/bind/named.conf').read_text() == '// edited by hand\n'
    assert not list((stock_root / 'etc/bind').glob('**/*' + agent_mod.STAGE_SUFFIX))


def test_config_stage_refusals(client, stock_root):
    bind = stock_root / 'etc/bind'
    files = generated(stock_root)

    def refused(status, *args, **kwargs):
        with pytest.raises(AgentError) as e:
            client.stage_config(*args, **kwargs)
        assert e.value.status == status, e.value.message
        return e.value.message
    assert 'not taken over' in refused(409, {'zones.conf': files['zones.conf']})
    assert 'unknown config file' in refused(400, {'../passwd': 'x'})
    assert 'options.conf rejected' in refused(422, dict(files, **{'options.conf': 'options { pid-file "/x"; };'}))
    refused(400, files, retire=['/etc/passwd'])
    refused(400, files, retire=[str(bind / 'named.conf.default-zones')])    # still included by the new set
    refused(400, files, retire=[str(bind / 'named.conf')])
    assert 'does not exist' in refused(400, generated(stock_root, [ZoneDecl('nofile.example')]))
    assert 'not a primary zone' in refused(400, files, {'other.example': NEW_ZONE})
    bad = generated(stock_root, [ZoneDecl('new.example')])
    assert 'named-checkzone' in refused(422, bad, {'new.example': NEW_ZONE + 'BADZONE\n'})
    assert not list(bind.glob('**/*' + agent_mod.STAGE_SUFFIX))
    client.abort_config(client.stage_config(files)['stage_id'])
    assert not list(bind.glob('**/*' + agent_mod.STAGE_SUFFIX))


def test_secondary_and_dynamic_dirs_are_created(client, stock_root):
    take_over(client, stock_root, [ZoneDecl('dyn.example', dynamic=True),
                                   ZoneDecl('sec.example', kind='secondary', primaries=['192.0.2.1'])],
              {'dyn.example': NEW_ZONE.replace('new.example', 'dyn.example')})
    dyn = stock_root / 'var/lib/bind/liteblox/dyn'
    assert (dyn / 'db.dyn.example').exists()
    assert dyn.stat().st_mode & 0o777 == 0o775
    assert (stock_root / 'var/lib/bind/liteblox/sec').is_dir()


def test_var_dirs_stay_writable_for_named_under_a_setgid_parent(client, stock_root):
    # bootstrap makes zone dirs g+s; dirs made under one inherit setgid with the agent's umask (2750),
    # and named couldn't create journals there
    var = stock_root / 'var/lib/bind'
    var.mkdir(parents=True, exist_ok=True)
    var.chmod(0o2775)
    take_over(client, stock_root, [ZoneDecl('dyn.example', dynamic=True)],
              {'dyn.example': NEW_ZONE.replace('new.example', 'dyn.example')})
    for d in (var / 'liteblox', var / 'liteblox/dyn'):
        assert d.stat().st_mode & 0o7777 == 0o775, oct(d.stat().st_mode)
    # one an older agent left behind is repaired at the next change
    (var / 'liteblox/dyn').chmod(0o2750)
    files = generated(stock_root, [ZoneDecl('dyn.example', dynamic=True)])
    client.commit_config(client.stage_config({'zones.conf': files['zones.conf']})['stage_id'])
    assert (var / 'liteblox/dyn').stat().st_mode & 0o7777 == 0o775


def test_switching_a_zone_to_dynamic_moves_its_file_and_drops_a_stale_journal(client, stock_root):
    take_over(client, stock_root, [ZoneDecl('new.example')], {'new.example': NEW_ZONE})
    dyn = stock_root / 'var/lib/bind/liteblox/dyn'
    dyn.mkdir(parents=True, exist_ok=True)
    (dyn / 'db.new.example.jnl').write_bytes(b'journal from an earlier dynamic spell')
    files = generated(stock_root, [ZoneDecl('new.example', dynamic=True, update_policy=['grant k zonesub ANY'])])
    staged = client.stage_config({'zones.conf': files['zones.conf']}, {'new.example': NEW_ZONE})
    client.commit_config(staged['stage_id'])
    assert (dyn / 'db.new.example').read_text() == NEW_ZONE and not (dyn / 'db.new.example.jnl').exists()
    # named owns the file now: neither /zones nor a config set may write it
    zone = client.get_zone('new.example')
    with pytest.raises(AgentError) as e:
        client.stage_zone('new.example', NEW_ZONE + '; x\n', zone['sha256'])
    assert e.value.status == 409 and 'is dynamic' in e.value.message
    with pytest.raises(AgentError) as e:
        client.stage_config({'zones.conf': files['zones.conf']}, {'new.example': NEW_ZONE})
    assert e.value.status == 409
    client.rollback_config()
    assert (dyn / 'db.new.example.jnl').read_bytes() == b'journal from an earlier dynamic spell'
    assert not (dyn / 'db.new.example').exists()
    assert client.get_zone('new.example')['content'] == NEW_ZONE


def test_switching_a_zone_off_dynamic_removes_named_s_file_and_journal(client, stock_root):
    dyn = stock_root / 'var/lib/bind/liteblox/dyn'
    take_over(client, stock_root, [ZoneDecl('new.example', dynamic=True, update_policy=['grant k zonesub ANY'])],
              {'new.example': NEW_ZONE})
    (dyn / 'db.new.example.jnl').write_bytes(b'named journal')
    files = generated(stock_root, [ZoneDecl('new.example')])
    staged = client.stage_config({'zones.conf': files['zones.conf']}, {'new.example': NEW_ZONE + '; static\n'})
    client.commit_config(staged['stage_id'])
    assert not (dyn / 'db.new.example').exists() and not (dyn / 'db.new.example.jnl').exists()
    assert client.get_zone('new.example')['content'] == NEW_ZONE + '; static\n'
    client.rollback_config()
    assert (dyn / 'db.new.example').read_text() == NEW_ZONE and (dyn / 'db.new.example.jnl').read_bytes() == b'named journal'


def test_freeze_holds_a_dynamic_zone_until_the_config_commit(client, stock_root):
    take_over(client, stock_root, [ZoneDecl('new.example', dynamic=True, update_policy=['grant k zonesub ANY'])],
              {'new.example': NEW_ZONE})
    with pytest.raises(AgentError) as e:
        client.thaw_zone('new.example')
    assert e.value.status == 404
    assert client.get_zone('new.example', sync=True)['content'] == NEW_ZONE
    assert 'sync new.example' in rndc_log(stock_root) and not any('freeze' in line for line in rndc_log(stock_root))
    client.get_zone('new.example', freeze=True)
    assert 'freeze new.example' in rndc_log(stock_root)
    files = generated(stock_root, [ZoneDecl('new.example', dynamic=True, update_policy=['grant k zonesub ANY'])])
    client.commit_config(client.stage_config({'zones.conf': files['zones.conf']})['stage_id'])
    assert rndc_log(stock_root)[-1] == 'thaw new.example'
    # an abort thaws too, and so does a thaw of its own
    client.get_zone('new.example', freeze=True)
    client.abort_config(client.stage_config({'zones.conf': files['zones.conf']})['stage_id'])
    assert rndc_log(stock_root)[-1] == 'thaw new.example'
    client.get_zone('new.example', freeze=True)
    assert client.thaw_zone('new.example') == {'thawed': 'new.example'}


def test_the_1_0_include_endpoints_are_gone(client):
    for action in ('stage', 'commit', 'abort'):
        with pytest.raises(AgentError) as e:
            client._request('POST', f'/managed/{action}', json={})
        assert e.value.status == 404


def test_static_primary_journals_go_under_the_journal_dir(client, stock_root):
    from liteblox.bindconf.model import ZoneDecl as Z
    layout = fake_layout(stock_root)
    zone = Z('new.example', ixfr=True)
    files = generated(stock_root, [zone])
    assert f'journal "{layout.jnl_dir}/db.new.example.jnl";' in files['zones.conf']
    take_over(client, stock_root, [zone], {'new.example': NEW_ZONE})
    jnl = stock_root / 'var/lib/bind/liteblox/jnl'
    assert jnl.is_dir() and jnl.stat().st_mode & 0o777 == 0o775
    bad = files['zones.conf'].replace(f'{layout.jnl_dir}/', f'{stock_root}/etc/bind/')
    with pytest.raises(AgentError) as e:
        client.check_config(dict(files, **{'zones.conf': bad}))
    assert e.value.status == 422 and 'journal must be directly inside' in e.value.message


# ── backup ─────────────────────────────────────────────────────────────────────

def _untar(data):
    tar = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
    manifest = json.load(tar.extractfile(f'{agent_mod.BACKUP_META}/manifest.json'))
    return tar.getnames(), manifest


def test_backup_contents(client, fake_root):
    data, manifest_hash = client.backup()
    names, manifest = _untar(data)
    bind, cache = fake_root / 'etc/bind', fake_root / 'var/cache/bind'
    assert str(bind / 'named.conf').lstrip('/') in names
    assert str(bind / 'rndc.key').lstrip('/') in names
    assert str(cache / 'db.rel').lstrip('/') in names            # zone file outside /etc/bind
    assert str(cache / 'sec.example.jnl').lstrip('/') not in names
    assert f'{agent_mod.BACKUP_META}/named-checkconf.txt' in names
    assert all(not n.startswith('liteblox/') for n in names)
    assert manifest['keys_included'] is True
    assert manifest['files'][str(bind / 'db.example.com')]['sha256'] == agent_mod.sha256(EXAMPLE.encode())
    assert manifest_hash

    again, again_hash = client.backup()
    assert again_hash == manifest_hash        # nothing changed: same manifest hash (dedup key)


def test_backup_keeps_owner_group_and_mode(client, fake_root):
    data, _ = client.backup()
    bind = fake_root / 'etc/bind'
    (bind / 'db.example.com').chmod(0o664)
    with tarfile.open(fileobj=io.BytesIO(client.backup()[0]), mode='r:gz') as tar:
        f = tar.getmember(str(bind / 'db.example.com').lstrip('/'))
        d = tar.getmember(str(bind).lstrip('/'))
    st = (bind / 'db.example.com').stat()
    assert (f.uid, f.gid, f.mode) == (st.st_uid, st.st_gid, 0o664) and f.uname
    assert d.isdir() and d.mode == bind.stat().st_mode & 0o7777


def test_backup_without_keys(client, fake_root):
    generated = fake_root / 'etc/bind/liteblox/keys.conf'
    generated.parent.mkdir(exist_ok=True)
    generated.write_text('key "dhcp" { algorithm hmac-sha256; secret "c2VjcmV0"; };\n')
    names, manifest = _untar(client.backup(include_keys=False)[0])
    for key in (fake_root / 'etc/bind/rndc.key', generated):
        assert str(key).lstrip('/') not in names
        assert manifest['skipped'][str(key)] == 'key excluded'
    assert str(generated).lstrip('/') in _untar(client.backup()[0])[0]


@pytest.mark.skipif(os.geteuid() == 0, reason='root can read anything')
def test_backup_records_unreadable_files(client, fake_root):
    secret = fake_root / 'etc/bind/secret.conf'
    secret.write_text('x')
    secret.chmod(0)
    names, manifest = _untar(client.backup()[0])
    assert str(secret) in manifest['skipped']


# ── who may connect ────────────────────────────────────────────────────────────

def test_client_from_another_ca_is_refused(server, tmp_path):
    stranger = PKI(tmp_path / 'other-pki').ensure()
    stranger.ca_cert_path.write_bytes(PKI(tmp_path / 'pki').ca_pem())   # trusts the server...
    with AgentClient('127.0.0.1', stranger, port=server.server_address[1]) as c:
        with pytest.raises(AgentError) as e:                           # ...but the server doesn't trust it
            c.status()
    assert e.value.status is None


def test_client_with_wrong_cn_is_refused(server, pki, tmp_path):
    key, cert = pki._issue('intruder', [], ExtendedKeyUsageOID.CLIENT_AUTH, 1)
    (tmp_path / 'i.key').write_bytes(key)
    (tmp_path / 'i.crt').write_bytes(cert)
    import ssl
    ctx = ssl.create_default_context(cafile=str(pki.ca_cert_path))
    ctx.load_cert_chain(str(tmp_path / 'i.crt'), str(tmp_path / 'i.key'))
    r = httpx.get(f'https://127.0.0.1:{server.server_address[1]}/status', verify=ctx)
    assert r.status_code == 403


def test_allowed_ips(server, client):
    server.agent.cfg['allowed_ips'] = ['192.0.2.10']
    with pytest.raises(AgentError) as e:
        client.status()
    assert e.value.status == 403
    server.agent.cfg['allowed_ips'] = ['127.0.0.1']
    assert client.status()['rndc_ok']


def test_agent_stays_python_3_9_compatible():
    import ast
    ast.parse((agent_dir() / 'liteblox_agent.py').read_text(), feature_version=(3, 9))


def test_config_says_where_keys_and_acls_are_declared(client, fake_root):
    bind = fake_root / 'etc/bind'
    (bind / 'named.conf.local').write_text((bind / 'named.conf.local').read_text() + 'acl lan { 10.0.0.0/8; };\n')
    declared = client.config()['declared']
    assert declared['key rndc-key'] == str(bind / 'rndc.key')
    assert declared['acl lan'] == str(bind / 'named.conf.local')
    assert agent_mod.validate_named_conf('include "/etc/bind/rndc.key";', agent_mod.DEFAULT_CONFIG)


def test_config_files_for_drift_with_secrets_masked(client, stock_root):
    take_over(client, stock_root, [ZoneDecl('new.example')], {'new.example': NEW_ZONE})
    keys = stock_root / 'etc/bind/liteblox/keys.conf'
    keys.write_text(keys.read_text() + 'key "x" { algorithm hmac-sha256; secret "c2VjcmV0"; };\n')
    assert 'files' not in client.config()
    files = client.config(files=True)['files']
    assert sorted(files) == ['acls.conf', 'keys.conf', 'named.conf', 'options.conf', 'top.conf', 'zones.conf']
    assert 'zone "new.example"' in files['zones.conf']
    assert 'secret "????????"' in files['keys.conf'] and 'c2VjcmV0' not in files['keys.conf']


def test_secondaries_check_their_primary_after_a_commit(client, stock_root):
    take_over(client, stock_root, [ZoneDecl('new.example'),
                                   ZoneDecl('sec.example', kind='secondary', primaries=['192.0.2.1'])],
              {'new.example': NEW_ZONE})
    log = rndc_log(stock_root)
    assert log.index('reconfig') < log.index('refresh sec.example')
    assert 'refresh new.example' not in log


# ── upgrades over mTLS (4.5) ───────────────────────────────────────────────────

def test_status_without_the_installer(client):
    s = client.status()
    assert s['install_rev'] == 0 and s['upgradable'] is False and s['last_upgrade'] is None
    with pytest.raises(AgentError) as e:
        client.upgrade_agent('4.5.0', '0' * 64, '# liteblox-agent\n')
    assert e.value.status == 409 and 'Repair' in e.value.message


@pytest.fixture
def upgradable(agent_config, monkeypatch):
    lib = Path(agent_config['agent_lib'])
    lib.mkdir()
    (lib / 'liteblox_agent_install.py').write_text('# the installer\n')
    (lib / 'VERSION').write_text('4.5.0\n')
    (lib / 'last-upgrade.json').write_text(json.dumps({'at': 1, 'result': 'running', 'detail': '',
                                                       'version': '4.5.0', 'sha256': 'ab' * 32}))
    agent_config['install_rev'] = 1
    restarts = threading.Event()
    monkeypatch.setattr(agent_mod.Agent, '_restart_for_upgrade', lambda self: restarts.set())
    return restarts


def test_status_with_the_installer(upgradable, client):
    s = client.status()
    assert s['install_rev'] == 1 and s['upgradable'] is True
    assert s['agent_version'] == '4.5.0'            # from VERSION, over config.json's
    assert s['last_upgrade']['result'] == 'running'


def test_upgrade_stages_and_restarts(upgradable, client, fake_root):
    import hashlib
    source = '#!/usr/bin/env python3\n# liteblox-agent\nprint("new")\n'
    digest = hashlib.sha256(source.encode()).hexdigest()
    assert client.upgrade_agent('4.6.0', digest, source) == {'staged': True, 'version': '4.6.0', 'sha256': digest}
    pending = fake_root / 'state' / 'pending'
    assert (pending / 'agent.py').read_text() == source
    assert json.loads((pending / 'manifest.json').read_text()) == {'version': '4.6.0', 'sha256': digest,
                                                                  'size': len(source)}
    assert oct((pending / 'agent.py').stat().st_mode & 0o777) == '0o600'
    assert sorted(p.name for p in pending.iterdir()) == ['agent.py', 'manifest.json']
    assert upgradable.wait(5)


@pytest.mark.parametrize('body, status', [
    ({'version': '4.6.0', 'sha256': '0' * 64, 'source': '# liteblox-agent\n'}, 400),     # not its hash
    ({'version': '4.6.0; rm', 'sha256': '0' * 64, 'source': 'x'}, 400),
    ({'version': '4.6.0', 'sha256': 'XYZ', 'source': 'x'}, 400),
    ({'version': '4.6.0', 'sha256': '0' * 64, 'source': 5}, 400),
    ({'version': '4.6.0', 'sha256': '0' * 64, 'source': '#' * (2 * 1024 * 1024 + 1)}, 413),
])
def test_upgrade_refusals(upgradable, client, fake_root, body, status):
    with pytest.raises(AgentError) as e:
        client._request('POST', '/agent/upgrade', json=body)
    assert e.value.status == status
    assert not (fake_root / 'state' / 'pending').exists() and not upgradable.is_set()


def test_no_upgrade_while_a_change_is_staged(upgradable, server, client):
    import time
    server.agent.stages['x'] = {'created': time.time()}
    with pytest.raises(AgentError) as e:
        client.upgrade_agent('4.6.0', '0' * 64, '')
    assert e.value.status in (400, 409)
    source = '# liteblox-agent\n'
    import hashlib
    with pytest.raises(AgentError) as e:
        client.upgrade_agent('4.6.0', hashlib.sha256(source.encode()).hexdigest(), source)
    assert e.value.status == 409 and 'staged' in e.value.message


def test_started_ok_names_the_running_agent(server, fake_root):
    server.agent.mark_started()
    assert (fake_root / 'state' / 'started-ok').read_text().strip() == agent_sha256()
