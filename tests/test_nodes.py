import json
import re
from pathlib import Path

import pytest

from liteblox import db, jobs
from liteblox.dns.repo import Repo
from liteblox.nodes import bootstrap as bootstrap_mod
from liteblox.nodes import service, ssh
from liteblox.pki import PKI

from conftest import csrf_from

ZONE = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()
HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
FP = ssh.fingerprint(HOST_KEY.split()[1])


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def token(client, path='/'):
    return csrf_from(client.get(path).text)


@pytest.fixture
def fake_hostkey(monkeypatch):
    seen = {}

    def fetch(host, port=22, timeout=10):
        seen['host'] = (host, port)
        return HOST_KEY, seen.get('fp', FP)
    monkeypatch.setattr(ssh, 'fetch_host_key', fetch)
    return seen


def add_node(conn, name='ns1', host='192.0.2.53'):
    return service.add_node(conn, name, host, 22, 8530, HOST_KEY, FP)


# ── add node / host key pinning ────────────────────────────────────────────────

def test_add_node_pins_confirmed_key(admin, fake_hostkey, conn):
    t = token(admin, '/nodes/new')
    r = admin.post('/nodes/new', data={'name': 'NS1', 'host': '192.0.2.53', 'ssh_port': 22,
                                        'agent_port': 8530, 'csrf_token': t})
    assert r.status_code == 200 and FP in r.text
    r = admin.post('/nodes/confirm', data={'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22,
                                            'agent_port': 8530, 'fingerprint': FP, 'csrf_token': t},
                   follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/nodes/1/bootstrap'
    node = service.get_node(conn, 'ns1')
    assert (node['host_key'], node['host_key_fp'], node['status']) == (HOST_KEY, FP, 'new')


def test_confirm_refuses_a_changed_key(admin, fake_hostkey, conn):
    t = token(admin, '/nodes/new')
    fake_hostkey['fp'] = 'SHA256:somethingelse'
    r = admin.post('/nodes/confirm', data={'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22,
                                            'agent_port': 8530, 'fingerprint': FP, 'csrf_token': t})
    assert r.status_code == 400 and 'host key changed' in r.text
    assert service.list_nodes(conn) == []


def test_add_node_validation(admin, fake_hostkey, conn):
    add_node(conn)
    t = token(admin, '/nodes/new')
    r = admin.post('/nodes/new', data={'name': 'ns1', 'host': 'x', 'csrf_token': t})
    assert r.status_code == 400 and 'already exists' in r.text
    r = admin.post('/nodes/new', data={'name': 'bad name!', 'host': 'x', 'csrf_token': t})
    assert r.status_code == 400 and 'lowercase' in r.text


def test_readonly_cannot_add_or_bootstrap(client, make_user, login, conn):
    login(*make_user('viewer', 'viewer-pass', 'readonly'))
    add_node(conn)
    assert client.get('/nodes').status_code == 200
    t = token(client, '/nodes')
    assert client.get('/nodes/new').status_code == 403
    assert client.post('/nodes/1/bootstrap', data={'ssh_user': 'x', 'ssh_password': 'y',
                                                   'csrf_token': t}).status_code == 403


# ── change address / re-pin, remove ───────────────────────────────────────────

def set_up(conn, node_id):
    with conn:
        conn.execute("UPDATE nodes SET status = 'ready', agent_version = '0.1.0', cert_fingerprint = 'ab:cd', "
                     "cert_not_after = '2030-01-01' WHERE id = ?", (node_id,))


def test_repin_a_changed_host_key(admin, fake_hostkey, conn):
    node_id = add_node(conn)
    set_up(conn, node_id)
    fake_hostkey['fp'] = 'SHA256:replacement'
    t = token(admin, f'/nodes/{node_id}/edit')
    r = admin.post(f'/nodes/{node_id}/edit', data={'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
                                                   'csrf_token': t})
    assert r.status_code == 200 and 'SHA256:replacement' in r.text and 'not</strong> the key pinned' in r.text
    assert 'Repair / upgrade agent' not in r.text      # same address: the certificate still fits
    r = admin.post(f'/nodes/{node_id}/edit/confirm', data={
        'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530, 'fingerprint': 'SHA256:replacement',
        'csrf_token': t}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == f'/nodes/{node_id}'
    node = service.get_node(conn, node_id)
    assert node['host_key_fp'] == 'SHA256:replacement' and node['cert_fingerprint'] == 'ab:cd'
    assert not service.needs_repair(node)
    detail = conn.execute("SELECT detail FROM audit WHERE action = 'node_update'").fetchone()[0]
    assert detail == f'ns1: host key {FP} → SHA256:replacement'


def test_new_address_needs_repair(admin, fake_hostkey, conn):
    node_id = add_node(conn)
    set_up(conn, node_id)
    t = token(admin, f'/nodes/{node_id}/edit')
    r = admin.post(f'/nodes/{node_id}/edit', data={'host': ' 192.0.2.99 ', 'ssh_port': 2222, 'agent_port': 8530,
                                                   'csrf_token': t})
    assert fake_hostkey['host'] == ('192.0.2.99', 2222)
    assert 'already pinned' in r.text and 'name the old address' in r.text
    admin.post(f'/nodes/{node_id}/edit/confirm', data={'host': '192.0.2.99', 'ssh_port': 2222, 'agent_port': 8530,
                                                       'fingerprint': FP, 'csrf_token': t})
    node = service.get_node(conn, node_id)
    assert (node['host'], node['ssh_port'], node['cert_fingerprint']) == ('192.0.2.99', 2222, None)
    assert service.needs_repair(node)
    assert 'certificate no longer matches' in admin.get(f'/nodes/{node_id}').text


def test_edit_confirm_refuses_a_changed_key(admin, fake_hostkey, conn):
    node_id = add_node(conn)
    t = token(admin, f'/nodes/{node_id}/edit')
    fake_hostkey['fp'] = 'SHA256:somethingelse'
    r = admin.post(f'/nodes/{node_id}/edit/confirm', data={'host': '192.0.2.99', 'ssh_port': 22, 'agent_port': 8530,
                                                           'fingerprint': FP, 'csrf_token': t})
    assert r.status_code == 400 and 'host key changed' in r.text
    assert service.get_node(conn, node_id)['host'] == '192.0.2.53'


def test_remove_node(admin, conn, settings):
    ns1, ns2 = add_node(conn), add_node(conn, 'ns2', '192.0.2.54')
    with conn:
        conn.execute('UPDATE nodes SET managed = 1 WHERE id = ?', (ns1,))
        shared = conn.execute("INSERT INTO zones (name, repo_file) VALUES ('example.com', 'x')").lastrowid
        alone = conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES ('example.net', 'managed', 'y')").lastrowid
        for zone_id, node_id in ((shared, ns1), (shared, ns2), (alone, ns1)):
            conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (?, ?, 'f')", (zone_id, node_id))
        job_id = conn.execute("INSERT INTO jobs (kind, node_id, status) VALUES ('bootstrap', ?, 'running')",
                              (ns1,)).lastrowid
        conn.execute("INSERT INTO backups (node_id, kind, status, file) VALUES (?, 'manual', 'ok', 'ns1/a.tgz')", (ns1,))
    archive = settings.backups_dir / 'ns1' / 'a.tgz'
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b'tgz')

    page = admin.get(f'/nodes/{ns1}/remove').text
    assert 'no other node serves it' in page and 'stay declared on the server' in page
    t = csrf_from(page)
    r = admin.post(f'/nodes/{ns1}/remove', data={'csrf_token': t})
    assert r.status_code == 409 and 'still running' in r.text
    with conn:
        conn.execute("UPDATE jobs SET status = 'ok' WHERE id = ?", (job_id,))
    r = admin.post(f'/nodes/{ns1}/remove', data={'csrf_token': t}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/nodes'
    assert [n['name'] for n in service.list_nodes(conn)] == ['ns2']
    assert [tuple(r) for r in conn.execute('SELECT zone_id, node_id FROM zone_nodes')] == [(shared, ns2)]
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 2
    assert conn.execute('SELECT node_id FROM jobs WHERE id = ?', (job_id,)).fetchone()[0] is None
    assert archive.exists()
    assert conn.execute("SELECT detail FROM audit WHERE action = 'node_remove'").fetchone()[0] == 'ns1 192.0.2.53'


def test_readonly_cannot_edit_or_remove(client, make_user, login, conn):
    login(*make_user('viewer', 'viewer-pass', 'readonly'))
    node_id = add_node(conn)
    t = token(client, '/nodes')
    assert client.get(f'/nodes/{node_id}/edit').status_code == 403
    assert client.post(f'/nodes/{node_id}/remove', data={'csrf_token': t}).status_code == 403
    assert 'Remove node' not in client.get(f'/nodes/{node_id}').text


def test_cli_node_edit_and_remove(conn, settings, fake_hostkey, monkeypatch, capsys):
    from liteblox import cli
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    node_id = add_node(conn)
    set_up(conn, node_id)
    assert cli.main(['node', 'edit', 'ns1', '--yes']) in (0, None)
    assert 'Nothing changed' in capsys.readouterr().out
    assert cli.main(['node', 'edit', 'ns1', '--host', '192.0.2.99', '--yes']) in (0, None)
    out = capsys.readouterr().out
    assert 'address 192.0.2.53 → 192.0.2.99' in out and 'node bootstrap ns1' in out
    assert cli.main(['node', 'remove', 'ns1', '--yes']) in (0, None)
    assert service.list_nodes(conn) == []


# ── bootstrap ──────────────────────────────────────────────────────────────────

def _boxes(page):
    """{name: ticked} for the bootstrap form's checkboxes."""
    import re
    return {m.group(1): 'checked' in m.group(0)
            for m in re.finditer(r'<input type="checkbox" name="(\w+)"[^>]*>', page)}


def test_bootstrap_form_ticks_from_the_nodes_state(admin, conn):
    add_node(conn)
    fresh = admin.get('/nodes/1/bootstrap').text
    assert _boxes(fresh) == {'bind': True, 'takeover': True, 'fix_permissions': True, 'install_bind': True,
                             'dhcp': False, 'radvd': False, 'ntp': False}
    assert 'Run setup' in fresh and 'install the agent' in fresh and 'Set up Kea DHCP' in fresh
    assert _boxes(admin.get('/nodes/1/bootstrap?dhcp=1&ntp=1').text)['dhcp'] is True
    assert _boxes(admin.get('/nodes/1/bootstrap?radvd=1').text)['radvd'] is True

    # set up, managed, with DHCP and time sync: a repair keeps them; the takeover box gives way to a line
    with conn:
        conn.execute("UPDATE nodes SET status = 'ready', agent_version = '3.3.0', managed = 1, dhcp = 1, ntp = 1, "
                     "radvd = 1 WHERE id = 1")
    page = admin.get('/nodes/1/bootstrap').text
    assert _boxes(page) == {'fix_permissions': True, 'install_bind': True, 'dhcp': True, 'radvd': True, 'ntp': True}
    assert 'Keep router advertisements (radvd, set up)' in page
    assert 'already manages this node' in page and 'Keep DHCP (set up)' in page and 'Leave Kea alone' in page
    assert 'Keep time sync (set up)' in page and 'Leave chrony alone' in page
    assert 'upgrade the agent to' in page and '(from 3.3.0)' in page and 'Repair / upgrade</button>' in page

    # set up but kept its own BIND config: the takeover box is there, unticked
    with conn:
        conn.execute('UPDATE nodes SET managed = 0, dhcp = 0, ntp = 0, radvd = 0 WHERE id = 1')
    page = admin.get('/nodes/1/bootstrap').text
    assert _boxes(page) == {'bind': True, 'takeover': False, 'fix_permissions': True, 'install_bind': True,
                            'dhcp': False, 'radvd': False, 'ntp': False}
    assert 'Leave the BIND config as it is' in page and 'No DHCP on this node' in page


def test_bootstrap_route_starts_job_without_storing_secrets(admin, conn, monkeypatch):
    add_node(conn)
    captured = {}

    def fake_start(settings, node_id, creds, options, username, background=True, echo=None):
        captured.update(creds=creds, options=options, username=username)
        return jobs.start(settings.db_path, 'bootstrap', lambda log: log(f'hello {creds!r}'),
                          node_id=node_id, username=username, background=False)
    monkeypatch.setattr(service, 'start_bootstrap', fake_start)

    t = token(admin, '/nodes/1/bootstrap')
    r = admin.post('/nodes/1/bootstrap', data={
        'ssh_user': 'claude', 'ssh_password': 's3cret-pass', 'fix_permissions': 'true',
        'takeover': 'true', 'csrf_token': t}, follow_redirects=False)
    assert r.headers['location'] == '/jobs/1'
    assert captured['creds'].password == 's3cret-pass' and captured['creds'].sudo_password is None
    assert captured['options'] == bootstrap_mod.Options(install_bind=False, fix_permissions=True, takeover=True)

    page = admin.get('/jobs/1')
    assert 'claude' in page.text and 's3cret-pass' not in page.text
    log = admin.get('/jobs/1/log')
    assert log.status_code == 286        # finished: htmx stops polling
    dump = '\n'.join(str(tuple(row)) for row in conn.execute('SELECT * FROM jobs'))
    assert 's3cret-pass' not in dump


class FakeRemote:
    """Records commands; answers the few whose output bootstrap reads."""

    def __init__(self, host, port, host_key, username, password=None, sudo_password=None,
                 use_local_keys=False):
        self.commands = []
        FakeRemote.last = self
        self.include_present = False
        self.kea = False            # Kea installed and set up by LiteBlox (test -f / test -x answer yes)
        self.uploads = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def run_bytes(self, cmd, sudo=False, check=True, label=None, timeout=600):
        self.commands.append(('sudo ' if sudo else '') + cmd)
        if cmd.startswith('tar czf'):
            return 0, b'fake-tgz', ''
        return 0, b'', ''

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        self.commands.append(('sudo ' if sudo else '') + cmd)
        if 'os-release' in cmd:
            return 0, 'Debian GNU/Linux 13 (trixie)'
        if cmd.startswith('python3'):
            return 0, '3.13.5'
        if cmd == '/usr/sbin/named -v':
            return 0, 'BIND 9.20.30'
        if cmd == '/usr/bin/named-checkconf -p':
            return 0, ('options { directory "/var/cache/bind"; };\n'
                       'zone "example.com" { type master; file "/etc/bind/db.example.com"; };\n'
                       'zone "rel.example" { type master; file "db.rel"; };\n'
                       'zone "localhost" { type master; file "/etc/bind/db.local"; };\n')
        if cmd.startswith('grep -qs'):
            return (0 if self.include_present else 1), ''
        if cmd.startswith('test '):
            return (0 if self.kea else 1), ''
        if cmd.startswith('ls -d /usr/lib/*/kea/hooks'):
            return 0, '/usr/lib/aarch64-linux-gnu/kea/hooks'
        if cmd == 'systemctl is-active kea-dhcp4-server kea-dhcp-ddns-server':
            return 0, 'active\nactive'
        if cmd.startswith('mktemp'):
            return 0, '/tmp/liteblox.abc'
        return 0, ''

    def upload(self, files):
        self.uploaded = files
        self.uploads.append(files)
        return '/tmp/liteblox.abc'


class FakeAgent:
    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def status(self):
        return {'agent_version': '0.1.0', 'agent_sha256': 'x', 'named_version': 'BIND 9.20.30',
                'rndc_ok': True, 'checkconf_ok': True, 'zones_writable': {'example.com': True}}


def test_bootstrap_command_sequence(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', lambda s: None)
    pki = PKI(tmp_path / 'pki').ensure()
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    lines = []
    creds = bootstrap_mod.Credentials('claude', password='pw-not-in-log')
    status = bootstrap_mod.bootstrap(node, creds, bootstrap_mod.Options(), pki,
                                     tmp_path / 'backups', '0.1.0', lines.append, connect=FakeRemote)
    cmds = FakeRemote.last.commands
    joined = '\n'.join(cmds)

    assert status['rndc_ok']
    assert (tmp_path / 'backups/ns1').glob('ns1-*-prebootstrap.tgz')
    assert 'sudo chgrp bind /etc/bind && chmod g+ws /etc/bind' in cmds
    assert 'sudo chgrp bind /var/cache/bind && chmod g+ws /var/cache/bind' in cmds      # relative file's dir
    assert 'sudo chgrp bind /etc/bind/db.example.com && chmod g+rw /etc/bind/db.example.com' in cmds
    assert 'db.local' not in joined                                                    # built-in zone untouched
    assert 'named.conf.liteblox' not in joined and 'named.conf.local' not in joined     # takeover does the rest
    assert 'systemctl restart liteblox-agent' in joined
    assert joined.index('tar czf') < joined.index('chmod')                             # snapshot before changes

    up = FakeRemote.last.uploaded
    assert set(up) == {'liteblox_agent.py', 'liteblox_agent_install.py', 'VERSION', 'liteblox-agent.service',
                       'config.json', 'agent.crt', 'agent.key', 'ca.crt'}
    assert re.search(r'^ReadWritePaths=/etc/bind /var/lib/bind /var/cache/bind$', up['liteblox-agent.service'].decode(), re.M)
    assert b'"version": "0.1.0"' in up['config.json'] and up['VERSION'] == b'0.1.0\n'
    assert json.loads(up['config.json'])['install_rev'] == bootstrap_mod.INSTALL_REV
    # the root installer runs before the sandboxed agent, from where Repair put it (root-owned)
    assert re.search(r'^ExecStartPre=\+/usr/bin/python3 -I /usr/local/lib/liteblox-agent/liteblox_agent_install.py$',
                     up['liteblox-agent.service'].decode(), re.M)
    assert 'install -m 0644 -o root -g root /tmp/' in joined and '/usr/local/lib/liteblox-agent/liteblox_agent_install.py' in joined
    assert 'rm -rf /var/lib/liteblox-agent/pending' in joined       # nothing half-staged survives a Repair
    assert node['cert_fingerprint'] and node['cert_not_after']
    assert 'pw-not-in-log' not in '\n'.join(lines) and 'pw-not-in-log' not in repr(creds)


def test_bootstrap_sets_up_kea_masked_and_serving_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', lambda s: None)
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    lines = []
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(dhcp=True),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', lines.append,
                            connect=FakeRemote)
    joined = '\n'.join(FakeRemote.last.commands)
    # masked before the packages go in, unmasked only after LiteBlox's config is written and checked
    assert joined.index('systemctl mask kea-dhcp4-server') < joined.index('install -y kea-dhcp4-server')
    assert joined.index('install -m 0640 -o liteblox-agent -g _kea') < joined.index('-t /etc/kea/kea-dhcp4.conf') \
        < joined.index('systemctl unmask')
    assert 'usermod -aG _kea liteblox-agent && chgrp _kea /etc/kea && chmod 2770 /etc/kea' in joined
    # kept by dpkg across kea-common upgrades (its postinst's statoverride says 0750)
    assert 'dpkg-statoverride --add $(stat -c "%U %G" /etc/kea) 2770 /etc/kea' in joined
    kea_files, agent_files = FakeRemote.last.uploads
    conf = json.loads(kea_files['kea-dhcp4.conf'])['Dhcp4']
    assert conf['interfaces-config']['interfaces'] == []                    # serves nothing
    assert conf['hooks-libraries'] == [{'library': '/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so'}]
    assert b'SocketGroup=liteblox-agent' in kea_files['liteblox-kea4-ctrl.socket']
    assert b'User=_kea' in kea_files['liteblox-kea-ddns-ctrl.service']
    unit = agent_files['liteblox-agent.service'].decode()
    assert re.search(r'^SupplementaryGroups=bind _kea$', unit, re.M)
    assert re.search(r'^ReadWritePaths=.* /etc/kea$', unit, re.M)
    assert node['dhcp_setup']['dhcp'] == 1 and node['dhcp_setup']['kea_hooks_dir'].startswith('/usr/lib/aarch64')
    assert json.loads(node['dhcp_setup']['dhcp_files']).keys() == {'kea-dhcp4.conf', 'kea-dhcp6.conf', 'kea-dhcp-ddns.conf'}


def test_a_repair_keeps_the_agents_access_to_kea(tmp_path, monkeypatch):
    class KeaRemote(FakeRemote):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.kea = True
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', lambda s: None)
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', print, connect=KeaRemote)
    joined = '\n'.join(KeaRemote.last.commands)
    assert 'install -y kea' not in joined and 'dhcp_setup' not in node

    # set up again with LiteBlox's config already there: it's kept (the check reads /etc/kea as root)
    class KeptRemote(KeaRemote):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.include_present = True
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(dhcp=True),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', print, connect=KeptRemote)
    joined = '\n'.join(KeptRemote.last.commands)
    assert "sudo grep -qs '\"generated-by\": \"LiteBlox\"' /etc/kea/kea-dhcp4.conf" in joined
    assert 'kea-dhcp4.conf' not in KeptRemote.last.uploads[0] and 'pre-liteblox' not in joined
    assert 'dhcp_files' not in node['dhcp_setup']
    assert 'SupplementaryGroups=bind _kea' in KeaRemote.last.uploaded['liteblox-agent.service'].decode()


def test_bootstrap_requires_install_option_when_bind_missing(tmp_path):
    class NoBind(FakeRemote):
        def run(self, cmd, **kw):
            if cmd == '/usr/sbin/named -v':
                return 127, 'not found'
            return super().run(cmd, **kw)
    node = {'name': 'ns2', 'host': '192.0.2.54', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    with pytest.raises(bootstrap_mod.BootstrapError, match='Install BIND'):
        bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('u', 'p'), bootstrap_mod.Options(),
                                PKI(tmp_path).ensure(), tmp_path, '0.1.0', lambda l: None, connect=NoBind)


def test_failed_job_is_recorded(app, settings):
    def boom(log):
        log('step one')
        raise RuntimeError('it broke')
    job_id = jobs.start(settings.db_path, 'test', boom, background=False)
    conn = db.connect(settings.db_path)
    job = jobs.get(conn, job_id)
    assert job['status'] == 'failed' and 'step one' in job['log'] and 'ERROR: it broke' in job['log']


# ── import ─────────────────────────────────────────────────────────────────────

class ImportAgent:
    zones = {}
    checkconf = ''

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        pass

    def config(self):
        return {'zones': [{'name': n, 'file': f'/etc/bind/db.{n}', 'type': 'primary', 'view': None,
                           'builtin': False, 'managed': False} for n in self.zones],
                'checkconf': self.checkconf, 'managed_include': None}

    def get_zone(self, name):
        from liteblox.nodes import agent_module
        content = self.zones[name]
        return {'name': name, 'content': content, 'sha256': agent_module().sha256(content.encode())}


@pytest.fixture
def import_agent(monkeypatch):
    monkeypatch.setattr(service, 'agent_client', lambda settings, node, timeout=10.0: ImportAgent())
    ImportAgent.zones = {'example.com': ZONE}
    return ImportAgent


def test_node_config_view_masks_key_secrets(admin, conn, import_agent):
    # agents before 1.0.1 print the config unmasked; the page must never show a secret
    add_node(conn, 'ns1')
    import_agent.checkconf = 'key "ddns" {\n\talgorithm "hmac-sha256";\n\tsecret "c2VjcmV0";\n};\n'
    r = admin.get('/nodes/1/zones')
    assert 'key &#34;ddns&#34;' in r.text or 'key "ddns"' in r.text
    assert 'c2VjcmV0' not in r.text and 'secret &#34;????????&#34;' in r.text


def test_node_zone_list_is_read_only(admin, conn, import_agent):
    add_node(conn, 'ns1')
    page = admin.get('/nodes/1/zones').text
    assert 'example.com' in page and 'not in LiteBlox' in page and 'Take over' in page
    assert 'name="zones"' not in page and admin.post('/nodes/1/import', data={}).status_code in (403, 404, 405)


def test_dns_address(admin, conn):
    add_node(conn, 'ns1', 'ns1.example.lab')
    page = admin.get('/nodes/1').text
    assert 'unknown' in page
    t = csrf_from(page)
    r = admin.post('/nodes/1/dns-address', data={'dns_address': 'not-an-ip', 'csrf_token': t}, follow_redirects=False)
    assert 'error=' in r.headers['location'] and service.get_node(conn, 1)['dns_address'] is None
    admin.post('/nodes/1/dns-address', data={'dns_address': ' 192.0.2.53 ', 'csrf_token': t})
    assert service.get_node(conn, 1)['dns_address'] == '192.0.2.53'
    assert '<code>192.0.2.53</code>' in admin.get('/nodes/1').text


def test_unit_text_sets_read_write_paths():
    text = bootstrap_mod.unit_text({'/etc/bind', '/srv/zones'})
    assert 'ReadWritePaths=/etc/bind /var/lib/bind /srv/zones\n' in text
    text = bootstrap_mod.unit_text({'/var/lib/bind', '/var/lib/bind/liteblox/dyn'})
    assert 'ReadWritePaths=/etc/bind /var/lib/bind\n' in text


def test_status_check_updates_the_header_pill(admin, conn, monkeypatch):
    from liteblox.nodes.client import AgentError
    node_id = add_node(conn)
    set_up(conn, node_id)
    assert 'id="node-status-pill" class="pill ready" title="agent set up"' in admin.get(f'/nodes/{node_id}').text

    class Down:
        def __enter__(self):
            raise AgentError(None, 'cannot reach agent at https://192.0.2.53:8530: refused')

        def __exit__(self, *exc):
            pass
    monkeypatch.setattr(service, 'agent_client', lambda settings, node, timeout=10.0: Down())
    r = admin.get(f'/nodes/{node_id}/status').text
    assert 'cannot reach agent' in r
    assert ('<span id="node-status-pill" class="pill error" title="cannot reach agent at https://192.0.2.53:8530: refused" '
            'hx-swap-oob="true">error</span>') in r
    # the same reason shows on the Nodes list and the dashboard
    for page in ('/nodes', '/'):
        assert 'class="pill error" title="cannot reach agent at https://192.0.2.53:8530: refused"' in admin.get(page).text


class LockedRemote(FakeRemote):
    """apt-get finds another apt run holding its lock the first `busy` times."""
    busy = 2

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        if 'apt-get' in cmd and LockedRemote.busy:
            LockedRemote.busy -= 1
            self.commands.append(('sudo ' if sudo else '') + cmd)
            raise bootstrap_mod.RemoteError(label, 100, 'E: Could not get lock /var/lib/dpkg/lock-frontend. '
                                                        'It is held by process 1299 (apt-get)')
        return super().run(cmd, sudo, check, label, timeout)


def test_setup_waits_for_another_apt_run(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    slept = []
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', slept.append)
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    lines = []
    LockedRemote.busy = 2
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(dhcp=True),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', lines.append,
                            connect=LockedRemote)
    apt = [c for c in LockedRemote.last.commands if 'install -y kea' in c]
    assert len(apt) == 3 and all('-o DPkg::Lock::Timeout=300' in c for c in apt)
    assert sum('holds its lock' in line for line in lines) == 1 and node['dhcp_setup']['dhcp'] == 1

    LockedRemote.busy = 10 ** 6         # never lets go: gives up after APT_LOCK_WAIT
    with pytest.raises(bootstrap_mod.RemoteError, match='Could not get lock'):
        bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'),
                                bootstrap_mod.Options(dhcp=True), PKI(tmp_path / 'pki').ensure(),
                                tmp_path / 'backups', '0.1.0', print, connect=LockedRemote)


class NoKeaRemote(FakeRemote):
    """A node whose package sources don't have Kea (Ubuntu 22.04 without universe), with an old Kea once there."""
    message = "E: Unable to locate package kea-dhcp4-server\nE: Package 'kea-dhcp-ddns-server' has no installation candidate"

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        if 'install -y kea' in cmd and NoKeaRemote.message:
            self.commands.append(('sudo ' if sudo else '') + cmd)
            raise bootstrap_mod.RemoteError(label, 100, NoKeaRemote.message)
        if cmd == '/usr/sbin/kea-dhcp4 -v':
            return 0, '2.0.2'
        return super().run(cmd, sudo, check, label, timeout)


def test_a_package_missing_from_the_sources_is_named(tmp_path, monkeypatch):
    assert bootstrap_mod.missing_packages(NoKeaRemote.message) == ['kea-dhcp-ddns-server', 'kea-dhcp4-server']
    assert bootstrap_mod.missing_packages('E: Could not get lock /var/lib/dpkg/lock-frontend') == []
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    node = {'name': 'ns1', 'host': '192.0.2.53', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    args = (bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(dhcp=True),
            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0')
    with pytest.raises(bootstrap_mod.BootstrapError, match=r"kea-dhcp-ddns-server, kea-dhcp4-server are not in this "
                                                           r"node's package sources .* universe has Kea"):
        bootstrap_mod.bootstrap(node, *args, print, connect=NoKeaRemote)
    monkeypatch.setattr(NoKeaRemote, 'message', '')         # Kea is there now, but old
    lines = []
    bootstrap_mod.bootstrap(node, *args, lines.append, connect=NoKeaRemote)
    assert any('Kea 2.0.2 is older than LiteBlox is tested with' in line for line in lines)
    assert not bootstrap_mod.kea_too_old('2.4.1') and not bootstrap_mod.kea_too_old('2.6.3')
    assert bootstrap_mod.kea_too_old('2.2.0') and not bootstrap_mod.kea_too_old('')


class StaleKeaRemote(FakeRemote):
    """An earlier run left LiteBlox's Kea config, which this Kea rejects until a fresh one is written."""

    def run(self, cmd, sudo=False, check=True, label=None, timeout=600):
        if cmd.startswith('grep -qs') and 'kea' in cmd:
            self.commands.append(cmd)
            return 0, ''
        if 'install kea config' == label and '/etc/kea/kea-dhcp4.conf' in cmd:
            self.fresh = True
        if cmd.startswith('runuser') and ' -t ' in cmd and not getattr(self, 'fresh', False):
            self.commands.append(cmd)
            return 1, 'got unexpected keyword "output-options"'
        return super().run(cmd, sudo, check, label, timeout)


def test_a_kept_kea_config_this_kea_rejects_is_written_again(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', FakeAgent)
    node = {'name': 'ns2', 'host': '192.0.2.54', 'ssh_port': 22, 'agent_port': 8530,
            'host_key': HOST_KEY, 'host_key_fp': FP}
    lines = []
    bootstrap_mod.bootstrap(node, bootstrap_mod.Credentials('claude', password='pw'), bootstrap_mod.Options(dhcp=True),
                            PKI(tmp_path / 'pki').ensure(), tmp_path / 'backups', '0.1.0', lines.append,
                            connect=StaleKeaRemote)
    assert any("doesn't pass this Kea's check: writing a fresh one" in line for line in lines)
    assert any('kea-dhcp4.conf' in u for u in StaleKeaRemote.last.uploads)


# ── the agent check at the end of bootstrap ─────────────────────────────────────

class _Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, s):
        self.now += s


def _slow_agent(monkeypatch, answers_after):
    """An agent that refuses connections until answers_after seconds have passed (a Pi after its apt run)."""
    clock = _Clock()
    monkeypatch.setattr(bootstrap_mod.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(bootstrap_mod.time, 'sleep', clock.sleep)

    class Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            if clock.now < answers_after:
                raise bootstrap_mod.AgentError(None, 'cannot reach agent: [Errno 111] Connection refused')
            return self

        def __exit__(self, *a):
            return False

        def status(self):
            return {'bind': False, 'agent_version': '4.7.1'}
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', Client)
    return clock


def test_bootstrap_waits_for_a_slow_agent(monkeypatch):
    _slow_agent(monkeypatch, answers_after=15)
    lines = []
    node = {'host': '192.0.2.9', 'agent_port': 8530}
    bootstrap_mod._verify(node, None, lines.append)
    assert any('waiting up to 90 s' in line for line in lines)


def test_bootstrap_gives_up_on_an_agent_that_never_answers(monkeypatch):
    clock = _slow_agent(monkeypatch, answers_after=10_000)
    with pytest.raises(bootstrap_mod.BootstrapError, match='within 90 s'):
        bootstrap_mod._verify({'host': '192.0.2.9', 'agent_port': 8530}, None, lambda line: None)
    assert 90 <= clock.now < 92


def test_bootstrap_check_names_kea_dhcp6(monkeypatch):
    class Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def status(self):
            return {'bind': False, 'agent_version': '6.0.0',
                    'kea': {'installed': True, 'version': '2.6.3',
                            'services': {'dhcp4': {'running': True}, 'dhcp6': {'running': False, 'error': 'refused'},
                                         'd2': {'running': True}}}}
    monkeypatch.setattr(bootstrap_mod, 'AgentClient', Client)
    lines = []
    bootstrap_mod._verify({'host': '192.0.2.9', 'agent_port': 8530}, None, lines.append)
    assert '  Kea 2.6.3: dhcp4 running, dhcp6 NOT reachable (refused), D2 running' in lines
