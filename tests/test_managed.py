import hashlib
import shutil
from pathlib import Path

import pytest

from liteblox import jobs
from liteblox.dns import declare
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file
from liteblox.dns.validate import named_checkzone
from liteblox.dns.zonefile import Zone
from liteblox.nodes import agent_module
from liteblox.nodes import service as nodes
from liteblox.nodes.client import AgentError

from conftest import csrf_from
from test_nodes import FP, HOST_KEY

EXAMPLE = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()
NS = [('ns1.new.lab', '192.0.2.53'), ('ns2.new.lab', '192.0.2.54')]


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class FakeNode:
    """Agent stand-in for a taken-over node; checks every config file with the real agent's allow-lists."""

    def __init__(self, name, calls):
        self.name = name
        self.config_files = {}          # role -> text, as last committed
        self.files = {}                 # zone -> primary-copy file text
        self.fail_stage = self.fail_commit = self.fail_check = False
        self.down = False               # True: the agent doesn't answer at all
        self.staged = None
        self.history = []
        self.calls = []
        self.all_calls = calls          # shared by every fake: the order across nodes
        self.kea_files = {}             # Kea: role -> text, as last committed
        self.kea_history = []
        self.kea_running = {'dhcp4': True, 'd2': True}
        self.fail_kea_stage = False
        self.kea_sockets = 'ready'      # what status-get says about kea-dhcp4's interface sockets
        self.kea_leases = []            # lease4-get-page rows
        self.kea_ha_state = None        # kea-dhcp4's HA state in status-get, when it's in a pair
        self.kea_commands = []
        self.chrony_files = {}          # chrony: role -> text, as last committed
        self.ntp_history = []
        self.fail_ntp = False
        self.ntp_synced = True

    def _call(self, what):
        self.calls.append(what)
        self.all_calls.append((self.name, what))

    @property
    def zones_conf(self):
        return self.config_files.get('zones.conf', '')

    def declared(self):
        agent = agent_module()
        return {z['name']: z for z in agent.validate_zones(self.zones_conf, agent.DEFAULT_CONFIG)}

    # agent API
    def status(self):
        return {'taken_over': True, 'client_address': '192.0.2.10', 'agent_version': '1.0.1', 'agent_sha256': 'x',
                'named_version': 'BIND 9.20', 'config_files': {r: sha(t) for r, t in self.config_files.items()},
                'interfaces': [{'name': 'ens18', 'up': True, 'addresses': ['192.0.2.53/24']},
                               {'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24']}],
                'kea': {'installed': True, 'version': '2.6.3', 'hooks_dir': '/usr/lib/x86_64-linux-gnu/kea/hooks',
                        'services': {s: ({'running': True, 'pid': 7, 'uptime': 60, 'reload': 5,
                                          **({'sockets': {'status': self.kea_sockets}} if s == 'dhcp4' else {}),
                                          **({'ha': {'local': {'state': self.kea_ha_state}, 'remote': {}}}
                                             if s == 'dhcp4' and self.kea_ha_state else {})} if up
                                         else {'running': False, 'error': 'connection refused'})
                                     for s, up in self.kea_running.items()},
                        'files': {r: sha(t) for r, t in self.kea_files.items()}},
                'time': self.time_status(), 'zones_writable': {}}

    # chrony
    def stats(self):
        self.queries = getattr(self, 'queries', 0) + 120
        return {'system': {'load': [0.5, 0.4, 0.3], 'cpus': 2, 'mem_total': 2000, 'mem_available': 1500,
                           'uptime': 600.0, 'disks': {'/': {'total': 1000, 'used': 250, 'available': 750}}},
                'bind': {'boot_time': 'boot', 'queries': self.queries}, 'errors': {}}

    # IPAM: the neighbour table (/neigh), empty unless a test fills it
    def neigh(self):
        return list(getattr(self, 'neighbours', []))

    def time_status(self):
        if not self.chrony_files:
            return {'daemon': 'timesyncd', 'installed': False, 'managed': False, 'files': {'chrony.conf': None}}
        return {'daemon': 'chrony', 'installed': True, 'managed': True,
                'files': {r: sha(t) for r, t in self.chrony_files.items()},
                'tracking': {'reference': '192.0.2.1', 'stratum': 3, 'offset': -0.0001,
                             'leap': 'Normal' if self.ntp_synced else 'Not synchronised'},
                'sources': [{'address': '192.0.2.1', 'state': '*' if self.ntp_synced else '?', 'stratum': 2,
                             'reach': 255, 'offset': -0.0001}]}

    def _check_chrony(self, files):
        agent = agent_module()
        agent.validate_chrony(files['chrony.conf'])
        if self.fail_ntp:
            raise AgentError(422, 'chronyd rejected chrony.conf', {'output': 'Invalid directive'})

    def check_ntp(self, files):
        self._call('check ntp')
        self._check_chrony(files)
        return {'ok': True}

    def stage_ntp(self, files):
        self._call('stage ntp')
        self._check_chrony(files)
        self.ntp_staged = dict(files)
        return {'stage_id': 'n1'}

    def commit_ntp(self, stage_id):
        self._call('commit ntp')
        self.ntp_history.append(dict(self.chrony_files))
        self.chrony_files.update(self.ntp_staged)
        return {'committed': True}

    def rollback_ntp(self):
        self._call('rollback ntp')
        self.chrony_files = self.ntp_history.pop()
        return {'rolled_back': 'x'}

    # Kea
    def check_dhcp(self, files):
        self._call('check dhcp')
        agent = agent_module()
        cfg = dict(agent.DEFAULT_CONFIG, kea_hooks_dir='/usr/lib/x86_64-linux-gnu/kea/hooks')
        for role, text in files.items():
            if role in agent.KEA_TLS:
                agent.validate_tls(role, text)
            else:
                agent.validate_kea(role, text, cfg)
        if self.fail_kea_stage:
            raise AgentError(422, 'Kea rejected kea-dhcp4.conf', {'output': 'fake'})
        return {'ok': True}

    def stage_dhcp(self, files):
        self._call('stage dhcp')
        agent = agent_module()
        cfg = dict(agent.DEFAULT_CONFIG, kea_hooks_dir='/usr/lib/x86_64-linux-gnu/kea/hooks')
        for role, text in files.items():
            if role in agent.KEA_TLS:
                agent.validate_tls(role, text)
            else:
                agent.validate_kea(role, text, cfg)
        if self.fail_kea_stage:
            raise AgentError(422, 'Kea rejected kea-dhcp4.conf', {'output': 'fake'})
        self.kea_staged = dict(files)
        return {'stage_id': 'd1'}

    def commit_dhcp(self, stage_id):
        self._call('commit dhcp')
        self.kea_history.append(dict(self.kea_files))
        self.kea_files.update(self.kea_staged)
        return {'committed': True}

    def rollback_dhcp(self):
        self._call('rollback dhcp')
        self.kea_files = self.kea_history.pop()
        return {'rolled_back': 'x'}

    def dhcp_command(self, service, command, arguments=None):
        if not self.kea_running[service]:
            raise AgentError(502, f'{command}: connection refused')
        self.kea_commands.append((command, arguments))
        if command == 'lease4-get-page':
            start = arguments['from']
            rows = sorted(self.kea_leases, key=lambda r: tuple(int(x) for x in r['ip-address'].split('.')))
            if start != 'start':
                rows = [r for r in rows if tuple(int(x) for x in r['ip-address'].split('.'))
                        > tuple(int(x) for x in start.split('.'))]
            page = rows[:arguments['limit']]
            return {'result': 0, 'arguments': {'leases': page, 'count': len(page)}} if page else {'result': 3}
        if command in ('lease4-get', 'lease4-del'):
            match = [r for r in self.kea_leases if r['ip-address'] == arguments['ip-address']]
            if not match:
                return {'result': 3, 'text': 'IPv4 lease not found.'}
            if command == 'lease4-del':
                self.kea_leases.remove(match[0])
                return {'result': 0, 'text': 'IPv4 lease deleted.'}
            return {'result': 0, 'arguments': match[0]}
        args = {'pid': 7, **({'sockets': {'status': self.kea_sockets}} if service == 'dhcp4' else {})}
        if service == 'dhcp4' and self.kea_ha_state and 'high-availability' in self.kea_files.get('kea-dhcp4.conf', ''):
            args['high-availability'] = [{'ha-servers': {'local': {'state': self.kea_ha_state}}}]
        return {'result': 0, 'arguments': args}

    def dhcp_files(self, secrets=False):
        return dict(self.kea_files)

    def ntp_files(self):
        return dict(self.chrony_files)

    def check_config(self, files):
        self._call('check')
        agent = agent_module()
        for role, text in files.items():
            agent.CONFIG_VALIDATORS[role](text, agent.DEFAULT_CONFIG)
        if self.fail_check:
            raise AgentError(422, 'named-checkconf rejected the config', {'output': 'options.conf:3: unknown option'})
        return {'ok': True, 'checkconf': ''}

    def config(self, secrets=False, files=False):
        zones = [{'name': n, 'declared_in': '/etc/bind/liteblox/zones.conf', 'type': z['type'], 'view': None,
                  'builtin': False, 'file': z['file']} for n, z in self.declared().items()]
        out = {'zones': zones, 'checkconf': self.zones_conf, 'declared': {}, 'conf_files': []}
        if files:
            out['files'] = {role: nodes.mask_secrets(text) for role, text in self.config_files.items()}
        return out

    def stage_config(self, files, zone_files=None, takeover=False, retire=None):
        self._call('stage')
        agent = agent_module()
        for role, text in files.items():
            agent.CONFIG_VALIDATORS[role](text, agent.DEFAULT_CONFIG)     # raises on anything off the allow-list
        if self.fail_stage:
            raise AgentError(422, 'named-checkzone rejected new.lab', {'output': 'bad'})
        self.staged = (dict(files), dict(zone_files or {}))
        return {'stage_id': 'c1', 'zones': []}

    def commit_config(self, stage_id):
        self._call('commit')
        if self.fail_commit:
            raise AgentError(422, 'named-checkconf rejected the config; rolled back')
        self.history.append((self.config_files, dict(self.files)))
        self.config_files, files = self.staged
        self.files.update(files)
        self.staged = None
        return {'committed': True}

    def rollback_config(self):
        self._call('rollback')
        self.config_files, self.files = self.history.pop()
        return {'rolled_back': 'x'}

    def abort_config(self, stage_id):
        self._call('abort')
        self.staged = None

    def get_zone(self, zone):
        return {'content': self.files[zone], 'sha256': sha(self.files[zone])}

    def stage_zone(self, zone, content, base_sha256):
        assert base_sha256 == sha(self.files[zone])
        self._call('stage zone')
        self.zone_staged = content
        return {'stage_id': 'z1'}

    def commit_zone(self, zone, stage_id):
        self._call('commit zone')
        self.files[zone] = self.zone_staged
        return {'committed': True}


class Client:
    def __init__(self, fake):
        self.fake = fake

    def __enter__(self):
        if self.fake.down:
            raise AgentError(0, f'cannot reach the agent on {self.fake.name}: connection refused')
        return self.fake

    def __exit__(self, *exc):
        pass


@pytest.fixture
def lab(conn, settings, monkeypatch):
    """Two taken-over nodes, no primary picked yet (dual-master)."""
    fakes, snapshots, calls = {}, [], []
    for i, host in enumerate(('192.0.2.53', '192.0.2.54'), 1):
        node_id = nodes.add_node(conn, f'ns{i}', host, 22, 8530, HOST_KEY, FP)
        with conn:
            conn.execute("UPDATE nodes SET status = 'ready', managed = 1 WHERE id = ?", (node_id,))
        fakes[node_id] = FakeNode(f'ns{i}', calls)
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['id']]))
    monkeypatch.setattr(declare.backups, 'snapshot_before_change',
                        lambda conn, settings, node, reason, username: snapshots.append((node['name'], reason)))
    # the forwarding probe is a real recursive query; these addresses answer nothing
    monkeypatch.setattr(declare, '_probe_forwarding',
                        lambda log, node, name: log(f"  {node['name']}: a recursive query for {name} (not sent in tests)"))
    return fakes, snapshots


def make_roles(conn, primary=1, secondary=2):
    from liteblox.nodes.roles import ensure_xfr_key
    ensure_xfr_key(conn)
    with conn:
        conn.execute("UPDATE nodes SET role = 'primary' WHERE id = ?", (primary,))
        conn.execute("UPDATE nodes SET role = 'secondary' WHERE id = ?", (secondary,))


def ok_verify(host, zone, expected, **kw):
    return expected


def log_to(lines):
    return lines.append


# ── rendering and validation ───────────────────────────────────────────────────

@pytest.mark.parametrize('value, ok', [
    ('192.0.2.1\n2001:db8::/32', True), ('key xfer; !192.0.2.7', True), ('none', True), ('trusted', True),
    ('192.0.2.1 }; options {', False), ('"quoted"', False),
])
def test_parse_list(value, ok):
    if ok:
        declare.parse_list(value)
    else:
        with pytest.raises(ValueError):
            declare.parse_list(value)


@pytest.mark.parametrize('network, zone', [
    ('192.168.1.0/24', '1.168.192.in-addr.arpa'),
    ('192.168.1.77/24', '1.168.192.in-addr.arpa'),
    ('10.0.0.0/8', '10.in-addr.arpa'),
    ('172.16.0.0/16', '16.172.in-addr.arpa'),
    ('2001:db8::/32', '8.b.d.0.1.0.0.2.ip6.arpa'),
    ('fd00:1:2::/52', '0.2.0.0.0.1.0.0.0.0.0.d.f.ip6.arpa'),
])
def test_reverse_zone_name(network, zone):
    assert declare.reverse_zone_name(network) == zone


@pytest.mark.parametrize('network, message', [
    ('192.168.1.0/23', 'split it into /24 zones'),
    ('192.168.1.0/26', 'classless delegation'),
    ('192.168.1.0', 'add the prefix length'),
    ('2001:db8::/30', 'multiple of 4'),
    ('example.com', 'not a network'),
])
def test_reverse_zone_name_refuses(network, message):
    with pytest.raises(declare.DeclareError, match=message):
        declare.reverse_zone_name(network)


def test_default_rname():
    assert declare.default_rname('new.lab', NS) == 'hostmaster.new.lab.'
    assert declare.default_rname('0.168.192.in-addr.arpa', [('ns1.example.com', None)]) == 'hostmaster.example.com.'
    assert declare.default_rname('8.b.d.0.1.0.0.2.ip6.arpa', [('ns1.example.com.', None)]) == 'hostmaster.example.com.'
    assert declare.default_rname('0.168.192.in-addr.arpa', [('ns1', None)]) == 'hostmaster.0.168.192.in-addr.arpa.'
    text = declare.starter_zone('0.168.192.in-addr.arpa', [('ns1.example.com', None)])
    assert 'ns1.example.com. hostmaster.example.com. (' in text


def test_starter_zone():
    text = declare.starter_zone('new.lab', NS + [('ns.example.net', None)], serial=2026102501)
    zone = Zone.parse(text, 'new.lab.')
    assert zone.serial == 2026102501
    assert sorted(r.rdata for r in zone.records() if r.rtype == 'NS') == ['ns.example.net.', 'ns1.new.lab.', 'ns2.new.lab.']
    assert {(r.relative_name(), r.rdata) for r in zone.records() if r.rtype == 'A'} == {('ns1', '192.0.2.53'), ('ns2', '192.0.2.54')}
    if shutil.which('named-checkzone'):
        assert named_checkzone('new.lab', text)[0]
    with pytest.raises(declare.DeclareError, match='needs an address'):
        declare.starter_zone('new.lab', [('ns1.new.lab', None)])
    with pytest.raises(declare.DeclareError, match='full zone name'):
        declare.check_zone_name('lab')


# ── create / add / remove / settings ───────────────────────────────────────────

def test_create_zone_on_two_nodes(conn, settings, lab):
    fakes, snapshots = lab
    text = declare.starter_zone('new.lab', NS)
    lines = []
    declare.create_zone(settings, 'new.lab', ['1', '2'], text, 'admin', log_to(lines), verify=ok_verify)

    for f in fakes.values():                    # no primary picked: both hold a primary copy
        assert f.declared()['new.lab']['type'] == 'primary' and f.files == {'new.lab': text}
        assert f.calls == ['stage', 'commit']
    assert snapshots == [('ns1', 'create zone new.lab'), ('ns2', 'create zone new.lab')]
    assert Repo(settings.repo_dir).read(zone_file('new.lab')) == text
    links = conn.execute('SELECT node_file, deployed_sha256 FROM zone_nodes').fetchall()
    assert [tuple(l) for l in links] == [('/etc/bind/liteblox/db.new.lab', sha(text))] * 2
    assert any('serving new.lab' in l for l in lines)
    assert conn.execute('SELECT config_sha256 FROM nodes WHERE id = 1').fetchone()[0]


def test_create_refused_on_a_node_not_taken_over_or_on_stage_failure(conn, settings, lab):
    fakes, snapshots = lab
    text = declare.starter_zone('new.lab', NS)
    with conn:
        conn.execute('UPDATE nodes SET managed = 0 WHERE id = 2')
    with pytest.raises(declare.DeclareError, match='ns2 is not taken over yet'):
        declare.create_zone(settings, 'new.lab', ['1', '2'], text, 'admin', print, verify=ok_verify)
    assert snapshots == []

    with conn:
        conn.execute('UPDATE nodes SET managed = 1 WHERE id = 2')
    fakes[2].fail_stage = True
    with pytest.raises(declare.DeclareError, match='ns2 rejected'):
        declare.create_zone(settings, 'new.lab', ['1', '2'], text, 'admin', print, verify=ok_verify)
    assert fakes[1].calls == ['stage', 'abort'] and fakes[1].zones_conf == ''
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0
    assert Repo(settings.repo_dir).read(zone_file('new.lab')) is None


def test_add_and_remove_node_and_settings(conn, settings, lab):
    fakes, snapshots = lab
    text = declare.starter_zone('new.lab', NS)
    declare.create_zone(settings, 'new.lab', ['1'], text, 'admin', print, verify=ok_verify)
    other = declare.starter_zone('other.lab', [('ns1.other.lab', '192.0.2.53')])
    declare.create_zone(settings, 'other.lab', ['1', '2'], other, 'admin', print, verify=ok_verify)
    assert set(fakes[2].declared()) == {'other.lab'}

    declare.add_node(settings, 'new.lab', 2, 'admin', print, verify=ok_verify)
    assert set(fakes[2].declared()) == {'new.lab', 'other.lab'}                 # keeps its other zones
    assert fakes[2].files['new.lab'] == text
    with pytest.raises(declare.DeclareError, match='already serves'):
        declare.add_node(settings, 'new.lab', 2, 'admin', print, verify=ok_verify)

    declare.update_settings(settings, 'new.lab', 'explicit', '192.0.2.99', '192.0.2.0/24', 'admin', print,
                            allow_query='trusted')
    for f in fakes.values():
        assert 'notify explicit;' in f.zones_conf and 'also-notify { 192.0.2.99; };' in f.zones_conf
        assert 'allow-query { trusted; };' in f.zones_conf
        assert f.zones_conf.count('notify explicit') == 1                       # other.lab untouched
    with pytest.raises(declare.DeclareError, match='notify must be'):
        declare.update_settings(settings, 'new.lab', 'sometimes', '', '', 'admin', print)

    declare.remove_node(settings, 'new.lab', 1, 'admin', print, verify=lambda *a, **k: None)
    assert set(fakes[1].declared()) == {'other.lab'}
    assert [r[0] for r in conn.execute('SELECT n.name FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id '
                                       "JOIN zones z ON z.id = zn.zone_id WHERE z.name = 'new.lab'")] == ['ns2']
    assert ('ns1', 'remove new.lab') in snapshots


def test_delete_zone(conn, settings, lab):
    fakes, snapshots = lab
    text = declare.starter_zone('new.lab', NS)
    declare.create_zone(settings, 'new.lab', ['1', '2'], text, 'admin', print, verify=ok_verify)
    other = declare.starter_zone('other.lab', [('ns1.other.lab', '192.0.2.53')])
    declare.create_zone(settings, 'other.lab', ['1'], other, 'admin', print, verify=ok_verify)
    zone = dict(conn.execute("SELECT * FROM zones WHERE name = 'new.lab'").fetchone())
    drafts = Drafts(settings)
    drafts.save(zone, text.replace('3600', '7200'), 'admin')

    lines = []
    declare.delete_zone(settings, 'new.lab', 'admin', log_to(lines), verify=lambda *a, **k: None)
    assert set(fakes[1].declared()) == {'other.lab'} and fakes[2].declared() == {}
    assert ('ns2', 'delete zone new.lab') in snapshots
    assert conn.execute("SELECT name FROM zones").fetchall()[0][0] == 'other.lab'
    assert conn.execute('SELECT COUNT(*) FROM zone_nodes').fetchone()[0] == 1
    repo = Repo(settings.repo_dir)
    assert repo.read(zone_file('new.lab')) is None
    assert [c['subject'] for c in repo.log(zone_file('new.lab'))] == ['Create new.lab']    # history kept
    assert drafts.load(zone) == ('', False)
    assert any('ns2 no longer serves new.lab' in line for line in lines)

    # created again, it starts from the new content but keeps the older versions
    declare.create_zone(settings, 'new.lab', ['1'], text, 'admin', print, verify=ok_verify)
    assert [c['subject'] for c in repo.log(zone_file('new.lab'))] == ['Create new.lab', 'Create new.lab']


def test_delete_changes_nothing_if_a_node_refuses(conn, settings, lab):
    fakes, _ = lab
    declare.create_zone(settings, 'new.lab', ['1', '2'], declare.starter_zone('new.lab', NS), 'admin', print,
                        verify=ok_verify)
    fakes[2].fail_stage = True
    with pytest.raises(declare.DeclareError, match='Nothing was deleted'):
        declare.delete_zone(settings, 'new.lab', 'admin', print, verify=ok_verify)
    assert 'new.lab' in fakes[1].declared() and 'new.lab' in fakes[2].declared()
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 1
    assert Repo(settings.repo_dir).read(zone_file('new.lab')) is not None


def test_delete_leaves_a_node_not_taken_over_alone(conn, settings, lab, imported_zone):
    fakes = imported_zone
    with conn:
        conn.execute('UPDATE nodes SET managed = 0 WHERE id = 2')
    lines = []
    declare.delete_zone(settings, 'example.com', 'admin', log_to(lines), verify=ok_verify)
    assert fakes[2].calls == [] and fakes[1].calls == ['stage', 'commit']
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0
    assert any('ns2 is not taken over' in line for line in lines)


def test_delete_route_needs_the_zone_name(client, make_user, login, conn, settings, lab, imported_zone, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    t = csrf_from(client.get('/zones/example.com/settings').text)
    r = client.post('/zones/example.com/delete', data={'csrf_token': t, 'confirm_name': 'example.org'},
                    follow_redirects=False)
    assert r.status_code == 303 and 'error=' in r.headers['location']
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 1
    r = client.post('/zones/example.com/delete', data={'csrf_token': t, 'confirm_name': 'Example.com.'},
                    follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0
    assert 'href="/zones">Zones</a>' in client.get(f"/jobs/{job['id']}").text


def test_commit_failure_is_reported(conn, settings, lab):
    fakes, _ = lab
    fakes[2].fail_commit = True
    with pytest.raises(declare.DeclareError, match='failed on ns2'):
        declare.create_zone(settings, 'new.lab', ['1', '2'], declare.starter_zone('new.lab', NS), 'admin', print,
                            verify=ok_verify)
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0


# ── primary / secondary ────────────────────────────────────────────────────────

def test_create_zone_with_a_primary(conn, settings, lab):
    fakes, _ = lab
    make_roles(conn)
    text = declare.starter_zone('new.lab', NS)
    verified = []
    declare.create_zone(settings, 'new.lab', ['2'], text, 'admin', print,
                        verify=lambda host, zone, serial, **kw: verified.append((host, kw)) or serial)
    calls = fakes[1].all_calls
    assert calls.index(('ns1', 'commit')) < calls.index(('ns2', 'commit'))      # the primary first
    assert fakes[1].files == {'new.lab': text} and fakes[2].files == {}
    primary, secondary = fakes[1].declared()['new.lab'], fakes[2].declared()['new.lab']
    assert primary['type'] == 'primary' and primary['journal'] == '/var/lib/bind/liteblox/jnl/db.new.lab.jnl'
    assert secondary == {'name': 'new.lab', 'type': 'secondary', 'dynamic': False, 'journal': None,
                         'file': '/var/lib/bind/liteblox/sec/db.new.lab'}
    assert 'also-notify { 192.0.2.54; };' in fakes[1].zones_conf
    assert 'allow-transfer { key liteblox-xfr; };' in fakes[1].zones_conf
    assert 'notify explicit;' in fakes[1].zones_conf and 'ixfr-from-differences yes;' in fakes[1].zones_conf
    assert 'primaries { 192.0.2.53 key liteblox-xfr; };' in fakes[2].zones_conf
    assert 'key "liteblox-xfr"' in fakes[2].config_files['keys.conf']
    links = dict(conn.execute('SELECT node_id, node_file FROM zone_nodes').fetchall())
    assert links == {1: '/etc/bind/liteblox/db.new.lab', 2: '/var/lib/bind/liteblox/sec/db.new.lab'}
    assert conn.execute('SELECT deployed_sha256 FROM zone_nodes WHERE node_id = 2').fetchone()[0] is None
    assert verified == [('192.0.2.53', {}), ('192.0.2.54', {'attempts': declare.SECONDARY_ATTEMPTS})]


def test_adding_and_removing_a_secondary_rewrites_the_primary(conn, settings, lab):
    fakes, _ = lab
    make_roles(conn)
    declare.create_zone(settings, 'new.lab', ['1'], declare.starter_zone('new.lab', NS), 'admin', print,
                        verify=ok_verify)
    assert 'also-notify' not in fakes[1].zones_conf and 'journal' not in fakes[1].zones_conf
    fakes[1].calls.clear()
    declare.add_node(settings, 'new.lab', 2, 'admin', print, verify=ok_verify)
    assert fakes[1].calls == ['stage', 'commit'] and 'also-notify { 192.0.2.54; };' in fakes[1].zones_conf
    assert fakes[2].declared()['new.lab']['type'] == 'secondary' and fakes[2].files == {}
    declare.remove_node(settings, 'new.lab', 2, 'admin', print, verify=lambda *a, **k: None)
    assert 'also-notify' not in fakes[1].zones_conf and fakes[2].declared() == {}
    with pytest.raises(declare.DeclareError, match='ns1 is the primary'):
        declare.remove_node(settings, 'new.lab', 1, 'admin', print, verify=lambda *a, **k: None)


@pytest.fixture
def imported_zone(conn, settings, lab):
    """example.com in LiteBlox, a primary copy on both nodes (as a takeover leaves it)."""
    fakes, _ = lab
    Repo(settings.repo_dir).ensure().write(zone_file('example.com'), EXAMPLE, 'Import', 'test')
    with conn:
        conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES ('example.com', 'managed', ?)",
                     (zone_file('example.com'),))
        for node_id in fakes:
            conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (1, ?, ?, ?)",
                         (node_id, '/etc/bind/liteblox/db.example.com', sha(EXAMPLE)))
            fakes[node_id].files['example.com'] = EXAMPLE
    return fakes


# ── pages ──────────────────────────────────────────────────────────────────────

def test_pages(client, make_user, login, conn, settings, lab, imported_zone, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    real_create = declare.create_zone
    monkeypatch.setattr(declare, 'create_zone', lambda *a, **k: real_create(*a, **{**k, 'verify': ok_verify}))
    login(*make_user('admin', 'admin-password', 'admin'))
    t = csrf_from(client.get('/zones/new').text)

    r = client.post('/zones/new', data={'csrf_token': t, 'name': 'new.lab', 'nameservers': 'ns1.new.lab', 'nodes': ['1']})
    assert r.status_code == 422 and 'needs an address' in r.text
    r = client.post('/zones/new', data={'csrf_token': t, 'name': 'new.lab', 'ttl': '600',
                                        'nameservers': 'ns1.new.lab 192.0.2.53', 'nodes': ['1', '2']},
                    follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert job['zone_id'] == conn.execute("SELECT id FROM zones WHERE name = 'new.lab'").fetchone()[0]
    assert 'href="/zones/new.lab">Open new.lab</a>' in client.get(f"/jobs/{job['id']}").text
    # the polled part shows it too, so the button appears without a reload
    assert 'href="/zones/new.lab">Open new.lab</a>' in client.get(f"/jobs/{job['id']}/log").text

    assert 'Zone name: <code>0.168.192.in-addr.arpa</code>' in client.get(
        '/zones/new/reverse-name', params={'network': '192.168.0.0/24'}).text
    assert 'classless' in client.get('/zones/new/reverse-name', params={'network': '192.168.0.0/25'}).text
    r = client.post('/zones/new', data={'csrf_token': t, 'name': '0.168.192.in-addr.arpa', 'nameservers': 'ns1.new.lab',
                                        'nodes': ['1']})
    assert r.status_code == 422 and 'choose Reverse' in r.text
    r = client.post('/zones/new', data={'csrf_token': t, 'kind': 'reverse', 'network': '192.168.0.0/25',
                                        'nameservers': 'ns1.new.lab', 'nodes': ['1']})
    assert r.status_code == 422 and 'classless' in r.text and 'value="reverse" checked' in r.text
    r = client.post('/zones/new', data={'csrf_token': t, 'kind': 'reverse', 'network': '192.168.0.0/24',
                                        'nameservers': 'ns1.new.lab 192.0.2.53', 'nodes': ['1']}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert 'hostmaster.new.lab.' in Repo(settings.repo_dir).read(zone_file('0.168.192.in-addr.arpa'))

    page = client.get('/zones/new.lab').text
    assert 'ns1 ✓' in page and 'Stop serving' not in page
    settings_page = client.get('/zones/new.lab/settings').text
    assert 'declares this zone in <code>zones.conf</code>' in settings_page
    assert 'notify no;' in settings_page and 'Save and apply' in settings_page
    assert 'Danger zone' in settings_page and 'Stop serving' in settings_page and 'Adopt' not in settings_page
    assert client.get('/zones/example.com/adopt').status_code == 404
    assert 'Add zone' in client.get('/zones').text

    make_roles(conn)                                    # the primary is listed, ticked and locked
    form = client.get('/zones/new').text
    assert '<input type="hidden" name="nodes" value="1">' in form and 'checked disabled' in form
    page = client.get('/zones/new.lab').text
    assert 'ns1 · primary' in page


# ── forwarding-only zones ──────────────────────────────────────────────────────

def options(conn, node_id):
    from liteblox.bindconf.model import NodeOptions
    return NodeOptions.from_json(conn.execute('SELECT options FROM nodes WHERE id = ?', (node_id,)).fetchone()[0])


def test_forwarding_zone_lifecycle(conn, settings, lab):
    fakes, snapshots = lab
    make_roles(conn)                    # ns1 is the primary, but a forwarding zone isn't tied to it
    lines = []
    declare.create_forwarding_zone(settings, 'corp.example', ['2'], '10.0.0.53\n10.0.1.53 port 5353', 'only', True,
                                   'admin', lines.append)
    assert fakes[1].calls == [] and fakes[2].calls == ['stage', 'commit']
    assert fakes[2].declared()['corp.example'] == {'name': 'corp.example', 'type': 'forward', 'file': None,
                                                   'dynamic': False, 'journal': None}
    assert 'forward only;' in fakes[2].zones_conf
    assert 'forwarders { 10.0.0.53; 10.0.1.53 port 5353; };' in fakes[2].zones_conf
    assert 'validate-except { "corp.example"; };' in fakes[2].config_files['options.conf']
    assert options(conn, 2).validate_except == ['corp.example'] and options(conn, 1).validate_except is None
    row = conn.execute("SELECT * FROM zones WHERE name = 'corp.example'").fetchone()
    assert (row['kind'], row['repo_file'], row['forward_mode']) == ('forwarding', '', 'only')
    assert any('recursive query for corp.example' in line for line in lines)

    # ns1 joins; it gets the validate-except entry too; the forwarders change everywhere
    declare.add_node(settings, 'corp.example', 1, 'admin', print)
    assert 'corp.example' in fakes[1].declared() and options(conn, 1).validate_except == ['corp.example']
    declare.update_forwarding(settings, 'corp.example', '10.0.0.54', 'first', 'admin', print)
    for f in fakes.values():
        assert 'forward first;' in f.zones_conf and 'forwarders { 10.0.0.54; };' in f.zones_conf
    with pytest.raises(declare.DeclareError, match='forwarding zone'):
        declare.update_settings(settings, 'corp.example', 'yes', '', '', 'admin', print)
    with pytest.raises(declare.DeclareError, match='IP address'):
        declare.update_forwarding(settings, 'corp.example', 'dns.example.com', 'only', 'admin', print)

    # the primary can stop serving it; then the zone goes, with its validate-except entries
    declare.remove_node(settings, 'corp.example', 1, 'admin', print)
    assert 'corp.example' not in fakes[1].declared() and options(conn, 1).validate_except is None
    declare.delete_zone(settings, 'corp.example', 'admin', print)
    assert fakes[2].declared() == {} and options(conn, 2).validate_except is None
    assert 'validate-except' not in fakes[2].config_files['options.conf']
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0


def test_forwarding_zone_failure_restores_validate_except(conn, settings, lab):
    fakes, _ = lab
    fakes[2].fail_stage = True
    with pytest.raises(declare.DeclareError, match='ns2 rejected'):
        declare.create_forwarding_zone(settings, 'corp', ['1', '2'], '10.0.0.53', 'only', True, 'admin', print)
    assert options(conn, 1).validate_except is None and options(conn, 2).validate_except is None
    assert conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0] == 0


def test_publish_and_make_primary_leave_forwarding_zones_alone(conn, settings, lab, monkeypatch):
    from liteblox.dns import publish as pub
    from liteblox.nodes import roles
    fakes, _ = lab
    declare.create_forwarding_zone(settings, 'corp.example', ['2'], '10.0.0.53', 'only', False, 'admin', print)
    with pytest.raises(pub.PublishError, match='no records to publish'):
        pub.publish(settings, 'corp.example', 'admin', print)
    monkeypatch.setattr(roles.nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['id']]))
    monkeypatch.setattr('liteblox.backups.service.snapshot_before_change', lambda *a, **k: None)
    roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    assert 'corp.example' not in fakes[1].declared()                   # not pulled onto the primary
    assert fakes[2].declared()['corp.example']['type'] == 'forward'     # still forwarding on ns2


def test_forwarding_pages(client, make_user, login, conn, settings, lab, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    page = client.get('/zones/new').text
    assert 'Forwarding only' in page and 'name="fwd_name"' in page and 'name="validate_except"' in page
    t = csrf_from(page)
    base = {'csrf_token': t, 'kind': 'forwarding', 'fwd_name': 'corp', 'forward_mode': 'only', 'nodes': ['2']}
    r = client.post('/zones/new', data=dict(base, forwarders='dns.corp'))
    assert r.status_code == 422 and 'IP address' in r.text and 'value="forwarding" checked' in r.text
    r = client.post('/zones/new', data=dict(base, forwarders=''))
    assert r.status_code == 422 and 'at least one forwarder' in r.text
    r = client.post('/zones/new', data=dict(base, fwd_name='', forwarders='10.0.0.53'))
    assert r.status_code == 422
    r = client.post('/zones/new', data=dict(base, forwarders='10.0.0.53', validate_except='1'), follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert options(conn, 2).validate_except == ['corp']

    for path in ('/zones/corp', '/zones/corp/raw', '/zones/corp/review', '/zones/corp/history'):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers['location'] == '/zones/corp/settings'
    settings_page = client.get('/zones/corp/settings').text
    assert 'Forwarding' in settings_page and '10.0.0.53' in settings_page and 'Record order' not in settings_page
    assert 'Stop serving' in settings_page and 'notify' not in settings_page
    assert '<span class="pill">forwarding</span> <span class="muted small">→ 10.0.0.53' in client.get('/zones').text
    r = client.post('/zones/corp/forwarders', data={'csrf_token': t, 'forwarders': '10.0.0.54', 'forward_mode': 'first'},
                    follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert 'forward first;' in lab[0][2].zones_conf
    r = client.post('/zones/corp/forwarders', data={'csrf_token': t, 'forwarders': 'nope', 'forward_mode': 'first'},
                    follow_redirects=False)
    assert 'error=' in r.headers['location']
