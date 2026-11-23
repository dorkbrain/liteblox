"""Re-adopting nodes after LiteBlox's data is lost: the model rebuilt from their generated files."""

import json

import dns.zone
import pytest

from liteblox import db
from liteblox.bindconf import apply as bind_apply
from liteblox.bindconf import readopt
from liteblox.bindconf.model import NodeOptions, for_node
from liteblox.bindconf.render import STATS_CHANNEL, render
from liteblox.config import load_settings
from liteblox.dhcp import apply as dhcp_apply
from liteblox.ntp import apply as ntp_apply
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation, Subnet, ha_pair, subnets as load_subnets
from liteblox.dns.declare import managed_file
from liteblox.nodes import roles
from liteblox.nodes import service as nodes
from liteblox.pki import PKI

from conftest import csrf_from
from test_managed import Client, FakeNode, sha
from test_nodes import FP, HOST_KEY

HOOKS = '/usr/lib/x86_64-linux-gnu/kea/hooks'
SECRET = 'c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I='
EXAMPLE = '$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. 7 3600 600 86400 300\n@ IN NS ns1.example.com.\n' \
          'ns1 IN A 192.0.2.53\n'
DDNS = '$TTL 300\n@ 300 IN SOA ns1.ddns.lab. admin.ddns.lab. 12 3600 600 86400 300\n@ 300 IN NS ns1.ddns.lab.\n' \
       'ns1 300 IN A 192.0.2.53\nclient 300 IN A 198.51.100.50\n'
REVERSE = '$TTL 300\n@ 300 IN SOA ns1.ddns.lab. admin.ddns.lab. 3 3600 600 86400 300\n@ 300 IN NS ns1.ddns.lab.\n' \
          '50 300 IN PTR client.ddns.lab.\n'
NTP_SOURCES = ('[{"kind": "pool", "address": "2.debian.pool.ntp.org", "iburst": true, "prefer": false, "nts": false, '
               '"minpoll": null, "maxpoll": null}, {"kind": "server", "address": "192.0.2.1", "iburst": false, '
               '"prefer": true, "nts": false, "minpoll": 4, "maxpoll": null}]')
DYNAMIC = {'ddns.lab': DDNS, '100.51.198.in-addr.arpa': REVERSE}
ADDRS = {'ns1': ['192.0.2.53/24', '198.51.100.53/24'], 'ns2': ['192.0.2.54/24', '198.51.100.54/24']}


class OldNode(FakeNode):
    """A node an earlier LiteBlox set up: its generated files, as the real agent reports them."""

    def status(self):
        out = super().status()
        out['interfaces'] = [{'name': 'ens18', 'up': True, 'addresses': ADDRS[self.name][:1]},
                             {'name': getattr(self, 'lab_name', 'ens19'), 'up': True, 'addresses': ADDRS[self.name][1:]}]
        out['kea']['installed'] = bool(self.kea_files)
        d4 = json.loads(self.kea_files.get('kea-dhcp4.conf') or '{}').get('Dhcp4') or {}
        out['kea'].update(liteblox=(d4.get('user-context') or {}).get('generated-by') == 'LiteBlox',
                          subnets=len(d4.get('subnet4') or []))
        return out

    def config(self, secrets=False, files=False):
        out = super().config(secrets, files)
        if secrets:     # named-checkconf -p prints every key with its secret
            out['checkconf'] = self.config_files.get('keys.conf', '')
        return out

    def dhcp_files(self, secrets=False):
        return {role: text if secrets and role == 'kea-dhcp-ddns.conf' else readopt._mask_kea(text)
                for role, text in self.kea_files.items()}


def transfer(host, name, keyring, algorithm):
    return dns.zone.from_text(DYNAMIC[name], name + '.', relativize=True)


def _insert(conn, table, **cols):
    with conn:
        return conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                            tuple(cols.values())).lastrowid


def build_old(tmp_path, dhcp=True):
    """A LiteBlox with a bit of everything; returns (its settings, conn)."""
    settings = load_settings(tmp_path / 'old' / 'data', tmp_path / 'old' / 'backups')
    db.migrate(settings.db_path)
    pki = PKI(settings.pki_dir).ensure()
    conn = db.connect(settings.db_path)
    ns1 = nodes.add_node(conn, 'ns1', '192.0.2.53', 22, 8530, HOST_KEY, FP)
    ns2 = nodes.add_node(conn, 'ns2', '192.0.2.54', 22, 8530, HOST_KEY, FP)
    roles.ensure_keys(conn)
    options1 = NodeOptions(allow_query=['trusted', 'localhost'], recursion=False, dnssec_validation='auto',
                           extra='minimal-responses yes;\nversion "none";')
    with conn:
        conn.execute("UPDATE nodes SET managed = 1, status = 'ready', distro_includes = ? ",
                     (json.dumps(['/etc/bind/named.conf.root-hints']),))
        conn.execute("UPDATE nodes SET role = 'primary', options = ?, top_extra = ? WHERE id = ?",
                     (options1.to_json(), 'server 192.0.2.99 {\n\tbogus yes;\n};', ns1))
        conn.execute("UPDATE nodes SET role = 'secondary', dns_address = '198.51.100.54', options = ? WHERE id = ?",
                     (NodeOptions(recursion=True, allow_recursion=['trusted']).to_json(), ns2))
    _insert(conn, 'acls', name='trusted', items=json.dumps(['192.0.2.0/24', '!192.0.2.7']))
    dhcp_key = _insert(conn, 'tsig_keys', name='dhcp', algorithm='hmac-sha256', secret=SECRET, purpose='user')
    acme = _insert(conn, 'tsig_keys', name='acme', algorithm='hmac-sha512', secret=SECRET * 2, purpose='user')
    _insert(conn, 'tsig_keys', name='old-import', algorithm='hmac-sha256', secret=SECRET[::-1], purpose='imported')

    def zone(name, serving, **cols):
        repo_file = '' if cols.get('kind') == 'forwarding' else f'zones/{name}.zone'
        zone_id = _insert(conn, 'zones', name=name, mode='managed', repo_file=repo_file, **cols)
        for node_id in serving:
            folder = ('/var/lib/bind/liteblox/sec' if node_id == ns2 else
                      '/var/lib/bind/liteblox/dyn' if cols.get('dynamic') else None)
            _insert(conn, 'zone_nodes', zone_id=zone_id, node_id=node_id,
                    node_file=f'{folder}/db.{name}' if folder else managed_file(name))
        return zone_id
    zone('example.com', [ns1, ns2], notify='no', also_notify='192.0.2.200', allow_transfer='192.0.2.201')
    zone('only1.lab', [ns1], allow_query='192.0.2.0/24', notify='yes')
    zone('restricted.lab', [ns1, ns2], allow_query='')
    zone('query.lab', [ns1, ns2], allow_query='trusted')
    ddns = zone('ddns.lab', [ns1, ns2], dynamic=1)
    reverse = zone('100.51.198.in-addr.arpa', [ns1, ns2], dynamic=1)
    zone('fwd.lab', [ns1, ns2], kind='forwarding', forwarders='192.0.2.250\n192.0.2.251 port 5353', forward_mode='only')
    for zone_id, key, scope, name, types in ((ddns, dhcp_key, 'zonesub', '', 'ANY'),
                                             (ddns, acme, 'name', '_acme-challenge.ddns.lab', 'TXT'),
                                             (reverse, dhcp_key, 'zonesub', '', 'PTR')):
        _insert(conn, 'key_grants', key_id=key, zone_id=zone_id, scope=scope, name=name, types=types)
    with conn:
        conn.execute("UPDATE zone_nodes SET node_file = '' WHERE zone_id = (SELECT id FROM zones WHERE name = 'fwd.lab')")
    if dhcp:
        with conn:
            conn.execute("UPDATE nodes SET dhcp = 1, kea_hooks_dir = ?, dhcp_interfaces = '[\"ens19\"]'", (HOOKS,))
            conn.execute("UPDATE dhcp4_settings SET valid_lifetime = 3600, options = ?, ddns_key_id = ?, ddns_mode = 'liteblox' "
                         'WHERE id = 1',
                         (json.dumps({'dns': ['198.51.100.53', '198.51.100.54'], 'domain': 'ddns.lab'}), dhcp_key))
        store.save_subnet(conn, Subnet(2, '198.51.100.0/24', 'ens19', ['198.51.100.100 - 198.51.100.199'],
                                       {'routers': ['198.51.100.1']}, [{'name': 'time-offset', 'data': '0'}],
                                       {'match-client-id': False}, renew_timer=900, ddns=True,
                                       ddns_zone_id=ddns, ddns_suffix='clients.ddns.lab', comment='lab'))
        store.save_subnet(conn, Subnet(5, '203.0.113.0/24', 'ens19', ['203.0.113.0/26']))
        for ip, mac, host in (('198.51.100.60', 'aa:bb:cc:dd:ee:02', ''), ('198.51.100.50', 'aa:bb:cc:dd:ee:01', 'client')):
            store.save_reservation(conn, Reservation(None, 2, mac, ip, host, {'routers': ['198.51.100.2']} if host else {}))
        store.set_pair(conn, pki, ns1, ns2, '198.51.100.53', '198.51.100.54', 8001)
    with conn:      # time: both run chrony, ns1 serves the DHCP network
        conn.execute("UPDATE ntp_settings SET sources = ? WHERE id = 1", (NTP_SOURCES,))
        conn.execute('UPDATE nodes SET ntp = 1')
        conn.execute("UPDATE nodes SET ntp_serve = 1, ntp_allow = '[\"198.51.100.0/24\"]', ntp_local = 10 WHERE id = ?",
                     (ns1,))
    return settings, conn


def render_old(conn):
    """Each old node's files, as its last commit left them."""
    calls, fakes = [], {}
    for node in nodes.list_nodes(conn):
        fake = OldNode(node['name'], calls)
        fake.config_files = render(for_node(conn, node))
        if node['dhcp']:
            fake.kea_files = dhcp_apply.files_for(conn, node)
            fake.kea_ha_state = 'hot-standby'
        if node['ntp']:
            fake.chrony_files = ntp_apply.files_for(conn, node)
        fake.files = {'example.com': EXAMPLE, 'only1.lab': EXAMPLE.replace('example.com', 'only1.lab'),
                      'restricted.lab': EXAMPLE, 'query.lab': EXAMPLE}
        fakes[node['name']] = fake
    return fakes


@pytest.fixture
def old(tmp_path, conn, settings, monkeypatch):
    """The lost LiteBlox's nodes, added again (in the other order) to a fresh one."""
    old_settings, old_conn = build_old(tmp_path)
    fakes = render_old(old_conn)
    for name, host in (('ns2', '192.0.2.54'), ('ns1', '192.0.2.53')):
        node_id = nodes.add_node(conn, name, host, 22, 8530, HOST_KEY, FP)
        nodes.record_status(conn, node_id, fakes[name].status())
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['name']]))
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    from liteblox.backups import service as backups
    monkeypatch.setattr(backups, 'snapshot_before_change', lambda *a, **kw: None)
    yield old_conn, fakes
    old_conn.close()


def ids(conn):
    return [r['id'] for r in readopt.candidates(conn)]


def test_candidates_need_the_flag_and_an_empty_instance(conn, old):
    assert [r['name'] for r in readopt.candidates(conn)] == ['ns1', 'ns2']
    assert readopt.not_fresh(conn) == []
    _insert(conn, 'acls', name='x', items='[]')
    assert readopt.not_fresh(conn) == ['LiteBlox has ACLs already']


def test_preview_renders_every_file_back(conn, settings, old):
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.blockers == []
    assert pv.diffs == {'ns1': '', 'ns2': ''} and pv.ready and pv.older == {}
    assert not conn.execute('SELECT 1 FROM zones').fetchone()       # a preview records nothing
    text = '\n'.join(line for _, lines in readopt.summary(pv.plan) for line in lines)
    assert 'ns1: primary' in text and 'ns2: secondary; DNS address 198.51.100.54' in text
    assert 'ddns.lab: dynamic (ns1, ns2); grants: acme name _acme-challenge.ddns.lab TXT; dhcp zonesub ANY' in text
    assert 'failover pair: ns1 serves, ns2 stands by' in text and 'subnet 198.51.100.0/24 (id 2)' in text
    assert 'ns1: chrony, serves 198.51.100.0/24, keeps serving without sources' in text and 'server 192.0.2.1 prefer minpoll 4' in text
    assert SECRET not in text


def table(conn, sql):
    return [tuple(r) for r in conn.execute(sql)]


def test_readopt_rebuilds_the_model(conn, settings, old):
    old_conn, fakes = old
    for f in fakes.values():
        f.calls.clear()
    before = {name: (dict(f.config_files), dict(f.kea_files)) for name, f in fakes.items()}
    lines = []
    readopt.readopt(conn, settings, ids(conn), 'admin', lines.append, transfer=transfer)
    log = '\n'.join(lines)
    assert '✓ LiteBlox manages ns1, ns2 again' in log and '✓ the pair runs on certificates from this LiteBlox' in log
    # nothing BIND changed on the nodes; Kea got new TLS files (standby first) and the same JSON
    for name, f in fakes.items():
        assert f.config_files == before[name][0]
        assert {r: t for r, t in f.kea_files.items() if r.endswith('.conf')} == \
            {r: t for r, t in before[name][1].items() if r.endswith('.conf')}
        assert f.kea_files['tls/ca.crt'] == PKI(settings.pki_dir).ca_pem().decode() != before[name][1]['tls/ca.crt']
        assert 'stage' not in f.calls and 'commit' not in f.calls
    assert [n for n, what in fakes['ns1'].all_calls if what == 'commit dhcp'] == ['ns2', 'ns1']

    # the same model, under the new ids
    by_name = {r['name']: r for r in nodes.list_nodes(conn)}
    for name in ('ns1', 'ns2'):
        o, n = nodes.get_node(old_conn, name), by_name[name]
        for col in ('managed', 'role', 'dns_address', 'options', 'top_extra', 'distro_includes', 'dhcp',
                    'kea_hooks_dir', 'dhcp_interfaces', 'ntp', 'ntp_serve', 'ntp_allow', 'ntp_local'):
            assert n[col] == o[col], (name, col)
        assert n['other_liteblox'] == 0 and n['drift'] is None
        assert json.loads(n['config_files']) == fakes[name].status()['config_files']
    assert table(conn, 'SELECT name, items FROM acls') == table(old_conn, 'SELECT name, items FROM acls')
    keys = 'SELECT name, algorithm, secret FROM tsig_keys ORDER BY name'
    assert table(conn, keys) == table(old_conn, keys)
    assert dict(table(conn, 'SELECT name, purpose FROM tsig_keys')) == {
        'acme': 'user', 'dhcp': 'user', 'liteblox': 'liteblox', 'liteblox-xfr': 'liteblox-xfr', 'old-import': 'imported'}
    cols = ('name, kind, dynamic, also_notify, allow_transfer, allow_query, forwarders, forward_mode, repo_file, mode')
    assert table(conn, f'SELECT {cols} FROM zones ORDER BY name') == table(old_conn, f'SELECT {cols} FROM zones ORDER BY name')
    assert dict(table(conn, 'SELECT name, notify FROM zones'))['example.com'] == 'explicit'   # 'no' and 'explicit' render alike
    grants = ('SELECT z.name, k.name, g.scope, g.name, g.types FROM key_grants g JOIN zones z ON z.id = g.zone_id '
              'JOIN tsig_keys k ON k.id = g.key_id ORDER BY 1, 2')
    assert table(conn, grants) == table(old_conn, grants)
    serving = ('SELECT z.name, n.name, zn.node_file FROM zone_nodes zn JOIN zones z ON z.id = zn.zone_id '
               'JOIN nodes n ON n.id = zn.node_id ORDER BY 1, 2')
    assert table(conn, serving) == table(old_conn, serving)
    deployed = dict(((z, n), d) for z, n, d in table(conn, 'SELECT z.name, n.name, zn.deployed_sha256 FROM zone_nodes zn '
                                                           'JOIN zones z ON z.id = zn.zone_id JOIN nodes n ON n.id = zn.node_id'))
    assert deployed[('example.com', 'ns1')] == sha(EXAMPLE) and deployed[('example.com', 'ns2')] is None
    assert deployed[('ddns.lab', 'ns1')] is None
    # the zones' contents are in the repo: static ones as the file, dynamic ones by AXFR
    from liteblox.dns.repo import Repo
    repo = Repo(settings.repo_dir)
    assert repo.read('zones/example.com.zone') == EXAMPLE
    assert 'client 300 IN A 198.51.100.50' in repo.read('zones/ddns.lab.zone')

    sub = 'SELECT id, prefix, interface, pools, options, extra, valid_lifetime, renew_timer, ddns, ddns_suffix FROM dhcp4_subnets'
    assert table(conn, sub) == table(old_conn, sub)
    extra = 'SELECT extra_options FROM dhcp4_subnets ORDER BY id'     # Kea's file sorts each option's keys
    assert [json.loads(r[0]) for r in table(conn, extra)] == [json.loads(r[0]) for r in table(old_conn, extra)]
    res = 'SELECT subnet_id, hw_address, ip_address, hostname, options FROM dhcp4_reservations ORDER BY ip_address'
    assert table(conn, res) == table(old_conn, res)
    assert store.next_subnet_id(conn) == 6
    assert json.loads(table(conn, 'SELECT sources FROM ntp_settings')[0][0]) == json.loads(NTP_SOURCES)
    sets = 'SELECT valid_lifetime, options, extra_options, authoritative FROM dhcp4_settings'
    assert table(conn, sets) == table(old_conn, sets)
    assert conn.execute('SELECT k.name FROM dhcp4_settings s JOIN tsig_keys k ON k.id = s.ddns_key_id').fetchone()[0] == 'dhcp'
    pair = ha_pair(conn)
    assert (pair.primary_name, pair.standby_name, pair.primary_address, pair.standby_address, pair.port) == \
        ('ns1', 'ns2', '198.51.100.53', '198.51.100.54', 8001)
    # from now on it's an ordinary LiteBlox: no drift, no stale DHCP
    from liteblox.nodes import drift
    for n in nodes.list_nodes(conn):
        assert drift.changed_roles(conn, n, fakes[n['name']].status()) == []
        assert drift.dhcp_changed(n, fakes[n['name']].status()) == [] and not dhcp_apply.stale(conn, n) and not ntp_apply.stale(conn, n)
        assert not bind_apply.stale(conn, n)


def written_by_32(fakes):
    """The nodes as LiteBlox 3.2 left them: no statistics channel, no Kea socket retries."""
    for f in fakes.values():
        assert STATS_CHANNEL in f.config_files['top.conf']
        f.config_files['top.conf'] = f.config_files['top.conf'].replace(f'\n{STATS_CHANNEL}\n', '')
        conf = json.loads(f.kea_files['kea-dhcp4.conf'])
        ifaces = conf['Dhcp4']['interfaces-config']
        del ifaces['service-sockets-max-retries'], ifaces['service-sockets-retry-wait-time']
        f.kea_files['kea-dhcp4.conf'] = json.dumps(conf, indent=2, sort_keys=True) + '\n'


def test_nodes_an_older_liteblox_wrote_are_brought_up_to_date(conn, settings, old, client, make_user, login,
                                                               monkeypatch):
    _, fakes = old
    written_by_32(fakes)
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.blockers == [] and pv.ready, pv.diffs
    assert pv.older == {'ns1': ['top.conf', 'kea-dhcp4.conf'], 'ns2': ['top.conf', 'kea-dhcp4.conf']}
    make_user()
    login('alice', 'correct-horse')
    token = csrf_from(client.get('/nodes/readopt').text)
    r = client.post('/nodes/readopt/preview', data={'node': [str(i) for i in ids(conn)]},
                    headers={'X-CSRF-Token': token})
    assert 'written by an older LiteBlox: brought up to date after re-adopt' in r.text and '>Re-adopt</button>' in r.text

    # the pair's new certificates would rewrite Kea at once; leave that to the health check here
    monkeypatch.setattr(dhcp_apply, 'apply_dhcp', lambda *a, **kw: None)
    lines = []
    readopt.readopt(conn, settings, ids(conn), 'admin', lines.append, transfer=transfer)
    assert 'ns1: top.conf, kea-dhcp4.conf written by an older LiteBlox' in '\n'.join(lines)
    from liteblox.nodes import drift
    for n in nodes.list_nodes(conn):
        status = fakes[n['name']].status()
        # the node's own hashes are recorded, so it isn't drift, but it is behind
        assert json.loads(n['config_files']) == status['config_files']
        assert json.loads(n['dhcp_files']) == status['kea']['files']
        assert drift.changed_roles(conn, n, status) == [] and drift.dhcp_changed(n, status) == []
        assert bind_apply.stale(conn, n) and dhcp_apply.stale(conn, n)


def test_a_node_from_before_the_ddns_override_is_only_behind(conn, settings, old):
    """3.3.0-3.3.3 rendered registering subnets without ddns-override-client-update."""
    _, fakes = old
    for f in fakes.values():
        conf = json.loads(f.kea_files['kea-dhcp4.conf'])
        registering = [s for s in conf['Dhcp4']['subnet4'] if s.get('ddns-send-updates')]
        assert registering and all(s.pop('ddns-override-client-update') is True for s in registering)
        f.kea_files['kea-dhcp4.conf'] = json.dumps(conf, indent=2, sort_keys=True) + '\n'
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.blockers == [] and pv.ready, pv.diffs
    assert pv.older == {'ns1': ['kea-dhcp4.conf'], 'ns2': ['kea-dhcp4.conf']}
    readopt.readopt(conn, settings, ids(conn), 'admin', print, transfer=transfer)
    extras = [json.loads(r[0]) for r in conn.execute('SELECT extra FROM dhcp4_subnets')]
    assert not any('ddns-override-client-update' in e for e in extras)
    # the pair's new certificates rewrite Kea straight away, so the nodes have the override again
    for f in fakes.values():
        subnets = json.loads(f.kea_files['kea-dhcp4.conf'])['Dhcp4']['subnet4']
        assert all(s['ddns-override-client-update'] is True for s in subnets if s.get('ddns-send-updates'))
    assert not any(dhcp_apply.stale(conn, n) for n in nodes.list_nodes(conn))


def test_an_older_node_that_differs_otherwise_still_blocks(conn, settings, old):
    _, fakes = old
    written_by_32(fakes)
    fakes['ns2'].config_files['options.conf'] = fakes['ns2'].config_files['options.conf'].replace(
        'recursion yes;', 'recursion yes;\n\tnotify-delay 2;')
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.diffs['ns1'] == '' and '--- ns2 options.conf now' in pv.diffs['ns2'] and not pv.ready
    assert 'top.conf' not in pv.diffs['ns2']
    with pytest.raises(readopt.ReadoptError, match='nothing was recorded'):
        readopt.readopt(conn, settings, ids(conn), 'admin', print, transfer=transfer)
    assert all(not n['managed'] for n in nodes.list_nodes(conn))


def test_a_hand_edited_file_records_nothing(conn, settings, old):
    _, fakes = old
    fakes['ns2'].config_files['options.conf'] = fakes['ns2'].config_files['options.conf'].replace(
        'recursion yes;', 'recursion yes;\n\tnotify-delay 2;')
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.diffs['ns1'] == '' and '--- ns2 options.conf now' in pv.diffs['ns2']
    assert '+\t// extra statements' in pv.diffs['ns2']       # read back as an extra statement, so it renders apart
    assert not pv.ready
    with pytest.raises(readopt.ReadoptError, match='nothing was recorded'):
        readopt.readopt(conn, settings, ids(conn), 'admin', print, transfer=transfer)
    assert not conn.execute('SELECT 1 FROM zones').fetchone() and not conn.execute('SELECT 1 FROM tsig_keys').fetchone()
    assert all(not n['managed'] for n in nodes.list_nodes(conn))


def test_a_key_secret_changed_by_hand_is_caught(conn, settings, old):
    _, fakes = old
    fakes['ns1'].config_files['keys.conf'] = fakes['ns1'].config_files['keys.conf'].replace(SECRET, SECRET[:-4] + 'AAA=')
    pv = readopt.preview(conn, settings, ids(conn))
    assert "its key secrets differ from the other nodes'" in ' '.join(pv.blockers)


@pytest.mark.parametrize('case, message', [
    ('without the primary', 'the primary, at 192.0.2.53, is not one of the nodes'),
    ('without the secondary', "ns1 had secondaries that aren't being re-adopted with it"),
    ('unreachable', 'ns1 is unreachable'),
    ('acls differ', "ns2: its ACLs differ from the other nodes'"),
    ('not liteblox', "LiteBlox didn't generate its BIND config"),
    ('pair renamed', "its Kea failover config calls it 'ns1'"),
])
def test_blockers(conn, settings, old, case, message):
    _, fakes = old
    chosen = ids(conn)
    if case == 'without the primary':
        chosen = [nodes.get_node(conn, 'ns2')['id']]
    elif case == 'without the secondary':
        chosen = [nodes.get_node(conn, 'ns1')['id']]
    elif case == 'unreachable':
        fakes['ns1'].down = True
    elif case == 'acls differ':
        fakes['ns2'].config_files['acls.conf'] += '\nacl "extra" { 192.0.2.9; };\n'
    elif case == 'not liteblox':
        real = fakes['ns2'].status
        fakes['ns2'].status = lambda: dict(real(), taken_over=False)
    elif case == 'pair renamed':
        with conn:
            conn.execute("UPDATE nodes SET name = 'lab-ns1' WHERE name = 'ns1'")
        fakes['lab-ns1'] = fakes['ns1']
    pv = readopt.preview(conn, settings, chosen)
    assert message in ' '.join(pv.blockers), pv.blockers
    with pytest.raises(readopt.ReadoptError):
        readopt.readopt(conn, settings, chosen, 'admin', print, transfer=transfer)
    assert not conn.execute('SELECT 1 FROM zones').fetchone()


def test_a_standby_with_its_own_interface_names(conn, settings, old):
    old_conn, fakes = old
    ns1, ns2 = (nodes.get_node(old_conn, n)['id'] for n in ('ns1', 'ns2'))
    store.set_pair(old_conn, PKI(settings.pki_dir), ns1, ns2, '198.51.100.53', '198.51.100.54', 8001, {'ens19': 'eth1'})
    for node in nodes.list_nodes(old_conn):
        fakes[node['name']].kea_files = dhcp_apply.files_for(old_conn, node)
    fakes['ns2'].lab_name = 'eth1'
    standby = json.loads(fakes['ns2'].kea_files['kea-dhcp4.conf'])['Dhcp4']
    assert standby['interfaces-config']['interfaces'] == ['eth1']
    readopt.readopt(conn, settings, ids(conn), 'admin', print, transfer=transfer)
    assert ha_pair(conn).interface_map == {'ens19': 'eth1'}
    assert {s.interface for s in load_subnets(conn)} == {'ens19'}
    assert nodes.get_node(conn, 'ns2')['dhcp_interfaces'] == '["eth1"]'
    from liteblox.nodes import drift
    for n in nodes.list_nodes(conn):
        assert drift.dhcp_changed(n, fakes[n['name']].status()) == [] and not dhcp_apply.stale(conn, n)


def test_a_standby_subnet_that_differs_beyond_its_interface_still_blocks(conn, settings, old):
    old_conn, fakes = old
    ns1, ns2 = (nodes.get_node(old_conn, n)['id'] for n in ('ns1', 'ns2'))
    store.set_pair(old_conn, PKI(settings.pki_dir), ns1, ns2, '198.51.100.53', '198.51.100.54', 8001, {'ens19': 'eth1'})
    for node in nodes.list_nodes(old_conn):
        fakes[node['name']].kea_files = dhcp_apply.files_for(old_conn, node)
    conf = json.loads(fakes['ns2'].kea_files['kea-dhcp4.conf'])
    conf['Dhcp4']['subnet4'][0]['pools'] = [{'pool': '198.51.100.100 - 198.51.100.120'}]
    fakes['ns2'].kea_files['kea-dhcp4.conf'] = json.dumps(conf, indent=2, sort_keys=True) + '\n'
    pv = readopt.preview(conn, settings, ids(conn))
    assert any('the nodes have it differently' in b for b in pv.blockers), pv.blockers


def test_a_kea_config_not_from_liteblox_is_left_alone(tmp_path, conn, settings, monkeypatch):
    old_settings, old_conn = build_old(tmp_path, dhcp=False)
    fakes = render_old(old_conn)
    fakes['ns1'].kea_files = {'kea-dhcp4.conf': '{"Dhcp4": {}}\n', 'kea-dhcp-ddns.conf': '{}\n'}
    for name, host in (('ns1', '192.0.2.53'), ('ns2', '192.0.2.54')):
        nodes.record_status(conn, nodes.add_node(conn, name, host, 22, 8530, HOST_KEY, FP), fakes[name].status())
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['name']]))
    readopt.readopt(conn, settings, ids(conn), 'admin', print, transfer=transfer)
    assert [n['dhcp'] for n in nodes.list_nodes(conn)] == [0, 0]
    assert not conn.execute('SELECT 1 FROM dhcp4_subnets').fetchone()
    old_conn.close()


def test_a_single_node_is_the_primary(tmp_path, conn, settings, monkeypatch):
    old_settings, old_conn = build_old(tmp_path, dhcp=False)
    with old_conn:
        old_conn.execute("DELETE FROM zone_nodes WHERE node_id = 2")
        old_conn.execute("DELETE FROM nodes WHERE id = 2")
        old_conn.execute("UPDATE nodes SET role = NULL")
    fakes = render_old(old_conn)
    nodes.record_status(conn, nodes.add_node(conn, 'ns1', '192.0.2.53', 22, 8530, HOST_KEY, FP), fakes['ns1'].status())
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['name']]))
    pv = readopt.preview(conn, settings, ids(conn))
    assert pv.ready, (pv.blockers, pv.diffs)
    assert pv.plan.nodes[1]['role'] == 'primary'
    old_conn.close()


def test_bootstrap_hint_and_pages(conn, settings, old, client, make_user, login, monkeypatch):
    make_user()
    login('alice', 'correct-horse')
    page = client.get('/nodes').text
    assert 'href="/nodes/readopt"' in page and 'ns1, ns2 run a config that a LiteBlox generated' in page
    assert 'href="/nodes/readopt">Re-adopt</a>' in client.get(f"/nodes/{nodes.get_node(conn, 'ns1')['id']}").text
    page = client.get('/nodes/readopt').text
    token = csrf_from(page)
    assert page.count('name="node"') == 2
    r = client.post('/nodes/readopt/preview', data={'node': [str(i) for i in ids(conn)]},
                    headers={'X-CSRF-Token': token})
    assert '✓ ns1: every generated file rendered back byte for byte' in r.text and '>Re-adopt</button>' in r.text
    real_start, real_contents = readopt.start, readopt._contents
    monkeypatch.setattr(readopt, 'start', lambda s, i, u: real_start(s, i, u, background=False))
    monkeypatch.setattr(readopt, '_contents', lambda settings, plan, s, t=None: real_contents(settings, plan, s, transfer))
    r = client.post('/nodes/readopt', data={'node': [str(i) for i in ids(conn)], 'csrf_token': token},
                    follow_redirects=False)
    assert r.status_code == 303
    job = conn.execute('SELECT * FROM jobs ORDER BY id DESC').fetchone()
    assert job['kind'] == 're-adopt' and job['status'] == 'ok', job['log']
    assert 'another LiteBlox' not in client.get('/nodes').text


def test_viewers_cannot_readopt(conn, old, client, make_user, login):
    make_user('viewer', 'correct-horse', 'readonly')
    login('viewer', 'correct-horse')
    assert client.get('/nodes/readopt').status_code == 403
    assert 'href="/nodes/readopt"' not in client.get('/nodes').text
