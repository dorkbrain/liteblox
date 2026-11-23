"""Make a node the primary: a dual-master pair (or a node taken over later) becomes primary + secondaries."""

import pytest

from liteblox import jobs
from liteblox.dns import declare, publish as pub
from liteblox.dns.drafts import Drafts
from liteblox.nodes import roles
from liteblox.nodes import service as nodes

from conftest import csrf_from
from test_managed import NS, Client, FakeNode, lab, ok_verify, sha  # noqa: F401 (fixtures)


@pytest.fixture
def pair(conn, settings, lab, monkeypatch):  # noqa: F811
    """new.lab on both nodes as primary copies, other.lab on ns2 only; nothing picked yet."""
    fakes, snapshots = lab
    monkeypatch.setattr(roles.nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['id']]))
    # secondaries are asked over DNS: they serve the primary's copy
    monkeypatch.setattr(pub, 'served_serial', lambda host, zone, timeout=2.0: pub._file_serial(
        fakes[1].files.get(zone, ''), zone))
    monkeypatch.setattr('liteblox.backups.service.snapshot_before_change',
                        lambda conn, settings, node, reason, username: snapshots.append((node['name'], reason)))
    declare.create_zone(settings, 'new.lab', ['1', '2'], declare.starter_zone('new.lab', NS), 'admin', print,
                        verify=ok_verify)
    declare.create_zone(settings, 'other.lab', ['2'], declare.starter_zone('other.lab', [('ns.example.net', None)]),
                        'admin', print, verify=ok_verify)
    for f in fakes.values():
        f.calls.clear()
    snapshots.clear()
    return fakes, snapshots


def test_make_primary_converts_a_dual_master_pair(conn, settings, pair):
    fakes, snapshots = pair
    lines = []
    roles.make_primary(settings, 1, 'admin', lines.append, verify=ok_verify)
    assert [n['role'] for n in nodes.list_nodes(conn)] == ['primary', 'secondary']
    ns1, ns2 = fakes[1], fakes[2]
    assert ns1.all_calls.index(('ns1', 'commit')) < ns1.all_calls.index(('ns2', 'commit'))   # the primary first
    assert snapshots == [('ns1', 'change node roles'), ('ns2', 'change node roles')]

    # ns1 holds both zones, other.lab copied from LiteBlox's published copy
    assert {n: z['type'] for n, z in ns1.declared().items()} == {'new.lab': 'primary', 'other.lab': 'primary'}
    other = conn.execute("SELECT * FROM zones WHERE name = 'other.lab'").fetchone()
    assert ns1.files['other.lab'] == Drafts(settings).published(other)
    assert ns1.zones_conf.count('also-notify { 192.0.2.54; };') == 2
    assert ns1.zones_conf.count('allow-transfer { key liteblox-xfr; };') == 2
    assert ns1.declared()['new.lab']['journal'] == '/var/lib/bind/liteblox/jnl/db.new.lab.jnl'
    # ns2 transfers both from ns1, with LiteBlox's key
    assert {n: z['type'] for n, z in ns2.declared().items()} == {'new.lab': 'secondary', 'other.lab': 'secondary'}
    assert ns2.zones_conf.count('primaries { 192.0.2.53 key liteblox-xfr; };') == 2
    for f in (ns1, ns2):
        assert 'key "liteblox-xfr"' in f.config_files['keys.conf']
    key = conn.execute("SELECT purpose, algorithm FROM tsig_keys WHERE name = 'liteblox-xfr'").fetchone()
    assert tuple(key) == ('liteblox-xfr', 'hmac-sha256')

    links = {(r['zone'], r['node']): (r['node_file'], r['deployed_sha256']) for r in conn.execute(
        'SELECT z.name AS zone, n.name AS node, zn.node_file, zn.deployed_sha256 FROM zone_nodes zn '
        'JOIN zones z ON z.id = zn.zone_id JOIN nodes n ON n.id = zn.node_id')}
    assert links[('other.lab', 'ns1')] == ('/etc/bind/liteblox/db.other.lab', sha(Drafts(settings).published(other)))
    assert links[('new.lab', 'ns2')] == ('/var/lib/bind/liteblox/sec/db.new.lab', None)
    assert any('ns1 is the primary; ns2 is its secondary' in line for line in lines)

    # running it again changes nothing that matters, and the topology has nothing pending
    roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    assert roles.topology(conn)['pending'] == []


def test_make_primary_refuses_drift_and_unknown_addresses(conn, settings, pair):
    fakes, snapshots = pair
    fakes[2].files['new.lab'] += '; edited on the node\n'
    with pytest.raises(roles.RoleError, match="new.lab: ns2's copy was changed outside LiteBlox"):
        roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    fakes[2].files['new.lab'] = fakes[1].files['new.lab']
    with conn:
        conn.execute("UPDATE nodes SET host = 'ns2.example.lab' WHERE id = 2")
    with pytest.raises(roles.RoleError, match="ns2's DNS address isn't known"):
        roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    with conn:
        conn.execute("UPDATE nodes SET dns_address = '192.0.2.54', managed = 0 WHERE id = 2")
    with pytest.raises(roles.RoleError, match="ns2 isn't taken over yet"):
        roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    assert snapshots == [] and all(f.calls == [] for f in fakes.values())
    assert [n['role'] for n in nodes.list_nodes(conn)] == [None, None]


def test_a_secondary_that_does_not_transfer_is_rolled_back(conn, settings, pair):
    fakes, _ = pair
    verify = lambda host, zone, serial, **kw: None if host == '192.0.2.54' else serial
    with pytest.raises(roles.RoleError, match='not every node became its secondary'):
        roles.make_primary(settings, 1, 'admin', print, verify=verify)
    assert fakes[2].calls[-1] == 'rollback'
    assert {z['type'] for z in fakes[2].declared().values()} == {'primary'}     # back to its primary copies
    assert [n['role'] for n in nodes.list_nodes(conn)] == ['primary', None]
    assert 'also-notify' not in fakes[1].zones_conf                              # rewritten without ns2
    assert roles.topology(conn)['pending'][0]['name'] == 'ns2'


def test_a_primary_that_fails_changes_nothing(conn, settings, pair):
    fakes, _ = pair
    fakes[1].fail_commit = True
    with pytest.raises(roles.RoleError, match='ns1 could not become the primary'):
        roles.make_primary(settings, 1, 'admin', print, verify=ok_verify)
    assert [n['role'] for n in nodes.list_nodes(conn)] == [None, None]
    assert fakes[2].calls == []
    assert not conn.execute("SELECT 1 FROM zone_nodes zn JOIN zones z ON z.id = zn.zone_id "
                            "WHERE z.name = 'other.lab' AND zn.node_id = 1").fetchone()


def test_nodes_page_and_route(client, make_user, login, conn, settings, pair, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'wait_for_serial', lambda host, zone, serial, attempts=6, delay=1.0: serial)
    login(*make_user('admin', 'admin-password', 'admin'))
    page = client.get('/nodes').text
    assert 'No primary is picked yet' in page and 'Make ns1 the primary' in page
    r = client.post('/nodes/1/primary', data={'csrf_token': csrf_from(page)}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    page = client.get('/nodes').text
    assert 'is the primary' in page and '<span class="pill">secondary</span>' in page
    assert 'ns2 · secondary' in client.get('/zones/new.lab').text
