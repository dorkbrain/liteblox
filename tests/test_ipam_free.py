"""IPAM (3.4 M5): next free and holds, assign and unassign, the sweep, the IPAM API and lbcli.py."""

import io
import json
import time

import pytest

from liteblox import jobs
from liteblox.dhcp import ops, store
from liteblox.dns.drafts import Drafts
from liteblox.ipam import assign, free, model, seen, sweep
from liteblox.nodes.client import AgentError
from test_api import bearer, make, people  # noqa: F401 (fixture)
from test_search import world  # noqa: F401 (fixture)

NOW = 1_800_000_000
A, B = 'aa:bb:cc:00:00:0a', 'aa:bb:cc:00:00:0b'


@pytest.fixture
def net(conn, world):  # noqa: F811
    """192.0.2.0/24 in IPAM, a ready node on it (its own .2 and .3), the subnet's router .1."""
    with conn:
        conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp, status, networks, addresses) VALUES "
                     "('ns1', '192.0.2.2', 'k', 'fp', 'ready', '[\"192.0.2.0/24\"]', '[\"192.0.2.2\", \"192.0.2.3\"]')")
        conn.execute('UPDATE dhcp4_subnets SET options = ? WHERE id = 1', (json.dumps({'routers': ['192.0.2.1']}),))
    return model.get(conn, model.add_network(conn, '192.0.2.0/24', 'Lab'))


class Probe:
    """A fake /probe: answers maps ip → result; every call is kept."""

    def __init__(self, answers=None, elapsed=2.0):
        self.answers, self.elapsed, self.calls = answers or {}, elapsed, []

    def __call__(self, node, ips):
        self.calls.append(list(ips))
        return {'method': 'icmp', 'elapsed': self.elapsed,
                'results': {ip: self.answers.get(ip, {'replied': False, 'mac': None, 'state': None, 'confirmed': None})
                            for ip in ips}}


REPLIED = {'replied': True, 'rtt_ms': 0.4, 'state': 'REACHABLE', 'mac': A, 'confirmed': 0}
ARP_ONLY = {'replied': False, 'state': 'REACHABLE', 'mac': B, 'confirmed': 1}
STALE = {'replied': False, 'state': 'STALE', 'mac': B, 'confirmed': 400}


def nf(conn, settings, tgt, **kw):
    kw.setdefault('probe', Probe())
    return free.next_free(conn, settings, tgt, **kw)


# ── targets and what's taken ───────────────────────────────────────────────────

def test_targets(conn, net):
    t = free.target(conn, network='192.0.2.0/24')
    assert (t.kind, str(t.first), str(t.last), t.skip) == ('network', '192.0.2.1', '192.0.2.254',
                                                           [(int(t.first) + 99, int(t.first) + 198)])
    rid = model.save_range(conn, net, '192.0.2.10', '192.0.2.19', 'static', 'Servers')
    t = free.target(conn, range_id=rid)
    assert (t.kind, str(t.first), str(t.last)) == ('range', '192.0.2.10', '192.0.2.19')
    assert free.target(conn, subnet='1').kind == 'subnet'
    model.add_network(conn, '192.0.0.0/16')
    with pytest.raises(free.FreeError, match='holds other networks'):
        free.target(conn, network='192.0.0.0/16')
    for kw in ({}, {'network': '10.9.9.0/24'}, {'subnet': '9'}, {'network': '1', 'subnet': '1'}):
        with pytest.raises(free.FreeError):
            free.target(conn, **kw)


def test_the_first_free_address_skips_what_is_used_and_what_answers(conn, settings, net):
    probe = Probe({'192.0.2.4': REPLIED, '192.0.2.5': STALE})
    out = nf(conn, settings, free.target(conn, network=net.id), probe=probe, username='alice', now=NOW)
    # .1 the router, .2/.3 the node: skipped on paper; .4 answers; .5's entry is old: free
    assert out['ips'] == ['192.0.2.5'] and out['checked'] and out['node'] == 'ns1'
    assert probe.calls[0][:2] == ['192.0.2.4', '192.0.2.5'] and len(probe.calls[0]) == free.BATCH
    assert not any(ip in probe.calls[0] for ip in ('192.0.2.51', '192.0.2.53', '192.0.2.60'))
    assert seen.at_address(conn, '192.0.2.4')[0]['source'] == 'probe'           # what answered was seen
    assert out['hold_until'] == NOW + 600 and free.holds(conn, NOW)['192.0.2.5']['username'] == 'alice'
    # held: the next caller gets another one; once the hold expires it's free again
    assert nf(conn, settings, free.target(conn, network=net.id), now=NOW)['ips'] == ['192.0.2.6']
    # an hour on, .4 and .5 count as seen (the probe saw their MACs), and .6's hold is over
    assert nf(conn, settings, free.target(conn, network=net.id), hold=False, now=NOW + 3600)['ips'] == ['192.0.2.6']


def test_next_free_passes_over_what_was_seen_within_keep_days(conn, settings, net):
    # seen 30 hours ago: free on the map (past the 24 h in use), but next free still leaves it alone
    now = int(time.time())
    seen.record(conn, 1, [{'ip': '192.0.2.4', 'mac': A, 'confirmed': 0}], now=now - 30 * 3600)
    assert nf(conn, settings, free.target(conn, network=net.id), hold=False, now=now)['ips'] == ['192.0.2.5']


def test_arp_without_a_ping_reply_is_in_use(conn, settings, net):
    probe = Probe({'192.0.2.4': ARP_ONLY})
    assert nf(conn, settings, free.target(conn, network=net.id), probe=probe, hold=False)['ips'] == ['192.0.2.5']


def test_a_subnet_target_stays_outside_its_pools(conn, settings, net):
    t = free.target(conn, subnet='192.0.2.0/24')
    probe = Probe({f'192.0.2.{n}': REPLIED for n in range(4, 100)})
    with pytest.raises(free.FreeError, match='No a free address|No free') as e:
        nf(conn, settings, t, probe=probe, hold=False)
    assert all(int(ip.split('.')[-1]) < 100 for call in probe.calls for ip in call)
    assert e.value.status == 409


def test_blocks(conn, settings, net):
    probe = Probe({'192.0.2.6': REPLIED})
    out = nf(conn, settings, free.target(conn, network=net.id), count=3, probe=probe, now=NOW)
    # .4-.6 is free on paper, but .6 answers: the next run starts after it
    assert probe.calls == [['192.0.2.4', '192.0.2.5', '192.0.2.6'], ['192.0.2.7', '192.0.2.8', '192.0.2.9']]
    assert out['ips'] == ['192.0.2.7', '192.0.2.8', '192.0.2.9']
    held = free.holds(conn, NOW)
    assert {held[ip]['hold_id'] for ip in out['ips']} == {out['hold_id']}
    assert free.release(conn, hold_id=out['hold_id']) == out['ips'] and free.holds(conn, NOW) == {}
    out = nf(conn, settings, free.target(conn, network=net.id), count=4, align=True, hold=False)
    assert out['ips'] == ['192.0.2.4', '192.0.2.5', '192.0.2.6', '192.0.2.7'] or out['ips'][0].endswith(('.8', '.12'))
    assert int(out['ips'][0].split('.')[-1]) % 4 == 0
    for count in (0, 65):
        with pytest.raises(free.FreeError, match='count is 1 to 64'):
            nf(conn, settings, free.target(conn, network=net.id), count=count)


def test_without_a_node_nothing_is_checked(conn, settings, net):
    with conn:
        conn.execute("UPDATE nodes SET status = 'error'")
    probe = Probe()
    out = nf(conn, settings, free.target(conn, network=net.id), probe=probe, hold=False)
    assert out['ips'] == ['192.0.2.4'] and not out['checked'] and 'nothing checked' in out['warnings'][0]
    assert probe.calls == []


def test_an_agent_that_cant_probe(conn, settings, net):
    def broken(node, ips):
        raise AgentError('not found', 404)
    out = nf(conn, settings, free.target(conn, network=net.id), probe=broken, hold=False)
    assert out['ips'] == ['192.0.2.4'] and not out['checked'] and "couldn't check" in out['warnings'][0]


# ── assign and unassign ────────────────────────────────────────────────────────

def test_assign_and_unassign_a_static_block(conn, settings, net, monkeypatch):
    published = []
    monkeypatch.setattr(assign, '_publish', lambda s, c, zones, *a: (published.append(sorted(zones)) or [77], []))
    free.next_free(conn, settings, free.target(conn, network=net.id), count=2, probe=Probe())
    with pytest.raises(free.FreeError, match=r'needs \{n\}'):
        assign.assign(conn, settings, ['192.0.2.4', '192.0.2.5'], 'k8s', 'lab.example')
    out = assign.assign(conn, settings, ['192.0.2.4', '192.0.2.5'], 'k8s-{n}', 'lab.example', group='k8s',
                        username='alice')
    assert out['names'] == ['k8s-1.lab.example', 'k8s-2.lab.example'] and out['jobs'] == [77]
    assert published == [['lab.example']] and free.holds(conn) == {}
    text, _ = Drafts(settings).load(conn.execute("SELECT * FROM zones WHERE name = 'lab.example'").fetchone())
    assert 'k8s-1\tIN\tA\t192.0.2.4' in text.replace(' ', '\t') or 'k8s-1' in text
    with pytest.raises(free.FreeError, match='already assigned'):
        assign.assign(conn, settings, ['192.0.2.4'], 'other', 'lab.example')
    out = assign.unassign(conn, settings, assign.expand('192.0.2.3-5'), username='alice')
    assert out['removed'] == ['192.0.2.4', '192.0.2.5'] and out['skipped'] == ['192.0.2.3']
    text, _ = Drafts(settings).load(conn.execute("SELECT * FROM zones WHERE name = 'lab.example'").fetchone())
    assert 'k8s-1' not in text and assign.assignments(conn, group='k8s') == []
    # a record assign didn't make is never touched
    assert assign.unassign(conn, settings, ['192.0.2.51'])['skipped'] == ['192.0.2.51']


def test_assign_reservations_by_mac(conn, settings, net, monkeypatch):
    zone = conn.execute("SELECT id FROM zones WHERE name = 'dyn.lab.example'").fetchone()[0]
    with conn:
        conn.execute('UPDATE dhcp4_subnets SET ddns_zone_id = ? WHERE id = 1', (zone,))
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'liteblox'")
    monkeypatch.setattr(ops, 'dhcp_interfaces', lambda s, c: [])
    started = []
    monkeypatch.setattr(ops, 'start_reservations', lambda s, c, add=(), delete=(), **kw:
                        started.append(([r.ip_address for r in add], [r.id for r in delete])) or 5)
    with pytest.raises(free.FreeError, match='one MAC per address'):
        assign.assign(conn, settings, ['192.0.2.20', '192.0.2.21'], 'node-{n}', macs=[A])
    with pytest.raises(free.FreeError, match='already has a reservation'):
        assign.assign(conn, settings, ['192.0.2.20'], 'dup', macs=['aa:bb:cc:00:00:01'])
    out = assign.assign(conn, settings, ['192.0.2.20', '192.0.2.21'], 'node-{n}', macs=['AA-BB-CC-00-00-0A', B],
                        group='lab')
    assert (out['kind'], out['names'], out['jobs']) == ('reservation', ['node-1', 'node-2'], [5])
    assert started == [(['192.0.2.20', '192.0.2.21'], [])]
    rows = assign.assignments(conn, group='lab')
    assert [(r['ip'], r['mac'], r['zone']) for r in rows] == [('192.0.2.20', A, None), ('192.0.2.21', B, None)]
    # the job would have saved them: unassign finds and deletes them in one job
    from liteblox.dhcp.model import Reservation
    store.save_reservation(conn, Reservation(None, 1, A, '192.0.2.20', 'node-1'))
    monkeypatch.setattr(ops, 'busy', lambda c: True)       # refused before anything is touched
    with pytest.raises(free.FreeError, match='still running'):
        assign.unassign(conn, settings, group='lab')
    with pytest.raises(free.FreeError, match='still running'):
        assign.assign(conn, settings, ['192.0.2.30'], 'later', macs=['aa:bb:cc:00:00:30'])
    assert len(assign.assignments(conn, group='lab')) == 2 and not assign.assignments(conn, ips=['192.0.2.30'])
    monkeypatch.setattr(ops, 'busy', lambda c: False)
    out = assign.unassign(conn, settings, group='lab')
    assert out['removed'] == ['192.0.2.20', '192.0.2.21'] and started[-1][0] == [] and len(started[-1][1]) == 1
    assert "192.0.2.21: its reservation for" in out['notes'][0]


# ── the sweep ──────────────────────────────────────────────────────────────────

def test_the_sweep(conn, settings, net):
    assert sweep.problem(conn, net) is None and sweep.due(conn) == []
    model.update_network(conn, net.id, 'Lab', '', 'hourly')
    assert [n.id for n in sweep.due(conn)] == [net.id]
    probe = Probe({'192.0.2.4': REPLIED, '192.0.2.70': ARP_ONLY, '192.0.2.71': STALE})
    job = sweep.start(settings, conn, model.get(conn, net.id), 'alice', background=False,
                      probe=lambda ips: probe(None, ips))
    row = jobs.get(conn, job)
    assert row['status'] == 'ok' and '✓ 2 of 254 addresses answered' in row['log'] and len(probe.calls) == 4
    assert {r['ip'] for r in conn.execute("SELECT ip FROM ipam_seen WHERE source = 'sweep'")} == {'192.0.2.4',
                                                                                                  '192.0.2.70'}
    assert sweep.due(conn) == []                     # swept just now
    big = model.get(conn, model.add_network(conn, '10.0.0.0/21'))
    assert 'too big' in sweep.problem(conn, big)
    assert 'no node' in sweep.problem(conn, model.get(conn, model.add_network(conn, '10.9.0.0/24')))


# ── the API ────────────────────────────────────────────────────────────────────

def test_the_ipam_api_reads(client, people, conn, settings, net):  # noqa: F811
    read = bearer(make(people, 'bob', 'read'))
    nets = client.get('/api/v1/ipam/networks', headers=read).json()
    assert [(n['prefix'], n['container']) for n in nets] == [('192.0.2.0/24', False)] and nets[0]['used'] >= 4
    detail = client.get(f'/api/v1/ipam/networks/{net.id}', headers=read).json()
    assert [r['kind'] for r in detail['ranges']] == ['dhcp']
    got = client.get(f'/api/v1/ipam/networks/{net.id}/addresses?used_only=true', headers=read).json()
    assert {'ip': '192.0.2.51', 'names': ['pc1.lab.example']}.items() <= {
        k: v for a in got['items'] if a['ip'] == '192.0.2.51' for k, v in a.items()}.items()
    seen.record(conn, None, [{'ip': '192.0.2.77', 'mac': A, 'confirmed': 5}])
    assert client.get('/api/v1/ipam/seen?network=192.0.2.0/24', headers=read).json()[0]['mac'] == A
    assert client.get(f'/api/v1/ipam/seen?mac={B}', headers=read).json() == []
    assert client.get('/api/v1/ipam/flapping', headers=read).json() == []
    assert client.get(f'/api/v1/ipam/devices/{A}', headers=read).json()['seen'][0]['ip'] == '192.0.2.77'
    for method, path in (('post', '/api/v1/ipam/next-free'), ('put', f'/api/v1/ipam/devices/{A}'),
                         ('post', '/api/v1/ipam/assign'), ('delete', '/api/v1/ipam/seen/192.0.2.77')):
        assert client.request(method.upper(), path, headers=read, json={'name': 'x'}).status_code == 403


def test_the_ipam_api_writes(client, people, conn, settings, net, monkeypatch):  # noqa: F811
    full = bearer(make(people, 'alice', 'full'))
    monkeypatch.setattr(free, '_agent_probe', lambda s, node, ips: Probe()(node, ips))
    monkeypatch.setattr(assign, '_publish', lambda *a: ([], []))
    r = client.post('/api/v1/ipam/networks', headers=full, json={'prefix': '198.51.100.0/24', 'name': 'DMZ'})
    assert r.status_code == 201 and r.json()['name'] == 'DMZ'
    nid = r.json()['id']
    assert client.post('/api/v1/ipam/networks', headers=full, json={'prefix': 'nope'}).status_code == 422
    assert client.patch(f'/api/v1/ipam/networks/{nid}', headers=full, json={'sweep': 'daily'}).json()['sweep'] == 'daily'
    r = client.post(f'/api/v1/ipam/networks/{nid}/ranges', headers=full,
                    json={'first': '198.51.100.10', 'last': '198.51.100.20', 'name': 'Servers'})
    assert r.status_code == 201
    rid = r.json()['id']
    assert client.patch(f'/api/v1/ipam/networks/{nid}/ranges/{rid}', headers=full,
                        json={'kind': 'reserved'}).json()['kind'] == 'reserved'
    assert client.delete(f'/api/v1/ipam/networks/{nid}/ranges/{rid}', headers=full).status_code == 204
    assert client.delete(f'/api/v1/ipam/networks/{nid}', headers=full).status_code == 204
    r = client.post('/api/v1/ipam/next-free', headers=full, json={'network': '192.0.2.0/24', 'count': 2})
    assert r.status_code == 200 and r.json()['ips'] == ['192.0.2.4', '192.0.2.5'] and r.json()['checked']
    hold = r.json()['hold_id']
    assert client.request('DELETE', f'/api/v1/ipam/holds?hold_id={hold}', headers=full).json()['released'] == [
        '192.0.2.4', '192.0.2.5']
    assert client.post('/api/v1/ipam/next-free', headers=full, json={'network': '10.1.1.0/24'}).status_code == 404
    r = client.post('/api/v1/ipam/assign', headers=full, json={'ip': '192.0.2.4', 'name': 'web', 'zone': 'lab.example',
                                                               'publish': False})
    assert r.status_code == 200 and r.json()['names'] == ['web.lab.example']
    r = client.post('/api/v1/ipam/unassign', headers=full, json={'range': '192.0.2.4-192.0.2.6', 'publish': False})
    assert r.json()['removed'] == ['192.0.2.4'] and r.json()['skipped'] == ['192.0.2.5', '192.0.2.6']
    assert client.put(f'/api/v1/ipam/devices/{A}', headers=full, json={'label': 'Tablet'}).json()['label'] == 'Tablet'
    assert client.delete(f'/api/v1/ipam/devices/{A}', headers=full).status_code == 204
    assert conn.execute("SELECT count(*) FROM audit WHERE action LIKE 'ipam_%' AND detail LIKE '%(token %'"
                        ).fetchone()[0] >= 8


# ── lbcli.py ───────────────────────────────────────────────────────────────────

def lbcli(client, monkeypatch):
    """The client, its opener talking to the test app."""
    import importlib.util
    import urllib.error
    from pathlib import Path
    spec = importlib.util.spec_from_file_location('lbcli', Path(__file__).parents[1] / 'liteblox/static/lbcli.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class Opener:
        def open(self, req, timeout=None, **kw):
            path = req.full_url.replace('http://lb', '')
            r = client.request(req.get_method(), path, headers=dict(req.header_items()), content=req.data)
            if r.status_code >= 400:
                raise urllib.error.HTTPError(req.full_url, r.status_code, r.reason_phrase, {}, io.BytesIO(r.content))
            return io.BytesIO(r.content)
    mod.opener = Opener()
    return mod


def test_lbcli(client, people, conn, settings, net, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(free, '_agent_probe', lambda s, node, ips: Probe()(node, ips))
    monkeypatch.setattr(assign, '_publish', lambda *a: ([], []))
    monkeypatch.setenv('LITEBLOX_URL', 'http://lb')
    monkeypatch.setenv('LITEBLOX_TOKEN', make(people, 'alice', 'full'))
    cli = lbcli(client, monkeypatch)
    assert cli.main(['next', '--network', '192.0.2.0/24', '--blocksize', '3', '--no-hold']) == 0
    assert capsys.readouterr().out.strip() == '192.0.2.4, 192.0.2.5, 192.0.2.6'
    assert cli.main(['reserve', 'k8s-{n}', '--network', '192.0.2.0/24', '--blocksize', '2', '--zone', 'lab.example',
                     '--group', 'k8s', '--no-publish']) == 0
    out = capsys.readouterr().out
    assert '✓ 192.0.2.4 k8s-1.lab.example (A record)' in out and '✓ 192.0.2.5 k8s-2.lab.example' in out
    assert cli.main(['--json', 'show', '192.0.2.4']) == 0
    assert json.loads(capsys.readouterr().out)['names'] == ['k8s-1.lab.example']     # from the draft
    assert cli.main(['unassign', '--group', 'k8s', '--no-publish']) == 0
    assert '✓ unassigned 192.0.2.4' in capsys.readouterr().out
    assert cli.main(['next', '--network', '10.1.1.0/24']) == 1
    assert 'ERROR: 404 no such network in IPAM' in capsys.readouterr().err
    monkeypatch.delenv('LITEBLOX_TOKEN')
    assert cli.main(['show', '192.0.2.4']) == 1 and 'LITEBLOX_TOKEN' in capsys.readouterr().err


def test_the_sweep_settings_page(client, make_user, login, conn, net, monkeypatch):
    from test_ipam_seen import post
    login(*make_user('carol', 'correct-horse', 'admin'))
    page = client.get(f'/ipam/networks/{net.id}/settings').text
    assert 'Sweep now' in page and '<option value="1">ns1</option>' in page and 'Not swept yet' in page
    r = post(client, f'/ipam/networks/{net.id}/settings', name='Lab', comment='', sweep='daily', sweep_node='1')
    assert r.status_code == 303 and (model.get(conn, net.id).sweep, model.get(conn, net.id).sweep_node_id) == ('daily', 1)
    monkeypatch.setattr(sweep, 'run', lambda settings, network_id, log, probe=None: log('Sweeping (test)'))
    r = post(client, f'/ipam/networks/{net.id}/sweep')
    assert r.status_code == 303 and r.headers['location'].startswith('/jobs/')
    big = model.add_network(conn, '10.0.0.0/21')
    assert 'Sweep now' not in client.get(f'/ipam/networks/{big}/settings').text
    assert 'too%20big' in post(client, f'/ipam/networks/{big}/sweep').headers['location']


def test_kept_back_ranges_apply_to_a_subnet_too(conn, settings, net):
    model.save_range(conn, net, '192.0.2.4', '192.0.2.9', 'infrastructure', 'Switches')
    t = free.target(conn, subnet='1')
    assert free.next_free(conn, settings, t, probe=Probe(), hold=False)['ips'] == ['192.0.2.10']


def test_publish_notes_dropped_for_zones_published():
    notes = ['adding the PTR for 192.0.2.4 in 2.0.192.in-addr.arpa is sent when you publish lab.example',
             'adding the PTR for 10.0.0.4 in 10.in-addr.arpa is sent when you publish other.example', 'kept']
    assert assign._published(notes, {'lab.example'}) == notes[1:]
