"""IPAM without DNS (4.0 M3): IPAM records (names kept in IPAM only), assign to them, and PTR lookups (rDNS)."""

import json
import socket
import threading

import dns.message
import dns.rcode
import dns.rrset
import pytest

from liteblox import db, modules, search
from liteblox.ipam import assign, checks, free, model, names, ptr, sweep, view
from test_api import bearer, make, people  # noqa: F401 (fixture)
from test_ipam import admin, post, viewer  # noqa: F401 (fixtures)
from test_ipam_free import Probe, lbcli, net  # noqa: F401 (fixture)
from test_search import world  # noqa: F401 (fixture)

A, B = 'aa:bb:cc:00:00:0a', 'aa:bb:cc:00:00:0b'


def dns_off(conn):
    """An IPAM-only install: no zones, DNS (and DHCP) off."""
    with conn:
        conn.execute('DELETE FROM zones')
        conn.execute('DELETE FROM dhcp4_subnets')
        conn.execute('UPDATE modules SET dns = 0, dhcp = 0')


@pytest.fixture
def bare(conn):
    """192.0.2.0/24 in IPAM, nothing else: no zones, no DHCP, DNS off."""
    dns_off(conn)
    return model.get(conn, model.add_network(conn, '192.0.2.0/24', 'Lab'))


def lab(conn, settings, network):
    facts = view.gather(conn, settings)
    rows = {str(r['ip']): r for r in view.rows(facts, network, model.all_ranges(conn, network, facts.subnets),
                                                model.notes(conn))}
    return facts, rows


# ── the migration ──────────────────────────────────────────────────────────────

def test_migration_34(conn):
    assert db.schema_version(conn) >= 34
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(ipam_settings)')}
    assert {'resolver', 'ptr_hours'} <= cols
    assert ptr.config(conn) == ('', 24)
    assert {r['name'] for r in conn.execute('PRAGMA table_info(ipam_ptr)')} == {'ip', 'name', 'looked_up_at', 'error'}
    with conn:      # kind 'ipam' is allowed now, anything else still isn't
        conn.execute("INSERT INTO ipam_assignments (ip, kind, name, created_at) VALUES ('192.0.2.9', 'ipam', 'x', 1)")
    with pytest.raises(Exception):
        with conn:
            conn.execute("INSERT INTO ipam_assignments (ip, kind, name, created_at) VALUES ('192.0.2.8', 'bad', 'x', 1)")
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'ipam_assignments_grp'").fetchone()


def test_migration_keeps_existing_assignments(tmp_path):
    path = tmp_path / 'old.db'
    conn = db.connect(path)
    for version, sql in enumerate(db.MIGRATIONS[:33], start=1):
        conn.executescript(f'BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;')
    with conn:
        conn.execute("INSERT INTO ipam_assignments (ip, grp, kind, name, zone, created_at) "
                     "VALUES ('192.0.2.7', 'lab', 'static', 'pc.lab.example', 'lab.example', 5)")
    conn.close()
    assert db.migrate(path) == len(db.MIGRATIONS)
    conn = db.connect(path)
    row = conn.execute('SELECT * FROM ipam_assignments').fetchone()
    assert (row['ip'], row['grp'], row['kind'], row['zone'], row['created_at']) == ('192.0.2.7', 'lab', 'static',
                                                                                   'lab.example', 5)
    conn.close()


# ── IPAM records ───────────────────────────────────────────────────────────────

def test_save_validate_and_delete(conn):
    assert names.save(conn, '192.0.2.10', 'NAS.Home.', 'AA-BB-CC-00-00-0A', ' the NAS ', 'alice') is True
    r = names.get(conn, '192.0.2.10')
    assert (r['name'], r['mac'], r['comment'], r['kind'], r['username']) == ('nas.home', A, 'the NAS', 'ipam', 'alice')
    assert names.save(conn, '192.0.2.10', 'nas2', '', '', 'bob') is False
    assert (names.get(conn, '192.0.2.10')['name'], names.get(conn, '192.0.2.10')['mac']) == ('nas2', None)
    with pytest.raises(model.IpamError) as e:
        names.save(conn, '192.0.2.11', 'bad name!', 'zz', '')
    assert set(e.value.errors) == {'name', 'mac'}
    with pytest.raises(model.IpamError, match='not an IPv4'):
        names.save(conn, '192.0.2.300', 'x')
    with conn:
        conn.execute("INSERT INTO ipam_assignments (ip, kind, name, created_at) VALUES ('192.0.2.12', 'static', "
                     "'pc.lab.example', 1)")
    with pytest.raises(model.IpamError, match='unassign it first'):
        names.save(conn, '192.0.2.12', 'pc')
    assert names.delete(conn, '192.0.2.10') and not names.delete(conn, '192.0.2.10')
    assert names.delete(conn, '192.0.2.12') is False            # never touches what assign made in DNS


def test_a_note_becomes_the_records_comment(conn):
    model.set_note(conn, '192.0.2.10', 'kept for the NAS', 'alice')
    names.save(conn, '192.0.2.10', 'nas')
    assert names.get(conn, '192.0.2.10')['comment'] == 'kept for the NAS' and model.notes(conn) == {}


def test_named_state_counts_map_and_checks(conn, settings, bare):
    names.save(conn, '192.0.2.10', 'nas', A, 'the NAS')
    from liteblox.ipam import seen
    seen.record(conn, None, [{'ip': '192.0.2.10', 'mac': B, 'confirmed': 0}])
    facts, rows = lab(conn, settings, bare)
    a = rows['192.0.2.10']
    assert (a['state'], a['label'], a['ipam']['name'], a['mac'], a['comment'], a['comment_from']) == (
        'named', 'Named', 'nas', A, 'the NAS', {'kind': 'ipam'})
    assert a['nameable'] and rows['192.0.2.11']['nameable']
    assert ('warn', f'IPAM has it for {A}, but the nodes last saw {B} on it.', '/ipam/seen?q=192.0.2.10') in a['checks']
    assert view.counts(facts, bare)['named'] == 1 and int(a['ip']) in facts.used
    cell = next(c for c in view.cells(list(rows.values()), []) if str(c['ip']) == '192.0.2.10')
    assert cell['state'] == 'named' and 'nas' in cell['title']
    assert int(a['ip']) in free.taken(conn, facts)                 # next free skips it


def test_the_ptr_check():
    rec = {'name': 'nas', 'mac': None}
    assert checks.address_checks(None, [], [], None, None, None, None, False, ipam=rec,
                                 rdns={'name': 'nas.home.lan', 'error': None}) == []
    found = checks.address_checks(None, [], [], None, None, None, None, False, ipam=rec,
                                  rdns={'name': 'printer.home.lan', 'error': None})
    assert found == [('warn', 'IPAM names it nas, but its PTR at the resolver says printer.home.lan.', None)]
    assert checks.address_checks(None, [], [], None, None, None, None, False, ipam=rec,
                                 rdns={'name': '', 'error': 'timeout'}) == []


def test_with_dns_on_only_uncovered_addresses_are_nameable(conn, settings, world):  # noqa: F811
    n = model.get(conn, model.add_network(conn, '192.0.2.0/24'))
    other = model.get(conn, model.add_network(conn, '198.51.100.0/24'))
    _, rows = lab(conn, settings, n)
    assert not rows['192.0.2.30']['nameable']           # 2.0.192.in-addr.arpa covers it
    _, rows = lab(conn, settings, other)
    assert rows['198.51.100.30']['nameable']


def test_search_finds_ipam_records(conn, settings, bare):
    names.save(conn, '192.0.2.10', 'nas.home', A, 'the big disk')
    for q in ('nas', 'big disk', '192.0.2.0/24', 'aa:bb:cc:00:00', '192.0.2.10'):
        assert [r['ip'] for r in search.search(conn, settings, q).ipam.hits] == ['192.0.2.10'], q
    res = search.search(conn, settings, '192.0.2.10')
    assert res.address['ipam']['name'] == 'nas.home' and res.address['used']
    out = search.to_dict(res)
    assert out['address']['ipam'] == {'name': 'nas.home', 'mac': A, 'comment': 'the big disk'}
    assert out['ipam']['items'][0]['name'] == 'nas.home'
    with conn:
        conn.execute('UPDATE modules SET ipam = 0, dns = 1')
    assert search.search(conn, settings, 'nas').ipam.count == 0


# ── pages ──────────────────────────────────────────────────────────────────────

def test_name_this_address(admin, conn, settings, bare):  # noqa: F811
    page = admin.get(f'/ipam/networks/{bare.id}').text
    assert '/ipam/names/192.0.2.10?back=' in page and 'Name…' in page
    form = admin.get('/ipam/names/192.0.2.10?back=/ipam/networks/1%3Fip%3D192.0.2.10').text
    assert 'Give this address a name kept in IPAM only' in form and 'Remove this name' not in form
    r = post(admin, '/ipam/names/192.0.2.10', name='bad name!', mac='', comment='', back='/ipam')
    assert r.status_code == 422 and 'is not a host name' in r.text
    r = post(admin, '/ipam/names/192.0.2.10', name='nas', mac=A, comment='the NAS',
             back=f'/ipam/networks/{bare.id}?ip=192.0.2.10')
    assert r.status_code == 303 and r.headers['location'].startswith(f'/ipam/networks/{bare.id}?ip=192.0.2.10&done=')
    page = admin.get(f'/ipam/networks/{bare.id}').text
    assert '<span class="pill s-named">Named</span>' in page and '<code>nas</code> <span class="muted small">IPAM' in page
    assert 'Named in IPAM' in page and 'IPAM record</span>' in page
    assert 'Remove this name' in admin.get('/ipam/names/192.0.2.10').text
    # the comment edit goes to the record
    r = post(admin, '/ipam/comment', ip='192.0.2.10', kind='ipam', comment='moved', back=f'/ipam/networks/{bare.id}')
    assert r.status_code == 303 and names.get(conn, '192.0.2.10')['comment'] == 'moved'
    card = admin.get('/search?q=192.0.2.10').text
    assert 'IPAM name' in card and '<code>nas</code>' in card and 'no A record' not in card
    r = post(admin, '/ipam/names/192.0.2.10/delete', back='/search?q=192.0.2.10#address')
    assert r.status_code == 303 and r.headers['location'].endswith('#address') and 'done=' in r.headers['location']
    assert names.get(conn, '192.0.2.10') is None
    assert post(admin, '/ipam/names/192.0.2.10/delete').status_code == 404
    assert 'Name this address…' in admin.get('/search?q=192.0.2.10').text
    assert post(admin, '/ipam/names/192.0.2.10', name='x', back='https://evil.example/').headers['location'].startswith(
        '/search?q=192.0.2.10')
    assert conn.execute("SELECT count(*) FROM audit WHERE action IN ('ipam_name', 'ipam_name_delete')").fetchone()[0] >= 3


def test_viewers_cant_name(viewer, conn, bare):  # noqa: F811
    assert viewer.get('/ipam/names/192.0.2.10').status_code == 403
    assert 'Name…' not in viewer.get(f'/ipam/networks/{bare.id}').text


def test_ptr_settings(admin, conn):  # noqa: F811
    page = admin.get('/settings/ipam').text
    assert 'Names from DNS (PTR lookups)' in page and 'name="resolver"' in page
    base = {'keep_days': '7', 'flap_changes': '3', 'flap_minutes': '10'}
    r = post(admin, '/settings/ipam', **base, resolver='dns.example', ptr_hours='24')
    assert r.status_code == 422 and 'give an IPv4 address' in r.text
    r = post(admin, '/settings/ipam', **base, resolver='192.0.2.53:99999', ptr_hours='0')
    assert r.status_code == 422 and 'from 1 to 65535' in r.text and 'from 1 to 720' in r.text
    with conn:
        conn.execute("INSERT INTO ipam_ptr VALUES ('192.0.2.10', 'old', 1, NULL)")
    r = post(admin, '/settings/ipam', **base, resolver='192.0.2.53:5353', ptr_hours='6')
    assert r.status_code == 303 and ptr.config(conn) == ('192.0.2.53:5353', 6)
    assert ptr.cached(conn) == {}                       # the old resolver's names go
    assert 'PTR lookups at 192.0.2.53:5353 every 6 h' in conn.execute(
        "SELECT detail FROM audit WHERE action = 'ipam_settings' ORDER BY id DESC").fetchone()[0]


# ── assign and unassign to IPAM records ────────────────────────────────────────

def test_assign_with_dns_off_makes_ipam_records(conn, settings, bare):
    out = assign.assign(conn, settings, ['192.0.2.20', '192.0.2.21'], 'k8s-{n}', group='k8s', comment='lab',
                        username='alice')
    assert (out['kind'], out['kinds'], out['names'], out['jobs']) == ('ipam', ['ipam', 'ipam'], ['k8s-1', 'k8s-2'], [])
    assert names.get(conn, '192.0.2.21')['comment'] == 'lab'
    out = assign.assign(conn, settings, ['192.0.2.22'], 'cam', zone='home.lan', macs=[A])
    assert out['names'] == ['cam.home.lan'] and names.get(conn, '192.0.2.22')['mac'] == A
    with pytest.raises(free.FreeError, match='already assigned'):
        assign.assign(conn, settings, ['192.0.2.20'], 'again')
    with pytest.raises(free.FreeError, match='DNS module is off'):
        assign.assign(conn, settings, ['192.0.2.23'], 'x', target='dns')
    with pytest.raises(free.FreeError, match='target is dns or ipam'):
        assign.assign(conn, settings, ['192.0.2.23'], 'x', target='bind')
    with pytest.raises(free.FreeError, match='not a MAC'):
        assign.assign(conn, settings, ['192.0.2.23'], 'x', macs=['nope'])
    out = assign.unassign(conn, settings, group='k8s')
    assert out['removed'] == ['192.0.2.20', '192.0.2.21'] and names.get(conn, '192.0.2.20') is None


def test_assign_target_ipam_with_dns_on(conn, settings, world, monkeypatch):  # noqa: F811
    from liteblox.dhcp import ops
    monkeypatch.setattr(assign, '_publish', lambda *a: ([], []))
    started = []
    monkeypatch.setattr(ops, 'start_reservations', lambda settings, conn, **kw: started.append(kw) or 7)
    monkeypatch.setattr(ops, 'dhcp_interfaces', lambda settings, conn: {})
    out = assign.assign(conn, settings, ['198.51.100.5'], 'gw', target='ipam')
    assert out['kinds'] == ['ipam'] and names.get(conn, '198.51.100.5')['name'] == 'gw'
    # a MAC in the DHCP subnet still makes a reservation, but no A record goes into a zone
    out = assign.assign(conn, settings, ['192.0.2.70', '198.51.100.6'], 'tv-{n}', macs=[A, B], target='ipam')
    assert out['kinds'] == ['reservation', 'ipam'] and out['kind'] == 'mixed' and out['jobs'] == [7]
    assert [r.hostname for r in started[0]['add']] == ['tv-1']
    assert search.search(conn, settings, 'tv-1').records.count == 0
    assert names.get(conn, '198.51.100.6')['mac'] == B


def test_api_names_assign_and_addresses(client, people, conn, settings, bare):  # noqa: F811
    full, ro = bearer(make(people, 'alice', 'full')), bearer(make(people, 'bob', 'read'))
    assert client.put('/api/v1/ipam/names/192.0.2.10', headers=ro, json={'name': 'nas'}).status_code == 403
    r = client.put('/api/v1/ipam/names/192.0.2.10', headers=full, json={'name': 'NAS', 'mac': A, 'comment': 'x'})
    assert r.status_code == 200 and r.json()['name'] == 'nas' and r.json()['mac'] == A
    assert client.put('/api/v1/ipam/names/192.0.2.11', headers=full, json={'name': '!'}).json()['errors']['name']
    assert [n['ip'] for n in client.get('/api/v1/ipam/names?network=192.0.2.0/24', headers=ro).json()] == ['192.0.2.10']
    assert client.get('/api/v1/ipam/names/192.0.2.10', headers=ro).json()['comment'] == 'x'
    r = client.post('/api/v1/ipam/assign', headers=full, json={'ip': '192.0.2.30', 'name': 'web'})
    assert r.status_code == 200 and r.json()['kinds'] == ['ipam']
    items = {a['ip']: a for a in client.get(f'/api/v1/ipam/networks/{bare.id}/addresses?used_only=true',
                                            headers=ro).json()['items']}
    assert (items['192.0.2.10']['state'], items['192.0.2.10']['ipam_name'], items['192.0.2.10']['comment_from']) == (
        'named', 'nas', 'ipam')
    a = client.get('/api/v1/search?q=192.0.2.30', headers=ro).json()['address']
    assert a['ipam']['name'] == 'web'
    assert client.delete('/api/v1/ipam/names/192.0.2.10', headers=full).status_code == 204
    assert client.delete('/api/v1/ipam/names/192.0.2.10', headers=full).status_code == 404


def test_lbcli_reserve_ipam(client, people, conn, settings, net, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(free, '_agent_probe', lambda s, node, ips: Probe()(node, ips))
    monkeypatch.setenv('LITEBLOX_URL', 'http://lb')
    monkeypatch.setenv('LITEBLOX_TOKEN', make(people, 'alice', 'full'))
    cli = lbcli(client, monkeypatch)
    assert cli.main(['reserve', 'box', '--network', '192.0.2.0/24', '--ipam']) == 0
    assert '✓ 192.0.2.4 box (IPAM name)' in capsys.readouterr().out
    assert cli.main(['show', '192.0.2.4']) == 0
    out = capsys.readouterr().out
    assert 'ipam name    box' in out and '  names        -' in out and '  lease        -' in out
    with conn:      # DNS off: no '-' names lines (the DHCP lines stay: a subnet holds the address)
        conn.execute('UPDATE modules SET dns = 0, dhcp = 0, ntp = 0')
    assert cli.main(['show', '192.0.2.4']) == 0
    out = capsys.readouterr().out
    assert 'ipam name    box' in out and '  names' not in out and '  ptr' not in out
    assert cli.main(['unassign', '192.0.2.4']) == 0


# ── PTR lookups ────────────────────────────────────────────────────────────────

def test_parse_resolver():
    assert ptr.parse_resolver('') is None and ptr.parse_resolver(' 192.0.2.53 ') == ('192.0.2.53', 53)
    assert ptr.parse_resolver('192.0.2.53:5353') == ('192.0.2.53', 5353)
    for bad in ('dns.example', '192.0.2.53:x', '192.0.2.53:0', '192.0.2.300'):
        with pytest.raises(ValueError):
            ptr.parse_resolver(bad)


class FakeDns:
    """A UDP DNS server on 127.0.0.1: answers PTR from names, NXDOMAIN otherwise; drop: never answers."""

    def __init__(self, names, drop=()):
        self.names, self.drop = names, set(drop)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            q = dns.message.from_wire(data)
            owner = q.question[0].name.to_text()
            if owner in self.drop:
                continue
            r = dns.message.make_response(q)
            if owner in self.names:
                r.answer.append(dns.rrset.from_text(owner, 300, 'IN', 'PTR', self.names[owner]))
            else:
                r.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(r.to_wire(), peer)

    def close(self):
        self.sock.close()


def test_lookup_against_a_real_server():
    server = FakeDns({'10.2.0.192.in-addr.arpa.': 'NAS.home.lan.'}, drop=['11.2.0.192.in-addr.arpa.'])
    try:
        assert ptr.lookup('127.0.0.1', server.port, '192.0.2.10') == ('nas.home.lan', None)
        assert ptr.lookup('127.0.0.1', server.port, '192.0.2.12') == ('', None)
        name, error = ptr.lookup('127.0.0.1', server.port, '192.0.2.11', timeout=0.3)
        assert name == '' and 'no answer in 0.3 s' in error
    finally:
        server.close()


@pytest.fixture
def fake(monkeypatch):
    calls = []
    answers = {'192.0.2.10': ('nas.home.lan', None), '192.0.2.11': ('', None), '192.0.2.12': ('', 'timeout')}

    def lookup(host, port, ip, timeout=ptr.TIMEOUT):
        calls.append((host, port, ip))
        return answers.get(ip, ('', None))
    monkeypatch.setattr(ptr, 'LOOKUP', lookup)
    return calls


def test_refresh_stale_and_retry(conn, fake):
    assert ptr.refresh(conn, ['192.0.2.10', '192.0.2.11', '192.0.2.12'], ('192.0.2.53', 53)) == {
        'names': 1, 'none': 1, 'errors': 1}
    cached = ptr.cached(conn)
    assert {str(ip): (r['name'], r['error']) for ip, r in cached.items()} == {
        '192.0.2.10': ('nas.home.lan', None), '192.0.2.11': ('', None), '192.0.2.12': ('', 'timeout')}
    t = cached[next(iter(cached))]['looked_up_at']
    ips = ['192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.13']
    assert ptr.stale(conn, ips, 24, now=t + 60) == ['192.0.2.13']
    assert ptr.stale(conn, ips, 24, now=t + ptr.RETRY) == ['192.0.2.12', '192.0.2.13']     # errors retry sooner
    assert ptr.stale(conn, ips, 24, now=t + 86400) == ips


def test_refresh_later_runs_in_the_background_and_only_when_set(conn, settings, fake):
    assert ptr.refresh_later(settings, conn, ['192.0.2.10']) == 0 and fake == []          # no resolver: off
    ptr.save(conn, '192.0.2.53:5353', 24)
    assert ptr.refresh_later(settings, conn, ['192.0.2.10', '192.0.2.11']) == 2
    ptr.wait()
    assert sorted(fake) == [('192.0.2.53', 5353, '192.0.2.10'), ('192.0.2.53', 5353, '192.0.2.11')]
    assert ptr.refresh_later(settings, conn, ['192.0.2.10', '192.0.2.11']) == 0            # fresh: nothing to do
    ips = [f'10.0.{n // 256}.{n % 256}' for n in range(400)]
    assert ptr.refresh_later(settings, conn, ips) == ptr.MAX
    ptr.wait()


def test_a_slow_resolver_never_holds_the_page(admin, conn, settings, bare, monkeypatch):  # noqa: F811
    gate = threading.Event()

    def slow(host, port, ip, timeout=ptr.TIMEOUT):
        gate.wait(5)
        return 'nas.home.lan', None
    monkeypatch.setattr(ptr, 'LOOKUP', slow)
    ptr.save(conn, '192.0.2.53', 24)
    names.save(conn, '192.0.2.10', 'printer')
    r = admin.get(f'/ipam/networks/{bare.id}')         # answers while the lookup still waits
    assert r.status_code == 200 and 'nas.home.lan' not in r.text
    gate.set()
    ptr.wait()
    page = admin.get(f'/ipam/networks/{bare.id}').text
    assert '<code>nas.home.lan</code> <span class="muted small" title="its PTR at 192.0.2.53, looked up just now' in page
    assert 'IPAM names it printer, but its PTR at the resolver says nas.home.lan.' in page
    card = admin.get('/search?q=192.0.2.10').text
    assert 'rDNS' in card and 'at 192.0.2.53' in card


def test_the_sweep_looks_up_what_answered(conn, settings, net, fake):  # noqa: F811
    ptr.save(conn, '192.0.2.53', 24)
    replied = {'replied': True, 'rtt_ms': 0.4, 'state': 'REACHABLE', 'mac': A, 'confirmed': 0}
    lines = []
    sweep.run(settings, net.id, lines.append, probe=lambda ips: Probe({'192.0.2.10': replied, '192.0.2.11': replied})(
        None, ips))
    assert sorted(ip for _, _, ip in fake) == ['192.0.2.10', '192.0.2.11']
    assert '  PTR lookups at 192.0.2.53: 1 named, 1 without a PTR' in lines
    assert ptr.get(conn, '192.0.2.10')['name'] == 'nas.home.lan'


def test_ipam_only_pages_render(admin, conn, settings, bare, fake):  # noqa: F811
    ptr.save(conn, '192.0.2.53', 24)
    names.save(conn, '192.0.2.10', 'nas', A)
    ptr.refresh(conn, ['192.0.2.10', '192.0.2.11'], ('192.0.2.53', 53))
    for path in ('/ipam', f'/ipam/networks/{bare.id}', f'/ipam/networks/{bare.id}?used=1', '/ipam/seen',
                 '/search?q=nas', '/search?q=192.0.2.10', '/search?q=192.0.2.0/24', '/ipam/names/192.0.2.10',
                 '/ipam/names/192.0.2.11', '/settings/ipam'):
        assert admin.get(path).status_code == 200, path
    assert json.dumps(admin.get('/search?q=192.0.2.0/24').text).count('IPAM names') >= 1
