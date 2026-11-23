import hashlib
import re
from pathlib import Path

import dns.name
import pytest

from liteblox import jobs
from liteblox.dns import ptr
from liteblox.dns import publish as pub
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file
from liteblox.dns.zonefile import Zone
from liteblox.nodes import service as nodes
from liteblox.nodes.client import AgentError

from conftest import csrf_from
from test_nodes import FP, HOST_KEY

FORWARD = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()
REVERSE = ('$TTL 1h\n'
           '@\tIN\tSOA\tns1.example.com. hostmaster.example.com. 2026010101 3600 900 1209600 300\n'
           '@\tIN\tNS\tns1.example.com.\n\n'                          # in sorted form, as LiteBlox saves it
           '1\tIN\tPTR\thost1.example.com.\n'
           '53\tIN\tPTR\tns1.example.com.\n'
           '200\tIN\tPTR\tx.example.com.\n')
V6 = ('$TTL 1h\n'
      '@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 1209600 300\n'
      '  IN NS ns1.example.com.\n')
REV = '2.0.192.in-addr.arpa'
N = dns.name.from_text


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ── the PTR logic ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize('old, new, expected', [
    (None, (N('a.example.com.'), 'A', '192.0.2.7'), [('add', '192.0.2.7', N('a.example.com.'))]),
    ((N('a.example.com.'), 'A', '192.0.2.7'), None, [('remove', '192.0.2.7', N('a.example.com.'))]),
    ((N('a.example.com.'), 'A', '192.0.2.7'), (N('a.example.com.'), 'A', '192.0.2.8'),
     [('remove', '192.0.2.7', N('a.example.com.')), ('add', '192.0.2.8', N('a.example.com.'))]),
    ((N('a.example.com.'), 'A', '192.0.2.7'), (N('b.example.com.'), 'A', '192.0.2.7'),
     [('remove', '192.0.2.7', N('a.example.com.')), ('add', '192.0.2.7', N('b.example.com.'))]),
    ((N('a.example.com.'), 'A', '192.0.2.7'), (N('a.example.com.'), 'A', '192.0.2.7'), []),     # comment/TTL edit
    ((N('a.example.com.'), 'A', '192.0.2.7'), (N('a.example.com.'), 'CNAME', 'b'),
     [('remove', '192.0.2.7', N('a.example.com.'))]),
    (None, (N('a.example.com.'), 'MX', '10 mail'), []),
    (None, (N('a.example.com.'), 'AAAA', '2001:DB8::0:1'), [('add', '2001:db8::1', N('a.example.com.'))]),
])
def test_changes(old, new, expected):
    assert ptr.changes(old, new) == expected


def test_reverse_zone_for_picks_the_most_specific():
    zones = ['example.com', '192.in-addr.arpa', '2.0.192.in-addr.arpa', '8.b.d.0.1.0.0.2.ip6.arpa']
    assert ptr.reverse_zone_for('192.0.2.40', zones) == '2.0.192.in-addr.arpa'
    assert ptr.reverse_zone_for('192.9.9.9', zones) == '192.in-addr.arpa'
    assert ptr.reverse_zone_for('2001:db8::1', zones) == '8.b.d.0.1.0.0.2.ip6.arpa'
    assert ptr.reverse_zone_for('10.0.0.1', zones) is None


def test_apply_add_keeps_address_order_and_layout():
    rzone = Zone.parse(REVERSE, REV + '.')
    changed, msg = ptr.apply(rzone, 'add', '192.0.2.77', N('web.example.com.'))
    assert changed and 'added PTR 192.0.2.77' in msg
    lines = rzone.render().splitlines()
    assert lines[lines.index('53\tIN\tPTR\tns1.example.com.') + 1] == '77\tIN\tPTR\tweb.example.com.'

    assert ptr.apply(rzone, 'add', '192.0.2.77', N('web.example.com.')) == (False, None)     # already there
    changed, msg = ptr.apply(rzone, 'add', '192.0.2.53', N('other.example.com.'))
    assert not changed and 'already points to ns1.example.com.' in msg

    rzone2 = Zone.parse(REVERSE, REV + '.')
    ptr.apply(rzone2, 'add', '192.0.2.0', N('net.example.com.'))       # lowest address: before the first PTR
    assert rzone2.render().splitlines()[3] == '0\tIN\tPTR\tnet.example.com.'


def test_apply_remove_only_matching_target():
    rzone = Zone.parse(REVERSE, REV + '.')
    assert ptr.apply(rzone, 'remove', '192.0.2.53', N('someone-else.example.com.')) == (False, None)
    changed, msg = ptr.apply(rzone, 'remove', '192.0.2.53', N('ns1.example.com.'))
    assert changed and '53\tIN\tPTR' not in rzone.render()


def test_apply_ipv6():
    rzone = Zone.parse(V6, '8.b.d.0.1.0.0.2.ip6.arpa.')
    ptr.apply(rzone, 'add', '2001:db8::1', N('v6.example.com.'))
    rec = [r for r in rzone.records() if r.rtype == 'PTR'][0]
    assert rec.name == N('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
    assert rec.rdata == 'v6.example.com.'


# ── in the editor ──────────────────────────────────────────────────────────────

@pytest.fixture
def zones(conn, settings):
    repo = Repo(settings.repo_dir).ensure()
    for name, text in (('example.com', FORWARD), (REV, REVERSE)):
        repo.write(zone_file(name), text, f'Import {name}', 'test')
        with conn:
            conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES (?, 'local', ?)", (name, zone_file(name)))


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    client.headers['X-CSRF-Token'] = csrf_from(client.get('/').text)
    return client


def draft(settings, name):
    path = settings.data_dir / 'drafts' / f'{name}.zone'
    return path.read_bytes().decode() if path.exists() else None


def grid_rev(html):
    return re.search(r'data-rev="([0-9a-f]+)"', html).group(1)


def row_id(html, needle):
    for m in re.finditer(r'<tr id="row-(\d+)"[^>]*data-search="([^"]*)"', html):
        if needle in m.group(2):
            return int(m.group(1))
    raise AssertionError(needle)


def test_add_change_delete_keeps_ptr_in_step(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    r = admin.post('/zones/example.com/records', data={
        'rev': grid_rev(page), 'name': 'web', 'type': 'A', 'value': '192.0.2.77', 'ptr_field': '1', 'ptr': '1'})
    assert 'added PTR 192.0.2.77 → web.example.com.' in r.text
    assert 'publishes together with' in r.text and REV in r.text
    assert '77\tIN\tPTR\tweb.example.com.' in draft(settings, REV)
    assert Drafts(settings).linked('example.com') == {REV}

    rid = row_id(r.text, 'web a 192.0.2.77')
    r = admin.post(f'/zones/example.com/records/{rid}', data={
        'rev': grid_rev(r.text), 'name': 'web', 'type': 'A', 'value': '192.0.2.78', 'ptr_field': '1', 'ptr': '1'})
    rev_text = draft(settings, REV)
    assert '78\tIN\tPTR\tweb.example.com.' in rev_text and '77\tIN\tPTR' not in rev_text

    rid = row_id(r.text, 'web a 192.0.2.78')
    r = admin.post(f'/zones/example.com/records/{rid}/delete', data={'rev': grid_rev(r.text)})
    assert 'removed PTR 192.0.2.78' in r.text
    assert draft(settings, REV) is None              # back to the published reverse zone: no draft left


def test_ptr_checkbox_and_zone_setting(admin, conn, settings, zones):
    page = admin.get('/zones/example.com').text
    admin.post('/zones/example.com/records', data={
        'rev': grid_rev(page), 'name': 'quiet', 'type': 'A', 'value': '192.0.2.90', 'ptr_field': '1'})  # unticked
    assert draft(settings, REV) is None

    t = csrf_from(page)
    admin.post('/zones/example.com/autoptr', data={'csrf_token': t})                 # turn it off
    assert conn.execute("SELECT auto_ptr FROM zones WHERE name = 'example.com'").fetchone()[0] == 0
    edit = admin.get(f"/zones/example.com/records/{row_id(admin.get('/zones/example.com').text, 'ns1 a')}/edit").text
    assert 'name="ptr" value="1" >' in edit or 'name="ptr" value="1">' in edit          # rendered unticked
    page = admin.get('/zones/example.com').text
    rid = row_id(page, 'ns1 a 192.0.2.53')
    admin.post(f'/zones/example.com/records/{rid}/delete', data={'rev': grid_rev(page)})
    assert draft(settings, REV) is None                                              # PTR 53 left alone


def test_existing_ptr_elsewhere_is_not_overwritten(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    r = admin.post('/zones/example.com/records', data={
        'rev': grid_rev(page), 'name': 'other', 'type': 'A', 'value': '192.0.2.53'})   # API-style: zone default on
    assert 'already points to ns1.example.com.' in r.text
    assert draft(settings, REV) is None


@pytest.mark.parametrize('name, ok', [
    ('web.example.com.', True), ('a-1.b2.example.com.', True), ('*.lab.example.com.', False),
    ('_sip._tcp.example.com.', False), ('-bad.example.com.', False), ('bad-.example.com.', False),
])
def test_is_host_name(name, ok):
    assert ptr.is_host_name(dns.name.from_text(name)) is ok


@pytest.mark.parametrize('owner', ['*.lab', '_svc'])
def test_no_ptr_for_names_that_are_not_host_names(admin, settings, zones, owner):
    page = admin.get('/zones/example.com').text
    r = admin.post('/zones/example.com/records', data={
        'rev': grid_rev(page), 'name': owner, 'type': 'A', 'value': '192.0.2.254', 'ptr_field': '1', 'ptr': '1'})
    assert r.status_code == 200
    assert f'no PTR for {owner}.example.com.: a PTR has to point at a host name' in r.text
    assert draft(settings, REV) is None                 # the reverse zone wasn't touched
    assert re.search(rf'^{re.escape(owner)}\s.*A\s+192\.0\.2\.254$', draft(settings, 'example.com'), re.M)


def test_no_reverse_zone_note(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    r = admin.post('/zones/example.com/records', data={
        'rev': grid_rev(page), 'name': 'far', 'type': 'A', 'value': '198.51.100.7'})
    assert 'no reverse zone for 198.51.100.7' in r.text


def test_review_and_discard_cover_linked_zones(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    admin.post('/zones/example.com/records', data={'rev': grid_rev(page), 'name': 'web', 'type': 'A',
                                                   'value': '192.0.2.77'})
    review = admin.get('/zones/example.com/review').text
    assert f'Also published: <a href="/zones/{REV}">' in review
    assert f'Publish example.com + {REV}' in review and f'name="rev:{REV}"' in review
    t = csrf_from(review)
    admin.post('/zones/example.com/discard', data={'csrf_token': t})
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None


# ── publishing linked zones together ───────────────────────────────────────────

class MultiNode:
    """A node serving several zones; stage/commit per zone."""

    def __init__(self, files):
        self.files = dict(files)
        self.staged, self.calls, self.fail_stage = {}, [], set()

    def get_zone(self, name):
        content = self.files[name]
        return {'content': content, 'sha256': sha(content),
                'loaded_serial': Zone.parse(content, name + '.').serial}

    def stage_zone(self, name, content, base):
        self.calls.append(('stage', name))
        if name in self.fail_stage:
            raise AgentError(422, 'named-checkzone rejected the zone')
        self.staged[name] = content
        return {'stage_id': name}

    def commit_zone(self, name, stage_id):
        self.calls.append(('commit', name))
        self.files[name] = self.staged.pop(stage_id)
        return {}

    def abort_zone(self, name, stage_id):
        self.calls.append(('abort', name))
        self.staged.pop(stage_id, None)


class Client:
    def __init__(self, fake):
        self.fake = fake

    def __enter__(self):
        return self.fake

    def __exit__(self, *exc):
        pass


@pytest.fixture
def served(conn, settings, zones, monkeypatch):
    fakes = {}
    for i, host in enumerate(('192.0.2.53', '192.0.2.54'), 1):
        node_id = nodes.add_node(conn, f'ns{i}', host, 22, 8530, HOST_KEY, FP)
        with conn:
            conn.execute("UPDATE nodes SET status = 'ready', managed = 1 WHERE id = ?", (node_id,))
            for zone_id, text in ((1, FORWARD), (2, REVERSE)):
                conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?)',
                             (zone_id, node_id, '/etc/bind/x', sha(text)))
        fakes[host] = MultiNode({'example.com': FORWARD, REV: REVERSE})
    monkeypatch.setattr(nodes, 'agent_client', lambda settings, node, timeout=10.0: Client(fakes[node['host']]))
    return fakes


def serves(fakes):
    return lambda host, zone, expected, **kw: Zone.parse(fakes[host].files[zone], zone + '.').serial


def make_linked_edit(admin):
    page = admin.get('/zones/example.com').text
    admin.post('/zones/example.com/records', data={'rev': grid_rev(page), 'name': 'web', 'type': 'A',
                                                   'value': '192.0.2.77'})


def test_publish_linked_zones_together(admin, conn, settings, served):
    make_linked_edit(admin)
    lines = []
    pub.publish(settings, 'example.com', 'admin', lines.append, linked=True, verify=serves(served))
    for f in served.values():
        assert re.search(r'^web\s+IN\s+A\s+192.0.2.77$', f.files['example.com'], re.M)
        assert '77\tIN\tPTR\tweb.example.com.' in f.files[REV]
        stages = [c for c in f.calls if c[0] == 'stage']
        first_commit = next(i for i, c in enumerate(f.calls) if c[0] == 'commit')
        assert len(stages) == 2 and all(f.calls.index(s) < first_commit for s in stages)   # all staged first
    assert [r['status'] for r in conn.execute('SELECT status FROM deploys ORDER BY id')] == ['ok', 'ok']
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None
    assert any(f'ns1 {REV}: serving serial' in l for l in lines)


def test_linked_stage_failure_changes_nothing(admin, conn, settings, served):
    make_linked_edit(admin)
    served['192.0.2.54'].fail_stage = {REV}
    with pytest.raises(pub.PublishError, match='no node was changed'):
        pub.publish(settings, 'example.com', 'admin', lambda l: None, linked=True, verify=serves(served))
    for f in served.values():
        assert f.files == {'example.com': FORWARD, REV: REVERSE}
    assert ('abort', 'example.com') in served['192.0.2.53'].calls and ('abort', REV) in served['192.0.2.53'].calls
    assert draft(settings, 'example.com') and draft(settings, REV)                   # drafts kept for a retry
    assert Repo(settings.repo_dir).read(zone_file(REV)) == REVERSE


def test_publish_route_sends_linked_revisions(admin, conn, settings, served, monkeypatch):
    real_start, real_publish = jobs.start, pub.publish
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'publish', lambda *a, **k: real_publish(*a, **{**k, 'verify': serves(served)}))
    make_linked_edit(admin)
    review = admin.get('/zones/example.com/review').text
    form = dict(re.findall(r'name="(rev(?::[^"]+)?)" value="([0-9a-f]+)"', review))
    r = admin.post('/zones/example.com/publish', data={'csrf_token': csrf_from(review), **form}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert '77\tIN\tPTR' in served['192.0.2.53'].files[REV]


def test_commit_message_goes_on_every_zone(admin, conn, settings, served, monkeypatch):
    real_start, real_publish = jobs.start, pub.publish
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'publish', lambda *a, **k: real_publish(*a, **{**k, 'verify': serves(served)}))
    make_linked_edit(admin)
    review = admin.get('/zones/example.com/review').text
    assert 'name="message" value="Publish example.com"' in review
    form = dict(re.findall(r'name="(rev(?::[^"]+)?)" value="([0-9a-f]+)"', review))
    admin.post('/zones/example.com/publish', data={'csrf_token': csrf_from(review), **form,
                                                   'message': '  Add web\n server  '})
    repo = Repo(settings.repo_dir)
    for name in ('example.com', REV):
        subject = repo.log(zone_file(name))[0]['subject']
        assert re.fullmatch(r'Add web server \(serial \d{10}\)', subject), subject
    assert [r[0] for r in conn.execute('SELECT message FROM deploys')] == ['Add web server', 'Add web server']
    history = admin.get('/zones/example.com/history').text
    assert '<td class="small">Add web server</td>' in history


def test_default_commit_message_stays_per_zone(admin, conn, settings, served):
    make_linked_edit(admin)
    pub.publish(settings, 'example.com', 'admin', print, linked=True, verify=serves(served), message=None)
    repo = Repo(settings.repo_dir)
    assert repo.log(zone_file(REV))[0]['subject'].startswith(f'Publish {REV} (serial ')
    assert [r[0] for r in conn.execute('SELECT message FROM deploys')] == [None, None]
