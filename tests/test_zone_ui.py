import json
import re
from urllib.parse import unquote, urlencode
from pathlib import Path

import dns.name
import pytest

from liteblox.dns import records
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file
from liteblox.dns.zonefile import Zone
from liteblox.nodes import service as nodes

from conftest import csrf_from

EXAMPLE = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()
ORIGIN = dns.name.from_text('example.com.')


@pytest.fixture
def zone(conn, settings):
    """example.com imported into LiteBlox (repo + zones row)."""
    def make(text=EXAMPLE):
        Repo(settings.repo_dir).ensure().write(zone_file('example.com'), text, 'Import example.com', 'test')
        with conn:
            conn.execute("INSERT OR IGNORE INTO zones (name, mode, repo_file) VALUES ('example.com', 'local', ?)",
                         (zone_file('example.com'),))
        return text
    return make


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    # htmx sends the session's CSRF token as a header (hx-headers on <body>)
    client.headers['X-CSRF-Token'] = csrf_from(client.get('/').text)
    return client


def draft_text(settings):
    path = settings.data_dir / 'drafts' / 'example.com.zone'
    return path.read_bytes().decode() if path.exists() else None


def page_rev(html):
    m = re.search(r'data-rev="([0-9a-f]+)"', html) or re.search(r'name="rev" value="([0-9a-f]+)"', html)
    return m.group(1)


def row_id(html, needle):
    """Id of the grid row whose data-search contains needle."""
    for m in re.finditer(r'<tr id="row-(\d+)"[^>]*data-search="([^"]*)"', html):
        if needle in m.group(2):
            return int(m.group(1))
    raise AssertionError(f'no row matching {needle}')


# ── form helpers and checks ────────────────────────────────────────────────────

@pytest.mark.parametrize('rtype, rdata, fields', [
    ('MX', '10 mail', {'priority': '10', 'exchange': 'mail'}),
    ('SRV', '10 60 5060 sip', {'srv_priority': '10', 'weight': '60', 'port': '5060', 'target': 'sip'}),
    ('CAA', '0 issue "letsencrypt.org"', {'flags': '0', 'tag': 'issue', 'caa_value': 'letsencrypt.org'}),
    ('A', '192.0.2.1', {'value': '192.0.2.1'}),
])
def test_decompose_compose_roundtrip(rtype, rdata, fields):
    assert records.decompose(rtype, rdata) == fields
    assert records.compose(rtype, fields) == rdata


def test_edit_row_field_names_are_unique():
    # the row posts every input, hidden ones too; a shared name would let one type's empty field win
    names = [key for flist in records.FIELDS.values() for key, _ in flist] + ['value']
    assert len(names) == len(set(names))


def test_txt_quoting_and_splitting():
    assert records.compose('TXT', {'text': 'v=spf1 mx -all'}) == '"v=spf1 mx -all"'
    assert records.compose('TXT', {'text': 'say "hi"'}) == '"say \\"hi\\""'
    long = records.compose('TXT', {'text': 'x' * 300})
    assert long == f'"{"x" * 255}" "{"x" * 45}"'
    assert records.decompose('TXT', long) == {'text': 'x' * 300}
    assert records.compose('TXT', {'text': '"a" "b"'}) == '"a" "b"'      # already quoted: kept


def test_same_data_and_preview():
    assert records.same_data('TXT', '"ab"', '"a" "b"', ORIGIN) is False
    assert records.same_data('MX', '10 mail', '10   mail', ORIGIN)
    assert records.same_data('CNAME', 'www', 'www.example.com.', ORIGIN)
    assert records.target_preview('CNAME', 'www', ORIGIN) == 'www.example.com.'
    assert records.target_preview('CNAME', 'www.example.net.', ORIGIN) is None
    assert records.target_preview('A', '192.0.2.1', ORIGIN) is None


@pytest.mark.parametrize('name, ttl, rtype, rdata, field', [
    ('host', '', 'A', '192.0.2.300', 'value'),
    ('host', 'soon', 'A', '192.0.2.1', 'ttl'),
    ('host.example.net.', '', 'A', '192.0.2.1', 'name'),
    ('host', '', 'BOGUS', 'x', 'type'),
    ('@', '', 'CNAME', 'www', 'type'),                 # apex CNAME
    ('mail', '', 'CNAME', 'www', 'type'),              # mail already has A + AAAA
    ('www', '', 'A', '192.0.2.5', 'type'),             # www is a CNAME
    ('host', '', 'SOA', 'a b 1 2 3 4 5', 'type'),
])
def test_check_errors(name, ttl, rtype, rdata, field):
    zone = Zone.parse(EXAMPLE, 'example.com.')
    with pytest.raises(records.RecordError) as e:
        records.check(zone, None, name, ttl, rtype, rdata)
    assert field in e.value.errors


def test_check_ok_and_missing_dot_warning():
    zone = Zone.parse(EXAMPLE, 'example.com.')
    owner, ttl, rtype, warnings = records.check(zone, None, 'alias', '1h', 'cname', 'host.example.com')
    assert (owner.to_text(), ttl, rtype) == ('alias.example.com.', 3600, 'CNAME')
    assert 'host.example.com.example.com.' in warnings[0]
    rec = next(r for r in zone.records() if r.rtype == 'CNAME')
    assert records.check(zone, rec, 'www', '', 'CNAME', 'ns1')[3] == []     # editing the CNAME itself is fine


def test_summarize():
    old = Zone.parse(EXAMPLE, 'example.com.')
    new = Zone.parse(EXAMPLE, 'example.com.')
    ns1 = next(r for r in new.records() if r.relative_name() == 'ns1')
    new.update(ns1, rdata='192.0.2.54')
    new.add('extra', 'A', '192.0.2.77')
    new.delete(next(r for r in new.records() if r.rtype == 'CAA'))
    s = records.summarize(old, new)
    assert [a['name'] for a in s['added']] == ['extra']
    assert [r['type'] for r in s['removed']] == ['CAA']
    assert [(o['data'], n['data']) for o, n in s['changed']] == [('192.0.2.53', '192.0.2.54')]
    assert records.count(s) == 3


# ── drafts ─────────────────────────────────────────────────────────────────────

def test_drafts_lifecycle(conn, settings, zone):
    zone()
    row = conn.execute('SELECT * FROM zones').fetchone()
    d = Drafts(settings)
    assert d.load(row) == (EXAMPLE, False)
    assert d.save(row, EXAMPLE + '; note\n', 'admin') is True
    assert d.load(row) == (EXAMPLE + '; note\n', True) and not d.is_stale(row)
    assert d.save(row, EXAMPLE, 'admin') is False and d.load(row)[1] is False     # back to published: no draft
    d.save(row, EXAMPLE + '; note\n', 'admin')
    Repo(settings.repo_dir).write(row['repo_file'], EXAMPLE + '; imported again\n', 'reimport', 'x')
    assert d.is_stale(row)


# ── pages ──────────────────────────────────────────────────────────────────────

def test_grid_edit_flow(admin, settings, zone):
    zone()
    page = admin.get('/zones/example.com')
    assert page.status_code == 200 and 'hostmaster.example.com.' in page.text
    rid, rev = row_id(page.text, 'ns1 a 192.0.2.53'), page_rev(page.text)

    edit = admin.get(f'/zones/example.com/records/{rid}/edit')
    assert 'value="192.0.2.53"' in edit.text and 'class="editing"' in edit.text

    r = admin.post(f'/zones/example.com/records/{rid}', data={
        'rev': rev, 'name': 'ns1', 'ttl': '', 'type': 'A', 'value': '192.0.2.54', 'comment': ''})
    assert r.status_code == 200 and '1</strong> pending change' in r.text
    assert f'id="soa-rev" value="{page_rev(r.text)}" hx-swap-oob="true"' in r.text
    assert 'ns1\tIN\tA\t192.0.2.54\n' in draft_text(settings)
    assert draft_text(settings).replace('192.0.2.54', '192.0.2.53') == EXAMPLE        # one-token change
    assert Repo(settings.repo_dir).read(zone_file('example.com')) == EXAMPLE           # not published

    # the old rev is now stale
    r = admin.post(f'/zones/example.com/records/{rid}', data={
        'rev': rev, 'name': 'ns1', 'type': 'A', 'value': '192.0.2.99'})
    assert r.status_code == 409 and r.headers['HX-Retarget'] == '#zone-alert'


def test_grid_validation_error_returns_edit_row(admin, settings, zone):
    zone()
    page = admin.get('/zones/example.com')
    rid = row_id(page.text, 'ns1 a 192.0.2.53')
    r = admin.post(f'/zones/example.com/records/{rid}', data={
        'rev': page_rev(page.text), 'name': 'ns1', 'type': 'A', 'value': 'not-an-ip'})
    assert r.status_code == 422 and r.headers['HX-Retarget'] == f'#row-{rid}'
    assert 'error-text' in r.text and draft_text(settings) is None


def test_unchanged_save_keeps_original_text(admin, settings, zone):
    zone()
    page = admin.get('/zones/example.com')
    rid = row_id(page.text, 'txt txt')
    edit = admin.get(f'/zones/example.com/records/{rid}/edit').text
    text = re.search(r'name="text" value="([^"]*)"', edit).group(1).replace('&#34;', '"').replace('&quot;', '"')
    assert text == '"semicolon ; inside quotes" "and \\"escaped\\" quotes"'     # two strings: shown quoted
    form = {'rev': page_rev(page.text), 'name': 'txt', 'ttl': '', 'type': 'TXT', 'text': text, 'comment': ''}
    r = admin.post(f'/zones/example.com/records/{rid}', data=form)
    assert r.status_code == 200 and draft_text(settings) is None         # same data: no draft at all


def test_add_below_delete_review_discard(admin, settings, zone):
    zone()
    page = admin.get('/zones/example.com')
    rid = row_id(page.text, 'ns1 a 192.0.2.53')
    r = admin.post('/zones/example.com/records', data={
        'rev': page_rev(page.text), 'after': rid, 'name': 'ns3', 'type': 'A', 'value': '192.0.2.55'})
    assert r.status_code == 200
    lines = draft_text(settings).splitlines()
    assert lines[lines.index('ns1\tIN\tA\t192.0.2.53') + 1] == 'ns3\tIN\tA\t192.0.2.55'

    caa = row_id(r.text, 'caa caa')
    r = admin.post(f'/zones/example.com/records/{caa}/delete', data={'rev': page_rev(r.text)})
    assert r.status_code == 200
    # regression: ids shown after an insert must match the next parse, or this deletes the wrong row
    assert draft_text(settings).count('\n') == EXAMPLE.count('\n')
    assert 'caa\tIN\tCAA' not in draft_text(settings)

    review = admin.get('/zones/example.com/review').text
    assert 'added' in review and 'ns3' in review and 'removed' in review and '+ns3\tIN\tA\t192.0.2.55' in review

    t = csrf_from(review)
    admin.post('/zones/example.com/discard', data={'csrf_token': t})
    assert draft_text(settings) is None
    assert 'No pending changes' in admin.get('/zones/example.com/review').text


def test_mx_add_with_structured_fields(admin, settings, zone):
    zone()
    page = admin.get('/zones/example.com')
    r = admin.post('/zones/example.com/records', data={
        'rev': page_rev(page.text), 'name': '@', 'type': 'MX', 'priority': '20', 'exchange': 'backup-mail',
        'value': 'ignored for MX'})
    assert r.status_code == 200 and '20 backup-mail' in draft_text(settings)


def test_soa_and_raw(admin, settings, zone):
    zone(EXAMPLE.replace('\n', '\r\n'))
    page = admin.get('/zones/example.com')
    t, rev = csrf_from(page.text), page_rev(page.text)
    r = admin.post('/zones/example.com/soa', data={
        'csrf_token': t, 'rev': rev, 'mname': 'ns1.example.com.', 'rname': 'hostmaster.example.com.',
        'refresh': '7200', 'retry': '900', 'expire': '1209600', 'minimum': '300'}, follow_redirects=False)
    assert r.status_code == 303
    text = draft_text(settings)
    assert '\t\t7200\t\t; refresh\r\n' in text and '2026010101' in text      # in place, serial untouched

    raw = admin.get('/zones/example.com/raw')
    # browsers always submit textareas with CRLF; the zone keeps CRLF
    edited = text.replace('\r\n', '\n').replace('192.0.2.53', '192.0.2.63').replace('\n', '\r\n')
    r = admin.post('/zones/example.com/raw', data={'csrf_token': t, 'rev': page_rev(raw.text), 'text': edited},
                   follow_redirects=False)
    assert r.status_code == 303 and '192.0.2.63\r\n' in draft_text(settings)

    r = admin.post('/zones/example.com/raw', data={'csrf_token': t, 'rev': page_rev(admin.get('/zones/example.com/raw').text),
                                                   'text': 'garbage ( unclosed'})
    assert r.status_code == 422


def test_readonly_can_view_not_edit(client, make_user, login, zone):
    zone()
    login(*make_user('viewer', 'viewer-pass', 'readonly'))
    page = client.get('/zones/example.com')
    assert page.status_code == 200 and 'Add below' not in page.text
    rid = row_id(page.text, 'ns1 a')
    assert client.get(f'/zones/example.com/records/{rid}/edit').status_code == 403
    r = client.post(f'/zones/example.com/records/{rid}', data={'rev': page_rev(page.text)},
                    headers={'X-CSRF-Token': csrf_from(page.text)})
    assert r.status_code == 403


def test_zones_list_history_and_serials(admin, conn, zone, monkeypatch):
    zone()
    from test_nodes import FP, HOST_KEY
    node_id = nodes.add_node(conn, 'ns1', '192.0.2.53', 22, 8530, HOST_KEY, FP)
    with conn:
        conn.execute("UPDATE nodes SET status = 'ready'")
        conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (1, ?, ?)', (node_id, '/x'))

    class Agent:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *e): pass
        def config(self): return {'zones': [{'name': 'example.com', 'loaded_serial': 2026010101}]}
    monkeypatch.setattr(nodes, 'agent_client', lambda *a, **k: Agent())

    listing = admin.get('/zones').text
    assert 'example.com' in listing and '2026010101' in listing
    serials = admin.get('/zones/serials').text
    assert 'id="serials-1"' in serials and 'hx-swap-oob' in serials and '<code>2026010101</code>' in serials

    hist = admin.get('/zones/example.com/history').text
    sha = re.search(r'/zones/example.com/history/([0-9a-f]{40})', hist).group(1)
    commit = admin.get(f'/zones/example.com/history/{sha}')
    assert commit.status_code == 200 and 'Import example.com' in commit.text
    assert admin.get('/zones/nope.example').status_code == 404


def test_zones_list_kinds_and_filter(admin, conn, zone):
    zone()
    with conn:
        conn.execute("INSERT INTO zones (name, kind, forwarders, repo_file) VALUES ('corp.lan', 'forwarding', '10.0.0.1\n10.0.0.2', '')")
    listing = admin.get('/zones').text
    assert '<span class="pill">forwarding</span>' in listing and '→ 10.0.0.1, …' in listing
    assert 'href="/zones?kind=forward"' in listing and 'href="/zones?kind=reverse"' not in listing     # none of those
    only = admin.get('/zones?kind=forwarding').text
    assert 'corp.lan' in only and 'example.com' not in only and 'aria-current="page">Forwarding' in only
    assert 'ids=' not in only or 'ids=2' in only
    assert 'No zones match this filter' in admin.get('/zones?kind=draft').text
    assert 'corp.lan' in admin.get('/zones?kind=bogus').text and 'example.com' in admin.get('/zones?kind=bogus').text


@pytest.mark.parametrize('row, draft, want', [
    ({'kind': 'primary', 'name': 'example.com', 'dynamic': 0}, False, {'forward'}),
    ({'kind': 'primary', 'name': '0.168.192.in-addr.arpa', 'dynamic': 1}, True, {'reverse', 'dynamic', 'draft'}),
    ({'kind': 'forwarding', 'name': 'corp.lan', 'dynamic': 0}, False, {'forwarding'}),
])
def test_zone_kinds(row, draft, want):
    from liteblox.dns.routes import _zone_kinds
    assert _zone_kinds(row, draft) == want


# ── zones LiteBlox keeps sorted ────────────────────────────────────────────────

SMALL = ('$TTL 1h\n@\tIN\tSOA\tns1 hostmaster 1 3600 900 1209600 300\n@\tIN\tNS\tns1\n\n'
         'ns1\tIN\tA\t192.0.2.53\nzz\tIN\tA\t192.0.2.99\n')


def test_edits_land_in_order(admin, conn, settings, zone):
    zone(SMALL)
    page = admin.get('/zones/example.com')
    assert 'Add below' not in page.text
    r = admin.post('/zones/example.com/records', data={
        'rev': page_rev(page.text), 'name': 'mail', 'type': 'A', 'value': '192.0.2.25'})
    assert r.status_code == 200
    assert draft_text(settings).endswith('ns1\tIN\tA\t192.0.2.53\nzz\tIN\tA\t192.0.2.99\n')
    assert 'mail\tA\t192.0.2.25\nns1' in draft_text(settings).replace(' ', '\t').replace('\tIN\t', '\t')
    # the saved row is highlighted where it now sits
    assert re.search(r'<tr id="row-(\d+)"[^>]*data-name="mail"[^>]*\n?[^>]*class="[^"]*focus', r.text)
    assert 'Record order' not in admin.get('/zones/example.com/settings').text


def test_a_zone_that_cant_be_sorted_keeps_its_order(admin, conn, settings, zone):
    zone(SMALL)
    raw = admin.get('/zones/example.com/raw').text
    assert "this one can't be" not in raw
    text = SMALL.replace('ns1\tIN\tA', '$INCLUDE /etc/bind/extra\nns1\tIN\tA')
    r = admin.post('/zones/example.com/raw', data={'rev': page_rev(raw), 'csrf_token': csrf_from(raw), 'text': text},
                   follow_redirects=False)
    assert r.status_code == 303 and draft_text(settings) == text          # saved as it is
    assert "LiteBlox keeps every zone sorted, but this one can't be ($INCLUDE on line" in \
        admin.get('/zones/example.com/raw').text
    from liteblox import status
    assert any("example.com can't be kept sorted" in p['what'] for p in status.problems(conn, settings))


def test_the_startup_pass_sorts_every_static_zone(conn, settings, zone):
    from liteblox.dns import importer
    from liteblox.dns.drafts import Drafts
    zone('$TTL 1h\n@ SOA ns1 hostmaster 1 3600 900 1209600 300\n@ NS ns1\n; mail\nzz A 192.0.2.99\nns1 A 192.0.2.53\n')
    assert importer.sort_all(conn, Drafts(settings)) == {'example.com': 'draft'}
    assert draft_text(settings).endswith('ns1 A 192.0.2.53\nzz A 192.0.2.99\n')
    assert Drafts(settings).meta('example.com')['moved_comments'] == ['mail  (above zz)']
    assert importer.sort_all(conn, Drafts(settings)) == {'example.com': 'unchanged'}     # once
    assert Drafts(settings).meta('example.com')['moved_comments'] == ['mail  (above zz)']
    with conn:
        conn.execute('UPDATE zones SET dynamic = 1')
    assert importer.sort_all(conn, Drafts(settings)) == {}                 # named orders a dynamic zone


def test_zone_notes(admin, client, conn, zone, make_user, login):
    zone(SMALL)
    assert 'zone-notes' not in admin.get('/zones/example.com').text
    page = admin.get('/zones/example.com/settings').text
    r = admin.post('/zones/example.com/notes', data={'csrf_token': csrf_from(page), 'notes': 'printers: ask Pat\r\n'},
                   follow_redirects=False)
    assert r.status_code == 303 and conn.execute('SELECT notes FROM zones').fetchone()[0] == 'printers: ask Pat'
    assert '<pre class="notes">printers: ask Pat</pre>' in admin.get('/zones/example.com').text
    assert conn.execute("SELECT count(*) FROM audit WHERE action = 'zone_notes'").fetchone()[0] == 1


# ── nameservers card ───────────────────────────────────────────────────────────

def test_nameservers_card(admin, settings, zone):
    zone(SMALL)
    page = admin.get('/zones/example.com').text
    assert 'data-type="NS"' not in page                       # apex NS live in the card, not the grid
    assert '<code>ns1.example.com.</code>' in page
    t = csrf_from(page)

    admin.post('/zones/example.com/ns', data={'csrf_token': t, 'rev': page_rev(page), 'target': 'ns2.example.net.'})
    assert '@\tIN\tNS\tns1\n@\tIN\tNS\tns2.example.net.\n' in draft_text(settings)
    page = admin.get('/zones/example.com').text
    assert 'address not held in LiteBlox' in page

    r = admin.post('/zones/example.com/ns', data={'csrf_token': t, 'rev': page_rev(page), 'target': 'ns1'},
                   follow_redirects=False)
    assert unquote(r.headers['location']).endswith('ns_error=ns1.example.com. is already a nameserver')

    ns2 = re.search(r'/ns/(\d+)/delete', page.split('ns2.example.net.')[1]).group(1)
    admin.post(f'/zones/example.com/ns/{ns2}/delete', data={'csrf_token': t, 'rev': page_rev(page)})
    assert draft_text(settings) is None                # back to the published copy, so no draft
    page = admin.get('/zones/example.com').text
    assert '/delete' not in page.split('Nameservers')[1].split('</section>')[0]     # the last one can't go


def test_mx_saved_with_every_row_field_posted(admin, settings, zone):
    """Post the edit row the way the browser does: every input in page order, other types' empty ones too."""
    zone(SMALL)
    page = admin.get('/zones/example.com').text
    row = admin.get('/zones/example.com/records/new', params={'type': 'MX'}).text
    wanted = {'name': '@', 'type': 'MX', 'priority': '10', 'exchange': 'ns1', 'rev': page_rev(page)}
    fields = []
    for n in re.findall(r'<(?:input|select)[^>]*\bname="([^"]+)"', row):
        fields.append((n, wanted.pop(n, '')))          # a repeated name (another type's field) stays empty
    r = admin.post('/zones/example.com/records', content=urlencode(fields),
                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert r.status_code == 200, r.text
    assert re.search(r'@\s+(IN\s+)?MX\s+10 ns1', draft_text(settings))


def test_htmx_swaps_validation_errors():
    # htmx 2 leaves 4xx responses unswapped unless told otherwise; the grid's errors come back as 409/422
    base = (Path(__file__).parents[1] / 'liteblox' / 'templates' / 'base.html').read_text()
    config = json.loads(re.search(r'name="htmx-config" content=\'([^\']+)\'', base).group(1))
    swapped = {rule['code'] for rule in config['responseHandling'] if rule.get('swap')}
    assert {'409', '422'} <= swapped


# ── comparing versions ─────────────────────────────────────────────────────────

def test_compare_two_versions(admin, conn, settings, zone):
    zone(SMALL)
    repo = Repo(settings.repo_dir)
    repo.write(zone_file('example.com'), SMALL.replace('zz\tIN\tA\t192.0.2.99', 'zz\tIN\tA\t192.0.2.98'), 'Move zz', 'admin')
    repo.write(zone_file('example.com'), SMALL.replace('zz\tIN\tA\t192.0.2.99\n', 'zz\tIN\tA\t192.0.2.98\nnew\tIN\tA\t192.0.2.7\n'),
               'Add new', 'admin')
    first, middle, last = [c['sha'] for c in reversed(repo.log(zone_file('example.com')))]
    with conn:
        conn.execute("INSERT INTO deploys (zone_id, status, commit_sha, serial) VALUES (1, 'ok', ?, 2)", (last,))

    history = admin.get('/zones/example.com/history').text
    assert history.count('type="checkbox" name="v"') == 4                       # three versions + the publish of the last one
    assert f'name="v" value="{last}" aria-label="Compare publish #1"' in history

    page = admin.get('/zones/example.com/compare', params=[('v', last), ('v', first)]).text   # any order
    assert 'From</dt><dd><a href="/zones/example.com/history/' + first in page
    assert '<span class="pill warn">changed</span> <code>zz A</code>' in page and '192.0.2.99' in page
    assert '<span class="pill ready">added</span> <code>new  A 192.0.2.7</code>' in page
    assert '2 versions apart' in page and 'Move zz' in page
    assert '+new\tIN\tA\t192.0.2.7' in page

    same = admin.get('/zones/example.com/compare', params=[('v', middle), ('v', middle), ('v', last)]).text
    assert '1 versions apart' not in same and 'Add new' in same    # a version picked twice counts once


@pytest.mark.parametrize('picks', [[], ['x'], ['a', 'b', 'c'], ['deadbeef', 'cafebabe']])
def test_compare_needs_exactly_two_known_versions(admin, settings, zone, picks):
    zone(SMALL)
    shas = [c['sha'] for c in Repo(settings.repo_dir).log(zone_file('example.com'))]
    params = [('v', shas[0] if p in ('a', 'x') else p) for p in picks]
    r = admin.get('/zones/example.com/compare', params=params, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'].endswith('error=pick-two')
    assert 'Pick exactly two.' in admin.get(r.headers['location']).text


def test_soa_change_names_the_fields(admin, settings, zone):
    zone(SMALL)
    repo = Repo(settings.repo_dir)
    repo.write(zone_file('example.com'), SMALL.replace('hostmaster 1 3600', 'hostmaster 2 7200'), 'Bump', 'admin')
    shas = [c['sha'] for c in repo.log(zone_file('example.com'))]
    page = admin.get('/zones/example.com/compare', params=[('v', s) for s in shas]).text
    assert 'serial <code>1</code> → <code>2</code>, refresh <code>3600</code> → <code>7200</code>' in ' '.join(page.split())
