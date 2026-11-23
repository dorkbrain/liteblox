"""Add many: pasted lines and CSV, the preview, Replace, export and the template."""

import re

import pytest

from liteblox.dns import many

from test_dynamic import dyn, server  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)
from test_ptr import REV, admin, draft, zones  # noqa: F401 (fixtures)


def outcomes(html):
    """[(outcome, record text, notes)] from the preview table."""
    out = []
    for m in re.finditer(r'<tr class="many-(\w+)">(.*?)</tr>', html, re.S):
        cells = re.findall(r'<td[^>]*>(.*?)</td>', m.group(2), re.S)
        text = re.sub(r'<[^>]+>', '', cells[2]).strip()
        notes = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', cells[3])).strip()
        out.append((m.group(1), text, notes))
    return out


def preview(client, text='', replace=False, csv=None, ptr=True):
    data = {'text': text, 'ptr_field': '1', **({'ptr': '1'} if ptr else {}), **({'replace': '1'} if replace else {})}
    files = {'csv': ('import.csv', csv.encode(), 'text/csv')} if csv is not None else None
    return client.post('/zones/example.com/records/many/preview', data=data, files=files)


def rev_of(html):
    return re.search(r'name="rev" value="([0-9a-f]+)"', html).group(1)


# ── parsing ────────────────────────────────────────────────────────────────────

def test_lines_from_text():
    lines = many.from_text('host1 A 192.0.2.10 ; printer\n\n$ORIGIN x.\nwww 3600 CNAME host1\nnot a record\n',
                           'example.com.')
    got = [(l.where, l.name, l.ttl, l.rtype, l.value, l.comment, bool(l.error)) for l in lines]
    assert got[0] == ('line 1', 'host1', None, 'A', '192.0.2.10', 'printer', False)
    assert got[1][0] == 'line 3' and got[1][6] and 'directives' in lines[1].error
    assert got[2] == ('line 4', 'www', 3600, 'CNAME', 'host1', None, False)
    assert got[3][0] == 'line 5'           # parsed as best it can; the preview's checks report its value


def test_lines_from_csv():
    text = ('name,ttl,type,value,comment\n# a note\n#host9,,A,192.0.2.9,\nhost1,,a,192.0.2.10,printer\n'
            '@,,TXT,"""v=spf1 mx -all"""\nbad,row\n,,A,192.0.2.11,\n')
    lines = many.from_csv(text)
    assert [(l.where, l.name, l.rtype, l.value, l.comment) for l in lines[:2]] == [
        ('line 4', 'host1', 'A', '192.0.2.10', 'printer'), ('line 5', '@', 'TXT', '"v=spf1 mx -all"', None)]
    assert '2 columns' in lines[2].error and 'no name' in lines[3].error


def test_too_many_lines():
    lines = many.from_text('\n'.join(f'h{i} A 192.0.2.1' for i in range(many.MAX_LINES + 1)), 'example.com.')
    assert len(lines) == 1 and 'at most' in lines[0].error


# ── the page ───────────────────────────────────────────────────────────────────

def test_preview_shows_each_line(admin, settings, zones):
    r = preview(admin, 'web1 A 192.0.2.71\nns1 A 192.0.2.53\nmail A 192.0.2.26\nweb2 A 192.0.2.300\n')
    assert r.status_code == 200
    rows = outcomes(r.text)
    assert [o for o, _, _ in rows] == ['add', 'same', 'add', 'error']
    assert 'already there' in rows[1][2] and 'adds a second A for mail' in rows[2][2]
    assert 'Make these' not in r.text and 'Fix the lines' in r.text
    assert draft(settings, 'example.com') is None


def test_add_goes_into_the_draft_with_ptrs(admin, conn, settings, zones):
    r = preview(admin, 'web1 A 192.0.2.71 ; first\nweb2 600 A 192.0.2.72\nalias CNAME web1\n')
    assert 'Make these 3 changes' in r.text
    r = admin.post('/zones/example.com/records/many', data={
        'rev': rev_of(r.text), 'text': 'web1 A 192.0.2.71 ; first\nweb2 600 A 192.0.2.72\nalias CNAME web1\n',
        'ptr_field': '1', 'ptr': '1'}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/zones/example.com/review'
    text = draft(settings, 'example.com')
    assert re.search(r'^web1\s+IN\s+A\s+192\.0\.2\.71\s+; first', text, re.M) and 'alias' in text
    rtext = draft(settings, REV)
    assert '71\tIN\tPTR\tweb1.example.com.' in rtext and '72\tIN\tPTR\tweb2.example.com.' in rtext
    assert [d for (d,) in conn.execute("SELECT detail FROM audit WHERE action = 'record_many'")] == [
        'example.com: 3 added']


def test_replace_changes_and_removes(admin, settings, zones):
    text = 'mail 600 A 192.0.2.25 ; new comment\nsip A 192.0.2.61\n'
    r = preview(admin, text, replace=True)
    rows = outcomes(r.text)
    assert ('remove', 'sip 120 A 192.0.2.60', '') in rows
    assert [o for o, _, _ in rows if o != 'remove'] == ['change', 'add']
    r = admin.post('/zones/example.com/records/many', data={'rev': rev_of(r.text), 'text': text, 'replace': '1',
                                                            'ptr_field': '1'}, follow_redirects=False)
    assert r.status_code == 303
    zone = draft(settings, 'example.com')
    assert re.search(r'^mail\s+600\s+IN\s+A\s+192\.0\.2\.25\s+; new comment', zone, re.M)
    assert '192.0.2.60' not in zone and '192.0.2.61' in zone


def test_a_bad_line_refuses_the_add(admin, settings, zones):
    rev = rev_of(preview(admin, 'ok A 192.0.2.80\n').text)
    r = admin.post('/zones/example.com/records/many', data={'rev': rev, 'text': 'ok A 192.0.2.80\nbad A nope\n'})
    assert r.status_code == 422 and 'Fix the lines marked as errors first' in r.text
    assert draft(settings, 'example.com') is None


def test_a_zone_changed_since_the_preview(admin, settings, zones):
    rev = rev_of(preview(admin, 'ok A 192.0.2.80\n').text)
    admin.post('/zones/example.com/records/many', data={'rev': rev, 'text': 'first A 192.0.2.81\n'})
    r = admin.post('/zones/example.com/records/many', data={'rev': rev, 'text': 'ok A 192.0.2.80\n'})
    assert r.status_code == 409 and 'changed since the preview' in r.text


def test_csv_upload_and_nothing_to_add(admin, zones):
    r = preview(admin, csv='name,ttl,type,value,comment\nweb9,,A,192.0.2.79,from csv\n')
    assert [o for o, _, _ in outcomes(r.text)] == ['add'] and 'import.csv' in r.text
    assert 'name="csv_text"' in r.text                       # carried to the Add form
    r = preview(admin, '')
    assert r.status_code == 422 and 'Nothing to add' in r.text


def test_export_then_import_changes_nothing(admin, zones):
    exported = admin.get('/zones/example.com/records.csv')
    assert exported.headers['content-type'].startswith('text/csv')
    assert exported.text.splitlines()[0] == 'name,ttl,type,value,comment'
    assert 'mail,3600,A,192.0.2.25,mail server' in exported.text
    rows = outcomes(preview(admin, csv=exported.text).text)
    assert rows and {o for o, _, _ in rows} == {'same'}, [r for r in rows if r[0] != 'same']


EMPTY = ('$TTL 1h\n@\tIN\tSOA\tns1.example.com. hostmaster.example.com. 1 3600 900 1209600 300\n'
         '@\tIN\tNS\tns1.example.com.\n')


@pytest.fixture
def empty_zones(conn, settings, zones):
    from liteblox.dns.repo import Repo, zone_file
    repo = Repo(settings.repo_dir)
    for name in ('empty.test', '100.51.198.in-addr.arpa'):
        repo.write(zone_file(name), EMPTY, f'Import {name}', 'test')
        with conn:
            conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES (?, 'local', ?)", (name, zone_file(name)))


@pytest.mark.parametrize('zone', ['empty.test', '100.51.198.in-addr.arpa'])
def test_the_template(admin, empty_zones, zone):
    t = admin.get(f'/zones/{zone}/records-template.csv').text
    assert t.splitlines()[0] == 'name,ttl,type,value,comment' and t.count('\n#') >= 3
    assert many.from_csv(t) == []                             # as downloaded: only the header and # rows
    samples = '\n'.join(line[1:] if line.startswith('#') and not line.startswith('# ') else line
                        for line in t.splitlines())
    r = admin.post(f'/zones/{zone}/records/many/preview', data={'ptr_field': '1'},
                   files={'csv': ('t.csv', samples.encode(), 'text/csv')})
    rows = outcomes(r.text)
    assert rows and {o for o, _, _ in rows} == {'add'}, rows
    if zone.endswith('.arpa'):
        assert [text.split(' ;')[0] for _, text, _ in rows] == ['1 PTR host1.empty.test.', '2 PTR host2.empty.test.']


def test_dynamic_zones_have_no_add_many(admin, dyn):
    assert admin.get('/zones/dyn.lab/records/many', follow_redirects=False).headers['location'] == '/zones/dyn.lab'
    assert 'records/many' not in admin.get('/zones/dyn.lab').text
    assert admin.get('/zones/dyn.lab/records.csv').text.startswith('name,ttl,type,value,comment')
