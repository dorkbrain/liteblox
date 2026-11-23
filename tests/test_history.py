"""Zone history: byte-exact reads, and restoring a version into a draft."""

from pathlib import Path

import pytest

from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file

from conftest import csrf_from

EXAMPLE = (Path(__file__).parent / 'fixtures' / 'zones' / 'example.com.zone').read_text()
CRLF = EXAMPLE.replace('\n', '\r\n')


# ── history: byte-exact reads and restore into a draft ─────────────────────────

def test_repo_show_keeps_crlf(settings):
    repo = Repo(settings.repo_dir).ensure()
    repo.write('zones/x.zone', CRLF, 'v1', 'test')
    sha = repo.log('zones/x.zone')[0]['sha']
    assert repo.show(sha, 'zones/x.zone') == CRLF


@pytest.fixture
def history(conn, settings):
    """example.com with two published versions (CRLF): v1 then v2 (ns1 moved)."""
    repo = Repo(settings.repo_dir).ensure()
    repo.write(zone_file('example.com'), CRLF, 'Import example.com', 'test')
    v2 = CRLF.replace('192.0.2.53', '192.0.2.153')
    repo.write(zone_file('example.com'), v2, 'Publish example.com', 'test')
    with conn:
        conn.execute("INSERT INTO zones (name, mode, repo_file) VALUES ('example.com', 'local', ?)",
                     (zone_file('example.com'),))
    commits = repo.log(zone_file('example.com'))
    return {'old': commits[1]['sha'], 'new': commits[0]['sha'], 'v2': v2}


@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def draft(settings):
    p = settings.data_dir / 'drafts' / 'example.com.zone'
    return p.read_bytes().decode() if p.exists() else None


def test_restore_old_version_into_draft(admin, settings, history):
    page = admin.get(f"/zones/example.com/history/{history['old']}").text
    assert 'Restore into a draft' in page and '+ns1\tIN\tA\t192.0.2.53' in page     # vs what's published now
    assert 'version that\'s published now' in admin.get(f"/zones/example.com/history/{history['new']}").text

    r = admin.post(f"/zones/example.com/history/{history['old']}/restore", data={'csrf_token': csrf_from(page)},
                   follow_redirects=False)
    assert r.headers['location'] == '/zones/example.com/review'
    assert draft(settings) == CRLF                                     # exact bytes, CRLF kept
    review = admin.get('/zones/example.com/review').text
    assert f"restores <a href=\"/zones/example.com/history/{history['old']}\">" in review
    assert Repo(settings.repo_dir).read(zone_file('example.com')) == history['v2']   # nothing published yet


def test_restore_over_an_existing_draft_needs_confirmation(admin, conn, settings, history):
    row = conn.execute('SELECT * FROM zones').fetchone()
    Drafts(settings).save(row, history['v2'] + '; pending\r\n', 'admin')
    page = admin.get(f"/zones/example.com/history/{history['old']}").text
    assert 'Replace the current draft' in page
    t = csrf_from(page)
    r = admin.post(f"/zones/example.com/history/{history['old']}/restore", data={'csrf_token': t},
                   follow_redirects=False)
    assert 'error=draft' in r.headers['location'] and draft(settings).endswith('; pending\r\n')
    admin.post(f"/zones/example.com/history/{history['old']}/restore", data={'csrf_token': t, 'replace': '1'})
    assert draft(settings) == CRLF


def test_restore_rules(client, make_user, login, history):
    login(*make_user('viewer', 'viewer-pass', 'readonly'))
    page = client.get(f"/zones/example.com/history/{history['old']}").text
    assert 'Restore into a draft' not in page
    r = client.post(f"/zones/example.com/history/{history['old']}/restore", data={'csrf_token': csrf_from(page)})
    assert r.status_code == 403


def test_restore_unknown_commit(admin, history):
    t = csrf_from(admin.get('/zones/example.com/history').text)
    assert admin.post('/zones/example.com/history/' + '0' * 40 + '/restore', data={'csrf_token': t}).status_code == 404
