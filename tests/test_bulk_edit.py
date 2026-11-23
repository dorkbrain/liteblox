"""Bulk record edits: editing.batch (all or nothing, PTRs once per reverse zone) and the grid's select-and-act."""

import re

import pytest

from liteblox.dns import editing
from liteblox.dns.drafts import Drafts
from liteblox.dns.records import RecordError

from conftest import csrf_from
from test_dynamic import dyn, row_token, server  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)
from test_ptr import REV, admin, draft, grid_rev, row_id, zones  # noqa: F401 (fixtures)


def edit_of(settings, conn, name):
    return editing.ZoneEdit(settings, conn, name)


# ── editing.batch ──────────────────────────────────────────────────────────────

def test_a_bad_op_saves_nothing(settings, conn, zones):
    edit = edit_of(settings, conn, 'example.com')
    ops = [editing.Op(None, 'ok1', '', 'A', '192.0.2.81'),
           editing.Op(None, '@', '', 'CNAME', 'elsewhere.example.net.')]      # the apex can't be a CNAME
    with pytest.raises(RecordError) as e:
        editing.batch(edit, ops, True, 'admin')
    assert e.value.index == 1 and 'apex' in e.value.errors['type']
    assert draft(settings, 'example.com') is None and draft(settings, REV) is None
    assert not any(r.relative_name(edit.zone.origin) == 'ok1' for r in edit.zone.records())   # staged work dropped


def test_many_a_records_get_their_ptrs_in_one_reverse_save(settings, conn, zones, monkeypatch):
    saves = []
    real = editing.ZoneEdit.save
    monkeypatch.setattr(editing.ZoneEdit, 'save', lambda self, u: (saves.append(self.name), real(self, u))[1])
    edit = edit_of(settings, conn, 'example.com')
    ops = [editing.Op(None, f'bulk{i}', '', 'A', f'192.0.2.{80 + i}') for i in range(1, 4)]
    notes, warnings, saved = editing.batch(edit, ops, True, 'admin')
    assert saves == ['example.com', REV]
    assert [s.rdata for s in saved] == ['192.0.2.81', '192.0.2.82', '192.0.2.83']
    rtext = draft(settings, REV)
    assert all(f'{80 + i}\tIN\tPTR\tbulk{i}.example.com.' in rtext for i in range(1, 4))
    assert Drafts(settings).linked('example.com') == {REV}
    assert sum('added PTR' in n for n in notes) == 3


def test_apply_row_and_delete_row_still_work_one_at_a_time(settings, conn, zones):
    edit = edit_of(settings, conn, 'example.com')
    notes, _, saved = editing.apply_row(edit, None, 'solo', '', 'A', '192.0.2.90', 'just one', True, None, 'admin')
    assert saved.comment == 'just one' and any('192.0.2.90' in n for n in notes)
    notes, _ = editing.delete_row(edit, saved, True, 'admin')
    assert any('removed PTR 192.0.2.90' in n for n in notes) and draft(settings, REV) is None


# ── the grid ───────────────────────────────────────────────────────────────────

def bulk(client, action, ids, rev, **extra):
    data = {'action': action, 'rev': rev, 'ids': [str(i) for i in ids], **extra}
    return client.post('/zones/example.com/records/bulk', data=data, headers={'HX-Request': 'true'})


def test_the_grid_has_checkboxes_and_a_bar_for_admins(admin, zones):
    page = admin.get('/zones/example.com').text
    assert 'id="select-shown"' in page and 'class="row-select"' in page and 'id="bulk-bar"' in page
    assert 'name="ttl"' in page and 'Set comment' in page


def test_bulk_delete(admin, conn, settings, zones):
    page = admin.get('/zones/example.com').text
    ids = [row_id(page, 'host.sub a 192.0.2.200'), row_id(page, 'last a 192.0.2.250')]
    r = bulk(admin, 'delete', ids, grid_rev(page))
    assert r.status_code == 200, r.text
    text = draft(settings, 'example.com')
    assert '192.0.2.200' not in text and '192.0.2.250' not in text and 'mail' in text
    assert draft(settings, REV) is None             # 192.0.2.200's PTR names x.example.com: not host's to remove
    details = [r['detail'] for r in conn.execute("SELECT detail FROM audit WHERE action = 'record_bulk'")]
    assert details == ['example.com: delete 2 records']


def test_bulk_ttl_and_comment(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    ids = [row_id(page, 'mail a 192.0.2.25'), row_id(page, 'sip a 192.0.2.60')]
    r = bulk(admin, 'ttl', ids, grid_rev(page), ttl='2h')
    assert r.status_code == 200, r.text
    text = draft(settings, 'example.com')
    assert re.search(r'^mail\s+7200\s+IN\s+A\s+192\.0\.2\.25\s+; mail server', text, re.M)
    assert re.search(r'^sip\s+.*7200.*192\.0\.2\.60', text, re.M)

    ids = [row_id(r.text, 'mail a 192.0.2.25'), row_id(r.text, 'sip a 192.0.2.60')]
    r = bulk(admin, 'comment', ids, grid_rev(r.text), comment='moved to rack 2')
    text = draft(settings, 'example.com')
    assert text.count('; moved to rack 2') == 2 and '; mail server' not in text


def test_a_bad_ttl_changes_nothing(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    r = bulk(admin, 'ttl', [row_id(page, 'mail a 192.0.2.25')], grid_rev(page), ttl='soon')
    assert r.status_code == 422 and r.headers['HX-Retarget'] == '#zone-alert' and 'mail A: TTL must be' in r.text
    assert draft(settings, 'example.com') is None


def test_a_stale_page_is_refused(admin, settings, zones):
    page = admin.get('/zones/example.com').text
    rid = row_id(page, 'mail a 192.0.2.25')
    bulk(admin, 'comment', [rid], grid_rev(page), comment='first')
    r = bulk(admin, 'delete', [rid], grid_rev(page))
    assert r.status_code == 409 and 'another tab' in r.text


def test_nothing_selected_and_unknown_actions(admin, zones):
    rev = grid_rev(admin.get('/zones/example.com').text)
    assert bulk(admin, 'delete', [], rev).status_code == 400
    assert bulk(admin, 'shred', [1], rev).status_code == 400


def test_only_admins(client, make_user, login, zones):
    login(*make_user('viewer', 'viewer-password', 'readonly'))
    page = client.get('/zones/example.com').text
    assert 'class="row-select"' not in page and 'id="bulk-bar"' not in page
    client.headers['X-CSRF-Token'] = csrf_from(page)
    assert bulk(client, 'delete', [1], grid_rev(page)).status_code == 403


def test_a_dynamic_zone_deletes_in_one_update(admin, conn, settings, dyn):
    _, srv = dyn
    page = admin.get('/zones/dyn.lab').text
    t = csrf_from(page)
    assert 'Set TTL' not in page                    # Delete is the only action on a dynamic zone
    before = len(srv.updates)
    tokens = [row_token(page, 'pc1')[1], row_token(page, 'ns1')[1]]
    r = admin.post('/zones/dyn.lab/records/bulk', data={'action': 'delete', 'rr': tokens},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 200, r.text
    assert len(srv.updates) == before + 1
    text = srv.text('dyn.lab')
    assert 'pc1' not in text and 'ns1 3600 IN A' not in text

    r = admin.post('/zones/dyn.lab/records/bulk', data={'action': 'ttl', 'rr': tokens[0], 'ttl': '1h'},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 400 and 'only Delete' in r.text


def test_a_dynamic_row_changed_since_the_page_is_refused_whole(admin, conn, settings, dyn):
    _, srv = dyn
    page = admin.get('/zones/dyn.lab').text
    t = csrf_from(page)
    tokens = [row_token(page, 'pc1')[1], row_token(page, 'ns1')[1]]
    seen = srv.text('dyn.lab')
    from liteblox.dns import dynamic
    row = conn.execute("SELECT * FROM zones WHERE name = 'dyn.lab'").fetchone()
    dynamic.update(conn, row, dynamic.changes(seen, seen.replace('192.168.0.51', '192.168.0.52'), 'dyn.lab.'))
    before = srv.text('dyn.lab')
    r = admin.post('/zones/dyn.lab/records/bulk', data={'action': 'delete', 'rr': tokens},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 409 and srv.text('dyn.lab') == before


def test_the_dashboard_shows_a_scanner_with_no_service_pills(admin, conn):
    with conn:
        conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp, bind, dhcp, ntp, status, agent_version) "
                     "VALUES ('scan1', '192.0.2.9', 'k', 'f', 0, 0, 0, 'ready', '4.1.0')")
    page = admin.get('/').text
    row = page[page.index('">scan1</a>'):]
    assert '<span class="muted small">agent only</span>' in row[:row.index('</tr>')]       # no networks to sweep yet
