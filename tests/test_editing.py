"""dns/editing.py: the record changes the grid and the API share."""

import threading

import pytest

from liteblox.dns import dynamic, editing
from liteblox.dns.zonefile import Zone

from test_ptr import FORWARD, REV, draft, zones  # noqa: F401 (fixture)


def edit(conn, settings, name='example.com'):
    return editing.ZoneEdit(settings, conn, name)


def test_missing_and_forwarding_zones(conn, settings, zones):  # noqa: F811
    with pytest.raises(editing.NoSuchZone):
        edit(conn, settings, 'nope.lab')
    with conn:
        conn.execute("UPDATE zones SET kind = 'forwarding' WHERE name = 'example.com'")
    with pytest.raises(editing.ForwardingZone):
        edit(conn, settings)
    assert editing.ZoneEdit(settings, conn, 'example.com', forwarding_ok=True).forwarding


def test_one_write_per_zone_at_a_time():
    order = []
    with editing.zone_lock('a.lab'):
        with editing.zone_lock('a.lab'):            # reentrant: a PTR change locks its reverse zone too
            pass
        t = threading.Thread(target=lambda: (editing.zone_lock('a.lab').__enter__(), order.append('a')))
        other = threading.Thread(target=lambda: order.append('b') if editing.zone_lock('b.lab').__enter__() is None else None)
        t.start(), other.start()
        other.join(1)
        t.join(0.2)
        assert order == ['b']                       # a.lab waits; b.lab doesn't
    t.join(1)
    assert order == ['b', 'a']


def test_find_by_position_content_and_rr(conn, settings, zones):  # noqa: F811
    e = edit(conn, settings)
    rec = next(r for r in e.zone.records() if r.rtype == 'A')
    assert editing.find(e, record_id=rec.id) is rec
    assert editing.find(e, key=dynamic.record_key(rec)) is rec
    assert editing.find(e, rr=dynamic.rr_token(e.zone, rec)) is rec
    assert editing.find(e, key='0' * 16) is None
    with pytest.raises(KeyError):
        editing.find(e, record_id=9999)


def test_apply_and_delete_with_the_ptr(conn, settings, zones):  # noqa: F811
    e = edit(conn, settings)
    notes, warnings, saved = editing.apply_row(e, None, 'web', '', 'A', '192.0.2.77', None, True, None, 'admin')
    assert saved.rtype == 'A' and saved.rdata == '192.0.2.77' and e.is_draft
    assert '77\tIN\tPTR\tweb.example.com.' in draft(settings, REV)
    assert REV in e.drafts.linked('example.com')
    e = edit(conn, settings)
    editing.delete_row(e, editing.find(e, key=dynamic.record_key(saved)), True, 'admin')
    assert 'web' not in (draft(settings, 'example.com') or FORWARD) and 'web.example.com' not in (draft(settings, REV) or '')


def test_soa_and_discard(conn, settings, zones):  # noqa: F811
    e = edit(conn, settings)
    assert editing.save_soa(e, {**editing.soa_fields(e.zone), 'refresh': 'soon'}, 'admin')     # an error text
    assert editing.save_soa(e, {**editing.soa_fields(e.zone), 'refresh': '2h'}, 'admin') is None
    assert Zone.parse(draft(settings, 'example.com'), 'example.com.').soa.rdata.split()[3] == '7200'
    assert editing.discard(edit(conn, settings), 'admin') == ['example.com']
    assert draft(settings, 'example.com') is None
