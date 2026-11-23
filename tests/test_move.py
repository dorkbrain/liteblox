"""Moving one address everywhere (4.1 M4): A records in every static zone, PTRs, the reservation, IPAM."""

import re

import pytest

from liteblox import move
from liteblox.dhcp import ops
from liteblox.dns.drafts import Drafts

from test_ptr import admin, draft  # noqa: F401 (fixtures)
from test_search import add_zone, kea_lease, world  # noqa: F401 (fixtures)

OTHER = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1.lab.example.
printer\tIN\tA\t192.0.2.60 ; by the stairs
nas\tIN\tA\t192.0.2.61
"""
REV = '2.0.192.in-addr.arpa'


@pytest.fixture
def place(conn, settings, world, monkeypatch):
    """world (lab.example has printer 192.0.2.60, the reverse zone a PTR for .60 to old-printer, a reservation
    on .60), plus other.example with printer at .60 too. DHCP jobs are recorded, not run."""
    add_zone(conn, settings, 'other.example', OTHER)
    started = []
    monkeypatch.setattr(ops, 'lease_warnings', lambda s, c, r: [])           # asks the node's Kea
    monkeypatch.setattr(ops, 'start_reservation',
                        lambda s, c, r, rid, user, via='': started.append(('one', r, rid)) or 7)
    monkeypatch.setattr(ops, 'start_reservations',
                        lambda s, c, add=(), delete=(), username=None, reason='': started.append(('many', add, delete)) or 8)
    world.started = started
    return world


def test_the_plan(conn, settings, place):
    p = move.plan(conn, settings, '192.0.2.60', '192.0.2.70')
    assert [(f['zone'], [r.name.to_text() for r in f['recs']]) for f in p['forward']] == [
        ('lab.example', ['printer.lab.example.']), ('other.example', ['printer.other.example.'])]
    assert [(m['zone'], m['target'].to_text()) for m in p['ptr_moves']] == [(REV, 'old-printer.lab.example.')]
    assert [i['r'].hw_address for i in p['reservations']] == ['aa:bb:cc:00:00:01']
    assert p['reservations'][0]['errors'] == {} and p['in_use'] == []
    assert p['zones'] == [REV, 'lab.example', 'other.example'] and not p['nothing']
    lines = move.ptr_lines(p)
    assert 'PTR 192.0.2.70 → printer.lab.example. is added in 2.0.192.in-addr.arpa' in lines
    assert any('old-printer' in line and 'goes' in line for line in lines)


def test_in_use_and_bad_addresses(conn, settings, place):
    p = move.plan(conn, settings, '192.0.2.60', '192.0.2.51')
    assert any('pc1.lab.example has it' in t for t in p['in_use'])
    p = move.plan(conn, settings, '192.0.2.60', '192.0.2.120')
    assert any('holds a lease' in t for t in p['in_use']) and any('DHCP pool' in t for t in p['in_use'])
    for new in ('192.0.2.60', 'nope'):
        with pytest.raises(move.MoveError):
            move.plan(conn, settings, '192.0.2.60', new)
    p = move.plan(conn, settings, '192.0.2.60', '198.51.100.7')
    assert 'no DHCP subnet' in p['reservations'][0]['errors']['ip_address']


def test_the_move(admin, conn, settings, place):
    page = admin.get('/addresses/192.0.2.60/move?to=192.0.2.70')
    assert page.status_code == 200 and 'Move to 192.0.2.70' in page.text and 'dyn.lab.example' not in page.text
    token = re.search(r'name="token" value="(\w+)"', page.text).group(1)
    r = admin.post('/addresses/192.0.2.60/move', data={'to': '192.0.2.70', 'token': token, 'reservation': '1',
                                                       'ipam': '1'}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == f'/zones/{REV}/review'
    lab, other, rev = draft(settings, 'lab.example'), draft(settings, 'other.example'), draft(settings, REV)
    assert re.search(r'^printer\s+IN\s+A\s+192\.0\.2\.70', lab, re.M) and '192.0.2.60' not in lab
    assert re.search(r'^printer\s+IN\s+A\s+192\.0\.2\.70\s+; by the stairs', other, re.M)
    assert '60\tIN\tPTR' not in rev and 'old-printer' not in rev
    assert '70\tIN\tPTR\tprinter.lab.example.' in rev and '70\tIN\tPTR\tprinter.other.example.' not in rev
    assert Drafts(settings).linked('lab.example') == {REV, 'other.example'}
    kind, moved, rid = place.started[0]
    assert kind == 'one' and moved.ip_address == '192.0.2.70' and moved.id == rid
    assert conn.execute("SELECT detail FROM audit WHERE action = 'address_move'").fetchone()[0].startswith(
        '192.0.2.60 → 192.0.2.70: 2 A in lab.example, other.example, 1 PTR, reservation')


def test_a_stale_preview_and_the_reservation_left(admin, conn, settings, place):
    token = move.plan(conn, settings, '192.0.2.60', '192.0.2.70')['token']
    from liteblox.dns import editing
    editing.apply_row(editing.ZoneEdit(settings, conn, 'other.example'), None, 'x', None, 'A', '192.0.2.9', None,
                      False, None, 'admin')
    r = admin.post('/addresses/192.0.2.60/move', data={'to': '192.0.2.70', 'token': token})
    assert r.status_code == 409 and 'changed since the preview' in r.text
    token = move.plan(conn, settings, '192.0.2.60', '192.0.2.70')['token']
    r = admin.post('/addresses/192.0.2.60/move', data={'to': '192.0.2.70', 'token': token}, follow_redirects=False)
    assert r.status_code == 303 and place.started == []                        # the reservation box unticked


def test_a_ptr_alone_moves(conn, settings, place):
    with conn:      # take the reservation and both A records off .60: only the PTR to old-printer is left
        conn.execute("DELETE FROM dhcp4_reservations")
    from liteblox.dns import editing
    for zone in ('lab.example', 'other.example'):
        edit = editing.ZoneEdit(settings, conn, zone)
        editing.delete_row(edit, next(r for r in edit.zone.records() if r.rdata == '192.0.2.60'), False, 'admin')
    p = move.plan(conn, settings, '192.0.2.60', '192.0.2.71')
    assert p['forward'] == [] and [m['remove_only'] for m in p['ptr_moves']] == [False]
    move.apply(conn, settings, '192.0.2.60', '192.0.2.71', p['token'], username='admin')
    rev = draft(settings, REV)
    assert '60\tIN\tPTR' not in rev and '71\tIN\tPTR\told-printer.lab.example.' in rev


def test_ipam_moves_with_it(conn, settings, place):
    from liteblox.ipam import model, names
    names.save(conn, '192.0.2.80', 'camera', comment='porch')
    model.set_note(conn, '192.0.2.81', 'spare', 'admin')
    p = move.plan(conn, settings, '192.0.2.80', '192.0.2.82')
    assert p['ipam']['assignment']['name'] == 'camera' and p['forward'] == []
    done = move.apply(conn, settings, '192.0.2.80', '192.0.2.82', p['token'], username='admin')
    assert done == {'zones': [], 'job': None, 'notes': [], 'warnings': []}
    assert names.get(conn, '192.0.2.82')['comment'] == 'porch' and names.get(conn, '192.0.2.80') is None
    p = move.plan(conn, settings, '192.0.2.81', '192.0.2.82')
    assert p['ipam']['note'] == 'spare' and p['ipam']['blocked'] is None
    move.apply(conn, settings, '192.0.2.81', '192.0.2.83', move.plan(conn, settings, '192.0.2.81', '192.0.2.83')['token'])
    assert model.notes(conn) == {'192.0.2.83': 'spare'}
    p = move.plan(conn, settings, '192.0.2.82', '192.0.2.83')
    assert p['ipam']['blocked'] is None                                         # a record onto a comment: fine
    names.save(conn, '192.0.2.84', 'other')
    p = move.plan(conn, settings, '192.0.2.82', '192.0.2.84')
    assert 'already has' in p['ipam']['blocked']
    with pytest.raises(move.MoveError):
        move.apply(conn, settings, '192.0.2.82', '192.0.2.84', p['token'])


def test_a_bad_record_moves_nothing(conn, settings, place):
    add_zone(conn, settings, 'cname.example', OTHER.replace('nas\tIN\tA\t192.0.2.61', 'nas\tIN\tCNAME\tprinter'))
    from liteblox.dns import editing
    edit = editing.ZoneEdit(settings, conn, 'cname.example')
    p = move.plan(conn, settings, '192.0.2.60', '192.0.2.70')
    monkey = editing.records.check
    calls = []

    def check(zone, rec, name, ttl, rtype, rdata):
        calls.append(zone.origin.to_text())
        if zone.origin.to_text() == 'other.example.':
            raise editing.records.RecordError({'value': 'refused for the test'})
        return monkey(zone, rec, name, ttl, rtype, rdata)
    editing.records.check = check
    try:
        with pytest.raises(move.MoveError):
            move.apply(conn, settings, '192.0.2.60', '192.0.2.70', p['token'], username='admin')
    finally:
        editing.records.check = monkey
    assert draft(settings, 'lab.example') is None and draft(settings, 'cname.example') is None
    assert draft(settings, REV) is None and place.started == [] and edit.zone is not None


def test_links_and_who_can_move(client, admin, conn, settings, place):
    card = admin.get('/search?q=192.0.2.60').text
    assert '/addresses/192.0.2.60/move' in card
    assert '/addresses/192.0.2.99/move' not in admin.get('/search?q=192.0.2.99').text      # nothing to move
    assert admin.get('/addresses/nope/move').status_code == 404
    assert admin.get('/addresses/192.0.2.60/move?to=bad').status_code == 422
