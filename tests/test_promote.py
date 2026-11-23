"""Promote (planned and failover), demoting a returning old primary, demote reports."""

import json

import dns.name
import dns.zone
import pytest

from liteblox.dns import declare, dynamic, publish as pub
from liteblox.dns.drafts import Drafts
from liteblox.nodes import reports, roles

from test_dynamic import FORWARD, dyn, server, zone_row  # noqa: F401 (fixtures)
from test_managed import lab, ok_verify  # noqa: F401 (fixtures)

STATIC = FORWARD.replace('dyn.lab', 'static.lab')
NS1, NS2 = '192.0.2.53', '192.0.2.54'


@pytest.fixture
def pair(conn, settings, dyn):
    """dyn.lab (dynamic) and static.lab on ns1 (primary) + ns2 (secondary). copies: {host: {zone: text}}
    stands in for what each node serves; a host or zone not in it answers like the primary."""
    fakes, server = dyn
    declare.create_zone(settings, 'static.lab', ['1', '2'], STATIC, 'admin', print, verify=ok_verify)
    copies = {}

    def transfer(host, name, keyring, algorithm):
        text = copies.get(host, {}).get(name)
        if text is None:
            return server.zones[name]
        return dns.zone.from_text(text, name + '.', relativize=False, check_origin=False)
    return fakes, server, copies, transfer


def kw(transfer):
    return {'transfer': transfer, 'verify': ok_verify, 'served': lambda host, name: None}


def role(conn, node_id):
    return conn.execute('SELECT role, pending FROM nodes WHERE id = ?', (node_id,)).fetchone()


def declared(fake):
    return {name: (z['type'], z['file']) for name, z in fake.declared().items()}


def test_planned_promote_moves_every_zone_and_demotes_the_old_primary(conn, settings, pair):
    fakes, server, copies, transfer = pair
    lines = []
    roles.promote(settings, 2, 'admin', lines.append, **kw(transfer))
    assert tuple(role(conn, 2)) == ('primary', None) and tuple(role(conn, 1)) == ('secondary', None)
    assert declared(fakes[2]) == {'dyn.lab': ('primary', '/var/lib/bind/liteblox/dyn/db.dyn.lab'),
                                  'static.lab': ('primary', '/etc/bind/liteblox/db.static.lab')}
    assert declared(fakes[1]) == {'dyn.lab': ('secondary', '/var/lib/bind/liteblox/sec/db.dyn.lab'),
                                  'static.lab': ('secondary', '/var/lib/bind/liteblox/sec/db.static.lab')}
    assert f'primaries {{ {NS2} key liteblox-xfr; }}' in fakes[1].zones_conf
    assert 'update-policy' in fakes[2].zones_conf and 'update-policy' not in fakes[1].zones_conf
    # the new primary starts from the old one's dynamic copy and LiteBlox's published static copy
    assert fakes[2].files['dyn.lab'] == server.text('dyn.lab')
    assert fakes[2].files['static.lab'] == Drafts(settings).published(zone_row(conn, 'static.lab'))
    assert any("ns1's copy" in line for line in lines) and conn.execute('SELECT COUNT(*) FROM demote_reports').fetchone()[0] == 0
    files = dict(conn.execute('SELECT node_id, node_file FROM zone_nodes WHERE zone_id = ?',
                              (zone_row(conn, 'dyn.lab')['id'],)).fetchall())
    assert files == {1: '/var/lib/bind/liteblox/sec/db.dyn.lab', 2: '/var/lib/bind/liteblox/dyn/db.dyn.lab'}
    # grid edits now go to ns2
    assert dynamic.primary_host(conn, zone_row(conn, 'dyn.lab')) == NS2


def test_failover_then_the_old_primary_is_demoted_with_a_report(conn, settings, pair):
    fakes, server, copies, transfer = pair
    # ns1 took an update ns2 never got, then went down
    ahead = server.text('dyn.lab').replace('2026102801', '2026102805') + 'pc9 300 IN A 192.168.0.59\n'
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    assert tuple(role(conn, 2)) == ('primary', None) and tuple(role(conn, 1)) == ('secondary', 'demote')
    assert declared(fakes[1])['dyn.lab'][0] == 'primary'            # untouched while down

    fakes[1].down = False
    copies[NS1] = {'dyn.lab': ahead}
    fakes[1].fail_commit = True                 # the first try fails after the report is kept
    with pytest.raises(roles.RoleError):
        roles.reconcile(settings, 1, 'liteblox', print, **kw(transfer))
    fakes[1].fail_commit = False
    roles.reconcile(settings, 1, 'liteblox', print, **kw(transfer))
    assert tuple(role(conn, 1)) == ('secondary', None)
    assert declared(fakes[1])['dyn.lab'] == ('secondary', '/var/lib/bind/liteblox/sec/db.dyn.lab')
    [report] = reports.open_reports(conn)
    assert report['node'] == 'ns1' and report['zone'] == 'dyn.lab' and report['node_serial'] == 2026102805
    assert report['rrsets'] == [['pc9', 'A', 300, ['192.168.0.59'], None]]
    # the primary's serial goes past the copy ns1 had, so it transfers again
    assert dynamic.serial(server.text('dyn.lab'), dns.name.from_text('dyn.lab.')) > 2026102805

    assert 'sent to' in reports.reapply(settings, conn, report['id'], [0], 'admin')
    assert 'pc9' in server.text('dyn.lab') and reports.open_reports(conn) == []


def test_promote_picks_the_newest_reachable_copy(conn, settings, pair):
    fakes, server, copies, transfer = pair
    fakes[1].down = True
    newer = server.text('dyn.lab').replace('2026102801', '2026102809')
    copies[NS2] = {'dyn.lab': newer}
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    assert fakes[2].files['dyn.lab'] == newer


def test_a_refused_promote_changes_nothing(conn, settings, pair):
    fakes, server, copies, transfer = pair
    before = conn.execute('SELECT * FROM zone_nodes ORDER BY zone_id, node_id').fetchall()
    fakes[2].fail_commit = True
    with pytest.raises(roles.RoleError, match='could not become the primary'):
        roles.promote(settings, 2, 'admin', print, **kw(transfer))
    assert tuple(role(conn, 1)) == ('primary', None) and tuple(role(conn, 2)) == ('secondary', None)
    assert [tuple(r) for r in conn.execute('SELECT * FROM zone_nodes ORDER BY zone_id, node_id')] == \
        [tuple(r) for r in before]


def test_promote_refusals(conn, settings, pair):
    fakes, server, copies, transfer = pair
    with pytest.raises(roles.RoleError, match='already the primary'):
        roles.promote(settings, 1, 'admin', print, **kw(transfer))
    fakes[2].down = True
    with pytest.raises(roles.RoleError, match='ns2 is unreachable'):
        roles.promote(settings, 2, 'admin', print, **kw(transfer))
    fakes[2].down = False
    with roles.ROLE_LOCK:
        with pytest.raises(roles.RoleError, match='another role change'):
            roles.promote(settings, 2, 'admin', print, **kw(transfer))
        with pytest.raises(pub.PublishError, match='role change'):
            pub.publish(settings, 'static.lab', 'admin', print)


def test_make_primary_on_a_secondary_promotes(conn, settings, pair):
    fakes, server, copies, transfer = pair
    roles.make_primary(settings, 2, 'admin', print, **kw(transfer))
    assert tuple(role(conn, 2)) == ('primary', None)


def test_a_hand_edit_on_the_old_primary_goes_into_the_draft(conn, settings, pair):
    fakes, server, copies, transfer = pair
    fakes[1].files['static.lab'] += 'extra\tIN\tTXT\t"hand made"\n'
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    fakes[1].down = False
    roles.reconcile(settings, 1, 'liteblox', print, **kw(transfer))
    [report] = reports.open_reports(conn, node_id=1)
    assert report['zone'] == 'static.lab' and report['rrsets'][0][:2] == ['extra', 'TXT']
    assert 'draft' in reports.reapply(settings, conn, report['id'], [0], 'admin')
    text, is_draft = Drafts(settings).load(zone_row(conn, 'static.lab'))
    assert is_draft and '"hand made"' in text


def test_dismiss_and_a_reconcile_failure_keeps_it_pending(conn, settings, pair):
    fakes, server, copies, transfer = pair
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    fakes[1].down = False
    fakes[1].fail_commit = True
    with pytest.raises(roles.RoleError):
        roles.reconcile(settings, 1, 'liteblox', print, **kw(transfer))
    assert role(conn, 1)['pending'] == 'demote'
    with conn:
        conn.execute("INSERT INTO demote_reports (node_id, zone_id, old_text, rrsets) VALUES (1, ?, '', ?)",
                     (zone_row(conn, 'dyn.lab')['id'], json.dumps([['x', 'A', 60, ['192.0.2.1'], None]])))
    report = reports.open_reports(conn)[0]
    reports.dismiss(conn, report['id'], 'admin')
    assert reports.open_reports(conn) == []


def lags_on(host):
    """verify: `host` answers one serial behind (still transferring), every other node is current."""
    return lambda h, zone, expected, **kw: expected - 1 if h == host else expected


def test_a_node_still_catching_up_is_a_warning_not_a_failure(conn, settings, pair):
    fakes, server, copies, transfer = pair
    lines = []
    roles.promote(settings, 2, 'admin', lines.append, **{**kw(transfer), 'verify': lags_on(NS1)})
    assert tuple(role(conn, 2)) == ('primary', None) and tuple(role(conn, 1)) == ('secondary', None)
    assert any(line.startswith('  ⚠ ns1 took its new config but is still catching up') for line in lines)
    assert lines[-1].endswith('(ns1 still catching up)')


def test_a_reconcile_that_lags_ends_ok(conn, settings, pair):
    fakes, server, copies, transfer = pair
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    fakes[1].down = False
    lines = []
    roles.reconcile(settings, 1, 'liteblox', lines.append, transfer=transfer, verify=lags_on(NS1))
    assert tuple(role(conn, 1)) == ('secondary', None)
    assert any('still catching up' in line for line in lines)


def test_a_crlf_copy_on_the_old_primary_is_still_compared(conn, settings, pair):
    """A zone file saved with CRLF: Promote still finds what only the old primary's copy holds."""
    fakes, server, copies, transfer = pair
    published = Drafts(settings).published(zone_row(conn, 'static.lab'))
    fakes[1].files['static.lab'] = (published + 'extra 300 IN A 192.0.2.99\n').replace('\n', '\r\n')
    lines = []
    roles.promote(settings, 2, 'admin', lines.append, **kw(transfer))
    assert not any("couldn't compare" in line for line in lines)
    rrsets = [json.loads(r[0]) for r in conn.execute('SELECT rrsets FROM demote_reports WHERE zone_id = ?',
                                                     (zone_row(conn, 'static.lab')['id'],))]
    assert rrsets == [[['extra', 'A', 300, ['192.0.2.99'], None]]]


def test_serial_and_changes_read_crlf_text():
    origin = dns.name.from_text('static.lab.')
    crlf = STATIC.replace('\n', '\r\n')
    assert dynamic.serial(crlf, origin) == dynamic.serial(STATIC, origin)
    assert dynamic.changes(crlf, STATIC, origin) == []
