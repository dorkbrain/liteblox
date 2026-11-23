"""Dynamic zones: AXFR reads, guarded updates, snapshots, the switch, the grid, the PTR matrix."""

import json

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.zone
import pytest

from liteblox import jobs
from liteblox.dns import declare, dynamic, publish as pub
from liteblox.dns.drafts import Drafts
from liteblox.dns.repo import Repo, zone_file
from liteblox.nodes import service as nodes

from conftest import csrf_from
from test_managed import Client, FakeNode, lab, make_roles, ok_verify  # noqa: F401 (fixtures)

FORWARD = """$TTL 3600
@\tIN\tSOA\tns1.dyn.lab. hostmaster.dyn.lab. 2026102801 3600 900 1209600 300
@\tIN\tNS\tns1.dyn.lab.
ns1\tIN\tA\t192.0.2.53
pc1\tIN\tA\t192.168.0.51
"""
REVERSE = """$TTL 3600
@\tIN\tSOA\tns1.dyn.lab. hostmaster.dyn.lab. 2026102801 3600 900 1209600 300
@\tIN\tNS\tns1.dyn.lab.
51\tIN\tPTR\tpc1.dyn.lab.
"""


class FakeServer:
    """named's side of a dynamic zone: AXFR from a dnspython zone, updates checked like named does."""

    def __init__(self):
        self.zones = {}
        self.updates = []
        self.refuse = None

    def load(self, name, text):
        self.zones[name] = dns.zone.from_text(text, name + '.', relativize=False, check_origin=False)

    def transfer(self, host, name, keyring, algorithm):
        return self.zones[name]

    def send(self, message, host):
        message = dns.message.from_wire(message.to_wire(), keyring=message.keyring)   # as named sees it
        self.updates.append(message)
        response = dns.message.make_response(message)
        if self.refuse:
            response.set_rcode(self.refuse)
            return response
        zone = self.zones[message.zone[0].name.to_text(omit_final_dot=True)]
        wanted = {}                                         # value-dependent prerequisites, per RRset (RFC 2136 3.2.5)
        for rrset in message.prerequisite:                  # all must hold, or nothing changes
            if rrset.ttl != 0:
                response.set_rcode(dns.rcode.FORMERR)           # named: "prerequisite TTL is not zero"
                return response
            have = zone.get_rdataset(rrset.name, rrset.rdtype)
            if rrset.deleting == dns.rdataclass.NONE and have is not None:
                response.set_rcode(dns.rcode.YXRRSET)
                return response
            if rrset.deleting is None:
                wanted.setdefault((rrset.name, rrset.rdtype), set()).update(rrset)
        for (name, rdtype), rdatas in wanted.items():
            have = zone.get_rdataset(name, rdtype)
            if have is None or set(have) != rdatas:
                response.set_rcode(dns.rcode.NXRRSET)
                return response
        for rrset in message.update:
            if rrset.deleting == dns.rdataclass.ANY:
                zone.delete_rdataset(rrset.name, rrset.rdtype)
            else:
                node = zone.find_node(rrset.name, create=True)
                rds = node.find_rdataset(rrset.rdclass, rrset.rdtype, create=True)
                rds.update_ttl(rrset.ttl)
                for rd in rrset:
                    rds.add(rd)
        soa = zone.get_rdataset(zone.origin, 'SOA')
        if not any(r.rdtype == dns.rdatatype.SOA for r in message.update):
            new = soa[0].replace(serial=soa[0].serial + 1)      # named bumps the serial on every update
            zone.replace_rdataset(zone.origin, dns.rdataset.from_rdata(soa.ttl, new))
        return response

    def text(self, name):
        return dynamic.to_text(self.zones[name])


@pytest.fixture
def server(monkeypatch):
    s = FakeServer()
    real_axfr, real_update = dynamic.axfr, dynamic.update
    monkeypatch.setattr(dynamic, 'axfr', lambda conn, zone, transfer=None: real_axfr(conn, zone, s.transfer))
    monkeypatch.setattr(dynamic, 'update', lambda conn, zone, todo, send=None: real_update(conn, zone, todo, s.send))
    return s


@pytest.fixture
def dyn(conn, settings, lab, server):  # noqa: F811
    """dyn.lab on ns1 (primary) + ns2 (secondary), switched to dynamic; its server is a FakeServer."""
    fakes, _ = lab
    make_roles(conn)
    declare.create_zone(settings, 'dyn.lab', ['1', '2'], FORWARD, 'admin', print, verify=ok_verify)
    server.load('dyn.lab', Drafts(settings).published(conn.execute("SELECT * FROM zones WHERE name = 'dyn.lab'").fetchone()))
    declare.set_dynamic(settings, 'dyn.lab', True, 'admin', print, verify=ok_verify)
    return fakes, server


def zone_row(conn, name):
    return conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()


# ── the pieces ─────────────────────────────────────────────────────────────────

def test_changes_and_update_messages(conn, settings, dyn):
    fakes, server = dyn
    old = server.text('dyn.lab')
    new = old.replace('192.168.0.51', '192.168.0.52') + 'pc2 3600 IN A 192.168.0.60\n'
    todo = dynamic.changes(old, new, 'dyn.lab.')
    assert [(n.to_text(), dns.rdatatype.to_text(t), b is not None, a is not None) for n, t, b, a in todo] == [
        ('pc1.dyn.lab.', 'A', True, True), ('pc2.dyn.lab.', 'A', False, True)]
    dynamic.update(conn, zone_row(conn, 'dyn.lab'), todo)
    msg = server.updates[-1]
    prereq = {(r.name.to_text(), r.deleting) for r in msg.prerequisite}
    assert prereq == {('pc1.dyn.lab.', None), ('pc2.dyn.lab.', dns.rdataclass.NONE)}      # exactly so / absent
    assert msg.keyname == dns.name.from_text('liteblox')                     # signed with LiteBlox's own key
    assert 'pc2' in server.text('dyn.lab') and '192.168.0.52' in server.text('dyn.lab')


def test_a_stale_view_is_refused_and_nothing_changes(conn, settings, dyn):
    fakes, server = dyn
    seen = server.text('dyn.lab')
    dynamic.update(conn, zone_row(conn, 'dyn.lab'),
                   dynamic.changes(seen, seen.replace('192.168.0.51', '192.168.0.99'), 'dyn.lab.'))  # DHCP, say
    with pytest.raises(dynamic.Conflict, match='changed on the server'):
        dynamic.update(conn, zone_row(conn, 'dyn.lab'),
                       dynamic.changes(seen, seen.replace('192.168.0.51', '192.168.0.52'), 'dyn.lab.'))
    assert '192.168.0.99' in server.text('dyn.lab') and '192.168.0.52' not in server.text('dyn.lab')
    server.refuse = dns.rcode.REFUSED
    with pytest.raises(dynamic.DynamicError, match='refused the update'):
        dynamic.update(conn, zone_row(conn, 'dyn.lab'), dynamic.changes(seen, seen + 'x 60 IN A 1.2.3.4\n', 'dyn.lab.'))


def test_a_soa_edit_goes_one_past_the_serial(conn, settings, dyn):
    _, server = dyn
    old = server.text('dyn.lab')
    serial = dynamic.serial(old, 'dyn.lab.')
    new = old.replace(' 3600 900 1209600 300', ' 7200 900 1209600 300')
    (name, rdtype, before, after), = dynamic.changes(old, new, 'dyn.lab.')
    assert rdtype == dns.rdatatype.SOA and after[0].serial == serial + 1 and after[0].refresh == 7200


def test_snapshots(conn, settings, dyn):
    _, server = dyn
    repo = Repo(settings.repo_dir)
    log = repo.log(zone_file('dyn.lab'))
    assert log[0]['subject'].startswith('Dynamic from now on (serial')
    lines = []
    dynamic.snapshot_all(settings, lines.append, transfer=server.transfer)
    assert lines == ['dyn.lab: unchanged']
    zone = server.zones['dyn.lab']
    node = zone.find_node(dns.name.from_text('pc9.dyn.lab.'), create=True)
    node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.A, create=True).add(
        dns.rdata.from_text('IN', 'A', '192.168.0.9'), 300)
    dynamic.snapshot_all(settings, lines.append, transfer=server.transfer)
    assert lines[-1].startswith('dyn.lab: committed')
    assert repo.log(zone_file('dyn.lab'))[0]['subject'].startswith('Snapshot (serial')
    assert 'pc9' in repo.read(zone_file('dyn.lab'))


# ── switching ──────────────────────────────────────────────────────────────────

def test_switch_on_moves_the_file_and_grants_liteblox(conn, settings, dyn):
    fakes, server = dyn
    primary = fakes[1].declared()['dyn.lab']
    assert primary == {'name': 'dyn.lab', 'type': 'primary', 'dynamic': True, 'journal': None,
                       'file': '/var/lib/bind/liteblox/dyn/db.dyn.lab'}
    assert 'update-policy { grant liteblox zonesub ANY; };' in fakes[1].zones_conf
    assert 'allow-transfer { key liteblox; key liteblox-xfr; };' in fakes[1].zones_conf
    assert fakes[2].declared()['dyn.lab']['type'] == 'secondary'
    assert 'key "liteblox"' in fakes[1].config_files['keys.conf']
    link = conn.execute('SELECT node_file, deployed_sha256 FROM zone_nodes WHERE node_id = 1').fetchone()
    assert tuple(link) == ('/var/lib/bind/liteblox/dyn/db.dyn.lab', None)
    assert zone_row(conn, 'dyn.lab')['dynamic'] == 1
    with pytest.raises(declare.DeclareError, match='already dynamic'):
        declare.set_dynamic(settings, 'dyn.lab', True, 'admin', print, verify=ok_verify)
    with pytest.raises(pub.PublishError, match='is dynamic'):
        pub.publish(settings, 'dyn.lab', 'admin', print)


def test_switch_off_keeps_what_named_serves(conn, settings, dyn):
    fakes, server = dyn
    seen = server.text('dyn.lab')
    dynamic.update(conn, zone_row(conn, 'dyn.lab'), dynamic.changes(seen, seen + 'dhcp1 300 IN A 192.168.0.70\n', 'dyn.lab.'))
    declare.set_dynamic(settings, 'dyn.lab', False, 'admin', print, verify=ok_verify, transfer=server.transfer)
    text = Repo(settings.repo_dir).read(zone_file('dyn.lab'))
    assert 'dhcp1' in text and Repo(settings.repo_dir).log(zone_file('dyn.lab'))[0]['subject'].startswith('Static again')
    assert fakes[1].files['dyn.lab'] == text
    assert fakes[1].declared()['dyn.lab']['file'] == '/etc/bind/liteblox/db.dyn.lab'
    assert 'update-policy' not in fakes[1].zones_conf and zone_row(conn, 'dyn.lab')['dynamic'] == 0


def test_switch_on_needs_a_primary_and_no_draft(conn, settings, lab, server):  # noqa: F811
    declare.create_zone(settings, 'dyn.lab', ['1', '2'], FORWARD, 'admin', print, verify=ok_verify)
    with pytest.raises(declare.DeclareError, match='pick a primary'):
        declare.set_dynamic(settings, 'dyn.lab', True, 'admin', print, verify=ok_verify)
    make_roles(conn, primary=1, secondary=99)           # ns2 keeps a primary copy
    with pytest.raises(declare.DeclareError, match='ns2 still hold'):
        declare.set_dynamic(settings, 'dyn.lab', True, 'admin', print, verify=ok_verify)
    make_roles(conn)
    Drafts(settings).save(zone_row(conn, 'dyn.lab'), FORWARD + 'x IN A 192.0.2.9\n', 'admin')
    with pytest.raises(declare.DeclareError, match='draft'):
        declare.set_dynamic(settings, 'dyn.lab', True, 'admin', print, verify=ok_verify)


# ── the grid ───────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login):
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def grid_rev(client, name):
    import re
    return re.search(r'id="zone-grid"[^>]*data-rev="([^"]+)"', client.get(f'/zones/{name}').text).group(1)


def test_grid_edits_are_updates(admin, conn, settings, dyn):
    fakes, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t = csrf_from(page)
    assert '>dynamic</a>' in page and '/zones/dyn.lab/review' not in page
    rev = grid_rev(admin, 'dyn.lab')
    r = admin.post('/zones/dyn.lab/records', data={'csrf_token': t, 'rev': rev, 'name': 'pc2', 'type': 'A',
                                                   'value': '192.168.0.60', 'ttl': '', 'comment': ''},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 200, r.text
    assert 'pc2' in server.text('dyn.lab') and Drafts(settings).load(zone_row(conn, 'dyn.lab'))[1] is False
    assert Repo(settings.repo_dir).log(zone_file('dyn.lab'))[0]['subject'].startswith('Edit (serial')

    # someone else changes the zone; the stale grid's edit is refused, nothing written
    seen = server.text('dyn.lab')
    dynamic.update(conn, zone_row(conn, 'dyn.lab'), dynamic.changes(seen, seen + 'x 300 IN A 192.0.2.7\n', 'dyn.lab.'))
    before = server.text('dyn.lab')
    r = admin.post('/zones/dyn.lab/records', data={'csrf_token': t, 'rev': rev, 'name': 'pc3', 'type': 'A',
                                                   'value': '192.168.0.61', 'ttl': '', 'comment': ''},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 409 and 'changed on the server' in r.text and server.text('dyn.lab') == before

    # from a fresh view it goes through; the other change gets a version of its own first
    r = admin.post('/zones/dyn.lab/records', data={'csrf_token': t, 'rev': grid_rev(admin, 'dyn.lab'), 'name': 'pc3',
                                                   'type': 'A', 'value': '192.168.0.61', 'ttl': '', 'comment': ''},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 200
    log = Repo(settings.repo_dir).log(zone_file('dyn.lab'))
    assert [(e['author'], e['subject'].split(' (')[0]) for e in log[:3]] == [
        ('admin', 'Edit'), ('liteblox', 'Snapshot'), ('admin', 'Edit')]
    snap, edit = (set(Repo(settings.repo_dir).show(e['sha'], zone_file('dyn.lab')).splitlines()) for e in log[1::-1])
    assert 'x 300 IN A 192.0.2.7' in snap and {line for line in edit - snap if 'SOA' not in line} == {
        'pc3 3600 IN A 192.168.0.61'}

    raw = admin.get('/zones/dyn.lab/raw').text
    assert 'readonly' in raw and 'Save draft' not in raw
    assert admin.get('/zones/dyn.lab/review', follow_redirects=False).headers['location'] == '/zones/dyn.lab'


def test_a_conflict_inside_save_shows_in_the_grid(admin, conn, settings, dyn):
    fakes, server = dyn
    t = csrf_from(admin.get('/zones/dyn.lab').text)
    rev = grid_rev(admin, 'dyn.lab')
    server.refuse = dns.rcode.NXRRSET                  # changed between this request's AXFR and its update
    r = admin.post('/zones/dyn.lab/records', data={'csrf_token': t, 'rev': rev, 'name': 'pc4', 'type': 'A',
                                                   'value': '192.168.0.62', 'ttl': '', 'comment': ''},
                   headers={'X-CSRF-Token': t, 'HX-Request': 'true'})
    assert r.status_code == 409 and 'changed on the server' in r.text and r.headers['HX-Retarget'] == '#zone-alert'


def row_token(page, name):
    """(record id, rr token) of the grid row for `name`."""
    import re
    m = re.search(rf'<tr id="row-(\d+)"[^>]*data-name="{name}".*?/records/\1/edit\?rr=([0-9a-f.]+)"', page, re.S)
    return int(m.group(1)), m.group(2)


def dhcp_adds(conn, server, line):
    seen = server.text('dyn.lab')
    dynamic.update(conn, zone_row(conn, 'dyn.lab'), dynamic.changes(seen, seen + line + '\n', 'dyn.lab.'))


def post_row(admin, t, url, **data):
    return admin.post(url, data={'csrf_token': t, 'ttl': '', 'comment': '', **data},
                      headers={'X-CSRF-Token': t, 'HX-Request': 'true'})


def test_a_busy_zone_only_checks_the_rrset_being_edited(admin, conn, settings, dyn):
    _, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t, rev = csrf_from(page), grid_rev(admin, 'dyn.lab')
    rid, rr = row_token(page, 'pc1')
    dhcp_adds(conn, server, 'aaa 300 IN A 192.168.0.90')      # a lease: new serial, positions shift

    # an edit elsewhere still goes through, on the record the page showed
    assert admin.get(f'/zones/dyn.lab/records/{rid}/edit?rr={rr}').status_code == 200
    r = post_row(admin, t, f'/zones/dyn.lab/records/{rid}', rev=rev, rr=rr, name='pc1', type='A', value='192.168.0.52')
    assert r.status_code == 200, r.text
    text = server.text('dyn.lab')
    assert 'pc1 3600 IN A 192.168.0.52' in text and 'aaa 300 IN A 192.168.0.90' in text
    assert 'ns1 3600 IN A 192.0.2.53' in text

    # a new record needs no check at all
    r = post_row(admin, t, '/zones/dyn.lab/records', rev=rev, rr='', name='pc7', type='A', value='192.168.0.57',
                 after=str(rid))
    assert r.status_code == 200, r.text
    assert 'pc7 3600 IN A 192.168.0.57' in server.text('dyn.lab')


def test_a_busy_zone_refuses_an_edit_of_the_rrset_that_changed(admin, conn, settings, dyn):
    _, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t, rev = csrf_from(page), grid_rev(admin, 'dyn.lab')
    rid, rr = row_token(page, 'pc1')
    dhcp_adds(conn, server, 'pc1 3600 IN A 192.168.0.59')    # pc1's RRset grows
    before = server.text('dyn.lab')
    r = post_row(admin, t, f'/zones/dyn.lab/records/{rid}', rev=rev, rr=rr, name='pc1', type='A', value='192.168.0.52')
    assert r.status_code == 409 and 'That record changed' in r.text and server.text('dyn.lab') == before
    r = admin.get(f'/zones/dyn.lab/records/{rid}/edit?rr={rr}')
    assert r.status_code == 409 and r.headers['HX-Retarget'] == '#zone-alert'
    r = post_row(admin, t, f'/zones/dyn.lab/records/{rid}/delete', rev=rev, rr=rr)
    assert r.status_code == 409 and server.text('dyn.lab') == before


def test_a_busy_zone_deletes_by_content(admin, conn, settings, dyn):
    _, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t, rev = csrf_from(page), grid_rev(admin, 'dyn.lab')
    rid, rr = row_token(page, 'pc1')
    dhcp_adds(conn, server, 'aaa 300 IN A 192.168.0.90')
    r = post_row(admin, t, f'/zones/dyn.lab/records/{rid}/delete', rev=rev, rr=rr)
    assert r.status_code == 200, r.text
    text = server.text('dyn.lab')
    assert 'pc1' not in text and 'aaa 300 IN A 192.168.0.90' in text and 'ns1 3600 IN A' in text


def test_a_busy_zone_soa_edit_ignores_the_serial(admin, conn, settings, dyn):
    import re
    _, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t, rev = csrf_from(page), grid_rev(admin, 'dyn.lab')
    soa_rr = re.search(r'name="rev" id="soa-rev"[^>]*>\s*<input type="hidden" name="rr" value="([^"]+)"', page).group(1)
    dhcp_adds(conn, server, 'aaa 300 IN A 192.168.0.90')      # the serial moves
    form = {'csrf_token': t, 'rev': rev, 'rr': soa_rr, 'mname': 'ns1.dyn.lab.', 'rname': 'hostmaster.dyn.lab.',
            'refresh': '3600', 'retry': '900', 'expire': '1209600', 'minimum': '600'}
    r = admin.post('/zones/dyn.lab/soa', data=form, follow_redirects=False)
    assert r.headers['location'] == '/zones/dyn.lab'
    assert re.search(r'SOA ns1 hostmaster \d+ 3600 900 1209600 600', server.text('dyn.lab'))
    # the same page again: the SOA it showed is gone now
    r = admin.post('/zones/dyn.lab/soa', data={**form, 'minimum': '900'}, follow_redirects=False)
    assert r.headers['location'] == '/zones/dyn.lab?conflict=1'


def test_a_busy_zone_nameserver_card(admin, conn, settings, dyn):
    import re
    _, server = dyn
    page = admin.get('/zones/dyn.lab').text
    t, rev = csrf_from(page), grid_rev(admin, 'dyn.lab')
    dhcp_adds(conn, server, 'aaa 300 IN A 192.168.0.90')
    r = admin.post('/zones/dyn.lab/ns', data={'csrf_token': t, 'rev': rev, 'rr': '', 'target': 'ns2.dyn.lab.'},
                   follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:300])
    assert r.headers['location'] == '/zones/dyn.lab' and '@ 3600 IN NS ns2' in server.text('dyn.lab')
    page = admin.get('/zones/dyn.lab').text
    rid, rr = re.search(r'<code>ns2.dyn.lab.</code>.*?/ns/(\d+)/delete".*?name="rr" value="([^"]+)"', page, re.S).groups()
    dhcp_adds(conn, server, 'bbb 300 IN A 192.168.0.91')
    r = admin.post(f'/zones/dyn.lab/ns/{rid}/delete', data={'csrf_token': t, 'rev': rev, 'rr': rr},
                   follow_redirects=False)
    assert r.status_code == 303
    assert r.headers['location'] == '/zones/dyn.lab'
    assert '@ 3600 IN NS ns1' in server.text('dyn.lab') and 'NS ns2' not in server.text('dyn.lab')


def test_settings_switch(admin, conn, settings, lab, server, monkeypatch):  # noqa: F811
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'wait_for_serial', ok_verify)
    monkeypatch.setattr(declare, 'wait_for_serial', ok_verify)
    declare.create_zone(settings, 'dyn.lab', ['1', '2'], FORWARD, 'admin', print, verify=ok_verify)
    page = admin.get('/zones/dyn.lab/settings').text
    assert 'pick a primary that serves this zone first' in page and '<button type="submit" disabled>Switch on' in page
    make_roles(conn)
    server.load('dyn.lab', FORWARD)
    page = admin.get('/zones/dyn.lab/settings').text
    r = admin.post('/zones/dyn.lab/dynamic', data={'dynamic': 'on', 'csrf_token': csrf_from(page)},
                   follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert 'Switch off' in admin.get('/zones/dyn.lab/settings').text


# ── PTR matrix ─────────────────────────────────────────────────────────────────

@pytest.fixture
def ptr_zones(conn, settings, dyn, server):
    """dyn.lab dynamic forward; 0.168.192.in-addr.arpa dynamic reverse; static.lab a static forward zone."""
    fakes, _ = dyn
    declare.create_zone(settings, '0.168.192.in-addr.arpa', ['1', '2'], REVERSE, 'admin', print, verify=ok_verify)
    server.load('0.168.192.in-addr.arpa', REVERSE)
    declare.set_dynamic(settings, '0.168.192.in-addr.arpa', True, 'admin', print, verify=ok_verify)
    declare.create_zone(settings, 'static.lab', ['1', '2'], FORWARD.replace('dyn.lab', 'static.lab'), 'admin', print,
                        verify=ok_verify)
    return fakes, server


def post_a(admin, zone, name, address):
    page = admin.get(f'/zones/{zone}').text
    t = csrf_from(page)
    return admin.post(f'/zones/{zone}/records', data={'csrf_token': t, 'rev': grid_rev(admin, zone), 'name': name,
                                                      'type': 'A', 'value': address, 'ttl': '', 'comment': '',
                                                      'ptr_field': '1', 'ptr': '1'},
                      headers={'X-CSRF-Token': t, 'HX-Request': 'true'})


def test_dynamic_forward_and_dynamic_reverse_both_apply_at_once(admin, conn, settings, ptr_zones):
    _, server = ptr_zones
    r = post_a(admin, 'dyn.lab', 'pc5', '192.168.0.55')
    assert r.status_code == 200, r.text
    assert 'pc5' in server.text('dyn.lab') and '55 3600 IN PTR pc5.dyn.lab.' in server.text('0.168.192.in-addr.arpa')


def test_static_forward_queues_ptr_for_a_dynamic_reverse_until_publish(admin, conn, settings, ptr_zones, monkeypatch):
    fakes, server = ptr_zones
    r = post_a(admin, 'static.lab', 'web', '192.168.0.31')
    assert 'sent when you publish static.lab' in r.text
    assert '31' not in server.text('0.168.192.in-addr.arpa')
    fwd = zone_row(conn, 'static.lab')
    assert dynamic.queued_ptr(conn, fwd['id']) == [('0.168.192.in-addr.arpa', [('add', '192.168.0.31', 'web.static.lab.')])]
    assert 'PTR updates sent with this publish' in admin.get('/zones/static.lab/review').text

    # publish the forward zone: the queued PTR goes out as an update
    monkeypatch.setattr(pub, 'served_serial', lambda host, zone, timeout=2.0: 2026102899)
    pub.publish(settings, 'static.lab', 'admin', print, verify=lambda host, zone, serial, **kw: serial)
    assert '31 3600 IN PTR web.static.lab.' in server.text('0.168.192.in-addr.arpa')
    assert dynamic.queued_ptr(conn, fwd['id']) == []


def test_discarding_the_draft_drops_queued_ptr(admin, conn, settings, ptr_zones):
    post_a(admin, 'static.lab', 'web', '192.168.0.31')
    fwd = zone_row(conn, 'static.lab')
    t = csrf_from(admin.get('/zones/static.lab/review').text)
    admin.post('/zones/static.lab/discard', data={'csrf_token': t})
    assert dynamic.queued_ptr(conn, fwd['id']) == []


def test_a_failed_ptr_send_waits_for_retry(admin, conn, settings, ptr_zones, monkeypatch):
    _, server = ptr_zones
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    monkeypatch.setattr(pub, 'served_serial', lambda host, zone, timeout=2.0: 2026102899)
    post_a(admin, 'static.lab', 'web', '192.168.0.31')
    fwd = zone_row(conn, 'static.lab')
    server.refuse = dns.rcode.REFUSED                    # e.g. the reverse zone frozen on the primary
    lines = []
    pub.publish(settings, 'static.lab', 'admin', lines.append, verify=lambda host, zone, serial, **kw: serial)
    assert any("stay queued (Retry on static.lab's page)" in line for line in lines)
    (rname, ops, failed_at, error), = dynamic.failed_ptr(conn, fwd['id'])
    assert rname == '0.168.192.in-addr.arpa' and ops == [('add', '192.168.0.31', 'web.static.lab.')]
    assert 'REFUSED' in error and failed_at
    page = admin.get('/zones/static.lab').text
    assert "PTR updates that didn't go out" in page and '/zones/static.lab/ptr-queue/retry' in page

    # a new draft's discard leaves them alone
    post_a(admin, 'static.lab', 'web2', '192.168.0.32')
    t = csrf_from(admin.get('/zones/static.lab/review').text)
    admin.post('/zones/static.lab/discard', data={'csrf_token': t})
    assert len(dynamic.failed_ptr(conn, fwd['id'])) == 1 and len(dynamic.queued_ptr(conn, fwd['id'])) == 1

    # Retry while it still fails: a failed job, still queued
    r = admin.post('/zones/static.lab/ptr-queue/retry', data={'csrf_token': t}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'failed' and 'stay queued' in job['log']
    server.refuse = None
    r = admin.post('/zones/static.lab/ptr-queue/retry', data={'csrf_token': t}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert '31 3600 IN PTR web.static.lab.' in server.text('0.168.192.in-addr.arpa')
    assert dynamic.queued_ptr(conn, fwd['id']) == [] and "didn't go out" not in admin.get('/zones/static.lab').text


def test_failed_ptr_changes_can_be_dropped(admin, conn, settings, ptr_zones, monkeypatch):
    _, server = ptr_zones
    monkeypatch.setattr(pub, 'served_serial', lambda host, zone, timeout=2.0: 2026102899)
    post_a(admin, 'static.lab', 'web', '192.168.0.31')
    server.refuse = dns.rcode.REFUSED
    pub.publish(settings, 'static.lab', 'admin', print, verify=lambda host, zone, serial, **kw: serial)
    fwd = zone_row(conn, 'static.lab')
    t = csrf_from(admin.get('/zones/static.lab').text)
    r = admin.post('/zones/static.lab/ptr-queue/drop', data={'csrf_token': t}, follow_redirects=False)
    assert r.headers['location'] == '/zones/static.lab'
    assert dynamic.queued_ptr(conn, fwd['id']) == [] and dynamic.failed_ptr(conn, fwd['id']) == []


def test_dynamic_forward_and_static_reverse_makes_a_draft(admin, conn, settings, dyn, server):
    declare.create_zone(settings, '0.168.192.in-addr.arpa', ['1', '2'], REVERSE, 'admin', print, verify=ok_verify)
    r = post_a(admin, 'dyn.lab', 'pc6', '192.168.0.56')
    assert 'publish it there' in r.text
    text, is_draft = Drafts(settings).load(zone_row(conn, '0.168.192.in-addr.arpa'))
    assert is_draft and 'pc6.dyn.lab.' in text


# ── restore ────────────────────────────────────────────────────────────────────

def test_restore_on_a_dynamic_zone_sends_the_difference(admin, conn, settings, dyn):
    _, server = dyn
    repo = Repo(settings.repo_dir)
    first = repo.log(zone_file('dyn.lab'))[0]['sha']             # "Dynamic from now on"
    seen = server.text('dyn.lab')
    dynamic.update(conn, zone_row(conn, 'dyn.lab'), dynamic.changes(seen, seen + 'gone 300 IN A 192.0.2.8\n', 'dyn.lab.'))
    t = csrf_from(admin.get('/zones/dyn.lab').text)
    r = admin.post(f'/zones/dyn.lab/history/{first}/restore', data={'csrf_token': t}, follow_redirects=False)
    assert r.headers['location'] == '/zones/dyn.lab'
    assert 'gone' not in server.text('dyn.lab')
    assert repo.log(zone_file('dyn.lab'))[0]['subject'].startswith(f'Restore {first[:10]}')
