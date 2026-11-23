"""DNS registration at another DNS server, or off (4.0 M4): rendering, validation, the form, the Test, migration."""

import json
import socket
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import dns.tsig
import pytest

from liteblox import db, jobs, modules
from liteblox.dhcp import ddnstest, store, validate
from liteblox.dhcp.model import Dhcp4Settings, KeaConfig, Subnet, for_node, settings as load_settings
from liteblox.dhcp.render import ddns_active, derived_reverse_zones, render

from conftest import csrf_from

KEY = {'name': 'kea-home', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0c2VjcmV0c2VjcmV0'}
NET = '198.51.100.0/24'


def ext_subnet(**kw):
    return Subnet(**{'id': 1, 'prefix': NET, 'interface': 'ens19', 'pools': ['198.51.100.100 - 198.51.100.199'],
                     'ddns': True, 'ddns_suffix': 'dhcp.home.lan', 'ddns_mode': 'external', **kw})


def ext_settings(**kw):
    return Dhcp4Settings(**{'ddns_mode': 'external', 'ddns_server': '192.0.2.99', 'ddns_port': 53,
                            'ddns_external_key': KEY, 'ddns_key': KEY, **kw})


# ── rendering ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize('prefix, zones', [
    ('198.51.100.0/24', ['100.51.198.in-addr.arpa']),
    ('198.51.100.64/26', ['100.51.198.in-addr.arpa']),
    ('10.1.4.0/22', ['4.1.10.in-addr.arpa', '5.1.10.in-addr.arpa', '6.1.10.in-addr.arpa', '7.1.10.in-addr.arpa']),
    ('10.1.0.0/20', [f'{n}.1.10.in-addr.arpa' for n in range(16)]),
    ('10.1.0.0/19', ['1.10.in-addr.arpa']),             # 32 /24s: the /16 holding them instead
    ('10.1.0.0/16', ['1.10.in-addr.arpa']),
    ('10.0.0.0/8', ['10.in-addr.arpa']),
])
def test_derived_reverse_zones(prefix, zones):
    assert derived_reverse_zones(prefix) == zones


def test_external_renders_the_server_port_key_and_zones():
    config = KeaConfig(['ens19'], ext_settings(ddns_port=5353),
                       [ext_subnet(), ext_subnet(id=2, prefix='10.1.4.0/22', pools=['10.1.4.10 - 10.1.4.20'],
                                                 ddns_suffix='lab.home.lan', ddns_reverse='4.1.10.in-addr.arpa.')],
                       primary='192.0.2.99', ddns_port=5353)
    files = render(config)
    first, second = json.loads(files['kea-dhcp4.conf'])['Dhcp4']['subnet4']
    assert first['ddns-qualifying-suffix'] == 'dhcp.home.lan.' and second['ddns-qualifying-suffix'] == 'lab.home.lan.'
    d2 = json.loads(files['kea-dhcp-ddns.conf'])['DhcpDdns']
    server = [{'ip-address': '192.0.2.99', 'port': 5353}]
    assert d2['tsig-keys'] == [KEY]
    assert d2['forward-ddns']['ddns-domains'] == [
        {'name': f'{z}.', 'key-name': 'kea-home', 'dns-servers': server} for z in ('dhcp.home.lan', 'lab.home.lan')]
    # the first derived from its prefix, the second the one zone given (not its four /24s)
    assert [d['name'] for d in d2['reverse-ddns']['ddns-domains']] == ['100.51.198.in-addr.arpa.', '4.1.10.in-addr.arpa.']


def test_off_renders_no_registration():
    config = KeaConfig(['ens19'], Dhcp4Settings(ddns_mode='off'), [ext_subnet(ddns_mode='off', ddns_zone='dyn.lab')],
                       primary=None)
    assert ddns_active(config) == [] and not config.subnets[0].registers
    d4 = json.loads(render(config)['kea-dhcp4.conf'])['Dhcp4']
    assert 'ddns-send-updates' not in d4['subnet4'][0]


def test_for_node_follows_the_mode(conn):
    store.save_subnet(conn, Subnet(1, NET, 'ens19', pools=['198.51.100.100 - 198.51.100.199'], ddns=True,
                                   ddns_suffix='dhcp.home.lan'))
    node = {'id': 9, 'name': 'dhcp1', 'dhcp_interfaces': '["ens19"]'}
    config = for_node(conn, node)
    assert config.settings.ddns_mode == 'off' and config.primary is None and ddns_active(config) == []
    store.save_settings(conn, ext_settings(ddns_port=5300))
    config = for_node(conn, node)
    assert (config.primary, config.ddns_port, config.settings.ddns_key) == ('192.0.2.99', 5300, KEY)
    assert [s.ddns_domain for s in ddns_active(config)] == ['dhcp.home.lan']


# ── validation ─────────────────────────────────────────────────────────────────

def test_check_ddns_external(conn):
    s = ext_settings()
    assert validate.check_ddns(conn, ext_subnet(ddns_suffix='Dhcp.Home.Lan.'), s) == {}
    assert validate.check_ddns(conn, ext_subnet(ddns_suffix=''), s)['ddns_suffix'].startswith('the domain')
    assert 'ddns_suffix' in validate.check_ddns(conn, ext_subnet(ddns_suffix='100.51.198.in-addr.arpa'), s)
    errors = validate.check_ddns(conn, ext_subnet(ddns_reverse='100.51.198.in-addr.arpa 0.168.192.in-addr.arpa'), s)
    assert errors == {'ddns_reverse': '0.168.192.in-addr.arpa: a reverse zone (…in-addr.arpa) that covers part of '
                                      f'{NET}'}
    assert validate.check_ddns(conn, ext_subnet(), ext_settings(ddns_server='', ddns_external_key=None))['ddns'] \
        .startswith('set the DNS server')
    assert validate.check_ddns(conn, ext_subnet(), Dhcp4Settings(ddns_mode='off'))['ddns'] \
        .startswith('DNS registration is off')


def test_a_lease_registered_elsewhere_is_checked_against_its_ptr():
    from liteblox.ipam.checks import address_checks
    lease = {'mac': 'aa:bb:cc:00:00:01', 'hostname': 'laptop.dhcp.home.lan'}
    run = lambda rdns, mode='external': [t for _, t, _ in address_checks(
        '198.51.100.120', [], [], None, None, lease, ext_subnet(ddns_mode=mode), True, rdns=rdns)]
    assert run(None) == [] and run({'name': 'laptop.dhcp.home.lan', 'error': None}) == []
    assert run({'name': 'old.dhcp.home.lan', 'error': None}) == [
        "The lease's hostname is laptop.dhcp.home.lan, but its PTR at the resolver says old.dhcp.home.lan."]
    assert run(None, mode='liteblox') == []      # no LiteBlox zone given: it registers nothing
    sub = ext_subnet(ddns_mode='liteblox', ddns_zone='dhcp.home.lan', ddns_suffix='')
    assert address_checks('198.51.100.120', [], [], None, None, lease, sub, True)[0][1] == \
        "The lease's hostname laptop.dhcp.home.lan isn't in DNS at this address."


def test_missing_grants_only_for_litebloxs_own_dns(conn):
    assert validate.missing_grants(conn, 'kea-home', ext_subnet(ddns_zone='dyn.lab'), []) == []


def test_name_only_reservations_need_a_registering_subnet():
    from liteblox.dhcp.model import Reservation
    r = lambda: Reservation(None, 1, 'aa:bb:cc:00:00:01', '', 'printer')
    assert 'ip_address' not in validate.check_reservation(r(), ext_subnet(), [])[0]
    assert 'ip_address' in validate.check_reservation(r(), ext_subnet(ddns_mode='off'), [])[0]


# ── the settings form ──────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def save(client, data):
    r = client.post('/dhcp/settings', data=data, follow_redirects=False)
    return r.status_code if r.status_code != 303 else r.headers['location'].split('/')[1]


def form(t, **kw):
    return {'csrf_token': t, 'ddns_mode': 'external', 'ddns_server': '192.0.2.99', 'ddns_port': '53',
            'ddns_key_name': KEY['name'], 'ddns_key_algorithm': KEY['algorithm'], 'ddns_key_secret': KEY['secret'], **kw}


def test_settings_save_an_external_server_and_keep_its_secret(admin, conn):
    page = admin.get('/dhcp/settings').text
    t = csrf_from(page)
    assert 'value="liteblox"' in page and 'value="external"' in page and 'value="off"' in page
    assert save(admin, form(t, ddns_port='5353')) == 'jobs'
    s = load_settings(conn)
    assert (s.ddns_mode, s.ddns_server, s.ddns_port, s.ddns_external_key, s.ddns_key) == (
        'external', '192.0.2.99', 5353, KEY, KEY)
    page = admin.get('/dhcp/settings').text
    assert KEY['secret'] not in page and 'saved: leave empty to keep it' in page
    # an empty secret keeps the saved one; switching off keeps the server's fields for later
    assert save(admin, form(t, ddns_key_secret='')) == 'jobs'
    assert load_settings(conn).ddns_external_key == KEY
    assert save(admin, form(t, ddns_mode='off', ddns_key_secret='')) == 'jobs'
    s = load_settings(conn)
    assert (s.ddns_mode, s.ddns_key, s.ddns_external_key, s.ddns_server) == ('off', None, KEY, '192.0.2.99')
    # a new key name needs its own secret
    r = admin.post('/dhcp/settings', data=form(t, ddns_key_name='other', ddns_key_secret=''))
    assert r.status_code == 422 and 'the base64 secret' in r.text


def test_settings_errors(admin, conn):
    t = csrf_from(admin.get('/dhcp/settings').text)
    r = admin.post('/dhcp/settings', data=form(t, ddns_server='dns.home.lan', ddns_port='0', ddns_key_algorithm='md4'))
    assert r.status_code == 422
    for text in ("the DNS server&#39;s IPv4 address", 'a port from 1 to 65535', 'one of hmac-'):
        assert text in r.text
    assert KEY['secret'] not in r.text


def test_liteblox_mode_needs_the_dns_module(admin, conn):
    assert modules.save(conn, {'dns': False, 'dhcp': True, 'ntp': True, 'ipam': True}) == {}
    page = admin.get('/dhcp/settings').text
    assert 'value="liteblox"' not in page
    t = csrf_from(page)
    r = admin.post('/dhcp/settings', data={'csrf_token': t, 'ddns_mode': 'liteblox'})
    assert r.status_code == 422 and 'the DNS module is off' in r.text


def test_the_review_says_which_subnets_stop_registering(admin, conn):
    store.save_subnet(conn, Subnet(1, NET, 'ens19', pools=['198.51.100.100 - 198.51.100.199'], ddns=True))
    store.save_settings(conn, ext_settings())
    t = csrf_from(admin.get('/dhcp/settings').text)
    h = {'X-CSRF-Token': t}
    review = admin.post('/dhcp/settings/preview', data=form(t, ddns_mode='off'), headers=h).text
    assert f'{NET} stops registering its clients in DNS' in review
    review = admin.post('/dhcp/settings/preview', data=form(t), headers=h).text
    assert f'{NET} has no domain at the DNS server to register in yet' in review


# ── the Test ───────────────────────────────────────────────────────────────────

class FakeAuthority:
    """A UDP DNS server on 127.0.0.1 that checks KEY: zones answer as given ('soa', 'inside', 'referral'),
    anything else NXDOMAIN."""

    def __init__(self, zones):
        self.zones = zones
        self.keyring = {dns.name.from_text(KEY['name']): dns.tsig.Key(KEY['name'], KEY['secret'], KEY['algorithm'])}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.signed = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            q = dns.message.from_wire(data, keyring=self.keyring)
            self.signed.append(q.had_tsig)
            owner = q.question[0].name.to_text().rstrip('.')
            r = dns.message.make_response(q)
            how = self.zones.get(owner)
            soa = lambda name: dns.rrset.from_text(name + '.', 300, 'IN', 'SOA', f'ns.{name}. h. 7 1 1 1 1')
            if how == 'soa':
                r.flags |= dns.flags.AA
                r.answer.append(soa(owner))
            elif how == 'inside':
                r.flags |= dns.flags.AA
                r.authority.append(soa(owner.split('.', 1)[1]))
            elif how == 'referral':
                pass
            else:
                r.set_rcode(dns.rcode.NXDOMAIN)
            try:
                self.sock.sendto(r.to_wire(), peer)
            except OSError:       # closed meanwhile
                return

    def close(self):
        self.sock.close()


def test_soa_against_a_signed_server():
    server = FakeAuthority({'dhcp.home.lan': 'soa', 'sub.home.lan': 'inside', 'away.lan': 'referral'})
    try:
        ask = lambda zone: ddnstest.soa('127.0.0.1', server.port, zone, KEY, timeout=1)
        ok = ask('dhcp.home.lan')
        assert ok['ok'] and f'127.0.0.1 port {server.port} holds it (primary ns.dhcp.home.lan, serial 7) and ' \
                            'accepted key kea-home' == ok['text']
        assert not ask('sub.home.lan')['ok'] and 'inside its zone home.lan' in ask('sub.home.lan')['text']
        assert "doesn't hold the zone itself" in ask('away.lan')['text']
        assert "doesn't hold 100.51.198.in-addr.arpa" in ask('100.51.198.in-addr.arpa')['text']
        assert all(server.signed)
    finally:
        server.close()
    assert 'no answer from' in ddnstest.soa('127.0.0.1', server.port, 'dhcp.home.lan', KEY, timeout=0.2)['text']


@pytest.mark.parametrize('error, text', [(dns.tsig.PeerBadKey, "doesn't know key kea-home (BADKEY)"),
                                         (dns.tsig.PeerBadSignature, 'not with this secret or algorithm (BADSIG)'),
                                         (dns.tsig.PeerBadTime, 'clocks')])
def test_soa_explains_tsig_errors(monkeypatch, error, text):
    def udp(*a, **kw):
        raise error()
    monkeypatch.setattr(ddnstest.dns.query, 'udp', udp)
    out = ddnstest.soa('192.0.2.99', 53, 'dhcp.home.lan', KEY)
    assert not out['ok'] and (text in out['text'] or (text == 'clocks' and 'BADTIME' in out['text']))


def test_the_test_button(admin, conn, monkeypatch):
    t = csrf_from(admin.get('/dhcp/settings').text)
    h = {'X-CSRF-Token': t}
    r = admin.post('/dhcp/settings/ddns-test', data=form(t, ddns_server=''), headers=h)
    assert r.status_code == 200 and 'IPv4 address' in r.text
    assert 'No subnet registers its clients yet' in admin.post('/dhcp/settings/ddns-test', data=form(t), headers=h).text
    store.save_subnet(conn, Subnet(1, NET, 'ens19', pools=['198.51.100.100 - 198.51.100.199'], ddns=True,
                                   ddns_suffix='dhcp.home.lan'))
    asked = []
    monkeypatch.setattr(ddnstest, 'SOA', lambda server, port, zone, key: asked.append((server, port, zone, key)) or
                        {'zone': zone, 'ok': zone == 'dhcp.home.lan', 'text': 'said so'})
    r = admin.post('/dhcp/settings/ddns-test', data=form(t, ddns_port='5353'), headers=h)
    assert asked == [('192.0.2.99', 5353, 'dhcp.home.lan', KEY), ('192.0.2.99', 5353, '100.51.198.in-addr.arpa', KEY)]
    assert '<code>dhcp.home.lan</code>: said so' in r.text and 'dot warn' in r.text
    # unsaved: the Test never stores anything
    assert load_settings(conn).ddns_mode == 'off'


def test_check_key():
    assert ddnstest.check_key(KEY) == {}
    assert set(ddnstest.check_key({'name': '', 'algorithm': 'x', 'secret': 'not base64!'})) == {
        'ddns_key_name', 'ddns_key_algorithm', 'ddns_key_secret'}


# ── migration ──────────────────────────────────────────────────────────────────

def test_migration_keeps_registration_where_a_key_was_set(tmp_path):
    path = tmp_path / 'old.db'
    conn = db.connect(path)
    for version, sql in enumerate(db.MIGRATIONS[:34], start=1):
        conn.executescript(f'BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;')
    with conn:
        key = conn.execute("INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES ('dhcp', 'hmac-sha256', "
                           "'c2VjcmV0c2VjcmV0', 'user')").lastrowid
        conn.execute('UPDATE dhcp4_settings SET ddns_key_id = ?', (key,))
    conn.close()
    assert db.migrate(path) == len(db.MIGRATIONS)
    conn = db.connect(path)
    s = load_settings(conn)
    assert (s.ddns_mode, s.ddns_key['name'], s.ddns_server, s.ddns_port) == ('liteblox', 'dhcp', '', 53)
    with conn:
        conn.execute('UPDATE dhcp4_settings SET ddns_key_id = NULL')
        conn.execute("UPDATE dhcp4_settings SET ddns_mode = 'off'")
    assert load_settings(conn).ddns_key is None
    conn.close()
