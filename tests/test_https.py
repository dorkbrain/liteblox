"""LiteBlox's own HTTPS (4.6): certificates, live reload, the HTTPS-only gate, the tab, the CLI, cookies."""

import asyncio
import datetime
import os
import re
import socket
import ssl
import stat
import subprocess
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from liteblox import cli, db, help as help_mod, listeners, status, web_tls
from liteblox.main import create_app
from tests.conftest import csrf_from

NOW = datetime.datetime.now(datetime.timezone.utc)


# ── helpers: a small CA and certificates it signs ─────────────────────────────────

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, signer, names=(), ca=False, before=None, after=None):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(before or NOW - datetime.timedelta(days=1))
         .not_valid_after(after or NOW + datetime.timedelta(days=90))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    if not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return b.sign(signer, hashes.SHA256())


def pem(*certs):
    return b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def key_pem(key, password=None):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


@pytest.fixture(scope='module')
def issued():
    """A CA, an intermediate and a leaf for liteblox.example.com (RSA, like most public CAs)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert('Test Root', 'Test Root', ca_key, ca_key, ca=True)
    mid_key = ec.generate_private_key(ec.SECP256R1())
    mid = _cert('Test Intermediate', 'Test Root', mid_key, ca_key, ca=True)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert('liteblox.example.com', 'Test Intermediate', leaf_key, mid_key, names=['liteblox.example.com'])
    return {'ca': ca, 'mid': mid, 'mid_key': mid_key, 'leaf': leaf, 'key': leaf_key}


def https_row(conn):
    return web_tls.load(conn)


# ── self-signed ──────────────────────────────────────────────────────────────

def test_self_signed_is_a_server_certificate_for_the_names():
    chain, key = web_tls.self_signed(['liteblox.lan', '192.168.1.10'])
    cert = x509.load_pem_x509_certificate(chain)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    info = web_tls.describe(chain)
    assert info['names'] == ['liteblox.lan', '192.168.1.10'] and info['self_signed']
    assert 824 <= info['days_left'] <= 825
    assert isinstance(serialization.load_pem_private_key(key, None), ec.EllipticCurvePrivateKey)
    web_tls.check_pair(chain, key)


def test_a_self_signed_certificate_is_its_own_trust_anchor(tmp_path):
    # what lbcli --ca and curl --cacert rely on: the downloaded certificate verifies the server
    chain, key = web_tls.self_signed(['localhost', '127.0.0.1'])
    server = web_tls.context_from(chain, key)
    (tmp_path / 'ca.pem').write_bytes(chain)
    client = ssl.create_default_context(cafile=str(tmp_path / 'ca.pem'))
    a, b = socket.socketpair()
    out = {}

    def serve():
        with server.wrap_socket(a, server_side=True) as s:
            out['ok'] = s.recv(2)
    t = threading.Thread(target=serve)
    t.start()
    with client.wrap_socket(b, server_hostname='localhost') as c:
        c.sendall(b'hi')
    t.join(5)
    assert out['ok'] == b'hi'


def test_names_are_checked():
    assert web_tls.parse_names('LiteBlox.lan, 192.168.1.10  [::1]') == ['liteblox.lan', '192.168.1.10', '::1']
    for bad in ('', 'bad_name!', 'a..b', ','.join(f'h{i}' for i in range(25))):
        with pytest.raises(web_tls.CertError):
            web_tls.parse_names(bad)
    assert web_tls.default_names('liteblox.lan') == ['liteblox.lan']
    assert web_tls.default_names('127.0.0.1') == ['localhost', '127.0.0.1']


def test_generate_writes_the_files(settings, conn):
    info = web_tls.generate(conn, settings, ['liteblox.lan'], 'alice')
    cert_path, key_path = web_tls.paths(settings)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(cert_path.stat().st_mode) == 0o644
    assert stat.S_IMODE(web_tls.tls_dir(settings).stat().st_mode) == 0o700
    row = https_row(conn)
    assert row['source'] == 'self-signed' and row['fingerprint'] == info['fingerprint']
    assert row['names'] == 'liteblox.lan' and row['updated_by'] == 'alice'
    assert web_tls.current(settings)['fingerprint'] == info['fingerprint']


# ── imports ──────────────────────────────────────────────────────────────────

def test_import_pem_puts_the_chain_in_order(issued):
    # the chain given root-first, leaf last: it comes back leaf, intermediate, root
    chain, key = web_tls.read_import(pem(issued['ca'], issued['leaf'], issued['mid']), key_pem(issued['key']))
    certs = x509.load_pem_x509_certificates(chain)
    assert [c.subject for c in certs] == [issued['leaf'].subject, issued['mid'].subject, issued['ca'].subject]
    info = web_tls.describe(chain)
    assert info['issuer'] == 'Test Intermediate' and info['chain'] == 2 and not info['self_signed']


def test_import_an_encrypted_key_and_a_key_in_the_certificate_file(issued):
    enc = key_pem(issued['key'], b'sekrit')
    with pytest.raises(web_tls.CertError, match='encrypted: give its password'):
        web_tls.read_import(pem(issued['leaf']), enc)
    with pytest.raises(web_tls.CertError, match='wrong password'):
        web_tls.read_import(pem(issued['leaf']), enc, password='nope')
    chain, key = web_tls.read_import(pem(issued['leaf']), enc, password='sekrit')
    assert b'ENCRYPTED' not in key and serialization.load_pem_private_key(key, None)
    chain, _ = web_tls.read_import(pem(issued['leaf']) + key_pem(issued['key']))
    assert web_tls.describe(chain)['subject'] == 'liteblox.example.com'


def test_import_pkcs12(issued):
    pfx = pkcs12.serialize_key_and_certificates(b'liteblox', issued['key'], issued['leaf'], [issued['mid']],
                                                serialization.BestAvailableEncryption(b'pfxpass'))
    with pytest.raises(web_tls.CertError, match='password'):
        web_tls.read_import(pfx=pfx, password='wrong')
    chain, key = web_tls.read_import(pfx=pfx, password='pfxpass')
    assert len(x509.load_pem_x509_certificates(chain)) == 2


def test_import_refusals(issued):
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(web_tls.CertError, match="doesn't belong"):
        web_tls.read_import(pem(issued['leaf']), key_pem(other))
    with pytest.raises(web_tls.CertError, match='not PEM'):
        web_tls.read_import(b'garbage', key_pem(other))
    with pytest.raises(web_tls.CertError, match='private key file too'):
        web_tls.read_import(pem(issued['leaf']))
    with pytest.raises(web_tls.CertError, match='bigger than'):
        web_tls.read_import(b'x' * (web_tls.MAX_UPLOAD + 1), b'')
    old = _cert('old.example.com', 'Test Intermediate', other, issued['mid_key'], names=['old.example.com'],
                before=NOW - datetime.timedelta(days=100), after=NOW - datetime.timedelta(days=1))
    with pytest.raises(web_tls.CertError, match='expired'):
        web_tls.read_import(pem(old), key_pem(other))
    soon = _cert('new.example.com', 'Test Intermediate', other, issued['mid_key'],
                 before=NOW + datetime.timedelta(days=2))
    with pytest.raises(web_tls.CertError, match='only valid from'):
        web_tls.read_import(pem(soon), key_pem(other))


def test_warnings_for_expiring_soon_and_other_names(issued):
    other = ec.generate_private_key(ec.SECP256R1())
    soon = _cert('soon.example.com', 'Test Intermediate', other, issued['mid_key'], names=['*.example.com'],
                 after=NOW + datetime.timedelta(days=10))
    info = web_tls.describe(pem(soon))
    w = web_tls.warnings(info, 'liteblox.lan')
    assert any('expires in' in x for x in w) and any("don't include liteblox.lan" in x for x in w)
    assert web_tls.covers(info, 'liteblox.example.com') and not web_tls.covers(info, 'a.b.example.com')


# ── live reload ──────────────────────────────────────────────────────────────

def test_live_reload_keeps_the_old_pair_when_the_new_one_is_bad(settings, conn):
    first = web_tls.generate(conn, settings, ['localhost'], 'alice')
    live = web_tls.Live(settings)
    assert live.refresh() and live.fingerprint == first['fingerprint'] and live.base is live.current
    assert not live.refresh()                           # nothing changed
    # a renewal caught halfway: a new key, the old certificate
    _, new_key = web_tls.self_signed(['localhost'])
    _, key_path = web_tls.paths(settings)
    key_path.write_bytes(new_key)
    assert not live.refresh()
    assert live.fingerprint == first['fingerprint'] and 'still serving the previous certificate' in live.error
    # it looks again next time even with nothing new (the rest of the renewal, or a chown)
    second = web_tls.generate(conn, settings, ['localhost'], 'alice')
    assert live.refresh() and live.fingerprint == second['fingerprint'] and live.error is None
    assert live.base is not live.current                # new connections get the new one through SNI


def test_an_unreadable_key_is_reported(settings, conn, monkeypatch):
    web_tls.generate(conn, settings, ['localhost'], 'alice')
    real = web_tls.Path.read_bytes

    def denied(self):
        if self.name == web_tls.KEY:
            raise PermissionError(13, 'Permission denied', str(self))
        return real(self)
    monkeypatch.setattr(web_tls.Path, 'read_bytes', denied)
    live = web_tls.Live(settings)
    assert not live.refresh() and "key.pem can't be read: it must be readable by uid" in live.error
    assert web_tls.current(settings) is None            # the page still renders


# ── the HTTP gate ────────────────────────────────────────────────────────────

@pytest.fixture
def gate(app, settings, monkeypatch):
    monkeypatch.setattr(listeners, 'GATE_CACHE', -1)
    return TestClient(listeners.Listener(app, 'http', settings))


def test_https_only_serves_a_page_on_plain_http(gate, conn, settings):
    assert gate.get('/login').status_code == 200
    web_tls.generate(conn, settings, ['localhost'], 'alice')
    web_tls.save(conn, 'alice', enabled=1, https_only=1)
    r = gate.get('/login', follow_redirects=False)
    assert r.status_code == 403 and 'location' not in r.headers and r.headers['cache-control'] == 'no-store'
    assert "HTTP isn't supported here" in r.text and '53443' in r.text
    r = gate.get('/api/v1/status')
    assert r.status_code == 403 and 'HTTPS only' in r.json()['detail']
    assert gate.get('/healthz').status_code == 200
    web_tls.save(conn, 'cli', https_only=0)
    assert gate.get('/login').status_code == 200


def test_https_only_needs_https_on(gate, conn):
    web_tls.save(conn, 'alice', https_only=1)              # left over, with HTTPS off: plain HTTP still works
    assert gate.get('/login').status_code == 200


# ── the tab ──────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login):
    login(*make_user())
    return client


@pytest.fixture
def admin_https(app, settings, make_user, monkeypatch):
    monkeypatch.setattr(listeners, 'GATE_CACHE', -1)
    c = TestClient(listeners.Listener(app, 'https', settings), base_url='https://testserver')
    username, password = make_user('carol')
    token = csrf_from(c.get('/login').text)
    c.post('/login', data={'username': username, 'password': password, 'csrf_token': token})
    return c


def post(c, path, page='/settings/https', files=None, **data):
    data['csrf_token'] = csrf_from(c.get(page).text)
    return c.post(path, data=data, files=files, follow_redirects=False)


def audits(conn):
    return [tuple(r) for r in conn.execute('SELECT username, action, detail FROM audit '
                                           "WHERE action LIKE 'https%' ORDER BY id")]


def test_the_tab_is_for_admins(client, make_user, login):
    make_user('bob', 'correct-horse', 'readonly')
    login('bob', 'correct-horse')
    assert client.get('/settings/https').status_code == 403
    assert client.get('/settings/https/cert.pem').status_code == 403


def test_writes_need_csrf(admin):
    assert admin.post('/settings/https/enabled', data={'enabled': '1'}).status_code == 403


def test_enable_makes_a_self_signed_certificate(admin, conn, settings):
    page = admin.get('/settings/https').text
    assert 'href="/settings/https"' in page and 'liteblox https allow-http' in page
    assert '/help/https#lets-encrypt-with-certbot' in page
    r = post(admin, '/settings/https/enabled', enabled='1')
    assert r.status_code == 303 and 'done=' in r.headers['location']
    row = https_row(conn)
    assert row['enabled'] and row['source'] == 'self-signed'
    assert web_tls.current(settings)['names'] == ['testserver']
    assert audits(conn)[-1][:2] == ('alice', 'https_enable')
    page = admin.get('/settings/https').text
    assert 'self-signed' in page and 'Download the certificate' in page
    pem_body = admin.get('/settings/https/cert.pem')
    assert pem_body.status_code == 200 and pem_body.content.startswith(b'-----BEGIN CERTIFICATE-----')
    assert b'PRIVATE' not in pem_body.content
    post(admin, '/settings/https/enabled')
    assert not https_row(conn)['enabled'] and audits(conn)[-1][:2] == ('alice', 'https_disable')


def test_https_only_only_from_the_https_listener(admin, admin_https, conn, settings):
    web_tls.enable(conn, settings, 'alice', 'testserver')
    web_tls.record(conn, listening=1)
    page = admin.get('/settings/https').text
    assert 'Open this page over HTTPS' in page
    r = post(admin, '/settings/https/only', https_only='1')
    assert 'error=' in r.headers['location'] and not https_row(conn)['https_only']
    r = post(admin_https, '/settings/https/only', https_only='1')
    assert 'done=' in r.headers['location'] and https_row(conn)['https_only']
    assert audits(conn)[-1][:2] == ('carol', 'https_only')
    post(admin_https, '/settings/https/only')
    assert not https_row(conn)['https_only'] and audits(conn)[-1][:2] == ('carol', 'https_allow_http')


def test_generate_with_names(admin, conn, settings):
    r = post(admin, '/settings/https/generate', names='bad name!')
    assert r.status_code == 422 and 'is not a hostname' in r.text
    r = post(admin, '/settings/https/generate', names='liteblox.lan, 192.168.1.10')
    assert r.status_code == 303
    assert web_tls.current(settings)['names'] == ['liteblox.lan', '192.168.1.10']
    assert audits(conn)[-1][:2] == ('alice', 'https_generate') and 'liteblox.lan' in audits(conn)[-1][2]


def test_import_checks_then_uses(admin, conn, settings, issued):
    files = {'cert': ('cert.pem', pem(issued['leaf'], issued['mid'])), 'key': ('key.pem', key_pem(issued['key']))}
    r = post(admin, '/settings/https/import', files=files)
    assert r.status_code == 303
    token = re.search(r'pending=([\w-]+)', r.headers['location']).group(1)
    page = admin.get(r.headers['location']).text
    assert 'Checked:' in page and 'liteblox.example.com' in page and "don&#39;t include testserver" in page
    assert web_tls.current(settings) is None                 # nothing in place until Use it
    r = post(admin, '/settings/https/import/use', token=token)
    assert 'done=' in r.headers['location']
    info = web_tls.current(settings)
    assert info['subject'] == 'liteblox.example.com' and info['chain'] == 1
    assert https_row(conn)['source'] == 'imported' and audits(conn)[-1][:2] == ('alice', 'https_import')
    assert not list(web_tls.tls_dir(settings).glob('.import-*'))
    r = post(admin, '/settings/https/import/use', token=token)
    assert 'error=' in r.headers['location']


def test_import_refusal_is_shown(admin, issued):
    other = ec.generate_private_key(ec.SECP256R1())
    files = {'cert': ('cert.pem', pem(issued['leaf'])), 'key': ('key.pem', key_pem(other))}
    r = post(admin, '/settings/https/import', files=files)
    assert r.status_code == 422 and "doesn&#39;t belong to the certificate" in r.text


def test_replaced_outside_liteblox(admin, conn, settings):
    web_tls.generate(conn, settings, ['testserver'], 'alice')
    web_tls.write(settings, *web_tls.self_signed(['testserver']))
    assert 'replaced outside LiteBlox' in admin.get('/settings/https').text


# ── cookies ──────────────────────────────────────────────────────────────────

def test_the_session_cookie_per_scheme(client, admin_https, make_user, login):
    r = login(*make_user())
    assert 'liteblox_session=' in r.headers['set-cookie'] and '__Host-' not in r.headers['set-cookie']
    assert 'secure' not in r.headers['set-cookie'].lower()
    assert any(c.name == '__Host-liteblox_session' and c.secure for c in admin_https.cookies.jar)


# ── the Dashboard ────────────────────────────────────────────────────────────

def test_problems(conn, settings, issued):
    assert web_tls.problems(conn, settings) == []
    web_tls.save(conn, 'alice', enabled=1)
    assert 'no certificate' in web_tls.problems(conn, settings)[0]['what']
    web_tls.generate(conn, settings, ['localhost'], 'alice')
    assert web_tls.problems(conn, settings) == []
    later = NOW + datetime.timedelta(days=810)
    (p,) = web_tls.problems(conn, settings, later)
    assert p['severity'] == 'warn' and p['area'] == 'web' and p['link'] == '/settings/https'
    (p,) = web_tls.problems(conn, settings, NOW + datetime.timedelta(days=900))
    assert p['severity'] == 'error' and 'expired' in p['what']
    web_tls.record(conn, error="KEY_VALUES_MISMATCH; still serving the previous certificate")
    assert any('KEY_VALUES_MISMATCH' in p['what'] for p in status.problems(conn, settings))


# ── the CLI ──────────────────────────────────────────────────────────────────

def test_the_cli(settings, conn, monkeypatch, capsys):
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    assert cli.main(['https', 'status']) == 0
    assert 'off (plain HTTP only' in capsys.readouterr().out
    assert cli.main(['https', 'on', '--name', 'liteblox.lan']) == 0
    out = capsys.readouterr().out
    assert '✓ Made a self-signed certificate for liteblox.lan' in out and '✓ HTTPS is on: port 53443' in out
    web_tls.save(conn, 'alice', https_only=1)
    assert cli.main(['https', 'allow-http']) == 0
    assert '✓ Plain HTTP works again' in capsys.readouterr().out and not https_row(conn)['https_only']
    assert cli.main(['https', 'regenerate']) == 0
    assert 'for liteblox.lan' in capsys.readouterr().out
    web_tls.record(conn, error='port 53443 could not be opened (Address already in use)')
    assert cli.main(['https', 'status']) == 1
    assert 'ERROR: port 53443 could not be opened' in capsys.readouterr().out
    assert cli.main(['https', 'off']) == 0
    assert not https_row(conn)['enabled']
    assert [a[1] for a in audits(conn)] == ['https_enable', 'https_allow_http', 'https_generate', 'https_disable']
    assert {a[0] for a in audits(conn)} == {'cli'}


# ── the schema and the docs ──────────────────────────────────────────────────

def test_v40_adds_the_row(conn):
    row = https_row(conn)
    assert not row['enabled'] and not row['https_only'] and not row['names']
    with pytest.raises(Exception):
        conn.execute('INSERT INTO https_settings (id) VALUES (2)')


def test_the_help_page(client):
    assert ('https', 'HTTPS') in help_mod.PAGES
    body, _ = help_mod.render('https')
    for anchor in ('lets-encrypt-with-certbot', 'https-only', 'getting-back-in', 'the-files-and-live-updates',
                   'trusting-a-self-signed-certificate'):
        assert f'id="{anchor}"' in body, anchor
    assert 'docker compose exec liteblox liteblox https allow-http' in body


def test_the_certbot_hook_in_help_writes_what_liteblox_loads(settings, tmp_path):
    text = (help_mod.DOCS_DIR / 'https.md').read_text() if hasattr(help_mod, 'DOCS_DIR') else \
        (web_tls.Path(help_mod.__file__).parent / 'docs' / 'https.md').read_text()
    script = re.search(r'```sh\n(#!/bin/sh\n.*?)```', text, re.S).group(1)
    assert 'liteblox.example.com' in text and '"$TLS/key.pem"' in script
    assert script.index('key.pem') < script.index('cert.pem')        # the key first
    tls = web_tls.tls_dir(settings)
    script = (script.replace('/srv/liteblox/data/tls', str(tls))
              .replace('-o 1000 -g 1000', f'-o {os.getuid()} -g {os.getgid()}'))
    lineage = tmp_path / 'live'
    lineage.mkdir()
    chain, key = web_tls.self_signed(['liteblox.example.com'])
    (lineage / 'fullchain.pem').write_bytes(chain)
    (lineage / 'privkey.pem').write_bytes(key)
    hook = tmp_path / 'liteblox-cert'
    hook.write_text(script)
    hook.chmod(0o755)
    subprocess.run([str(hook)], env={**os.environ, 'RENEWED_LINEAGE': str(lineage)}, check=True)
    cert_path, key_path = web_tls.paths(settings)
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    live = web_tls.Live(settings)
    assert live.refresh() and live.fingerprint == web_tls.describe(chain)['fingerprint']


# ── both ports, for real ─────────────────────────────────────────────────────

def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _get(port, path, context=None):
    import http.client
    c = (http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=5) if context
         else http.client.HTTPConnection('127.0.0.1', port, timeout=5))
    try:
        c.request('GET', path)
        r = c.getresponse()
        return r.status, r.read().decode(), (c.sock.getpeercert(binary_form=True) if context else None)
    finally:
        c.close()


def _until(check, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check():
                return True
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError('timed out')


def _client_for(chain, tmp_path, name):
    (tmp_path / name).write_bytes(chain)
    ctx = ssl.create_default_context(cafile=str(tmp_path / name))
    ctx.check_hostname = False          # 127.0.0.1 is in the names, but http.client sends no SNI for an address
    return ctx


def test_both_ports_for_real(settings, conn, tmp_path, monkeypatch):
    monkeypatch.setattr(listeners, 'CHECK_EVERY', 0.2)
    monkeypatch.setattr(listeners, 'GATE_CACHE', -1)
    http_port, https_port = _free_port(), _free_port()
    first = web_tls.generate(conn, settings, ['localhost', '127.0.0.1'], 'alice')
    web_tls.save(conn, 'alice', enabled=1)
    app = create_app(settings)
    loop = asyncio.new_event_loop()
    task = {}

    def run():
        asyncio.set_event_loop(loop)
        task['t'] = loop.create_task(listeners.serve(app, settings, '127.0.0.1', http_port, https_port))
        try:
            loop.run_until_complete(task['t'])
        except asyncio.CancelledError:
            pass
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        _until(lambda: _get(http_port, '/healthz')[0] == 200)
        trust_first = _client_for(web_tls.read(settings)[0], tmp_path, 'first.pem')
        _until(lambda: _get(https_port, '/healthz', trust_first)[0] == 200)
        _, _, der = _get(https_port, '/login', trust_first)
        assert x509.load_der_x509_certificate(der).fingerprint(hashes.SHA256()).hex(':').upper() == \
            first['fingerprint']
        _until(lambda: https_row(conn)['listening'] == 1)

        # a new pair written from outside: new connections get it
        chain, key = web_tls.self_signed(['localhost', '127.0.0.1'])
        web_tls.write(settings, chain, key)
        trust_second = _client_for(chain, tmp_path, 'second.pem')
        _until(lambda: _get(https_port, '/healthz', trust_second)[0] == 200)

        # HTTPS only: plain HTTP gets the page, /healthz still answers
        web_tls.save(conn, 'alice', https_only=1)
        code, body, _ = _get(http_port, '/login')
        assert code == 403 and "HTTP isn't supported here" in body and str(https_port) in body
        assert _get(http_port, '/healthz')[0] == 200
        assert _get(https_port, '/login', trust_second)[0] == 200

        # off: the HTTPS port closes, plain HTTP works again
        web_tls.disable(conn, 'cli')
        _until(lambda: https_row(conn)['listening'] == 0)
        assert _get(http_port, '/login')[0] == 200
        with pytest.raises(OSError):
            _get(https_port, '/healthz', trust_second)
    finally:
        loop.call_soon_threadsafe(task['t'].cancel)
        thread.join(15)
    assert not thread.is_alive()
