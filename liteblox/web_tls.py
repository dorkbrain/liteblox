"""Built-in HTTPS (4.6): the certificate in <data>/tls, its settings row, and the context the HTTPS listener serves.

HTTPS is opt-in (Settings → HTTPS, or `liteblox https on`) and listens on its own port (53443) beside plain HTTP
(53530). The certificate is two files, so the admin's own tools (certbot, acme.sh) can renew it: LiteBlox
notices a change within seconds and serves the new pair to new connections, and keeps the old one while a new
pair doesn't load (a renewal caught halfway, a key that doesn't match).
"""

import datetime
import ipaddress
import os
import re
import shutil
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .pki import _san

CERT, KEY = 'cert.pem', 'key.pem'
DEFAULT_PORT = 53443
SELF_SIGNED_DAYS = 825          # the longest that Apple platforms accept for a certificate a user trusts
EXPIRY_WARN_DAYS = 30
MAX_UPLOAD = 256 * 1024
MAX_NAMES = 20
_HOSTNAME = re.compile(r'(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*\.?')


class CertError(ValueError):
    pass


def https_port():
    try:
        return int(os.environ.get('LITEBLOX_HTTPS_PORT') or DEFAULT_PORT)
    except ValueError:
        return DEFAULT_PORT


def tls_dir(settings):
    return Path(settings.data_dir) / 'tls'


def paths(settings):
    d = tls_dir(settings)
    return d / CERT, d / KEY


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# ── the settings row ───────────────────────────────────────────────────────────

def load(conn):
    return dict(conn.execute('SELECT * FROM https_settings WHERE id = 1').fetchone())


def save(conn, username, **fields):
    """A change an admin made (the page or the CLI)."""
    fields = {**fields, 'updated_by': username}
    with conn:
        conn.execute(f"UPDATE https_settings SET {', '.join(f'{k} = ?' for k in fields)}, "
                     "updated_at = datetime('now') WHERE id = 1", tuple(fields.values()))


def record(conn, **fields):
    """What the running server found (listening, the last error, the certificate it serves)."""
    with conn:
        conn.execute(f"UPDATE https_settings SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = 1",
                     tuple(fields.values()))


# ── names ──────────────────────────────────────────────────────────────────────

def parse_names(text):
    """'liteblox.lan, 192.168.1.10' → ['liteblox.lan', '192.168.1.10']: hostnames and IP addresses."""
    names = []
    for raw in re.split(r'[\s,]+', (text or '').strip().lower()):
        if not raw:
            continue
        try:
            name = str(ipaddress.ip_address(raw.strip('[]')))
        except ValueError:
            if not _HOSTNAME.fullmatch(raw):
                raise CertError(f'{raw} is not a hostname or an IP address')
            name = raw.rstrip('.')
        if name not in names:
            names.append(name)
    if not names:
        raise CertError('give at least one name: the hostname or address you open LiteBlox with')
    if len(names) > MAX_NAMES:
        raise CertError(f'at most {MAX_NAMES} names')
    return names


def default_names(host):
    """The names a first self-signed certificate gets: the host the admin is browsing from."""
    host = (host or '').strip('[]').lower()
    return [host] if host and host not in ('localhost', '127.0.0.1', '::1') else ['localhost', '127.0.0.1']


# ── certificates ───────────────────────────────────────────────────────────────

def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _chain_pem(certs):
    return b''.join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def self_signed(names, now=None, days=SELF_SIGNED_DAYS):
    """(certificate PEM, key PEM): ECDSA P-256, CA:FALSE, serverAuth. Not signed by the agents' CA: trusting
    that CA in a browser would make anyone holding ./data trusted for every site."""
    now = now or _now()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LiteBlox (self-signed)')])
    # no KeyUsage: OpenSSL then takes a self-signed leaf as its own trust anchor (lbcli --ca, curl --cacert)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([_san(n) for n in names]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return _chain_pem([cert]), _key_pem(key)


def _same_key(cert, key):
    fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return cert.public_key().public_bytes(*fmt) == key.public_key().public_bytes(*fmt)


def _ordered(leaf, others):
    """The leaf, then each issuer in turn, then anything left over (as given)."""
    chain, rest = [leaf], [c for c in others if c != leaf]
    while rest:
        nxt = next((c for c in rest if c.subject == chain[-1].issuer and c.subject != chain[-1].subject), None)
        if nxt is None:
            break
        chain.append(nxt)
        rest.remove(nxt)
    return chain + rest


def read_import(cert=b'', key=b'', pfx=b'', password='', now=None):
    """What an admin uploaded → (certificate chain PEM, unencrypted key PEM). A PEM certificate (with its chain)
    and a PEM key (the key may be in the certificate's file, and may be encrypted), or a PKCS#12 (.pfx/.p12)."""
    now = now or _now()
    pw = password.encode() if password else None
    for data in (cert, key, pfx):
        if len(data) > MAX_UPLOAD:
            raise CertError(f'a file is bigger than {MAX_UPLOAD // 1024} KB')
    if pfx:
        try:
            private, leaf, extra = pkcs12.load_key_and_certificates(pfx, pw)
        except ValueError as e:
            raise CertError('the .pfx/.p12 could not be read: '
                            + ('a wrong or missing password?' if 'password' in str(e).lower() or not pw else str(e)))
        if private is None or leaf is None:
            raise CertError('the .pfx/.p12 has no certificate with its key')
        certs = [leaf, *extra]
    else:
        if not cert:
            raise CertError('choose a certificate file (PEM), or a .pfx/.p12')
        try:
            certs = x509.load_pem_x509_certificates(cert)
        except ValueError:
            raise CertError('the certificate file is not PEM (-----BEGIN CERTIFICATE-----)')
        key = key or (cert if b'PRIVATE KEY-----' in cert else b'')
        if not key:
            raise CertError('choose the private key file too (PEM)')
        try:
            private = serialization.load_pem_private_key(key, pw)
        except TypeError:
            raise CertError('the private key is encrypted: give its password')
        except ValueError as e:
            raise CertError('the private key could not be read: '
                            + ('a wrong password?' if pw else str(e).split('\n')[0]))
    if not isinstance(private, (ec.EllipticCurvePrivateKey,)) and not hasattr(private, 'key_size'):
        raise CertError('the key is not an RSA or EC key')
    leaf = next((c for c in certs if _same_key(c, private)), None)
    if leaf is None:
        raise CertError("the private key doesn't belong to the certificate")
    if leaf.not_valid_after_utc <= now:
        raise CertError(f'the certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d}')
    if leaf.not_valid_before_utc > now + datetime.timedelta(minutes=5):
        raise CertError(f'the certificate is only valid from {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} UTC')
    chain_pem, key_pem = _chain_pem(_ordered(leaf, certs)), _key_pem(private)
    check_pair(chain_pem, key_pem)
    return chain_pem, key_pem


def _context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['http/1.1'])
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def context_from(chain_pem, key_pem, scratch=None):
    """An SSLContext for this pair, loaded from private copies (ssl only reads files): CertError if it doesn't
    load. The copies go in scratch (the tls folder) or a private temp folder, and are removed."""
    folder = tempfile.mkdtemp(prefix='.load-', dir=scratch)
    try:
        cert_path, key_path = Path(folder) / CERT, Path(folder) / KEY
        key_path.touch(mode=0o600)
        key_path.write_bytes(key_pem)
        cert_path.write_bytes(chain_pem)
        try:
            return _context(str(cert_path), str(key_path))
        except ssl.SSLError as e:
            raise CertError(f"the certificate and key don't load together ({e.reason or e})")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def check_pair(chain_pem, key_pem):
    context_from(chain_pem, key_pem)


def describe(chain_pem, now=None):
    """The leaf of a chain: what the page and `liteblox https status` show."""
    now = now or _now()
    certs = x509.load_pem_x509_certificates(chain_pem)
    leaf = certs[0]
    try:
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n) for n in sans.get_values_for_type(x509.DNSName)] + \
                [str(n) for n in sans.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []

    def cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()
    digest = leaf.fingerprint(hashes.SHA256())
    after = leaf.not_valid_after_utc
    return {
        'subject': cn(leaf.subject), 'issuer': cn(leaf.issuer), 'self_signed': leaf.issuer == leaf.subject,
        'names': names, 'not_before': leaf.not_valid_before_utc, 'not_after': after,
        'days_left': (after - now).days, 'expired': after <= now, 'chain': len(certs) - 1,
        'fingerprint': ':'.join(f'{b:02X}' for b in digest),
    }


def covers(info, host):
    """Does the certificate name host (wildcards one label deep)?"""
    host = (host or '').strip('[]').lower().rstrip('.')
    for name in info['names']:
        name = name.lower()
        if name == host or (name.startswith('*.') and host.count('.') >= name.count('.')
                            and host.split('.', 1)[-1] == name[2:]):
            return True
    return False


def warnings(info, host=None):
    out = []
    if info['days_left'] < EXPIRY_WARN_DAYS:
        out.append(f"it expires in {max(info['days_left'], 0)} days ({info['not_after']:%Y-%m-%d})")
    if host and not covers(info, host):
        out.append(f"its names ({', '.join(info['names']) or 'none'}) don't include {host}: browsers will warn")
    return out


# ── the files ──────────────────────────────────────────────────────────────────

def _atomic(path, data, mode):
    tmp = path.with_name(f'.{path.name}.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def write(settings, chain_pem, key_pem):
    """The key first, then the certificate: a reload between the two sees a mismatch and keeps the old pair."""
    d = tls_dir(settings)
    d.mkdir(mode=0o700, exist_ok=True)
    cert_path, key_path = paths(settings)
    _atomic(key_path, key_pem, 0o600)
    _atomic(cert_path, chain_pem, 0o644)


def read(settings):
    """(certificate PEM, key PEM) on disk, or None while there's none."""
    cert_path, key_path = paths(settings)
    try:
        return cert_path.read_bytes(), key_path.read_bytes()
    except FileNotFoundError:
        return None
    except PermissionError as e:
        raise CertError(f'{Path(e.filename).name} can\'t be read: it must be readable by uid {os.getuid()}, '
                        'the user LiteBlox runs as') from None


def current(settings, now=None):
    """The certificate on disk, described; None while there's none or it can't be read."""
    try:
        pair = read(settings)
        return describe(pair[0], now) if pair else None
    except ValueError:              # CertError too: a file it can't read
        return None


def install(conn, settings, chain_pem, key_pem, source, username, names=None):
    """Put a certificate in place (it's checked first) and remember that LiteBlox wrote it."""
    check_pair(chain_pem, key_pem)
    write(settings, chain_pem, key_pem)
    info = describe(chain_pem)
    fields = {'source': source, 'fingerprint': info['fingerprint']}
    if names is not None:
        fields['names'] = ', '.join(names)
    save(conn, username, **fields)
    return info


def generate(conn, settings, names, username):
    chain_pem, key_pem = self_signed(names)
    return install(conn, settings, chain_pem, key_pem, 'self-signed', username, names)


def enable(conn, settings, username, host=None):
    """HTTPS on; a first self-signed certificate when there's none. Returns the certificate made, or None."""
    made = None
    if current(settings) is None:
        row = load(conn)
        names = parse_names(row['names']) if row['names'] else default_names(host)
        made = generate(conn, settings, names, username)
    save(conn, username, enabled=1)
    return made


def disable(conn, username):
    save(conn, username, enabled=0, https_only=0)


# ── what the HTTPS listener serves ─────────────────────────────────────────────

class Live:
    """The SSLContext the HTTPS listener was started with, and the pair it hands to each new connection.

    Each new handshake gets the newest context that loaded (through the SNI callback, which OpenSSL calls with or
    without a server name), so a renewal never needs a restart and a bad pair never replaces a good one."""

    def __init__(self, settings):
        self.settings = settings
        self.base = None            # what the listener was started with
        self.current = None         # what new connections get
        self.fingerprint = None
        self.error = None
        self._stamp = None

    def _files_stamp(self):
        stamps = []
        for path in paths(self.settings):
            try:
                st = path.stat()
            except FileNotFoundError:
                return None
            stamps.append((st.st_mtime_ns, st.st_size, st.st_ino))
        return tuple(stamps)

    def _pick(self, ssl_obj, server_name, base):
        if self.current is not None and self.current is not base:
            ssl_obj.context = self.current

    def refresh(self):
        """Load the files again if they changed. True when what new connections get changed."""
        stamp = self._files_stamp()
        if stamp is None:
            self.error = None if self.current else 'there is no certificate in ./data/tls yet'
            self._stamp = None
            return False
        if stamp == self._stamp:
            return False
        self._stamp = stamp
        try:
            pair = read(self.settings)
            if pair is None:
                raise CertError('the certificate files went away while being read')
            ctx = context_from(*pair, scratch=tls_dir(self.settings))
            info = describe(pair[0])
        except (CertError, ValueError, OSError) as e:
            self.error = f'{e}' + ('; still serving the previous certificate' if self.current else '')
            self._stamp = None      # look again next time: a renewal caught halfway, or a chown still to come
            return False
        if self.base is None:
            ctx.sni_callback = self._pick
            self.base = ctx
        self.current = ctx
        self.fingerprint, self.error = info['fingerprint'], None
        return True


# ── the Dashboard ──────────────────────────────────────────────────────────────

def problems(conn, settings, now=None):
    row = load(conn)
    if not row['enabled']:
        return []
    link = '/settings/https'

    def problem(severity, what):
        return {'severity': severity, 'area': 'web', 'node': None, 'link': link, 'what': what}
    out = []
    if row['error']:
        out.append(problem('error', f"HTTPS: {row['error']}"))
    info = current(settings, now)
    if info is None:
        if not row['error']:
            out.append(problem('error', 'HTTPS is on, but there is no certificate in ./data/tls'))
        return out
    if info['expired']:
        out.append(problem('error', f"the HTTPS certificate expired on {info['not_after']:%Y-%m-%d}"))
    elif info['days_left'] < EXPIRY_WARN_DAYS:
        out.append(problem('warn', f"the HTTPS certificate expires in {info['days_left']} days "
                                   f"({info['not_after']:%Y-%m-%d})"))
    return out
