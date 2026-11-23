"""Private CA for LiteBlox <-> agent mutual TLS.

LiteBlox owns a small CA in <data>/pki. It issues one client certificate for
LiteBlox itself and a server certificate per node; agents trust only this CA
and only a client certificate with CN=liteblox.
"""

import datetime
import ipaddress
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CLIENT_CN = 'liteblox'
CA_DAYS = 3650
CLIENT_DAYS = 1825
SERVER_DAYS = 825


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _write_private(path, data):
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_bytes(data)


def _san(host):
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def fingerprint(cert_pem):
    """SHA-256 fingerprint as colon-separated hex."""
    digest = x509.load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA256())
    return ':'.join(f'{b:02X}' for b in digest)


def not_after(cert_pem):
    return x509.load_pem_x509_certificate(cert_pem).not_valid_after_utc


class PKI:
    def __init__(self, directory):
        self.dir = Path(directory)
        self.ca_cert_path = self.dir / 'ca.crt'
        self.ca_key_path = self.dir / 'ca.key'
        self.client_cert_path = self.dir / 'client.crt'
        self.client_key_path = self.dir / 'client.key'

    def ensure(self):
        """Create the CA and the LiteBlox client certificate on first run."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self.dir.chmod(0o700)
        if not self.ca_cert_path.exists():
            self._create_ca()
        if not self.client_cert_path.exists():
            key, cert = self._issue(CLIENT_CN, [], ExtendedKeyUsageOID.CLIENT_AUTH, CLIENT_DAYS)
            _write_private(self.client_key_path, key)
            self.client_cert_path.write_bytes(cert)
        return self

    def ca_pem(self):
        return self.ca_cert_path.read_bytes()

    def issue_server_cert(self, node_name, hosts):
        """(key_pem, cert_pem) for a node agent; hosts are the IPs/DNS names LiteBlox connects to."""
        if not hosts:
            raise ValueError('a server certificate needs at least one host')
        return self._issue(node_name, hosts, ExtendedKeyUsageOID.SERVER_AUTH, SERVER_DAYS)

    def issue_peer_cert(self, name, hosts):
        """(key_pem, cert_pem) for a DHCP failover peer: it serves its partner and connects to it, so the
        certificate is good for both ends of a mutual-TLS link."""
        if not hosts:
            raise ValueError('a peer certificate needs at least one host')
        return self._issue(name, hosts, [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH],
                           SERVER_DAYS)

    def _create_ca(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LiteBlox'),
            x509.NameAttribute(NameOID.COMMON_NAME, f'LiteBlox CA {secrets.token_hex(4)}'),
        ])
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        _write_private(self.ca_key_path, _key_pem(key))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _issue(self, common_name, hosts, usage, days):
        ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), None)
        ca_cert = x509.load_pem_x509_certificate(self.ca_pem())
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'LiteBlox'),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=True, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage(usage if isinstance(usage, list) else [usage]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
        )
        if hosts:
            builder = builder.add_extension(x509.SubjectAlternativeName([_san(h) for h in hosts]),
                                            critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        return _key_pem(key), cert.public_bytes(serialization.Encoding.PEM)
