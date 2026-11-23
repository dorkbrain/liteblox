from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from liteblox import pki as pki_mod
from liteblox.pki import PKI


def _cert(pem):
    return x509.load_pem_x509_certificate(pem)


def test_ensure_creates_ca_and_client_once(tmp_path):
    p = PKI(tmp_path / 'pki').ensure()
    ca_before = p.ca_cert_path.read_bytes()
    PKI(tmp_path / 'pki').ensure()
    assert p.ca_cert_path.read_bytes() == ca_before
    for key in (p.ca_key_path, p.client_key_path):
        assert key.stat().st_mode & 0o777 == 0o600
    assert p.dir.stat().st_mode & 0o777 == 0o700

    ca = _cert(ca_before)
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    client = _cert(p.client_cert_path.read_bytes())
    client.verify_directly_issued_by(ca)
    assert client.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == pki_mod.CLIENT_CN
    eku = client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_server_cert_has_sans_and_server_usage(tmp_path):
    p = PKI(tmp_path).ensure()
    key_pem, cert_pem = p.issue_server_cert('lab-ns1', ['172.16.1.4', 'lab-ns1.example.net'])
    assert b'PRIVATE KEY' in key_pem
    cert = _cert(cert_pem)
    cert.verify_directly_issued_by(_cert(p.ca_pem()))
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ['172.16.1.4']
    assert san.get_values_for_type(x509.DNSName) == ['lab-ns1.example.net']
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(
        x509.ExtendedKeyUsage).value
    assert len(pki_mod.fingerprint(cert_pem).split(':')) == 32
    assert pki_mod.not_after(cert_pem) > pki_mod._now()


def test_app_startup_creates_pki(settings, app):
    assert (settings.pki_dir / 'ca.crt').exists()
