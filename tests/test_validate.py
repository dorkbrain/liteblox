import shutil
from pathlib import Path

import dns.name
import pytest

from liteblox.dns import validate
from liteblox.dns.zonefile import Zone

from conftest import private_zone_params

FIXTURES = Path(__file__).parent / 'fixtures'
EXAMPLE = (FIXTURES / 'zones' / 'example.com.zone').read_text()
ORIGIN = dns.name.from_text('example.com.')

needs_named = pytest.mark.skipif(shutil.which('named-checkzone') is None,
                                 reason='named-checkzone not installed')


@pytest.mark.parametrize('rtype, rdata, ok', [
    ('A', '192.0.2.1', True),
    ('A', '192.0.2.256', False),
    ('AAAA', '2001:db8::1', True),
    ('MX', '10 mail', True),
    ('MX', 'mail', False),
    ('SRV', '0 0 1688 host.example.com.', True),
    ('SRV', '0 0 host', False),
    ('CNAME', 'www', True),
    ('TXT', '"hello" "world"', True),
    ('CAA', '0 issue "letsencrypt.org"', True),
])
def test_check_rdata(rtype, rdata, ok):
    assert (validate.check_rdata(rtype, rdata, ORIGIN) is None) == ok


def test_fixture_records_all_valid():
    assert validate.check_records(Zone.parse(EXAMPLE, ORIGIN)) == []


@pytest.mark.parametrize('path, origin', private_zone_params())
def test_private_records_all_valid(path, origin):
    assert validate.check_records(Zone.parse(path.read_bytes().decode(), origin)) == []


@needs_named
def test_named_checkzone_accepts_and_rejects():
    ok, output = validate.named_checkzone('example.com', EXAMPLE)
    assert ok, output
    ok, output = validate.named_checkzone('example.com', EXAMPLE.replace('192.0.2.53', '192.0.2.999'))
    assert not ok and 'example.com' in output


def test_named_checkzone_missing_tool(monkeypatch):
    monkeypatch.setattr(shutil, 'which', lambda name: None)
    with pytest.raises(validate.ToolMissing):
        validate.named_checkzone('example.com', EXAMPLE)


def test_bad_address_message():
    from liteblox.dns.validate import check_rdata
    assert check_rdata('A', '999.1.1.1', dns.name.from_text('example.com.')) == "999.1.1.1 isn't a valid IPv4 address"
    assert check_rdata('AAAA', '192.0.2.1', dns.name.from_text('example.com.')) == "192.0.2.1 isn't a valid IPv6 address"
