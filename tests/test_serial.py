from datetime import date

import pytest

from liteblox.dns import serial
from liteblox.dns.zonefile import Zone

TODAY = date(2026, 10, 24)


@pytest.mark.parametrize('current, live, expected', [
    (2026102305, (), 2026102401),        # yesterday's serial: start today's range
    (2026102401, (), 2026102402),        # same day: count up
    (2026102499, (), 2026102500),        # past nn=99: keeps increasing into tomorrow's range
    (2026102401, (2026102407,), 2026102408),  # a node serves a higher serial: jump past it
    (2099010100, (), 2099010101),        # serial ahead of the date scheme: just +1
    (42, (), 2026102401),                # tiny legacy serial
])
def test_next_serial(current, live, expected):
    assert serial.next_serial(current, TODAY, live) == expected


def test_serial_overflow():
    with pytest.raises(ValueError):
        serial.next_serial(serial.MAX_SERIAL, TODAY)


def test_bump_updates_zone():
    zone = Zone.parse('@ IN SOA ns1 host 2026102305 60 60 3600 60\n', 'example.com.')
    assert serial.bump(zone, TODAY) == (2026102305, 2026102401)
    assert zone.render() == '@ IN SOA ns1 host 2026102401 60 60 3600 60\n'
