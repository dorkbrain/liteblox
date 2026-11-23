"""SOA serial policy: date-based YYYYMMDDnn that only ever moves forward."""

from datetime import date

MAX_SERIAL = 2**32 - 1


def next_serial(current, today=None, live=()):
    """Next serial after current, never below today's YYYYMMDD01 or any serial a node is serving.

    Past nn=99 the serial simply keeps counting into tomorrow's range; it still
    increases, which is all secondaries and resolvers care about.
    """
    today = today or date.today()
    base = int(today.strftime('%Y%m%d')) * 100
    new = max(base + 1, current + 1, *(s + 1 for s in live))
    if new > MAX_SERIAL:
        raise ValueError(f'serial {new} exceeds the 32-bit maximum')
    return new


def bump(zone, today=None, live=()):
    """Set the zone's SOA serial to the next one; returns (old, new)."""
    old = zone.serial
    zone.serial = next_serial(old, today, live)
    return old, zone.serial
