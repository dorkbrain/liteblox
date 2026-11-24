"""Router advertisements from LiteBlox's nodes (6.0): a DHCPv6 subnet may have its serving nodes send them (radvd,
router lifetime 0), off by default. In development, LITEBLOX_DEV_RA_MAX_MINUTES turns them off again by itself."""

import ipaddress
import os
from datetime import datetime, timedelta, timezone

from .. import db
from .model import ha_pair, has_dhcp6, has_radvd, serves, subnets6

DEV_RA_MAX = 'LITEBLOX_DEV_RA_MAX_MINUTES'
RETRY_AFTER = timedelta(minutes=10)


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def max_minutes():
    """The development backstop: minutes after which RA turns itself off (None: no limit, a real install)."""
    raw = os.environ.get(DEV_RA_MAX, '').strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def serving_nodes(conn, subnet):
    """The DHCP nodes (with kea-dhcp6) that answer for the subnet, so would send its advertisements."""
    from ..nodes import service as nodes
    pair = ha_pair(conn)
    return [n for n in nodes.list_nodes(conn) if n['dhcp'] and has_dhcp6(n) and serves(pair, n, subnet)]


def check(conn, subnet):
    """Errors for a subnet with router advertisements on: a /64, and radvd on every node that serves it."""
    if not subnet.ra:
        return {}
    if ipaddress.ip_network(subnet.prefix, strict=False).prefixlen != 64:
        return {'ra': 'router advertisements need a /64 subnet (SLAAC and on-link prefixes are /64s)'}
    missing = [n['name'] for n in serving_nodes(conn, subnet) if not has_radvd(n)]
    if missing:
        return {'ra': f"{', '.join(missing)} can't send router advertisements: Repair "
                      f"{'it' if len(missing) == 1 else 'each'} (its page) with Router advertisements (radvd) "
                      'ticked first'}
    return {}


def notes(conn):
    """Review notes: subnets that send RAs where a serving node has no radvd (it sends none there)."""
    out = []
    for s in subnets6(conn):
        if s.ra:
            missing = [n['name'] for n in serving_nodes(conn, s) if not has_radvd(n)]
            if missing:
                out.append(f"{s.prefix} sends router advertisements, but {', '.join(missing)} has no radvd: "
                           'none are sent from there until a Repair with Router advertisements ticked')
    return out


def sending(conn):
    """The DHCPv6 subnets with router advertisements on."""
    return [s for s in subnets6(conn) if s.ra]


def expired(conn, limit=None, at=None):
    """Subnets whose RA has been on longer than the development backstop allows."""
    limit = max_minutes() if limit is None else limit
    if not limit:
        return []
    cutoff = ((at or datetime.now(timezone.utc)) - timedelta(minutes=limit)).strftime('%Y-%m-%d %H:%M:%S')
    return [s for s in sending(conn) if not s.ra_since or s.ra_since <= cutoff]


def _tried_recently(conn):
    since = (datetime.now(timezone.utc) - RETRY_AFTER).strftime('%Y-%m-%d %H:%M:%S')
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'ra auto off' AND created_at > ?", (since,)).fetchone() is not None


def backstop(settings, conn, background=True):
    """The health check's part: turn RA off on subnets past LITEBLOX_DEV_RA_MAX_MINUTES (audited). A line for its
    log, or None."""
    from . import apply
    due = expired(conn)
    if not due or _tried_recently(conn):
        return None
    ids = [s.id for s in due]
    prefixes = ', '.join(s.prefix for s in due)
    snap_rows = [(s.id, int(s.ra), s.ra_since) for s in due]

    def change(c):
        with c:
            c.executemany('UPDATE dhcp6_subnets SET ra = 0, ra_since = NULL WHERE id = ?', [(i,) for i in ids])

    def undo(c):
        with c:
            c.executemany('UPDATE dhcp6_subnets SET ra = ?, ra_since = ? WHERE id = ?',
                          [(ra, since, i) for i, ra, since in snap_rows])
    db.audit(conn, 'liteblox', 'dhcp6_ra_auto_off', f'{prefixes} (after {max_minutes()} minutes, {DEV_RA_MAX})')
    apply.start(settings, [n['id'] for n in apply.dhcp_nodes(conn)],
                f'router advertisements off for {prefixes} ({DEV_RA_MAX})', 'liteblox', change=change, undo=undo,
                background=background, kind='ra auto off')
    return f'router advertisements on {prefixes} for over {max_minutes()} minutes: turning them off ({DEV_RA_MAX})'
