"""What the nodes see: each address's MACs from their neighbour (ARP) tables, read by the health check every minute.

An entry's last_seen is when a node last had the neighbour confirmed (an ARP answer, or traffic from it), so a
stale entry a node keeps for hours doesn't look fresh, and last_seen never moves back. When an address turns up
with a different MAC than the one seen last, the change is kept: several changes in a few minutes is flapping,
two devices on one address, which goes to Needs attention until an admin acknowledges it.

One read a minute catches flapping that lasts a few minutes; ARP sniffing (later) will catch it sooner. IPv6
neighbours (NDP) are kept the same way, global and ULA addresses only.
"""

import ipaddress
import json
import time
from dataclasses import dataclass

from ..addrs import sort_key
from ..search import bare_mac

NOT_A_DEVICE = {'000000000000', 'ffffffffffff'}


@dataclass
class Settings:
    keep_days: int = 7
    seen_hours: int = 24        # how long a seen address counts as in use (keep_days: how long it's kept)
    flap_changes: int = 3
    flap_minutes: int = 10
    oui_checked_at: int = None
    oui_error: str = None


def settings(conn):
    row = conn.execute('SELECT * FROM ipam_settings WHERE id = 1').fetchone()
    return Settings(row['keep_days'], row['seen_hours'], row['flap_changes'], row['flap_minutes'], row['oui_checked_at'],
                    row['oui_error'])


def save_settings(conn, keep_days, flap_changes, flap_minutes, seen_hours=None):
    with conn:
        conn.execute('UPDATE ipam_settings SET keep_days = ?, flap_changes = ?, flap_minutes = ? WHERE id = 1',
                     (keep_days, flap_changes, flap_minutes))
        if seen_hours is not None:
            conn.execute('UPDATE ipam_settings SET seen_hours = ? WHERE id = 1', (seen_hours,))


def mac_text(mac):
    """'BC-24-11-6C-51-D8' or 'bc2411...' → 'bc:24:11:6c:51:d8'."""
    b = bare_mac(mac)
    return ':'.join(b[i:i + 2] for i in range(0, 12, 2)) if len(b) == 12 else (mac or '').lower()


def _device(mac):
    b = bare_mac(mac)
    # multicast MACs (the low bit of the first octet) aren't devices
    return len(b) == 12 and b not in NOT_A_DEVICE and not int(b[:2], 16) & 1


def record(conn, node_id, entries, now=None, source='neigh'):
    """Store a node's neighbour entries ({ip, mac, confirmed} as /neigh gives them). Returns the changes found:
    [(ip, old_mac, new_mac, at)]."""
    now = int(now if now is not None else time.time())
    changes = []
    seen = []
    for e in entries:
        try:
            ip = ipaddress.ip_address(e.get('ip') or '')
        except ValueError:
            continue
        # a PERMANENT entry (no confirmed age) was typed in, not seen; an IPv6 link-local address (fe80::) is on
        # every link and says nothing about which address a device uses
        if e.get('confirmed') is None or not _device(e.get('mac')) or ip.is_multicast or ip.is_loopback \
                or ip.is_unspecified or (ip.version == 6 and ip.is_link_local):
            continue
        seen.append((str(ip), mac_text(e['mac']), now - max(0, int(e['confirmed']))))
    seen.sort(key=lambda x: x[2])      # oldest first, so a change is judged against what was seen before it
    with conn:
        for ip, mac, at in seen:
            newest = conn.execute('SELECT mac, last_seen FROM ipam_seen WHERE ip = ? ORDER BY last_seen DESC, '
                                  'rowid DESC LIMIT 1', (ip,)).fetchone()
            if newest is not None and newest['mac'] != mac and at > newest['last_seen']:
                conn.execute('INSERT INTO ipam_changes (ip, at, old_mac, new_mac) VALUES (?, ?, ?, ?)',
                             (ip, at, newest['mac'], mac))
                changes.append((ip, newest['mac'], mac, at))
            conn.execute(
                'INSERT INTO ipam_seen (ip, mac, first_seen, last_seen, node_id, source) VALUES (?, ?, ?, ?, ?, ?) '
                'ON CONFLICT (ip, mac) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), '
                'node_id = CASE WHEN excluded.last_seen > last_seen THEN excluded.node_id ELSE node_id END, '
                'source = CASE WHEN excluded.last_seen > last_seen THEN excluded.source ELSE source END, '
                'last_seen = max(last_seen, excluded.last_seen)',
                (ip, mac, at, at, node_id, source))
    return changes


def prune(conn, now=None):
    """Drop what's older than keep_days."""
    now = int(now if now is not None else time.time())
    before = now - settings(conn).keep_days * 86400
    with conn:
        conn.execute('DELETE FROM ipam_seen WHERE last_seen < ?', (before,))
        conn.execute('DELETE FROM ipam_changes WHERE at < ?', (before,))
        # expected MACs stay until someone unmutes them
        conn.execute('DELETE FROM ipam_acks WHERE acked_at < ? AND expected IS NULL '
                     'AND ip NOT IN (SELECT ip FROM ipam_changes)', (before,))


def forget(conn, ip, mac=None):
    """Forget an address (or one MAC on it) at once: its entries, and its changes when nothing's left of it."""
    with conn:
        if mac:
            conn.execute('DELETE FROM ipam_seen WHERE ip = ? AND mac = ?', (ip, mac_text(mac)))
        else:
            conn.execute('DELETE FROM ipam_seen WHERE ip = ?', (ip,))
        if not conn.execute('SELECT 1 FROM ipam_seen WHERE ip = ?', (ip,)).fetchone():
            conn.execute('DELETE FROM ipam_changes WHERE ip = ?', (ip,))
            conn.execute('DELETE FROM ipam_acks WHERE ip = ? AND expected IS NULL', (ip,))


# ── flapping ───────────────────────────────────────────────────────────────────

def flapping(conn, now=None):
    """[{ip, changes, macs, last_at}]: addresses whose MAC changed flap_changes times or more within flap_minutes,
    counting only changes after the address's ACK, so an acknowledged address comes back only if it flaps again.
    A change between two of the address's expected MACs never counts, nor one to or from a repeater's MAC (it
    stands in for whatever is connected through the repeater)."""
    from .devices import repeaters
    now = int(now if now is not None else time.time())
    cfg = settings(conn)
    behind = repeaters(conn)
    since = now - cfg.flap_minutes * 60
    acks = {r['ip']: r for r in conn.execute('SELECT * FROM ipam_acks')}
    by_ip = {}
    for c in conn.execute('SELECT ip, at, old_mac, new_mac FROM ipam_changes WHERE at >= ? ORDER BY at, id',
                          (since,)):
        a = acks.get(c['ip'])
        if a is not None and c['at'] <= a['acked_at']:
            continue
        expected = set(json.loads(a['expected'])) if a is not None and a['expected'] else set()
        if c['old_mac'] in expected and c['new_mac'] in expected:
            continue
        if c['old_mac'] in behind or c['new_mac'] in behind:
            continue
        by_ip.setdefault(c['ip'], []).append(c)
    out = []
    for ip, found in by_ip.items():
        if len(found) >= cfg.flap_changes:
            macs = sorted({c['old_mac'] for c in found} | {c['new_mac'] for c in found})
            out.append({'ip': ip, 'changes': len(found), 'macs': macs, 'last_at': max(c['at'] for c in found)})
    return sorted(out, key=lambda x: sort_key(x['ip']))


def ack(conn, ip, username, now=None):
    now = int(now if now is not None else time.time())
    with conn:
        conn.execute('INSERT INTO ipam_acks (ip, acked_at, username) VALUES (?, ?, ?) ON CONFLICT (ip) DO UPDATE '
                     'SET acked_at = excluded.acked_at, username = excluded.username', (ip, now, username))


def expect(conn, ip, macs, reason, username, now=None):
    """Mark macs as expected on ip (added to any already expected): changes between them stop counting as
    flapping, for good; a change to any other MAC still does. It acknowledges the flapping so far too."""
    now = int(now if now is not None else time.time())
    held = expected(conn).get(ip)
    macs = sorted(set(held['macs'] if held else ()) | {mac_text(m) for m in macs if _device(m)})
    with conn:
        conn.execute('INSERT INTO ipam_acks (ip, acked_at, username, expected, reason) VALUES (?, ?, ?, ?, ?) '
                     'ON CONFLICT (ip) DO UPDATE SET acked_at = excluded.acked_at, username = excluded.username, '
                     'expected = excluded.expected, reason = excluded.reason',
                     (ip, now, username, json.dumps(macs), (reason or '').strip()[:200]))
    return macs


def unmute(conn, ip, now=None):
    """Expected MACs no longer: every change from now on counts again."""
    now = int(now if now is not None else time.time())
    with conn:
        conn.execute("UPDATE ipam_acks SET expected = NULL, reason = '', acked_at = ? WHERE ip = ?", (now, ip))


def expected(conn):
    """{ip: {macs, reason, username, at}} for the addresses with expected MACs."""
    return {r['ip']: {'macs': json.loads(r['expected']), 'reason': r['reason'], 'username': r['username'],
                      'at': r['acked_at']}
            for r in conn.execute('SELECT * FROM ipam_acks WHERE expected IS NOT NULL')}


# ── reading it ─────────────────────────────────────────────────────────────────

def at_address(conn, ip):
    """[{mac, first_seen, last_seen, node, source}] seen on ip, newest first."""
    return [dict(r) for r in conn.execute(
        'SELECT s.mac, s.first_seen, s.last_seen, s.source, n.name AS node FROM ipam_seen s '
        'LEFT JOIN nodes n ON n.id = s.node_id WHERE s.ip = ? ORDER BY s.last_seen DESC', (str(ip),))]


def changes_at(conn, ip, limit=20):
    return [dict(r) for r in conn.execute('SELECT at, old_mac, new_mac FROM ipam_changes WHERE ip = ? '
                                          'ORDER BY at DESC, id DESC LIMIT ?', (str(ip), limit))]


def in_use(latest_seen, hours, now=None):
    """The addresses of latest_seen (seen.latest) seen within the last hours: the ones that count as in use."""
    since = int(now if now is not None else time.time()) - hours * 3600
    return {ip for ip, s in latest_seen.items() if s['last_seen'] >= since}


def latest(conn):
    """{IPv4Address or IPv6Address: {mac, last_seen, macs}} for every address seen: its newest MAC, and how many it
    had."""
    out = {}
    for r in conn.execute('SELECT ip, mac, last_seen FROM ipam_seen ORDER BY last_seen'):
        ip = ipaddress.ip_address(r['ip'])
        held = out.get(ip)
        out[ip] = {'mac': r['mac'], 'last_seen': r['last_seen'], 'macs': (held['macs'] + 1) if held else 1}
    return out


def devices(conn):
    """One row per MAC, like the ARP monitor: [{mac, ip, last_seen, first_seen, earlier: [ips], v6: [ips], node,
    source}], the most recently seen first. ip is its newest IPv4 address (IPv6 when it has none): a dual-stack
    device keeps its IPv4 address there, with its IPv6 ones (newest first) in v6."""
    by_mac = {}
    for r in conn.execute('SELECT s.*, n.name AS node FROM ipam_seen s LEFT JOIN nodes n ON n.id = s.node_id '
                          'ORDER BY s.last_seen DESC'):
        d = by_mac.get(r['mac'])
        if d is None:
            d = by_mac[r['mac']] = {'mac': r['mac'], 'ip': None, 'last_seen': r['last_seen'],
                                    'first_seen': r['first_seen'], 'earlier': [], 'v6': [], 'node': r['node'],
                                    'source': r['source']}
        d['first_seen'] = min(d['first_seen'], r['first_seen'])
        if ':' in r['ip']:
            d['v6'].append(r['ip'])
        elif d['ip'] is None:
            d['ip'] = r['ip']
        else:
            d['earlier'].append(r['ip'])
    for d in by_mac.values():
        if d['ip'] is None:
            d['ip'] = d['v6'].pop(0)
    return list(by_mac.values())


def recent_mac(conn, ip, within=86400, now=None):
    """{mac: last_seen} seen on ip within the last `within` seconds."""
    now = int(now if now is not None else time.time())
    return {r['mac']: r['last_seen'] for r in conn.execute(
        'SELECT mac, last_seen FROM ipam_seen WHERE ip = ? AND last_seen >= ?', (str(ip), now - within))}
