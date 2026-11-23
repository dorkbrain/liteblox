"""MAC vendors, from the IEEE's list of assigned prefixes (oui.txt), kept in the data folder and refreshed weekly.

A MAC with the locally administered bit set was made up by its device (phones and laptops randomise theirs per
network): it has no vendor, so it shows as a private address. When the list can't be fetched, vendors are blank.
"""

import email.utils
import os
import re
import threading
import time
import urllib.error
import urllib.request

URL = 'https://standards-oui.ieee.org/oui.txt'
MAX_AGE = 7 * 86400
TIMEOUT = 60
PRIVATE = 'private address'
_LINE = re.compile(r'^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$')
_cache, _lock = {}, threading.Lock()


def path(settings):
    return settings.data_dir / 'oui.txt'


def parse(text):
    """{'bc2411': 'Proxmox Server Solutions GmbH', ...} from oui.txt's '(hex)' lines."""
    out = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            out[(m.group(1) + m.group(2) + m.group(3)).lower()] = m.group(4)
    return out


def table(settings):
    """The parsed list, read again only when the file changes; {} without one."""
    p = path(settings)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return {}
    with _lock:
        hit = _cache.get(p)
        if hit and hit[0] == mtime:
            return hit[1]
    parsed = parse(p.read_text(encoding='utf-8', errors='replace'))
    with _lock:
        _cache[p] = (mtime, parsed)
    return parsed


def vendor(settings, mac, vendors=None):
    """The vendor of a MAC, 'private address' for a made-up one, or ''."""
    from ..search import bare_mac
    b = bare_mac(mac)
    if len(b) < 6:
        return ''
    if int(b[:2], 16) & 2:
        return PRIVATE
    return (vendors if vendors is not None else table(settings)).get(b[:6], '')


def _fetch(since=None):
    """(status, body or None): 304 when the IEEE's copy hasn't changed since `since` (unix time)."""
    from ..version import __version__
    headers = {'User-Agent': f'LiteBlox/{__version__}'}
    if since:
        headers['If-Modified-Since'] = email.utils.formatdate(since, usegmt=True)
    try:
        with urllib.request.urlopen(urllib.request.Request(URL, headers=headers), timeout=TIMEOUT) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None
        raise


def due(settings, now=None):
    now = now if now is not None else time.time()
    try:
        return now - path(settings).stat().st_mtime > MAX_AGE
    except OSError:
        return True


def refresh(settings, conn, force=False, fetch=None, now=None):
    """Fetch the list when it's missing or a week old (or force). Returns a line for the log; failures are
    recorded on Settings → IPAM and leave the old list in place."""
    now = int(now if now is not None else time.time())
    if not force and not due(settings, now):
        return 'the MAC vendor list is current'
    p = path(settings)
    since = int(p.stat().st_mtime) if p.exists() and not force else None
    try:
        status, body = (fetch or _fetch)(since)
        if status == 304:
            os.utime(p, (now, now))
            message, error = "the MAC vendor list hasn't changed", None
        else:
            text = body.decode('utf-8', errors='replace')
            count = len(parse(text))
            if count < 1000:
                raise ValueError(f'the list has only {count} entries')
            tmp = p.with_suffix('.tmp')
            tmp.write_text(text, encoding='utf-8')
            os.replace(tmp, p)
            message, error = f'fetched {count} prefixes from the MAC vendor list', None
    except Exception as e:      # the network, the IEEE, a short read: vendors stay as they were
        message = error = f"couldn't fetch the MAC vendor list: {e}"
    with conn:
        conn.execute('UPDATE ipam_settings SET oui_checked_at = ?, oui_error = ? WHERE id = 1', (now, error))
    return message


def info(settings):
    """{'date': mtime or None, 'count': n} of the list in use."""
    p = path(settings)
    try:
        return {'date': p.stat().st_mtime, 'count': len(table(settings))}
    except OSError:
        return {'date': None, 'count': 0}
