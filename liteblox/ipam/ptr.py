"""PTR lookups (rDNS): the names a resolver gives IPAM's used addresses, for names that live in DNS LiteBlox
doesn't run.

Off until Settings → IPAM has a resolver. Opening a network's page looks up its used addresses whose answer is
older than ptr_hours (MAX per view, in a background thread, so the page never waits); a sweep looks up what
answered. Each answer (a name, none, or an error) is kept in ipam_ptr; a failed lookup is tried again after an hour.
"""

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.reversename

MAX = 256               # lookups per page view
TIMEOUT = 2.0
WORKERS = 8
RETRY = 3600            # a failed lookup is tried again after this many seconds
HOURS = (1, 720)

_lock = threading.Lock()
_busy = set()           # addresses being looked up now (one thread each, never twice)
_threads = []


def parse_resolver(text):
    """'192.0.2.53' or '192.0.2.53:5353' → (host, port); '' → None. ValueError when it's neither."""
    text = (text or '').strip()
    if not text:
        return None
    host, _, port = text.partition(':')
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError:
        raise ValueError(f'{text}: give an IPv4 address, with :port when it isn\'t 53')
    if port:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(f'{text}: the port is a number from 1 to 65535')
        return host, int(port)
    return host, 53


def config(conn):
    """(resolver text, hours)."""
    row = conn.execute('SELECT resolver, ptr_hours FROM ipam_settings WHERE id = 1').fetchone()
    return row['resolver'], row['ptr_hours']


def save(conn, resolver, hours):
    """A changed resolver drops the names the old one gave."""
    old, _ = config(conn)
    with conn:
        conn.execute('UPDATE ipam_settings SET resolver = ?, ptr_hours = ? WHERE id = 1', (resolver, hours))
        if resolver != old:
            conn.execute('DELETE FROM ipam_ptr')


def lookup(server, port, ip, timeout=TIMEOUT):
    """(name, error) for ip's PTR at server: ('', None) when it has none."""
    q = dns.message.make_query(dns.reversename.from_address(ip), dns.rdatatype.PTR)
    try:
        r = dns.query.udp(q, server, timeout=timeout, port=port)
    except dns.exception.Timeout:
        return '', f'{server} gave no answer in {timeout:g} s'
    except (OSError, dns.exception.DNSException) as e:
        return '', f'{server}: {e}'
    if r.rcode() == dns.rcode.NXDOMAIN:
        return '', None
    if r.rcode() != dns.rcode.NOERROR:
        return '', f'{server} answered {dns.rcode.to_text(r.rcode())}'
    for rrset in r.answer:
        if rrset.rdtype == dns.rdatatype.PTR:
            for rd in rrset:
                return rd.target.to_text().rstrip('.').lower(), None
    return '', None


LOOKUP = lookup         # tests put a fake resolver here


def cached(conn):
    """{IPv4Address or IPv6Address: {name, looked_up_at, error}}."""
    return {ipaddress.ip_address(r['ip']): dict(r) for r in conn.execute('SELECT * FROM ipam_ptr')}


def get(conn, ip):
    row = conn.execute('SELECT * FROM ipam_ptr WHERE ip = ?', (str(ip),)).fetchone()
    return dict(row) if row else None


def stale(conn, ips, hours, now=None):
    """The addresses of ips whose answer is missing or old, in order."""
    now = now or time.time()
    known = {r['ip']: r for r in conn.execute('SELECT * FROM ipam_ptr')}
    out = []
    for ip in ips:
        r = known.get(str(ip))
        if r is None or now - r['looked_up_at'] >= (RETRY if r['error'] else hours * 3600):
            out.append(str(ip))
    return out


def refresh(conn, ips, server):
    """Look ips up now (WORKERS at a time) and keep the answers: {'names': n, 'none': n, 'errors': n}."""
    host, port = server
    ips = [str(ip) for ip in ips]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        answers = list(pool.map(lambda ip: LOOKUP(host, port, ip), ips))
    now = int(time.time())
    with conn:
        conn.executemany('INSERT INTO ipam_ptr (ip, name, looked_up_at, error) VALUES (?, ?, ?, ?) '
                         'ON CONFLICT (ip) DO UPDATE SET name = excluded.name, looked_up_at = excluded.looked_up_at, '
                         'error = excluded.error', [(ip, name, now, error) for ip, (name, error) in zip(ips, answers)])
    return {'names': sum(1 for n, e in answers if n), 'none': sum(1 for n, e in answers if not n and not e),
            'errors': sum(1 for n, e in answers if e)}


def refresh_later(settings, conn, ips):
    """Look up the stale ones of ips (MAX at most) in a background thread. Returns how many it started."""
    resolver, hours = config(conn)
    try:
        server = parse_resolver(resolver)
    except ValueError:
        return 0
    if server is None:
        return 0
    with _lock:
        todo = [ip for ip in stale(conn, ips, hours) if ip not in _busy][:MAX]
        _busy.update(todo)
    if not todo:
        return 0

    def work():
        from .. import db
        c = db.connect(settings.db_path)
        try:
            refresh(c, todo, server)
        except Exception:       # a lookup that fails is tried again on the next view
            pass
        finally:
            c.close()
            with _lock:
                _busy.difference_update(todo)

    t = threading.Thread(target=work, name='ptr-lookups', daemon=True)
    _threads.append(t)
    t.start()
    return len(todo)


def wait(timeout=10.0):
    """Until the background lookups are done (tests)."""
    while _threads:
        _threads.pop().join(timeout)


def describe(server, counts):
    host, port = server
    at = host if port == 53 else f'{host}:{port}'
    return (f"PTR lookups at {at}: {counts['names']} named, {counts['none']} without a PTR"
            + (f", {counts['errors']} failed" if counts['errors'] else ''))
