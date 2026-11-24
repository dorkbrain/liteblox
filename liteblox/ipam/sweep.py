"""The sweep: probe every address of a network through a node on it, so quiet devices show up in what was seen.

Off by default, per network: hourly or daily (checked every 10 minutes by the scheduler), or Sweep now. It probes
64 addresses at a time at 10 a second, and records what answered (a ping, or ARP during the probe) as seen, with
source 'sweep'. Networks bigger than a /22 aren't swept. With a resolver in Settings → IPAM, what answered gets
its PTR looked up afterwards.
"""

import ipaddress
import json

EVERY = {'hourly': 3600, 'daily': 86400}
CHUNK = 64
LARGEST = 22            # a /22: 1022 addresses, about 2.5 minutes


def node_for(conn, network):
    """The node to sweep from: the one picked, else the first ready one on the network; None without one."""
    from .free import node_on
    if network.sweep_node_id:
        row = conn.execute("SELECT * FROM nodes WHERE id = ? AND status = 'ready'", (network.sweep_node_id,)).fetchone()
        if row is not None and any(':' not in p and ipaddress.IPv4Network(p).overlaps(network.net)
                                   for p in json.loads(row['networks'] or '[]')):
            return row
    return node_on(conn, network.net.network_address + 1)


def problem(conn, network):
    """Why the network can't be swept, or None."""
    if network.version == 6:
        return 'an IPv6 network is never swept (a /64 has 2^64 addresses): the nodes\' neighbour tables show what\'s there'
    if network.container:
        return f'{network.prefix} holds other networks: sweep those'
    if network.net.prefixlen < LARGEST:
        return f'{network.prefix} is bigger than a /{LARGEST}: too big to sweep'
    if node_for(conn, network) is None:
        return f'no node is on {network.prefix}, so nothing can sweep it'
    return None


def running(conn, network):
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'ipam sweep' AND status = 'running' AND log LIKE ?",
                        (f'%Sweeping {network.prefix} from %',)).fetchone() is not None


def due(conn):
    """The networks whose sweep is due (and can run)."""
    from . import model
    rows = conn.execute(
        "SELECT id FROM ipam_networks WHERE sweep != 'off' AND (swept_at IS NULL OR "
        "CAST(strftime('%s', 'now') AS INTEGER) - CAST(strftime('%s', swept_at) AS INTEGER) >= "
        "CASE sweep WHEN 'hourly' THEN 3600 ELSE 86400 END)").fetchall()
    found = {n.id: n for n in model.networks(conn)}
    return [found[r['id']] for r in rows if r['id'] in found and problem(conn, found[r['id']]) is None
            and not running(conn, found[r['id']])]


def run(settings, network_id, log, probe=None):
    """The job: probe the network in chunks and record what answered."""
    from .. import db
    from ..nodes import service as nodes
    from . import model, seen
    from .free import _in_use
    conn = db.connect(settings.db_path)
    try:
        network = next(n for n in model.networks(conn) if n.id == network_id)
        node = node_for(conn, network)
        log(f'Sweeping {network.prefix} from {node["name"]}')

        def agent(ips):
            with nodes.agent_client(settings, node, timeout=60.0) as c:
                return c.probe(ips, interval_ms=100, wait=1.5)
        probe = probe or agent
        hosts = [str(ip) for ip in network.net.hosts()]
        answered = []
        for i in range(0, len(hosts), CHUNK):
            chunk = hosts[i:i + CHUNK]
            answer = probe(chunk)
            elapsed, results = answer.get('elapsed') or 0, answer.get('results') or {}
            live = [ip for ip in chunk if _in_use(results.get(ip), elapsed)]
            seen.record(conn, node['id'], [{'ip': ip, 'mac': results[ip].get('mac'),
                                            'confirmed': results[ip].get('confirmed') or 0}
                                           for ip in live if results[ip].get('mac')], source='sweep')
            answered += live
            log(f'  {chunk[0]} – {chunk[-1]}: {len(live)} answered')
        with conn:
            conn.execute("UPDATE ipam_networks SET swept_at = datetime('now') WHERE id = ?", (network.id,))
        log(f'✓ {len(answered)} of {len(hosts)} addresses answered')
        _lookups(conn, answered, log)
    finally:
        conn.close()


def _lookups(conn, ips, log):
    from . import ptr
    try:
        server = ptr.parse_resolver(ptr.config(conn)[0])
    except ValueError as e:
        log(f'  no PTR lookups: {e}')
        return
    if server and ips:
        log('  ' + ptr.describe(server, ptr.refresh(conn, ips, server)))


def start(settings, conn, network, username=None, background=True, probe=None):
    """Sweep now, as a job; returns its id. Raises ValueError when it can't run."""
    from .. import jobs
    why = problem(conn, network)
    if why:
        raise ValueError(why)
    if running(conn, network):
        raise ValueError(f'a sweep of {network.prefix} is already running')
    return jobs.start(settings.db_path, 'ipam sweep', lambda log: run(settings, network.id, log, probe),
                      username=username, background=background)
