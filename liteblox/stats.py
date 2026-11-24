"""Figures over time for the Dashboard's graphs.

The health check samples every node each minute (load, memory, disk, DNS queries per
minute) and the active DHCP leases per subnet. Per-minute rows are kept for two days,
then rolled up into 15-minute averages kept for 30 days.
"""

import time

KEEP_MINUTES = 48 * 3600
KEEP_ROLLED = 30 * 24 * 3600
BUCKET = 900

# BIND's query counter at the last sample, per node: {node id: (time, queries, boot time)}.
# In memory: after a restart of LiteBlox the first sample only sets the base.
_last_queries = {}


def _add(conn, metric, value, at, node_id=None, subnet_id=None, subnet6_id=None):
    conn.execute('INSERT INTO samples (node_id, subnet_id, subnet6_id, metric, at, value) VALUES (?, ?, ?, ?, ?, ?)',
                 (node_id, subnet_id, subnet6_id, metric, int(at), float(value)))


def node_figures(stats, node_id, at):
    """{metric: value} from an agent's /stats answer (parts it couldn't read are left out)."""
    out = {}
    system = stats.get('system') or {}
    if system.get('load'):
        out['load1'] = system['load'][0]
    total, available = system.get('mem_total'), system.get('mem_available')
    if total and available is not None:
        out['mem_used_pct'] = 100.0 * (total - available) / total
    root = (system.get('disks') or {}).get('/')
    if root and root.get('total'):
        out['disk_used_pct'] = 100.0 * root['used'] / root['total']
    bind = stats.get('bind')
    if bind and bind.get('queries') is not None:
        last = _last_queries.get(node_id)
        _last_queries[node_id] = (at, bind['queries'], bind.get('boot_time'))
        if last and last[2] == bind.get('boot_time') and at > last[0] and bind['queries'] >= last[1]:
            out['dns_qpm'] = (bind['queries'] - last[1]) * 60.0 / (at - last[0])
    return out


def sample_node(conn, node_id, stats, at=None):
    at = at or time.time()
    figures = node_figures(stats, node_id, at)
    with conn:
        for metric, value in figures.items():
            _add(conn, metric, value, at, node_id=node_id)
    return figures


def sample_leases(conn, use, at=None):
    """use: leases.pool_use() ({subnet id: {active, in_pool, outside, size}}): the active leases, the pool
    addresses taken (active or declined), and the active leases outside the pools."""
    at = at or time.time()
    with conn:
        for subnet_id, u in use.items():
            _add(conn, 'leases_active', u['active'], at, subnet_id=subnet_id)
            _add(conn, 'leases_in_pool', u['in_pool'], at, subnet_id=subnet_id)
            _add(conn, 'leases_outside', u['outside'], at, subnet_id=subnet_id)


def sample_leases6(conn, use, at=None):
    """use: leases.pool_use6() ({subnet id: {addresses, in_pool, prefixes}})."""
    at = at or time.time()
    with conn:
        for subnet_id, u in use.items():
            _add(conn, 'leases6_active', u['addresses'], at, subnet6_id=subnet_id)
            _add(conn, 'leases6_in_pool', u['in_pool'], at, subnet6_id=subnet_id)
            _add(conn, 'prefixes6_active', u['prefixes'], at, subnet6_id=subnet_id)


def prune(conn, now=None):
    """Roll per-minute rows older than two days into 15-minute averages; drop rolled rows after 30 days."""
    now = now or time.time()
    cutoff = int(now - KEEP_MINUTES) // BUCKET * BUCKET      # whole buckets only
    with conn:
        conn.execute('INSERT INTO samples (node_id, subnet_id, subnet6_id, metric, at, period, value) '
                     'SELECT node_id, subnet_id, subnet6_id, metric, at / ? * ?, ?, AVG(value) FROM samples '
                     'WHERE period = 60 AND at < ? GROUP BY node_id, subnet_id, subnet6_id, metric, at / ?',
                     (BUCKET, BUCKET, BUCKET, cutoff, BUCKET))
        conn.execute('DELETE FROM samples WHERE period = 60 AND at < ?', (cutoff,))
        conn.execute('DELETE FROM samples WHERE period = ? AND at < ?', (BUCKET, int(now - KEEP_ROLLED)))


def series(conn, metric, node_id=None, subnet_id=None, hours=24, now=None, subnet6_id=None):
    """[(unix time, value), ...] oldest first, for one node's or one subnet's metric."""
    now = now or time.time()
    rows = conn.execute('SELECT at, value FROM samples WHERE metric = ? AND node_id IS ? AND subnet_id IS ? '
                        'AND subnet6_id IS ? AND at >= ? ORDER BY at',
                        (metric, node_id, subnet_id, subnet6_id, int(now - hours * 3600)))
    return [(r['at'], r['value']) for r in rows]


def latest(conn, metric, node_id=None, subnet_id=None, within=300, now=None, subnet6_id=None):
    """The newest value if it's recent (default: the last 5 minutes), else None."""
    now = now or time.time()
    row = conn.execute('SELECT value FROM samples WHERE metric = ? AND node_id IS ? AND subnet_id IS ? '
                       'AND subnet6_id IS ? AND at >= ? ORDER BY at DESC LIMIT 1',
                       (metric, node_id, subnet_id, subnet6_id, int(now - within))).fetchone()
    return row['value'] if row else None


def spark(points, hours=24, now=None, width=100, height=24, gap=None):
    """SVG path data for a small graph over the last `hours`: {'line', 'area', 'last', 'peak'}, or None
    with fewer than two points. y runs from 0 to the peak; a hole in the samples (LiteBlox or the node
    down) breaks the line instead of drawing across it."""
    if len(points) < 2:
        return None
    now = now or time.time()
    span = hours * 3600
    gap = gap or (180 if hours <= KEEP_MINUTES / 3600 else 3 * BUCKET)
    peak = max(v for _, v in points)
    scale = peak or 1

    def xy(at, value):
        x = min(width, max(0.0, (at - (now - span)) / span * width))
        return f'{x:.1f},{height - value / scale * (height - 2) - 1:.1f}'
    segments, current = [], [points[0]]
    for prev, point in zip(points, points[1:]):
        if point[0] - prev[0] > gap:
            segments.append(current)
            current = []
        current.append(point)
    segments.append(current)
    line = ' '.join('M' + ' L'.join(xy(*p) for p in seg) for seg in segments)
    area = ' '.join(f"M{xy(seg[0][0], 0)} L" + ' L'.join(xy(*p) for p in seg) + f" L{xy(seg[-1][0], 0)} Z"
                    for seg in segments if len(seg) > 1)
    return {'line': line, 'area': area, 'last': points[-1][1], 'peak': peak}
