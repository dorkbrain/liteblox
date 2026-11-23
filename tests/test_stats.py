"""The Dashboard's graph samples: figures from an agent's /stats, roll-up and series."""

import pytest

from liteblox import stats

T0 = 1_800_000_000          # a whole 15-minute bucket


@pytest.fixture(autouse=True)
def fresh_counters(monkeypatch):
    monkeypatch.setattr(stats, '_last_queries', {})


def answer(queries=None, boot='b1', load=0.5):
    return {'system': {'load': [load, 0.4, 0.3], 'mem_total': 4000, 'mem_available': 1000,
                       'disks': {'/': {'total': 200, 'used': 50, 'available': 150}, '/var/lib/bind': {}}},
            'bind': None if queries is None else {'queries': queries, 'boot_time': boot}, 'errors': {}}


def test_node_figures_and_the_query_rate():
    first = stats.node_figures(answer(1000), 1, T0)
    assert first == {'load1': 0.5, 'mem_used_pct': 75.0, 'disk_used_pct': 25.0}   # the first count is the base
    assert stats.node_figures(answer(1300), 1, T0 + 120)['dns_qpm'] == 150.0          # 300 in two minutes
    # named restarted (new boot time, counter back near 0): no figure, the new count is the base
    assert 'dns_qpm' not in stats.node_figures(answer(20, boot='b2'), 1, T0 + 180)
    assert stats.node_figures(answer(80, boot='b2'), 1, T0 + 240)['dns_qpm'] == 60.0
    # each node has its own base
    assert 'dns_qpm' not in stats.node_figures(answer(5), 2, T0 + 240)


def test_parts_the_agent_could_not_read_are_left_out():
    assert stats.node_figures({'system': None, 'bind': None, 'errors': {'system': 'x'}}, 1, T0) == {}
    no_avail = answer()
    no_avail['system']['mem_available'] = None
    assert 'mem_used_pct' not in stats.node_figures(no_avail, 1, T0)


def test_samples_series_and_latest(conn):
    conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp) VALUES ('ns1', '192.0.2.1', 'k', 'f')")
    conn.execute("INSERT INTO dhcp4_subnets (prefix, interface) VALUES ('192.0.2.0/24', 'ens19')")
    stats.sample_node(conn, 1, answer(10), at=T0)
    stats.sample_node(conn, 1, answer(70, load=0.7), at=T0 + 60)
    stats.sample_leases(conn, {1: {'active': 0, 'in_pool': 0, 'outside': 0, 'size': 10}}, at=T0)
    stats.sample_leases(conn, {1: {'active': 4, 'in_pool': 3, 'outside': 1, 'size': 10}}, at=T0 + 60)
    assert stats.series(conn, 'load1', node_id=1, now=T0 + 60) == [(T0, 0.5), (T0 + 60, 0.7)]
    assert stats.series(conn, 'dns_qpm', node_id=1, now=T0 + 60) == [(T0 + 60, 60.0)]
    assert stats.series(conn, 'leases_active', subnet_id=1, now=T0 + 60) == [(T0, 0.0), (T0 + 60, 4.0)]
    assert stats.latest(conn, 'leases_in_pool', subnet_id=1, now=T0 + 60) == 3.0
    assert stats.latest(conn, 'leases_outside', subnet_id=1, now=T0 + 60) == 1.0
    assert stats.latest(conn, 'load1', node_id=1, now=T0 + 120) == 0.7
    assert stats.latest(conn, 'load1', node_id=1, now=T0 + 3600) is None       # too old to call current
    # a removed node takes its samples with it
    with conn:
        conn.execute('DELETE FROM nodes WHERE id = 1')
    assert stats.series(conn, 'load1', node_id=1, now=T0 + 60) == []


def test_prune_rolls_up_then_forgets(conn):
    conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp) VALUES ('ns1', '192.0.2.1', 'k', 'f')")
    with conn:
        for minute, value in enumerate((1.0, 2.0, 3.0)):            # one bucket
            stats._add(conn, 'load1', value, T0 + minute * 60, node_id=1)
        stats._add(conn, 'load1', 9.0, T0 + 900, node_id=1)          # the next bucket
    now = T0 + 1800 + stats.KEEP_MINUTES          # both buckets are older than two days
    stats.prune(conn, now=now)
    rows = conn.execute('SELECT at, period, value FROM samples ORDER BY at').fetchall()
    assert [tuple(r) for r in rows] == [(T0, 900, 2.0), (T0 + 900, 900, 9.0)]
    assert stats.series(conn, 'load1', node_id=1, hours=72, now=now) == [(T0, 2.0), (T0 + 900, 9.0)]

    # a bucket only partly past the cutoff stays per-minute until all of it is
    with conn:
        stats._add(conn, 'load1', 5.0, T0 + 1800, node_id=1)
        stats._add(conn, 'load1', 7.0, T0 + 2400, node_id=1)
    stats.prune(conn, now=T0 + 2100 + stats.KEEP_MINUTES)
    assert conn.execute('SELECT COUNT(*) FROM samples WHERE period = 60').fetchone()[0] == 2

    stats.prune(conn, now=T0 + stats.KEEP_ROLLED + 1800)
    assert conn.execute('SELECT COUNT(*) FROM samples WHERE period = 900 AND at < ?', (T0 + 1800,)).fetchone()[0] == 0
