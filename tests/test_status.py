"""What needs an admin (status.problems), the Dashboard's activity feed, and the small formatters."""

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from liteblox import activity, db, jobs, status, timefmt
from liteblox.backups import service as backups

from test_managed import lab, make_roles  # noqa: F401 (fixture)

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
SEEN = (NOW - timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')


@pytest.fixture
def healthy(conn, settings, lab, monkeypatch):  # noqa: F811
    """Two ready nodes, ns1 the primary, seen just now, backed up, clocks in step."""
    make_roles(conn, primary=1, secondary=2)
    with conn:
        conn.execute('UPDATE nodes SET last_seen_at = ?, clock_skew = 0.2, clock_synced = 1', (SEEN,))
    monkeypatch.setattr(backups, 'is_stale', lambda conn, settings, node_id, now=None: False)
    return lab


ZONE = "INSERT INTO zones (name, kind, mode, repo_file) VALUES ('a.lab', 'primary', 'managed', 'a.lab.zone')"


def found(conn, settings):
    return [(p['severity'], p['area'], p['what']) for p in status.problems(conn, settings, now=NOW)]


def test_a_healthy_lab_has_nothing(conn, settings, healthy):
    assert found(conn, settings) == []
    assert status.level([]) == 'ok'


def test_times_in_problems_are_local(conn, settings, healthy, monkeypatch):
    """Stored times are UTC; Needs attention shows them in the container's zone (TZ), like every page."""
    import time
    monkeypatch.setenv('TZ', 'America/Chicago')
    time.tzset()
    try:
        with conn:
            conn.execute("UPDATE nodes SET last_seen_at = '2026-11-01 11:50:00', cert_not_after = '2026-11-20 03:00:00' "
                         "WHERE id = 1")
        words = ' | '.join(p[2] for p in found(conn, settings))
        assert "checked since 2026-11-01 05:50:00 CST" in words and 'UTC' not in words
        assert 'certificate expires 2026-11-19' in words
    finally:
        monkeypatch.delenv('TZ')
        time.tzset()


@pytest.mark.parametrize('sql, severity, area, words', [
    ("UPDATE nodes SET status = 'error', status_detail = 'connection refused\nmore' WHERE id = 1",
     'error', 'node', "ns1 doesn't answer: connection refused"),
    ("UPDATE nodes SET last_seen_at = '2026-11-01 11:50:00' WHERE id = 1", 'warn', 'node', "hasn't been checked since"),
    ("UPDATE nodes SET status = 'new' WHERE id = 2", 'warn', 'node', 'ns2 is not set up yet'),
    ("UPDATE nodes SET pending = 'demote' WHERE id = 2", 'warn', 'dns', 'its demotion runs when it answers'),
    ("UPDATE nodes SET second_primary = '[\"a.lab\"]' WHERE id = 2", 'error', 'dns', 'declares a.lab as primary'),
    ("UPDATE nodes SET drift = '[\"options.conf\"]' WHERE id = 2", 'warn', 'dns', 'changed outside LiteBlox (options.conf)'),
    ("UPDATE nodes SET dhcp = 1, dhcp_ha_state = 'partner-down' WHERE id = 1", 'warn', 'dhcp', 'failover is partner-down'),
    ("UPDATE nodes SET dhcp = 1, dhcp_ha_state = 'terminated' WHERE id = 1", 'error', 'dhcp', 'failover is terminated'),
    ("UPDATE nodes SET dhcp = 1, dhcp_drift = '[\"kea-dhcp4.conf\"]' WHERE id = 1", 'warn', 'dhcp', "Kea config was changed"),
    ("UPDATE nodes SET ntp = 1, ntp_state = NULL WHERE id = 1", 'error', 'time', "chrony isn't running"),
    ("UPDATE nodes SET ntp = 1, ntp_state = '{\"synced\": false}' WHERE id = 1", 'warn', 'time', 'no usable time source'),
    ("UPDATE nodes SET ntp = 1, ntp_state = '{\"synced\": true}', ntp_drift = '[\"chrony.conf\"]' WHERE id = 1",
     'warn', 'time', 'chrony config was changed'),
    ("UPDATE nodes SET clock_skew = 45 WHERE id = 1", 'warn', 'time', "ns1's clock is +45 s"),
    ("UPDATE nodes SET clock_skew = -200 WHERE id = 1", 'error', 'time', "ns1's clock is -200 s"),
    ("UPDATE nodes SET clock_synced = 0 WHERE id = 1", 'warn', 'time', "clock isn't synchronized"),
    ("UPDATE nodes SET cert_not_after = '2026-11-20 12:00:00' WHERE id = 1", 'warn', 'node', 'certificate expires 2026-11-20'),
    ("UPDATE nodes SET cert_not_after = '2026-10-20 00:00:00' WHERE id = 1", 'error', 'node', 'certificate expired'),
    ("UPDATE nodes SET role = 'secondary'", 'warn', 'dns', 'no primary yet'),
    ("UPDATE nodes SET dhcp = 1, dhcp_sockets = '{\"status\": \"retrying\", \"errors\": [\"the interface ens19 is not running\"]}' "
     "WHERE id = 1", 'warn', 'dhcp', "ns1: Kea can't listen for DHCP yet and keeps trying (the interface ens19 is not running)"),
    ("UPDATE nodes SET dhcp = 1, dhcp_sockets = '{\"status\": \"failed\", \"errors\": [\"the interface ens19 is not running\"]}' "
     "WHERE id = 1", 'error', 'dhcp', "ns1: Kea isn't serving DHCP (the interface ens19 is not running); LiteBlox reloads it"),
    ("UPDATE nodes SET dhcp = 1, dhcp_drift = '[\"dhcp4\"]', dhcp_sockets = '{\"status\": \"failed\", \"errors\": [\"x\"]}' "
     "WHERE id = 1", 'error', 'dhcp', "ns1: Kea isn't serving DHCP (x); Rewrite DHCP config makes it try again"),
    ("UPDATE nodes SET dhcp = 1, dhcp_sockets = '{\"status\": \"down\", \"errors\": [\"connection refused\"]}' WHERE id = 1",
     'error', 'dhcp', "ns1: Kea isn't serving DHCP (connection refused)"),
    ("INSERT INTO demote_reports (node_id, zone_id, old_text, rrsets) VALUES (2, 1, '', '[]')", 'warn', 'dns',
     'ns2 kept 1 record report when it was demoted'),
])
def test_each_problem(conn, settings, healthy, sql, severity, area, words):
    with conn:
        conn.execute(ZONE)
        conn.execute(sql)
    hits = [p for p in found(conn, settings) if words in p[2]]
    assert len(hits) == 1, found(conn, settings)
    assert hits[0][:2] == (severity, area)
    assert status.level(status.problems(conn, settings, now=NOW)) == severity


def test_a_stale_backup(conn, settings, lab):  # noqa: F811
    with conn:
        conn.execute('UPDATE nodes SET last_seen_at = ?', (SEEN,))
    assert ('warn', 'node', 'ns1 has had no successful backup in 48 hours') in found(conn, settings)


def test_a_failed_publish_and_a_draft(conn, settings, healthy):
    with conn:
        conn.execute(ZONE)
        conn.execute("INSERT INTO deploys (zone_id, status, error) VALUES (1, 'failed', 'x')")
    (settings.data_dir / 'drafts').mkdir(parents=True, exist_ok=True)
    (settings.data_dir / 'drafts' / 'a.lab.zone').write_text('$ORIGIN a.lab.\n')
    got = found(conn, settings)
    assert ('error', 'dns', 'the last publish of a.lab failed') in got
    assert ('info', 'dns', 'a.lab has unpublished changes') in got
    assert got[0][0] == 'error'                    # the worst first
    with conn:
        conn.execute('DELETE FROM deploys')
    assert status.level(status.problems(conn, settings, now=NOW)) == 'ok'     # a draft alone isn't a problem


def test_the_cached_level(conn, settings, healthy, monkeypatch):
    monkeypatch.setattr(status, '_cache', {})
    with conn:          # cached_level() asks at the real time
        conn.execute("UPDATE nodes SET clock_skew = 500, last_seen_at = datetime('now') WHERE id = 1")
        conn.execute("UPDATE nodes SET last_seen_at = datetime('now') WHERE id = 2")
    assert status.cached_level(settings) == ('error', 1)
    with conn:
        conn.execute('UPDATE nodes SET clock_skew = 0 WHERE id = 1')
    assert status.cached_level(settings) == ('error', 1)      # shared for a few seconds
    monkeypatch.setattr(status, 'CACHE_FOR', 0)
    assert status.cached_level(settings) == ('ok', 0)


# ── activity ───────────────────────────────────────────────────────────────────

def test_activity_shows_a_job_once_and_leaves_out_logins(conn, settings):
    db.audit(conn, 'alice', 'login')
    db.audit(conn, 'alice', 'key_add', 'dhcp')
    with conn:          # a minute before the job: its own change, not the job's
        conn.execute("UPDATE audit SET at = datetime('now', '-1 minute')")
    job_id = jobs.start(settings.db_path, 'bootstrap', lambda log: db.audit(db.connect(settings.db_path), 'alice',
                                                                           'node_bootstrap', 'ns1'),
                        username='alice', background=False)
    feed = activity.recent(conn)
    assert [(a['kind'], a['label']) for a in feed] == [('job', f'#{job_id} Bootstrap'), ('change', 'Added a TSIG key')]
    assert feed[0]['link'] == f'/jobs/{job_id}' and feed[0]['status'] == 'ok'


def test_activity_leaves_out_scheduled_jobs_unless_they_fail(conn, settings):
    def run(username, fail=False):
        def work(log):
            if fail:
                raise RuntimeError('no answer')
        return jobs.start(settings.db_path, 'ipam sweep', work, username=username, background=False)
    mine, quiet, failed, fix = run('alice'), run(None), run(None, fail=True), run('liteblox')
    shown = [a['link'] for a in activity.recent(conn)]
    assert shown == [f'/jobs/{fix}', f'/jobs/{failed}', f'/jobs/{mine}'] and f'/jobs/{quiet}' not in shown


def test_every_audited_action_has_a_label():
    actions = set()
    for path in Path(activity.__file__).parent.rglob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', getattr(node.func, 'attr', None)) == 'audit':
                action = node.args[2] if len(node.args) >= 3 else None
                if isinstance(action, ast.IfExp):           # 'acl_add' if create else 'acl_change'
                    action = [action.body, action.orelse]
                for a in action if isinstance(action, list) else [action]:
                    if isinstance(a, ast.Constant):
                        actions.add(a.value)
                    elif a is not None:
                        pytest.fail(f'{path.name}:{node.lineno}: audit() with an action that is not a literal')
    assert len(actions) > 40
    assert sorted(actions - set(activity.LABELS)) == []


# ── formatters ─────────────────────────────────────────────────────────────────

def test_ago():
    now = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    assert timefmt.ago('2026-11-01 11:59:40', now) == 'just now'
    assert timefmt.ago('2026-11-01 11:55:00', now) == '5 min ago'
    assert timefmt.ago('2026-11-01 09:00:00', now) == '3 h ago'
    assert timefmt.ago(now.timestamp() - 30 * 3600, now) == 'yesterday'
    assert timefmt.ago('2026-10-28 12:00:00', now) == '4 days ago'
    assert timefmt.ago(None, now) == ''


def test_offset():
    assert timefmt.offset(0.000181) == '+181 µs'
    assert timefmt.offset(-0.0021) == '-2.1 ms'
    assert timefmt.offset(1.5, sign=False) == '1.5 s'


def test_api_problems_are_json(conn, settings, healthy):
    with conn:
        conn.execute('UPDATE nodes SET clock_skew = 45 WHERE id = 1')
    assert json.dumps(status.problems(conn, settings, now=NOW))


def test_a_node_that_does_not_answer_hides_its_old_kea_state(conn, settings, healthy):
    with conn:
        conn.execute("UPDATE nodes SET status = 'error', dhcp = 1, "
                     "dhcp_sockets = '{\"status\": \"failed\", \"errors\": [\"x\"]}' WHERE id = 1")
    assert [p for p in found(conn, settings) if p[1] == 'dhcp'] == []


@pytest.mark.parametrize('dhcp4, want', [
    ({}, None),
    ({'running': True, 'pid': 7}, None),                                   # Kea 1.x: no sockets field
    ({'running': True, 'sockets': {'status': 'ready'}}, None),
    ({'running': True, 'sockets': {'status': 'retrying', 'errors': ['the interface ens19 is not running']}},
     {'status': 'retrying', 'errors': ['the interface ens19 is not running']}),
    ({'running': True, 'sockets': {'status': 'failed'}}, {'status': 'failed', 'errors': ['no details']}),
    ({'running': False, 'error': 'connection refused'}, {'status': 'down', 'errors': ['connection refused']}),
])
def test_listening(dhcp4, want):
    from liteblox.nodes.health import listening
    assert listening(dhcp4) == want
