"""The health check (status, config drift, a second primary, pending changes) and the drift/report pages."""

import json

import pytest

from liteblox import jobs, stats
from liteblox.bindconf import apply
from liteblox.dns import dynamic, publish as pub
from liteblox.nodes import health, roles
from liteblox.nodes import service as nodes

from conftest import csrf_from
from test_dynamic import dyn, server, zone_row  # noqa: F401 (fixtures)
from test_managed import lab, ok_verify  # noqa: F401 (fixtures)
from test_promote import kw, pair  # noqa: F401 (fixtures)


@pytest.fixture(autouse=True)
def offline(monkeypatch, server):  # noqa: F811
    """No real DNS: node copies come from the fake server, serial checks pass, apply's probes pass."""
    real_from = dynamic.axfr_from
    monkeypatch.setattr(dynamic, 'axfr_from', lambda conn, zone, host, keys=(dynamic.UPDATE_KEY,), transfer=None,
                        where='': real_from(conn, zone, host, keys, transfer or server.transfer, where))
    monkeypatch.setattr(pub, 'wait_for_serial', ok_verify)
    monkeypatch.setattr(apply, '_served', lambda host, zone: True)
    monkeypatch.setattr(apply, 'recursive_ok', lambda host: True)


def node(conn, node_id):
    return nodes.get_node(conn, node_id)


def test_status_and_unreachable(conn, settings, pair):
    fakes = pair[0]
    fakes[2].down = True
    lines = []
    health.check_all(settings, lines.append)
    assert lines == ['ns1: ok', 'ns2: unreachable (cannot reach the agent on ns2: connection refused)']
    assert node(conn, 1)['status'] == 'ready' and node(conn, 1)['agent_version'] == '1.0.1'
    assert node(conn, 2)['status'] == 'error'


def test_drift_and_a_second_primary(conn, settings, pair):
    fakes = pair[0]
    fakes[2].config_files['options.conf'] += '// hand edit\n'
    health.check_all(settings, print)
    assert json.loads(node(conn, 2)['drift']) == ['options.conf'] and node(conn, 2)['second_primary'] is None
    assert node(conn, 1)['drift'] is None

    fakes[2].config_files['zones.conf'] = fakes[1].config_files['zones.conf']   # ns2 made a primary by hand
    health.check_all(settings, print)
    assert json.loads(node(conn, 2)['second_primary']) == ['dyn.lab', 'static.lab']


def test_a_returning_node_gets_its_pending_change_once(conn, settings, pair, monkeypatch):
    fakes, server, copies, transfer = pair
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    health.check_all(settings, print, background=False)          # still down: nothing to do
    assert node(conn, 1)['pending'] == 'demote'

    fakes[1].down = False
    with roles.ROLE_LOCK:                                          # another role change is running: wait
        assert 'waits' in health.check_node(settings, conn, node(conn, 1), background=False)
    fakes[1].fail_commit = True
    assert 'running its pending change' in health.check_node(settings, conn, node(conn, 1), background=False)
    assert node(conn, 1)['pending'] == 'demote'                    # failed: kept, and not retried at once
    assert 'waits' in health.check_node(settings, conn, node(conn, 1), background=False)

    fakes[1].fail_commit = False
    with conn:
        conn.execute("UPDATE jobs SET created_at = datetime('now', '-1 hour') WHERE kind = 'reconcile'")
    health.check_node(settings, conn, node(conn, 1), background=False)
    assert node(conn, 1)['pending'] is None
    job = conn.execute("SELECT * FROM jobs WHERE kind = 'reconcile' ORDER BY id DESC").fetchone()
    assert job['status'] == 'ok' and job['username'] == 'liteblox' and 'demoting it' in job['log']
    assert fakes[1].declared()['dyn.lab']['type'] == 'secondary'


# ── pages ──────────────────────────────────────────────────────────────────────

@pytest.fixture
def admin(client, make_user, login, monkeypatch):
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    return client


def post(client, url, page, **data):
    return client.post(url, data={'csrf_token': csrf_from(client.get(page).text), **data}, follow_redirects=False)


def test_drift_page_overwrite_and_keep(admin, conn, settings, pair):
    fakes = pair[0]
    original = fakes[2].config_files['options.conf']
    fakes[2].config_files['options.conf'] = original.replace('options {', 'options {\n\tminimal-responses yes;')
    health.check_all(settings, print)
    page = admin.get('/nodes/2').text
    assert 'changed outside LiteBlox' in page and '/nodes/2/drift' in page
    drift_page = admin.get('/nodes/2/drift').text
    assert '+\tminimal-responses yes;' in drift_page and 'Keep the node' in drift_page

    keep = admin.get('/nodes/2/drift/keep')
    assert keep.status_code == 200 and 'minimal-responses yes;' in keep.text and 'changed outside LiteBlox' in keep.text

    r = post(admin, '/nodes/2/drift/overwrite', '/nodes/2/drift')
    assert jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))['status'] == 'ok'
    assert fakes[2].config_files['options.conf'] == original and node(conn, 2)['drift'] is None


def test_keep_is_refused_for_shared_files(admin, conn, settings, pair):
    fakes = pair[0]
    fakes[2].config_files['zones.conf'] += '// hand edit\n'
    health.check_all(settings, print)
    page = admin.get('/nodes/2/drift').text
    assert 'Keep the node' not in page and 'Only changes to options.conf' in page
    r = admin.get('/nodes/2/drift/keep', follow_redirects=False)
    assert r.status_code == 303 and 'only changes to options.conf' in r.headers['location'].replace('%20', ' ')


def test_report_pages(admin, conn, settings, pair):
    fakes, server, copies, transfer = pair
    fakes[1].down = True
    roles.promote(settings, 2, 'admin', print, **kw(transfer))
    fakes[1].down = False
    copies['192.0.2.53'] = {'dyn.lab': server.text('dyn.lab').replace('2026102801', '2026102805')
                            + 'pc9 300 IN A 192.168.0.59\n'}
    roles.reconcile(settings, 1, 'liteblox', print, **kw(transfer))
    report = conn.execute('SELECT id FROM demote_reports').fetchone()['id']
    assert f'/nodes/1/reports/{report}' in admin.get('/nodes/1').text
    assert 'report' in admin.get('/nodes').text and 'report' in admin.get('/').text
    page = admin.get(f'/nodes/1/reports/{report}').text
    assert 'pc9' in page and '192.168.0.59' in page
    assert 'pc9' in admin.get(f'/nodes/1/reports/{report}/old').text
    r = post(admin, f'/nodes/1/reports/{report}/reapply', f'/nodes/1/reports/{report}')
    assert 'pick' in r.headers['location']                         # nothing ticked
    r = post(admin, f'/nodes/1/reports/{report}/reapply', f'/nodes/1/reports/{report}', pick='0')
    assert 'sent' in r.headers['location'] and 'pc9' in server.text('dyn.lab')
    assert 'Done' in admin.get(f'/nodes/1/reports/{report}').text


def test_promote_button_and_cli(admin, conn, settings, pair, monkeypatch):
    fakes, server, copies, transfer = pair
    assert 'Promote to primary' in admin.get('/nodes/2').text and 'Promote ns2' in admin.get('/nodes').text
    assert 'Promote to primary' not in admin.get('/nodes/1').text
    from liteblox import cli
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    monkeypatch.setattr(roles, 'promote', lambda s, node_id, user, log: roles.make_primary(
        s, node_id, user, log, **kw(transfer)))
    assert cli.main(['node', 'promote', 'ns1', '--yes']) == 1      # already the primary
    assert cli.main(['node', 'promote', 'ns2', '--yes']) == 0
    assert node(conn, 2)['role'] == 'primary'
    assert cli.main(['node', 'drift', 'ns2']) == 0


def test_the_check_samples_each_node(conn, settings, pair, monkeypatch):
    monkeypatch.setattr(stats, '_last_queries', {})
    health.check_all(settings, print)
    health.check_all(settings, print)
    rows = conn.execute('SELECT node_id, metric, value FROM samples WHERE node_id = 1 ORDER BY id').fetchall()
    metrics = [r['metric'] for r in rows]
    assert metrics.count('load1') == 2 and metrics.count('mem_used_pct') == 2 and metrics.count('disk_used_pct') == 2
    assert metrics.count('dns_qpm') == 1           # the first answer only sets the counter's base
    assert {r['metric']: r['value'] for r in rows}['mem_used_pct'] == 25.0


def test_a_node_whose_config_is_behind_is_written_again(conn, settings, pair):
    fakes = pair[0]
    # as an older LiteBlox left it: the same config without the statistics channel
    for i in (1, 2):
        fakes[i].config_files['top.conf'] = fakes[i].config_files['top.conf'].replace('statistics-channels', '#x', 1)
    with conn:
        conn.execute("UPDATE nodes SET config_sha256 = 'older', "
                     "config_files = json_set(config_files, '$.\"top.conf\"', ?) WHERE id = 1",
                     (pub.sha(fakes[1].config_files['top.conf']),))
    assert apply.stale(conn, node(conn, 1)) and not apply.stale(conn, node(conn, 2))

    with conn:                                    # another job is running: wait for it
        job = conn.execute("INSERT INTO jobs (kind, status) VALUES ('publish', 'running')").lastrowid
    assert 'behind' not in health.check_node(settings, conn, node(conn, 1), background=False)
    with conn:
        conn.execute("UPDATE jobs SET status = 'ok' WHERE id = ?", (job,))

    line = health.check_node(settings, conn, node(conn, 1), background=False)
    assert line == 'ns1: ok; its BIND config is behind: rewriting it'
    assert 'statistics-channels' in fakes[1].config_files['top.conf'] and not apply.stale(conn, node(conn, 1))
    job = conn.execute("SELECT * FROM jobs WHERE kind = 'bind config'").fetchone()
    assert job['status'] == 'ok' and job['username'] == 'liteblox' and job['node_id'] == 1
    assert conn.execute("SELECT detail FROM audit WHERE action = 'node_rewrite'").fetchone()[0] == \
        'ns1: BIND config catches up'
    assert health.check_node(settings, conn, node(conn, 1), background=False) == 'ns1: ok'


def test_a_behind_node_with_drift_is_left_for_its_overwrite(conn, settings, pair):
    fakes = pair[0]
    with conn:
        conn.execute("UPDATE nodes SET config_sha256 = 'older' WHERE id = 2")
    fakes[2].config_files['options.conf'] += '// hand edit\n'
    line = health.check_node(settings, conn, node(conn, 2), background=False)
    assert 'changed outside LiteBlox' in line and 'behind' not in line
    assert conn.execute("SELECT COUNT(*) FROM jobs WHERE kind = 'bind config'").fetchone()[0] == 0


def test_an_os_upgrade_that_drops_a_distro_include_is_written_around(conn, settings, pair):
    """Ubuntu 26.04's bind9 has no named.conf.default-zones: the generated named.conf must stop including it
    (named-checkconf fails, so the package's postinst and the next named start do), with root-hints instead."""
    fakes = pair[0]
    zones, hints, rndc = ('/etc/bind/named.conf.default-zones', '/etc/bind/named.conf.root-hints',
                          '/etc/bind/rndc.key')
    with conn:
        conn.execute('UPDATE nodes SET distro_includes = ? WHERE id = 1', (json.dumps([zones, rndc]),))
    apply.rewrite(settings, 1, 'admin', 'setup', print)
    assert f'include "{zones}";' in fakes[1].config_files['named.conf'] and not apply.stale(conn, node(conn, 1))

    real = fakes[1].status
    fakes[1].status = lambda: {**real(), 'bind': True, 'distro_includes': [hints, rndc]}   # after the upgrade
    line = health.check_node(settings, conn, node(conn, 1), background=False)
    assert line == 'ns1: ok; its BIND config is behind: rewriting it'
    named_conf = fakes[1].config_files['named.conf']
    assert zones not in named_conf and f'include "{hints}";' in named_conf and f'include "{rndc}";' in named_conf
    assert json.loads(node(conn, 1)['distro_present']) == [hints, rndc] and not apply.stale(conn, node(conn, 1))


def test_distro_includes_as_kept_until_the_agent_says():
    from liteblox.bindconf.model import distro_includes
    zones, hints = '/etc/bind/named.conf.default-zones', '/etc/bind/named.conf.root-hints'
    kept = json.dumps([zones, '/etc/bind/rndc.key'])
    assert distro_includes({'distro_includes': kept, 'distro_present': None}) == [zones, '/etc/bind/rndc.key']
    assert distro_includes({'distro_includes': kept}) == [zones, '/etc/bind/rndc.key']       # an older row
    assert distro_includes({'distro_includes': kept, 'distro_present': json.dumps([zones, hints])}) == [zones]
    # gone without a root-hints file to take its place: left out
    assert distro_includes({'distro_includes': kept, 'distro_present': '[]'}) == []
    assert distro_includes({'distro_includes': json.dumps([zones, hints]),
                            'distro_present': json.dumps([hints])}) == [hints]


def test_a_failing_named_checkconf_needs_attention(conn, settings, pair):
    from liteblox import status
    fakes = pair[0]
    real = fakes[1].status
    fakes[1].status = lambda: {**real(), 'bind': True, 'taken_over': True, 'checkconf_ok': False}
    health.check_node(settings, conn, node(conn, 1), background=False)
    found = [p['what'] for p in status.problems(conn, settings) if p['node'] == 'ns1']
    assert any('named-checkconf fails' in w for w in found)
    fakes[1].status = lambda: {**real(), 'bind': True, 'taken_over': True, 'checkconf_ok': True}
    health.check_node(settings, conn, node(conn, 1), background=False)
    assert not [p for p in status.problems(conn, settings) if 'named-checkconf' in p['what']]
