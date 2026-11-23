"""The Jobs page, the audit log's labels and sign-ins toggle, and the relative-time filter."""

from datetime import datetime, timezone

import pytest

from liteblox import activity, db, timefmt
from liteblox.nodes import routes as node_routes

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def admin(make_user, login):
    login(*make_user('alice'))


def add_job(conn, kind, status='ok', node_id=None, log='', created='2026-11-01 10:00:00', finished='2026-11-01 10:01:05'):
    with conn:
        return conn.execute('INSERT INTO jobs (kind, node_id, username, status, log, created_at, finished_at) '
                            "VALUES (?, ?, 'alice', ?, ?, ?, ?)", (kind, node_id, status, log, created, finished)).lastrowid


@pytest.fixture
def nodes(conn):
    with conn:
        for name in ('ns1', 'ns2'):
            conn.execute("INSERT INTO nodes (name, host, host_key, host_key_fp) VALUES (?, '192.0.2.1', 'k', 'f')", (name,))


def job_ids(html):
    import re
    return [int(n) for n in re.findall(r'<a href="/jobs/(\d+)">', html)]


def test_reltime_puts_the_full_time_in_a_tooltip():
    html = str(timefmt.reltime('2026-11-01 11:55:00', NOW))
    assert html.startswith('<time datetime="2026-11-01T11:55:00+00:00" title="')
    assert html.endswith('>5 min ago</time>')
    assert timefmt.reltime(None) == '' and timefmt.reltime('') == ''
    assert str(timefmt.reltime('<not a time>')) == '&lt;not a time&gt;'


def test_job_labels():
    assert [activity.job_label(k) for k in ('bootstrap', 'bind config', 'tsig key', 'dhcp config', 'Re-adopt', '')] == \
        ['Bootstrap', 'BIND config', 'TSIG key', 'DHCP config', 'Re-adopt', '']


def test_took():
    assert node_routes._took({'created_at': '2026-11-01 10:00:00', 'finished_at': '2026-11-01 10:00:42'}) == '42 s'
    assert node_routes._took({'created_at': '2026-11-01 10:00:00', 'finished_at': '2026-11-01 10:02:05'}) == '2 min 5 s'
    assert node_routes._took({'created_at': '2026-11-01 10:00:00', 'finished_at': None}) == ''


def test_jobs_page_filters(client, conn, admin, nodes):
    boot = add_job(conn, 'bootstrap', node_id=1)
    failed = add_job(conn, 'bind config', status='failed', node_id=2)
    warned = add_job(conn, 'publish', log='✓ ns1\n⚠ ns2 answered late')
    running = add_job(conn, 'promote', status='running', node_id=2, finished=None)
    page = client.get('/jobs').text
    assert job_ids(page) == [running, warned, failed, boot]
    assert 'BIND config' in page and '1 min 5 s' in page and 'warnings' in page
    assert job_ids(client.get('/jobs?status=failed').text) == [failed]
    assert job_ids(client.get('/jobs?kind=bootstrap').text) == [boot]
    assert job_ids(client.get('/jobs?node=ns2').text) == [running, failed]
    assert job_ids(client.get('/jobs?node=ns2&status=running').text) == [running]
    assert 'No jobs' in client.get('/jobs?kind=reconcile').text


def test_jobs_page_pages_by_id(client, conn, admin, monkeypatch):
    monkeypatch.setattr(node_routes, 'JOBS_PAGE', 2)
    ids = [add_job(conn, 'publish') for _ in range(5)]
    first = client.get('/jobs?kind=publish').text
    assert job_ids(first) == [ids[4], ids[3]]
    assert f'href="/jobs?kind=publish&status=&node=&before={ids[3]}"' in first
    assert job_ids(client.get(f'/jobs?kind=publish&before={ids[1]}').text) == [ids[0]]


def test_job_page_has_a_breadcrumb(client, conn, admin, nodes):
    job = add_job(conn, 'bind config', node_id=1)
    page = client.get(f'/jobs/{job}').text
    assert f'<a href="/jobs">Jobs</a> · #{job} BIND config' in page
    assert f'<title>#{job} BIND config · Jobs · LiteBlox</title>' in page


def test_node_page_links_its_jobs(client, conn, admin, nodes):
    add_job(conn, 'bootstrap', node_id=1)
    page = client.get('/nodes/1').text
    assert 'href="/jobs?node=ns1"' in page and 'Bootstrap</a>' in page
    assert 'href="/jobs"' in client.get('/nodes').text


def test_audit_hides_sign_ins_unless_asked(client, conn, admin):
    db.audit(conn, 'alice', 'zone_create', 'a.lab')
    db.audit(conn, 'mallory', 'login_failed', None)
    page = client.get('/audit').text
    assert 'Created a zone' in page and '<code class="muted small nowrap">zone_create</code>' in page
    assert 'mallory' not in page.split('<tbody>')[1]
    shown = client.get('/audit?logins=1').text.split('<tbody>')[1]
    assert 'mallory' in shown and 'Created a zone' in shown
    assert 'mallory' in client.get('/audit?action=login_failed').text.split('<tbody>')[1]
    # the dropdown shows labels and sends codes
    assert '<option value="zone_create">Created a zone</option>' in page


def test_audit_older_link_keeps_the_toggle(client, conn, admin, monkeypatch):
    from liteblox import accounts
    monkeypatch.setattr(accounts, 'AUDIT_PAGE', 1)
    db.audit(conn, 'alice', 'zone_create', 'a.lab')
    db.audit(conn, 'alice', 'zone_delete', 'a.lab')
    assert '&logins=1&before=' in client.get('/audit?logins=1').text.replace('&amp;', '&')
    assert '&logins=1' not in client.get('/audit').text.replace('&amp;', '&')
