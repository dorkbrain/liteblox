"""The Dashboard: the first steps, tiles, services, pools from the samples, problems, the API and the dot."""

import pytest

from liteblox.dhcp import store
from liteblox.pki import PKI

from test_dhcp_ha import both_dhcp, paired_lab  # noqa: F401 (fixtures)
from test_managed import lab  # noqa: F401 (fixture)


def lease(ip, subnet_id=1, state=0):
    return {'ip-address': ip, 'hw-address': 'aa:bb:cc:dd:ee:01', 'subnet-id': subnet_id, 'state': state,
            'cltt': 1_000_000_000, 'valid-lft': 3600, 'hostname': ''}


@pytest.fixture
def admin(client, make_user, login):
    make_user()
    login('alice', 'correct-horse')
    return client


def test_an_empty_instance_shows_the_first_steps(admin, conn):
    assert 'What will this LiteBlox run?' in admin.get('/').text      # until the modules are chosen
    with conn:
        conn.execute("UPDATE modules SET chosen_at = datetime('now')")
    page = admin.get('/').text
    assert 'Getting started' in page and 'href="/nodes/new">Add a BIND node' in page
    assert 'class="tiles"' not in page


@pytest.fixture
def pair(conn, settings, paired_lab):  # noqa: F811
    store.set_pair(conn, PKI(settings.pki_dir), 1, 2, '198.51.100.53', '198.51.100.54', 8001)
    with conn:
        conn.execute("UPDATE nodes SET dhcp_ha_state = 'hot-standby', last_seen_at = datetime('now')")
    return paired_lab


def tile(page, key):
    part = page[page.index(f'data-tile="{key}"'):]
    return part[:part.index('</a>')]


def test_the_tiles_and_services(admin, conn, pair):
    page = admin.get('/').text
    assert 'Setup' not in page or 'Make one node the primary' in page      # no primary in this lab yet
    assert '2 / 2' in tile(page, 'nodes') and 'no primary' in tile(page, 'nodes')
    assert 'no lease counts yet' in tile(page, 'dhcp') and 'pair hot-standby' in tile(page, 'dhcp')
    services = page[page.index('<table class="matrix">'):]
    assert services.count('title="hot-standby"') == 2 and services.count('>DHCP</span>') == 2
    assert '<span class="pill ready" title="hot-standby">primary</span>' in services
    assert '<span class="pill " title="hot-standby">standby</span>' in services
    assert '<th>DNS</th>' in services and '<th>Zones</th>' not in services


def test_no_subnet_served_yet(admin, conn, pair):
    with conn:
        conn.execute("UPDATE nodes SET dhcp_interfaces = '[]'")
    assert 'no subnet served yet' in tile(admin.get('/').text, 'dhcp')


def test_pools_from_the_samples(admin, conn, settings, pair):
    from liteblox.nodes import health
    # a declined address (a client found it in use) is held back, so it's taken in the pool, but not a lease
    declined = {**lease('198.51.100.170', state=1), 'hw-address': ''}
    pair[1].kea_leases = [lease('198.51.100.100'), lease('198.51.100.150'), lease('198.51.100.20'),
                          lease('198.51.100.160', state=2), declined]
    health.check_all(settings, print)
    page = admin.get('/').text
    pools = page[page.index('DHCP pools'):]
    assert '3 / 100' in pools and '1 outside the pools' in pools and 'aria-valuenow="3"' in pools
    assert '>3</span>' in tile(page, 'dhcp') and '3 of 100 in the pools' in tile(page, 'dhcp')


def test_the_health_check_reads_the_standby_when_the_primary_does_not_answer(conn, settings, pair):
    from liteblox import stats
    from liteblox.nodes import health
    pair[1].kea_running['dhcp4'] = False
    pair[2].kea_leases = [lease('198.51.100.100')]
    health.check_all(settings, print)
    assert stats.latest(conn, 'leases_in_pool', subnet_id=1) == 1.0


def test_reservations_are_counted(admin, conn, pair):
    from liteblox.dhcp.model import Reservation
    store.save_reservation(conn, Reservation(None, 1, 'aa:bb:cc:dd:ee:09', '198.51.100.9'))
    assert '1 reservation ' in admin.get('/').text.replace('1 reservation<', '1 reservation <')


def test_problems_show_with_their_page(admin, conn, lab):  # noqa: F811
    with conn:
        conn.execute("UPDATE nodes SET clock_skew = 45, last_seen_at = datetime('now') WHERE name = 'ns1'")
        conn.execute("UPDATE nodes SET dhcp = 1, dhcp_ha_state = 'terminated', last_seen_at = datetime('now') "
                     "WHERE name = 'ns2'")
    page = admin.get('/').text
    attention = page[page.index('id="attention"'):page.index('Services')]
    assert "ns1&#39;s clock is +45 s" in attention and 'ns2: DHCP failover is terminated' in attention
    assert 'href="/dhcp"' in attention


def test_a_viewer_sees_it_without_the_actions(client, make_user, login, conn, pair):
    make_user('viewer', 'correct-horse', 'readonly')
    login('viewer', 'correct-horse')
    page = client.get('/').text
    assert 'class="tiles"' in page and 'Quick actions' not in page and '>read-only</span>' in page
    assert 'href="/settings/time"' not in page
    body = client.get('/dashboard/body')
    assert body.status_code == 200 and '<html' not in body.text and 'class="tiles"' in body.text


def test_the_top_bar_dot(admin, conn, lab, monkeypatch):  # noqa: F811
    from liteblox import status
    monkeypatch.setattr(status, 'CACHE_FOR', 0)
    with conn:
        conn.execute("UPDATE nodes SET status = 'error', last_seen_at = datetime('now')")
    page = admin.get('/zones').text
    assert 'class="dot error" id="health-dot"' in page and 'need attention' in page


def test_the_status_api(client, conn, lab):  # noqa: F811
    from liteblox import auth
    from liteblox.api import tokens
    auth.create_user(conn, 'bob', 'correct-horse', 'readonly')
    secret = tokens.create(conn, 'bob', 'mon', 'read', 'test')[1]
    with conn:
        conn.execute("UPDATE nodes SET clock_skew = 45, last_seen_at = datetime('now')")
    got = client.get('/api/v1/status', headers={'Authorization': f'Bearer {secret}'}).json()
    assert got['level'] == 'warn' and got['attention'] >= 2
    assert {'severity': 'warn', 'area': 'time', 'node': 'ns1', 'link': '/nodes/1',
            'what': "ns1's clock is +45 s from LiteBlox's (signed updates fail at 300 s)"} in got['problems']
    assert [t['key'] for t in got['tiles']] == ['nodes', 'dns', 'dhcp', 'time', 'ipam', 'attention']
    assert client.get('/api/v1/status').status_code == 401


def test_the_sparkline_macro():
    from liteblox import stats
    from liteblox.templating import templates
    macro = templates.env.get_template('partials/charts.html').module.sparkline
    assert 'no history yet' in str(macro(stats.spark([])))
    assert 'no history yet' in str(macro(stats.spark([(T, 1.0)], now=T)))
    svg = str(macro(stats.spark([(T - 120, 1.0), (T - 60, 3.0), (T, 2.0)], now=T), 'q'))
    assert svg.startswith('<svg class="spark"') and 'peak 3' in svg and svg.count('<path') == 2


T = 1_800_000_000


def test_the_health_check_samples_active_leases(conn, settings, pair):
    from liteblox import stats
    from liteblox.nodes import health
    pair[1].kea_leases = [lease('198.51.100.100'), lease('198.51.100.20'), lease('198.51.100.160', state=2)]
    health.check_all(settings, print)
    assert [v for _, v in stats.series(conn, 'leases_active', subnet_id=1)] == [2.0]   # the pair counted once
    # neither server answers: no sample (rather than a false 0)
    pair[1].kea_running['dhcp4'] = pair[2].kea_running['dhcp4'] = False
    health.check_all(settings, print)
    assert len(stats.series(conn, 'leases_active', subnet_id=1)) == 1


def test_a_node_that_does_not_answer_shows_no_old_values(admin, conn, settings, pair):
    import time
    from liteblox import stats
    with conn:
        conn.execute("UPDATE nodes SET status = 'error', clock_skew = 2, dhcp_ha_state = 'hot-standby' WHERE id = 1")
        conn.execute("UPDATE nodes SET dhcp_ha_state = 'partner-down' WHERE id = 2")
    with conn:
        for metric, value in (('load1', 0.5), ('mem_used_pct', 40), ('disk_used_pct', 10)):
            stats._add(conn, metric, value, int(time.time()), node_id=1)
    page = admin.get('/').text
    row = page[page.index('">ns1</a>'):]
    row = row[:row.index('</tr>')]
    assert 'unknown' in row and 'hot-standby' not in row and '0.50' not in row and '+2 s' not in row
    assert 'pair partner-down' in tile(page, 'dhcp')         # not "hot-standby, partner-down"


def test_kea_not_listening_shows_on_the_dashboard(admin, conn, pair):
    with conn:
        conn.execute("UPDATE nodes SET dhcp_sockets = '{\"status\": \"failed\", \"errors\": [\"the interface ens19 is "
                     "not running\"]}' WHERE id = 1")
    page = admin.get('/').text
    assert "ns1: Kea isn&#39;t serving DHCP (the interface ens19 is not running)" in page
    assert 'class="pill error" title="not listening: the interface ens19 is not running">primary</span>' in page


def test_role_shows_each_nodes_modules(admin, conn, pair):
    from liteblox.ipam import model
    with conn:
        conn.execute("UPDATE nodes SET ntp = 1 WHERE id = 1")
        conn.execute("UPDATE nodes SET dhcp = 0, networks = '[\"198.51.100.0/24\"]' WHERE id = 2")
    model.add_network(conn, '198.51.100.0/24', sweep='hourly', sweep_node_id=2)
    services = admin.get('/').text
    services = services[services.index('<table class="matrix">'):]
    ns1 = services[services.index('">ns1</a>'):]
    ns1 = ns1[:ns1.index('</tr>')]
    ns2 = services[services.index('">ns2</a>'):]
    ns2 = ns2[:ns2.index('</tr>')]
    assert '>DNS</span> <span class="pill">DHCP</span> <span class="pill">NTP</span>' in ns1 and 'IPAM' not in ns1
    assert 'title="IPAM sweeps and checks 198.51.100.0/24 from here">IPAM</span>' in ns2 and '>DHCP</span>' not in ns2
    with conn:
        conn.execute("UPDATE nodes SET bind = 0, dhcp = 0, ntp = 0 WHERE id = 1")
    assert 'agent only' in admin.get('/').text
