"""Every page renders for an admin and a viewer on a filled-in instance, and forms end the same way."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route

from liteblox import db, jobs
from liteblox.dhcp import store
from liteblox.dhcp.model import Reservation

from conftest import csrf_from
from test_api import EXAMPLE, zone  # noqa: F401 (fixture)
from test_dhcp_reservations import serve
from test_managed import lab, make_roles  # noqa: F401 (fixtures)

TEMPLATES = Path(__file__).parent.parent / 'liteblox' / 'templates'
PARAMS = {'node_id': '1', 'name': 'example.com', 'subnet_id': '1', 'reservation_id': '1', 'job_id': '1', 'slug': 'dhcp'}
# downloads, one-time reveals, logout and what needs a real git sha or a saved backup file
SKIP = re.compile(r'^/(api|static|healthz|favicon|logout|tokens/reveal|settings/keys/reveal|backups)|/download|/old$|'
                  r'/history/\{sha\}|/deploys/|/reports/|/compare$|/text$|/drift/keep')


@pytest.fixture
def filled(conn, settings, lab, zone):  # noqa: F811
    for fake in lab[0].values():
        fake.files['example.com'] = EXAMPLE
    make_roles(conn)
    serve(conn)
    store.save_reservation(conn, Reservation(None, 1, '52:54:00:12:34:56', '198.51.100.50', 'printer'))
    jobs.start(settings.db_path, 'bind config', lambda log: log('✓ done'), node_id=1, username='alice', background=False)
    db.audit(conn, 'alice', 'zone_create', 'example.com')


@pytest.fixture(params=['ipam', 'dhcp+ipam'])
def modular(request, conn, settings, lab):  # noqa: F811
    """An install without the DNS module: IPAM only (a scanner), or DHCP + IPAM registering at another server."""
    from liteblox.dhcp.model import Dhcp4Settings
    from liteblox.ipam import model as ipam, names
    key = {'name': 'kea', 'algorithm': 'hmac-sha256', 'secret': 'c2VjcmV0c2VjcmV0'}
    dhcp = request.param == 'dhcp+ipam'
    with conn:
        conn.execute('UPDATE nodes SET bind = 0, managed = 0')
        conn.execute("UPDATE modules SET dns = 0, ntp = 0, dhcp = ?, ipam = 1, chosen_at = datetime('now')",
                     (int(dhcp),))
    if dhcp:
        serve(conn)
        store.save_settings(conn, Dhcp4Settings(ddns_mode='external', ddns_server='192.0.2.99',
                                                ddns_external_key=key))
        with conn:
            conn.execute("UPDATE dhcp4_subnets SET ddns = 1, ddns_suffix = 'dhcp.home.lan' WHERE id = 1")
        store.save_reservation(conn, Reservation(None, 1, '52:54:00:12:34:56', '198.51.100.50', 'printer'))
    ipam.add_network(conn, '198.51.100.0/24', 'Lab')
    names.save(conn, '198.51.100.20', 'nas', '52:54:00:12:34:57', 'the NAS', 'alice')
    jobs.start(settings.db_path, 'dhcp', lambda log: log('✓ done'), node_id=1, username='alice', background=False)
    db.audit(conn, 'alice', 'ipam_name', '198.51.100.20')
    return request.param


def routes(items):
    for r in items:
        if isinstance(r, Route):
            yield r
        elif hasattr(r, 'original_router') and not r.include_context.prefix:     # the UI routers (the API has /api/v1)
            yield from routes(r.original_router.routes)


def pages(app):
    for route in routes(app.routes):
        if 'GET' not in route.methods or SKIP.search(route.path):
            continue
        names = re.findall(r'\{(\w+)\}', route.path)
        if all(n in PARAMS for n in names):
            yield re.sub(r'\{(\w+)\}', lambda m: PARAMS[m.group(1)], route.path)


@pytest.mark.parametrize('role', ['admin', 'readonly'])
def test_every_page_renders(app, make_user, login, filled, role):
    client = TestClient(app, raise_server_exceptions=False)
    token = csrf_from(client.get('/login').text)
    username, password = make_user('alice', role=role)
    client.post('/login', data={'username': username, 'password': password, 'csrf_token': token})
    seen = list(pages(app))
    assert len(seen) > 40
    broken = [(p, r.status_code) for p in seen if (r := client.get(p, follow_redirects=False)).status_code >= 500]
    assert broken == [], broken


def test_forms_end_through_the_action_bar():
    """A hand-made Cancel link drifts from the rest (order, style); partials/ui.html's action_bar is the one place."""
    stray = [str(p.relative_to(TEMPLATES)) for p in TEMPLATES.rglob('*.html')
             if p.name != 'ui.html' and re.search(r'>Cancel</a>', p.read_text())]
    assert stray == []


def test_every_page_renders_without_dns(app, make_user, login, modular):
    client = TestClient(app, raise_server_exceptions=False)
    token = csrf_from(client.get('/login').text)
    client.post('/login', data={'username': 'alice', 'password': make_user('alice', role='admin')[1],
                                'csrf_token': token})
    broken = [(p, r.status_code) for p in pages(app) if (r := client.get(p, follow_redirects=False)).status_code >= 500]
    assert broken == [], broken
    assert client.get('/ipam').status_code == 200 and 'nas' in client.get('/ipam/networks/1').text
    assert client.get('/zones').status_code == 404
    assert client.get('/dhcp').status_code == (200 if modular == 'dhcp+ipam' else 404)
