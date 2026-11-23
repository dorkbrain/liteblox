import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from liteblox import auth, db
from liteblox.config import load_settings
from liteblox.main import create_app


@pytest.fixture
def settings(tmp_path):
    return load_settings(tmp_path / 'data', tmp_path / 'backups')


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def conn(app, settings):
    c = db.connect(settings.db_path)
    yield c
    c.close()


@pytest.fixture
def client(app):
    return TestClient(app)


def csrf_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture
def make_user(conn):
    def _make(username='alice', password='correct-horse', role='admin'):
        auth.create_user(conn, username, password, role)
        return username, password
    return _make


@pytest.fixture
def login(client):
    def _login(username, password):
        token = csrf_from(client.get('/login').text)
        return client.post('/login', data={'username': username, 'password': password,
                                           'csrf_token': token}, follow_redirects=False)
    return _login


PRIVATE_ZONES = Path(__file__).parent / 'fixtures' / 'private'


def private_zone_params():
    """pytest params (path, origin) for the real zone files in fixtures/private (gitignored), named
    db.<origin>: db.example.net, or db.192.168.1 for 1.168.192.in-addr.arpa. One skipped param when
    there are none, so no zone name lives in the tests."""
    params = []
    for path in sorted(PRIVATE_ZONES.glob('db.*')):
        name = path.name[3:]
        parts = name.split('.')
        if all(p.isdigit() for p in parts) and len(parts) <= 3:
            origin = '.'.join(reversed(parts)) + '.in-addr.arpa.'
        else:
            origin = name.rstrip('.') + '.'
        params.append(pytest.param(path, origin, id=path.name))
    return params or [pytest.param(None, None, id='none', marks=pytest.mark.skip(reason='no private fixtures'))]
