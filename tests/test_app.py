import pytest
from fastapi import Depends

from liteblox import auth, db
from liteblox.main import create_app
from liteblox.version import __version__

from conftest import csrf_from


def test_healthz_reports_version(client):
    r = client.get('/healthz')
    assert r.status_code == 200
    assert r.json() == {'status': 'ok', 'version': __version__}


def test_first_run_creates_config_secret_and_schema(settings, app):
    assert settings.config_file.exists()
    assert settings.secret_file.stat().st_mode & 0o777 == 0o600
    assert settings.db_path.stat().st_mode & 0o777 == 0o600
    assert db.migrate(settings.db_path) == len(db.MIGRATIONS)  # idempotent


def test_dashboard_requires_login(client):
    r = client.get('/', follow_redirects=False)
    assert r.status_code == 303
    assert r.headers['location'] == '/login'


def test_htmx_requests_get_hx_redirect(client):
    r = client.get('/', headers={'HX-Request': 'true'}, follow_redirects=False)
    assert r.status_code == 204
    assert r.headers['HX-Redirect'] == '/login'


def test_login_page_hints_when_no_users(client):
    assert 'No accounts yet' in client.get('/login').text


def test_login_success_and_logout(client, make_user, login):
    username, password = make_user()
    r = login(username, password)
    assert r.status_code == 303 and r.headers['location'] == '/'

    page = client.get('/')
    assert page.status_code == 200
    assert username in page.text

    r = client.post('/logout', data={'csrf_token': csrf_from(page.text)}, follow_redirects=False)
    assert r.headers['location'] == '/login'
    assert client.get('/', follow_redirects=False).status_code == 303


def test_login_wrong_password(client, make_user, login, conn):
    username, _ = make_user()
    r = login(username, 'wrong-password')
    assert r.status_code == 401
    assert 'Invalid username or password' in r.text
    assert conn.execute("SELECT action FROM audit").fetchall()[-1]['action'] == 'login_failed'


def test_login_unknown_user(client, make_user, login):
    make_user()
    assert login('nobody', 'whatever-pass').status_code == 401


def test_post_without_csrf_is_rejected(client, make_user, login):
    login(*make_user())
    assert client.post('/logout').status_code == 403
    assert client.post('/logout', data={'csrf_token': 'forged'}).status_code == 403


def test_deleted_user_session_is_dropped(client, make_user, login, conn):
    make_user('keeper', 'keeper-password', 'admin')
    username, password = make_user()
    login(username, password)
    auth.delete_user(conn, username)
    assert client.get('/', follow_redirects=False).status_code == 303


def test_password_change_logs_out_other_sessions(client, make_user, login, conn):
    username, password = make_user()
    login(username, password)
    assert client.get('/', follow_redirects=False).status_code == 200
    auth.set_password(conn, username, 'a-new-password')
    assert client.get('/', follow_redirects=False).status_code == 303


def test_require_admin(app, client, make_user, login):
    @app.get('/admin-only')
    def admin_only(user=Depends(auth.require_admin)):
        return {'ok': True}

    login(*make_user('reader', 'reader-pass', 'readonly'))
    assert client.get('/admin-only').status_code == 403

    client.cookies.clear()
    login(*make_user('boss', 'boss-pass1', 'admin'))
    assert client.get('/admin-only').json() == {'ok': True}


def test_confirmations_use_the_dialog():
    """Every confirmation goes through the HTML dialog in base.html, never the browser's confirm()."""
    from pathlib import Path
    root = Path(__file__).parents[1] / 'liteblox'
    for tpl in (root / 'templates').rglob('*.html'):
        assert 'confirm(' not in tpl.read_text(), tpl.name
    base = (root / 'templates' / 'base.html').read_text()
    assert 'id="confirm-dialog"' in base and "asset('app.js')" in base


def test_a_database_from_a_newer_liteblox_stops_the_start(settings, monkeypatch, capsys):
    from liteblox import cli
    db.migrate(settings.db_path)
    conn = db.connect(settings.db_path)
    conn.execute(f'PRAGMA user_version = {len(db.MIGRATIONS) + 1}')
    conn.close()
    with pytest.raises(db.SchemaTooNew, match=f'schema v{len(db.MIGRATIONS) + 1}, written by a newer LiteBlox'):
        db.migrate(settings.db_path)
    with pytest.raises(db.SchemaTooNew):
        create_app(settings)
    monkeypatch.setenv('LITEBLOX_DATA', str(settings.data_dir))
    monkeypatch.setenv('LITEBLOX_BACKUPS', str(settings.backups_dir))
    monkeypatch.setattr('uvicorn.run', lambda *a, **k: pytest.fail('started anyway'))
    assert cli.main(['serve']) == 1 and cli.main(['check']) == 1
    err = capsys.readouterr().err
    assert err.startswith('ERROR: the database') and 'restore the copy of the data from before the upgrade' in err
