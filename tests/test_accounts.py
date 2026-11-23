from fastapi.testclient import TestClient

from liteblox import auth
from liteblox.db import audit

from conftest import csrf_from


def login_as(app, username, password):
    c = TestClient(app)
    t = csrf_from(c.get('/login').text)
    assert c.post('/login', data={'username': username, 'password': password, 'csrf_token': t},
                  follow_redirects=False).status_code == 303
    return c, csrf_from(c.get('/account').text)


def test_readonly_sees_only_their_account(app, conn):
    auth.create_user(conn, 'viewer', 'viewer-password', 'readonly')
    c, t = login_as(app, 'viewer', 'viewer-password')
    assert c.get('/users').status_code == 403 and c.get('/audit').status_code == 403
    assert c.post('/users', data={'username': 'x', 'password': 'p' * 8, 'password2': 'p' * 8,
                                  'csrf_token': t}).status_code == 403
    page = c.get('/account').text
    assert 'Change your password' in page and 'href="/users"' not in page


def test_add_change_reset_delete(app, conn):
    auth.create_user(conn, 'root', 'root-password', 'admin')
    c, t = login_as(app, 'root', 'root-password')
    assert 'href="/users"' in c.get('/').text

    r = c.post('/users', data={'username': 'Bob', 'password': 'bob-password', 'password2': 'bob-passw0rd',
                               'csrf_token': t})
    assert r.status_code == 400 and "don&#39;t match" in r.text and 'value="bob"' in r.text
    r = c.post('/users', data={'username': 'Bob', 'password': 'bob-password', 'password2': 'bob-password',
                               'csrf_token': t})
    assert 'Added bob' in r.text and '<strong>bob</strong>' in r.text
    assert auth.authenticate(conn, 'bob', 'bob-password').role == 'readonly'

    bob, _ = login_as(app, 'bob', 'bob-password')
    assert 'bob is now admin' in c.post('/users/bob/role', data={'role': 'admin', 'csrf_token': t}).text
    assert 'href="/users"' in bob.get('/').text                      # role applies on the next request

    c.post('/users/bob/password', data={'password': 'reset-password', 'password2': 'reset-password',
                                        'csrf_token': t})
    assert bob.get('/', follow_redirects=False).status_code == 303   # bob's session was logged out
    assert auth.authenticate(conn, 'bob', 'reset-password')

    r = c.post('/users/root/delete', data={'csrf_token': t})
    assert r.status_code == 400 and "can&#39;t delete your own account" in r.text
    assert 'Deleted bob' in c.post('/users/bob/delete', data={'csrf_token': t}).text
    r = c.post('/users/root/role', data={'role': 'readonly', 'csrf_token': t})
    assert r.status_code == 400 and 'only admin' in r.text

    actions = [row[0] for row in conn.execute("SELECT action FROM audit WHERE username = 'root' ORDER BY id")]
    assert actions == ['login', 'user_add', 'user_role', 'user_password_reset', 'user_delete']


def test_change_own_password(app, conn):
    auth.create_user(conn, 'root', 'root-password', 'admin')
    c, t = login_as(app, 'root', 'root-password')
    other, _ = login_as(app, 'root', 'root-password')

    r = c.post('/account/password', data={'current': 'wrong-password', 'password': 'new-password',
                                          'password2': 'new-password', 'csrf_token': t})
    assert r.status_code == 400 and 'current password is not right' in r.text
    r = c.post('/account/password', data={'current': 'root-password', 'password': 'short',
                                          'password2': 'short', 'csrf_token': t})
    assert r.status_code == 400 and 'at least 8' in r.text

    r = c.post('/account/password', data={'current': 'root-password', 'password': 'new-password',
                                          'password2': 'new-password', 'csrf_token': t})
    assert 'Password changed' in r.text
    assert c.get('/', follow_redirects=False).status_code == 200      # still logged in here
    assert other.get('/', follow_redirects=False).status_code == 303  # but not elsewhere
    assert auth.authenticate(conn, 'root', 'new-password')
    # your own password is never reset from the Users page
    assert c.post('/users/root/password', data={'password': 'x' * 8, 'password2': 'x' * 8, 'csrf_token': t},
                  follow_redirects=False).headers['location'] == '/account'


def test_audit_filters_and_paging(app, conn, monkeypatch):
    from liteblox import accounts
    auth.create_user(conn, 'root', 'root-password', 'admin')
    c, _ = login_as(app, 'root', 'root-password')
    for i in range(5):
        audit(conn, 'alice', 'zone_edit', f'zone{i}.lab 50%_off' if i == 3 else f'zone{i}.lab')
    audit(conn, 'bob', 'node_add', 'ns9')

    page = c.get('/audit').text
    assert 'zone4.lab' in page and 'ns9' in page and '<option>alice</option>' in page
    page = c.get('/audit', params={'who': 'bob'}).text
    assert 'ns9' in page and 'zone4.lab' not in page
    page = c.get('/audit', params={'action': 'zone_edit', 'q': '50%_'}).text
    assert 'zone3.lab' in page and 'zone2.lab' not in page            # % and _ are literal
    assert 'Nothing recorded that matches' in c.get('/audit', params={'q': 'nope'}).text

    monkeypatch.setattr(accounts, 'AUDIT_PAGE', 2)
    page = c.get('/audit', params={'who': 'alice'}).text
    assert 'zone4.lab' in page and 'zone3.lab' in page and 'zone2.lab' not in page and 'Older' in page
    before = page.split('before=')[1].split('"')[0]
    page = c.get('/audit', params={'who': 'alice', 'before': before}).text
    assert 'zone2.lab' in page and 'zone4.lab' not in page
