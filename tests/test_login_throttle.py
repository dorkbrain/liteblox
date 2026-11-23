"""Login throttling: per-username and per-address limits on failed logins."""

from fastapi.testclient import TestClient

from liteblox import auth
from liteblox.api import tokens

from conftest import csrf_from


def attempt(client, username, password):
    t = csrf_from(client.get('/login').text)
    return client.post('/login', data={'username': username, 'password': password, 'csrf_token': t},
                       follow_redirects=False)


def actions(conn, action):
    return conn.execute('SELECT username, detail FROM audit WHERE action = ? ORDER BY id', (action,)).fetchall()


def test_sixth_attempt_refused_even_with_the_right_password(client, conn, make_user):
    make_user()
    for _ in range(auth.LOGIN_MAX_PER_USER):
        assert attempt(client, 'alice', 'wrong-password').status_code == 401
    r = attempt(client, 'alice', 'correct-horse')
    assert r.status_code == 429 and 'Too many failed logins; try again in 15 minutes' in r.text
    assert client.get('/', follow_redirects=False).headers['location'].endswith('/login')
    # the address is recorded with each failure
    assert [tuple(row) for row in actions(conn, 'login_failed')] == [('alice', 'testclient')] * 5
    assert actions(conn, 'login') == []


def test_a_success_resets_the_user_count(app, client, conn, make_user):
    make_user()
    for _ in range(auth.LOGIN_MAX_PER_USER - 1):
        attempt(client, 'alice', 'wrong-password')
    assert attempt(client, 'alice', 'correct-horse').status_code == 303
    assert [tuple(row) for row in actions(conn, 'login')] == [('alice', 'testclient')]
    other = TestClient(app)
    for _ in range(auth.LOGIN_MAX_PER_USER - 1):
        assert attempt(other, 'alice', 'wrong-password').status_code == 401
    assert attempt(other, 'alice', 'correct-horse').status_code == 303


def test_per_address_limit_across_usernames(client, conn, make_user):
    make_user()
    for i in range(auth.LOGIN_MAX_PER_ADDRESS):
        assert attempt(client, f'user{i}', 'wrong-password').status_code == 401
    # alice herself has no failures, but this address is used up
    r = attempt(client, 'alice', 'correct-horse')
    assert r.status_code == 429 and 'Too many failed logins' in r.text
    # other addresses aren't affected
    conn.execute("UPDATE audit SET detail = '192.0.2.9' WHERE action = 'login_failed'")
    conn.commit()
    assert attempt(client, 'alice', 'correct-horse').status_code == 303


def test_the_window_expires(client, conn, make_user):
    make_user()
    for _ in range(auth.LOGIN_MAX_PER_USER):
        attempt(client, 'alice', 'wrong-password')
    assert attempt(client, 'alice', 'correct-horse').status_code == 429
    # the oldest failure 14 minutes ago: one more minute to wait
    conn.execute("UPDATE audit SET at = datetime('now', '-14 minutes') WHERE action = 'login_failed'")
    conn.commit()
    assert 'try again in 1 minute<' in attempt(client, 'alice', 'correct-horse').text
    conn.execute("UPDATE audit SET at = datetime('now', '-16 minutes') WHERE action = 'login_failed'")
    conn.commit()
    assert attempt(client, 'alice', 'correct-horse').status_code == 303


def test_login_blocked_written_once_per_lockout(client, conn, make_user):
    make_user()
    for _ in range(auth.LOGIN_MAX_PER_USER):
        attempt(client, 'alice', 'wrong-password')
    for _ in range(3):
        assert attempt(client, 'alice', 'correct-horse').status_code == 429
    assert [tuple(row) for row in actions(conn, 'login_blocked')] == [('alice', 'testclient')]
    # a new lockout after the first one lifts is recorded again
    conn.execute("UPDATE audit SET at = datetime('now', '-16 minutes')")
    conn.commit()
    for _ in range(auth.LOGIN_MAX_PER_USER):
        assert attempt(client, 'alice', 'wrong-password').status_code == 401
    assert attempt(client, 'alice', 'correct-horse').status_code == 429
    assert len(actions(conn, 'login_blocked')) == 2


def test_api_tokens_are_not_throttled(client, conn, make_user):
    make_user()
    for _ in range(auth.LOGIN_MAX_PER_USER):
        attempt(client, 'alice', 'wrong-password')
    assert attempt(client, 'alice', 'correct-horse').status_code == 429
    token = tokens.create(conn, 'alice', 'ci', 'read', 'test')[1]
    assert client.get('/api/v1/zones', headers={'Authorization': 'Bearer ' + token}).status_code == 200
