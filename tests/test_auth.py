import pytest

from liteblox import auth


def test_create_user_validation(conn):
    with pytest.raises(auth.AuthError, match='role'):
        auth.create_user(conn, 'bob', 'long-enough', 'superuser')
    with pytest.raises(auth.AuthError, match='at least'):
        auth.create_user(conn, 'bob', 'short')
    with pytest.raises(auth.AuthError, match='username'):
        auth.create_user(conn, 'Bob Smith', 'long-enough')

    auth.create_user(conn, 'bob', 'long-enough')
    with pytest.raises(auth.AuthError, match='already exists'):
        auth.create_user(conn, 'bob', 'long-enough')


def test_passwords_are_hashed(conn):
    auth.create_user(conn, 'bob', 'long-enough')
    stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith('$argon2') and 'long-enough' not in stored


def test_password_and_role_changes(conn):
    auth.create_user(conn, 'bob', 'first-password', 'readonly')
    auth.set_password(conn, 'bob', 'second-password')
    assert auth.authenticate(conn, 'bob', 'first-password') is None
    assert auth.authenticate(conn, 'bob', 'second-password') == auth.User('bob', 'readonly', epoch=1)

    auth.set_role(conn, 'bob', 'admin')
    assert auth.authenticate(conn, 'bob', 'second-password').is_admin

    with pytest.raises(auth.AuthError, match='no such user'):
        auth.set_password(conn, 'nobody', 'whatever-pass')


def test_the_last_admin_stays(conn):
    auth.create_user(conn, 'root', 'root-password', 'admin')
    with pytest.raises(auth.AuthError, match='only admin'):
        auth.set_role(conn, 'root', 'readonly')
    with pytest.raises(auth.AuthError, match='only admin'):
        auth.delete_user(conn, 'root')
    auth.create_user(conn, 'second', 'second-password', 'admin')
    auth.set_role(conn, 'root', 'readonly')
    with pytest.raises(auth.AuthError, match='second is the only admin'):
        auth.delete_user(conn, 'second')
    auth.delete_user(conn, 'root')
    with pytest.raises(auth.AuthError, match='no such user'):
        auth.delete_user(conn, 'root')


def test_check_password(conn):
    auth.create_user(conn, 'bob', 'first-password', 'readonly')
    assert auth.check_password(conn, 'bob', 'first-password')
    assert not auth.check_password(conn, 'bob', 'wrong-password')
    assert not auth.check_password(conn, 'nobody', 'first-password')
    assert conn.execute("SELECT last_login_at FROM users").fetchone()[0] is None
