"""Local accounts: argon2 password hashes, session login, roles, CSRF."""

import re
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request

from .db import audit, get_db

ROLES = ('admin', 'readonly')
USERNAME_RE = re.compile(r'[a-z_][a-z0-9_.-]{0,31}')
MIN_PASSWORD = 8
SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}
# failed logins counted over the last LOGIN_WINDOW minutes before a password is even checked
LOGIN_WINDOW = 15
LOGIN_MAX_PER_USER = 5          # failures since that user's last successful login
LOGIN_MAX_PER_ADDRESS = 20      # across usernames, so spraying many names is slowed too

_hasher = PasswordHasher()
# verified against when the username doesn't exist, so a miss costs the same as a wrong password
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))


class AuthError(ValueError):
    pass


class LoginRequired(Exception):
    """Raised by current_user; the app turns it into a redirect to /login."""


@dataclass(frozen=True)
class User:
    username: str
    role: str
    epoch: int = 0          # the account's session_epoch when this session logged in

    @property
    def is_admin(self):
        return self.role == 'admin'


# ── Account management (CLI and the Users page) ────────────────────────────────

def _check_role(role):
    if role not in ROLES:
        raise AuthError(f"role must be one of: {', '.join(ROLES)}")


def _check_password(password):
    if len(password) < MIN_PASSWORD:
        raise AuthError(f'password must be at least {MIN_PASSWORD} characters')


def create_user(conn, username, password, role='admin'):
    if not USERNAME_RE.fullmatch(username):
        raise AuthError('username must be lowercase letters, digits, _ . - (max 32)')
    _check_role(role)
    _check_password(password)
    if conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
        raise AuthError(f'user {username} already exists')
    with conn:
        conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                     (username, _hasher.hash(password), role))


def set_password(conn, username, password):
    """New password; the account's existing sessions stop working (see current_user)."""
    _check_password(password)
    with conn:
        cur = conn.execute('UPDATE users SET password_hash = ?, session_epoch = session_epoch + 1 '
                           'WHERE username = ?', (_hasher.hash(password), username))
    if cur.rowcount == 0:
        raise AuthError(f'no such user: {username}')


def _last_admin(conn, username):
    row = conn.execute('SELECT role FROM users WHERE username = ?', (username,)).fetchone()
    if row is None:
        raise AuthError(f'no such user: {username}')
    admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
    return row['role'] == 'admin' and admins == 1


def set_role(conn, username, role):
    _check_role(role)
    if role != 'admin' and _last_admin(conn, username):
        raise AuthError(f'{username} is the only admin; make someone else admin first')
    with conn:
        cur = conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
    if cur.rowcount == 0:
        raise AuthError(f'no such user: {username}')


def delete_user(conn, username):
    if _last_admin(conn, username):
        raise AuthError(f'{username} is the only admin; make someone else admin first')
    with conn:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))


def check_password(conn, username, password):
    """True when password is the user's current one (no side effects, unlike authenticate)."""
    row = conn.execute('SELECT password_hash FROM users WHERE username = ?', (username,)).fetchone()
    try:
        return _hasher.verify(row['password_hash'] if row else _DUMMY_HASH, password) and row is not None
    except (VerificationError, InvalidHashError):
        return False


def list_users(conn):
    return conn.execute(
        'SELECT username, role, created_at, last_login_at FROM users ORDER BY username'
    ).fetchall()


def user_count(conn):
    return conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]


def authenticate(conn, username, password):
    """Return a User for valid credentials, else None."""
    row = conn.execute('SELECT username, password_hash, role, session_epoch FROM users WHERE username = ?',
                       (username,)).fetchone()
    try:
        _hasher.verify(row['password_hash'] if row else _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return None
    if row is None:
        return None

    with conn:
        if _hasher.check_needs_rehash(row['password_hash']):
            conn.execute('UPDATE users SET password_hash = ? WHERE username = ?',
                         (_hasher.hash(password), username))
        conn.execute("UPDATE users SET last_login_at = datetime('now') WHERE username = ?",
                     (username,))
    return User(row['username'], row['role'], row['session_epoch'])


# ── Login throttling ───────────────────────────────────────────────────────────

def _lockout(conn, where, args, limit):
    """(seconds left, newest counted failure id) when `limit` failures match, else None."""
    rows = conn.execute(
        "SELECT id, CAST((julianday(at, ?) - julianday('now')) * 86400 AS INTEGER) AS secs "
        f"FROM audit WHERE action = 'login_failed' AND at > datetime('now', ?) AND {where} "
        'ORDER BY id DESC LIMIT ?',
        (f'+{LOGIN_WINDOW} minutes', f'-{LOGIN_WINDOW} minutes', *args, limit)).fetchall()
    if len(rows) < limit:
        return None
    # it lifts when the limit-th newest failure leaves the window
    return rows[-1]['secs'], rows[0]['id']


def login_throttled(conn, username, address):
    """Minutes until username may try a password from address again, or 0.

    Records one login_blocked per lockout. Those rows aren't counted, so refused
    attempts can't stretch a lockout out."""
    since_login = "COALESCE((SELECT MAX(id) FROM audit WHERE action = 'login' AND username = ?), 0)"
    lock = _lockout(conn, f'username = ? AND id > {since_login}', (username, username), LOGIN_MAX_PER_USER)
    seen = 'username = ?', username
    if lock is None:
        lock = _lockout(conn, 'detail = ?', (address,), LOGIN_MAX_PER_ADDRESS)
        seen = 'detail = ?', address
    if lock is None:
        return 0
    left, last_failure = lock
    if not conn.execute(f"SELECT 1 FROM audit WHERE action = 'login_blocked' AND id > ? AND {seen[0]}",
                        (last_failure, seen[1])).fetchone():
        audit(conn, username, 'login_blocked', address)
    return max(1, -(-left // 60))


# ── Sessions ───────────────────────────────────────────────────────────────────

def login_session(request, user):
    # fresh session on login so a pre-login session id/token can't be reused
    request.session.clear()
    request.session['user'] = user.username
    request.session['epoch'] = user.epoch
    request.session['csrf'] = secrets.token_urlsafe(32)


def logout_session(request):
    request.session.clear()


def current_user(request: Request, conn=Depends(get_db)):
    username = request.session.get('user')
    if not username:
        raise LoginRequired()
    # re-read every request so deleted users, role changes and password changes apply immediately
    row = conn.execute('SELECT username, role, session_epoch FROM users WHERE username = ?', (username,)).fetchone()
    if row is None or request.session.get('epoch', 0) != row['session_epoch']:
        request.session.clear()
        raise LoginRequired()
    return User(row['username'], row['role'], row['session_epoch'])


def optional_user(request: Request, conn=Depends(get_db)):
    """The logged-in user, or None (for pages anyone may read, like /help)."""
    try:
        return current_user(request, conn)
    except LoginRequired:
        return None


def require_admin(user: User = Depends(current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail='admin role required')
    return user


# ── CSRF ───────────────────────────────────────────────────────────────────────

def csrf_token(request):
    token = request.session.get('csrf')
    if not token:
        token = request.session['csrf'] = secrets.token_urlsafe(32)
    return token


async def verify_csrf(request: Request):
    """App-wide dependency: unsafe methods need the session's token in a header or form field."""
    if request.method in SAFE_METHODS:
        return
    if request.url.path.startswith('/api/v1/'):
        return      # the API takes only bearer tokens, never the session cookie: nothing to forge
    sent = request.headers.get('X-CSRF-Token')
    if sent is None and request.headers.get('content-type', '').startswith(
            ('application/x-www-form-urlencoded', 'multipart/form-data')):
        sent = (await request.form()).get('csrf_token')
    expected = request.session.get('csrf')
    if not sent or not expected or not secrets.compare_digest(str(sent), expected):
        raise HTTPException(status_code=403, detail='CSRF token missing or invalid')
