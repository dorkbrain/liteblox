"""API tokens: per user, read-only or full, shown once and kept only as a SHA-256 hash.

A token is high-entropy, so a plain hash is enough (no argon2 per request). The
user's role is read again on every call, so a role change or a deleted user
applies at once; a password change leaves the tokens alone (they're separate
credentials).
"""

import hashlib
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PREFIX = 'lbx_'
SCOPES = ('read', 'full')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}')
USED_EVERY = 60             # seconds between last-used updates for one token
REVEAL_SECONDS = 600


class TokenError(ValueError):
    pass


@dataclass(frozen=True)
class ApiUser:
    username: str
    role: str
    scope: str
    token_id: int
    token_name: str

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def can_write(self):
        return self.scope == 'full' and self.is_admin


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def create(conn, username, name, scope, created_by, expires_days=None):
    """(token id, the token itself): the only time it exists outside the caller's hands."""
    name = (name or '').strip()
    if not NAME_RE.fullmatch(name):
        raise TokenError('name it with letters, digits, spaces, . _ - (up to 64)')
    if scope not in SCOPES:
        raise TokenError(f"scope must be one of: {', '.join(SCOPES)}")
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if user is None:
        raise TokenError(f'no such user: {username}')
    if conn.execute('SELECT 1 FROM api_tokens WHERE user_id = ? AND name = ?', (user['id'], name)).fetchone():
        raise TokenError(f'{username} has a token named {name!r} already')
    expires = None
    if expires_days:
        if not 1 <= int(expires_days) <= 3650:
            raise TokenError('expiry is 1 to 3650 days')
        expires = (datetime.now(timezone.utc) + timedelta(days=int(expires_days))).strftime('%Y-%m-%d %H:%M:%S')
    token = PREFIX + secrets.token_urlsafe(32)
    with conn:
        token_id = conn.execute(
            'INSERT INTO api_tokens (user_id, name, prefix, token_hash, scope, created_by, expires_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user['id'], name, token[:len(PREFIX) + 6], digest(token), scope, created_by, expires)).lastrowid
    return token_id, token


def list_tokens(conn, username=None):
    sql = ('SELECT t.*, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id'
           + (' WHERE u.username = ?' if username else '') + ' ORDER BY u.username, t.name')
    return conn.execute(sql, (username,) if username else ()).fetchall()


def get(conn, token_id):
    return conn.execute('SELECT t.*, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?',
                        (token_id,)).fetchone()


def revoke(conn, token_id):
    row = get(conn, token_id)
    if row is None:
        raise TokenError('no such token')
    with conn:
        conn.execute('DELETE FROM api_tokens WHERE id = ?', (token_id,))
    return row


def expired(row):
    return bool(row['expires_at']) and row['expires_at'] <= now()


def authenticate(conn, token, client_ip=None):
    """The ApiUser for a token, or None (unknown, expired, or its user is gone)."""
    if not token or not token.startswith(PREFIX):
        return None
    row = conn.execute('SELECT t.*, u.username, u.role FROM api_tokens t JOIN users u ON u.id = t.user_id '
                       'WHERE t.token_hash = ?', (digest(token),)).fetchone()
    if row is None or expired(row):
        return None
    stale = (datetime.now(timezone.utc) - timedelta(seconds=USED_EVERY)).strftime('%Y-%m-%d %H:%M:%S')
    if not row['last_used_at'] or row['last_used_at'] < stale or row['last_used_ip'] != client_ip:
        with conn:
            conn.execute('UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?',
                         (now(), client_ip, row['id']))
    return ApiUser(row['username'], row['role'], row['scope'], row['id'], row['name'])


# ── one-time reveal (memory only), like a TSIG key's ───────────────────────────

_reveals, _lock = {}, threading.Lock()


def reveal(token_id, token, viewer, back):
    key = secrets.token_urlsafe(24)
    with _lock:
        t = time.time()
        for k in [k for k, r in _reveals.items() if r['expires'] < t]:
            del _reveals[k]
        _reveals[key] = {'token_id': token_id, 'token': token, 'viewer': viewer, 'back': back,
                         'expires': t + REVEAL_SECONDS}
    return key


def revealed(key, viewer):
    with _lock:
        r = _reveals.get(key)
    if r is None or r['expires'] < time.time() or r['viewer'] != viewer:
        return None
    return r


def forget(key, viewer):
    with _lock:
        r = _reveals.get(key)
        if r and r['viewer'] == viewer:
            del _reveals[key]
            return r
    return None
