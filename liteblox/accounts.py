"""Accounts pages: Users (admin), My account (everyone), and the audit log (admin)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from . import activity, auth
from .api import tokens
from .auth import User, current_user, require_admin
from .db import audit, get_db
from .templating import templates

router = APIRouter()

AUDIT_PAGE = 100


def _token_context(conn, username=None):
    return {'api_tokens': tokens.list_tokens(conn, username), 'all_users': username is None, 'now': tokens.now()}


def _users_page(request, user, conn, error=None, notice=None, form=None, status_code=200):
    return templates.TemplateResponse(request, 'users.html', {
        'user': user, 'users': auth.list_users(conn), 'roles': auth.ROLES, 'error': error or request.query_params.get('error'),
        'notice': notice or request.query_params.get('notice'), 'form': form or {}, 'back': 'users',
        **_token_context(conn)}, status_code=status_code)


@router.get('/users')
def users(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _users_page(request, user, conn)


@router.post('/users')
def user_add(request: Request, username: str = Form(...), password: str = Form(...), password2: str = Form(...),
             role: str = Form('readonly'), user: User = Depends(require_admin), conn=Depends(get_db)):
    username = username.strip().lower()
    form = {'username': username, 'role': role}
    try:
        if password != password2:
            raise auth.AuthError("the two passwords don't match")
        auth.create_user(conn, username, password, role)
    except auth.AuthError as e:
        return _users_page(request, user, conn, error=str(e), form=form, status_code=400)
    audit(conn, user.username, 'user_add', f'{username} ({role})')
    return RedirectResponse(f'/users?notice=Added {username}', status_code=303)


@router.post('/users/{username}/role')
def user_role(request: Request, username: str, role: str = Form(...), user: User = Depends(require_admin),
              conn=Depends(get_db)):
    try:
        auth.set_role(conn, username, role)
    except auth.AuthError as e:
        return _users_page(request, user, conn, error=str(e), status_code=400)
    audit(conn, user.username, 'user_role', f'{username}: {role}')
    return RedirectResponse(f'/users?notice={username} is now {role}', status_code=303)


@router.post('/users/{username}/password')
def user_password(request: Request, username: str, password: str = Form(...), password2: str = Form(...),
                  user: User = Depends(require_admin), conn=Depends(get_db)):
    if username == user.username:
        return RedirectResponse('/account', status_code=303)     # your own goes through My account
    try:
        if password != password2:
            raise auth.AuthError("the two passwords don't match")
        auth.set_password(conn, username, password)
    except auth.AuthError as e:
        return _users_page(request, user, conn, error=str(e), status_code=400)
    audit(conn, user.username, 'user_password_reset', username)
    return RedirectResponse(f'/users?notice=Set a new password for {username}; their sessions were logged out',
                            status_code=303)


@router.post('/users/{username}/delete')
def user_delete(request: Request, username: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    if username == user.username:
        return _users_page(request, user, conn, error="you can't delete your own account", status_code=400)
    try:
        auth.delete_user(conn, username)
    except auth.AuthError as e:
        return _users_page(request, user, conn, error=str(e), status_code=400)
    audit(conn, user.username, 'user_delete', username)
    return RedirectResponse(f'/users?notice=Deleted {username}', status_code=303)


# ── my account ─────────────────────────────────────────────────────────────────

def _account_page(request, user, conn, error=None, notice=None, status_code=200):
    row = conn.execute('SELECT created_at, last_login_at FROM users WHERE username = ?', (user.username,)).fetchone()
    return templates.TemplateResponse(request, 'account.html', {
        'user': user, 'account': row, 'error': error or request.query_params.get('error'),
        'notice': notice or request.query_params.get('notice'), 'back': 'account',
        **_token_context(conn, user.username)}, status_code=status_code)


@router.get('/account')
def account(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    return _account_page(request, user, conn)


@router.post('/account/password')
def account_password(request: Request, current: str = Form(...), password: str = Form(...),
                     password2: str = Form(...), user: User = Depends(current_user), conn=Depends(get_db)):
    try:
        if not auth.check_password(conn, user.username, current):
            raise auth.AuthError('your current password is not right')
        if password != password2:
            raise auth.AuthError("the two new passwords don't match")
        auth.set_password(conn, user.username, password)
    except auth.AuthError as e:
        return _account_page(request, user, conn, error=str(e), status_code=400)
    audit(conn, user.username, 'password_change')
    # stay logged in here; every other session of this account is logged out
    epoch = conn.execute('SELECT session_epoch FROM users WHERE username = ?', (user.username,)).fetchone()[0]
    request.session['epoch'] = epoch
    return _account_page(request, User(user.username, user.role, epoch), conn,
                         notice='Password changed. Your other sessions were logged out.')


# ── API tokens ─────────────────────────────────────────────────────────────────

BACK = {'users': '/users#tokens', 'account': '/account#tokens'}


def _back(where, **query):
    from urllib.parse import urlencode
    path, _, anchor = BACK.get(where, BACK['account']).partition('#')
    return RedirectResponse(f"{path}?{urlencode(query)}#{anchor}", status_code=303)


@router.post('/tokens')
def token_add(request: Request, name: str = Form(''), scope: str = Form('read'), expires_days: str = Form(''),
              username: str = Form(''), back: str = Form('account'), user: User = Depends(current_user),
              conn=Depends(get_db)):
    # an admin makes tokens for anyone (service accounts); everyone else for themselves
    owner = username.strip() if user.is_admin and username.strip() else user.username
    try:
        token_id, secret = tokens.create(conn, owner, name, scope, user.username,
                                         int(expires_days) if expires_days.strip() else None)
    except (tokens.TokenError, ValueError) as e:
        return _back(back, error=f'Token not created: {e}')
    audit(conn, user.username, 'token_add', f"{owner}: {name.strip()} ({scope})")
    return RedirectResponse(f'/tokens/reveal/{tokens.reveal(token_id, secret, user.username, back)}', status_code=303)


@router.get('/tokens/reveal/{key}')
def token_reveal(request: Request, key: str, user: User = Depends(current_user), conn=Depends(get_db)):
    r = tokens.revealed(key, user.username)
    row = tokens.get(conn, r['token_id']) if r else None
    if row is None:
        raise HTTPException(status_code=404, detail='this token has been shown already, or the link has expired')
    return templates.TemplateResponse(request, 'token_reveal.html', {
        'user': user, 'r': r, 't': row, 'key': key, 'base': str(request.base_url)})


@router.post('/tokens/reveal/{key}/done')
def token_reveal_done(key: str, user: User = Depends(current_user)):
    r = tokens.forget(key, user.username)
    return _back(r['back'] if r else 'account', notice='The token is ready to use')


@router.post('/tokens/{token_id}/revoke')
def token_revoke(token_id: int, back: str = Form('account'), user: User = Depends(current_user), conn=Depends(get_db)):
    row = tokens.get(conn, token_id)
    if row is None or (not user.is_admin and row['username'] != user.username):
        raise HTTPException(status_code=404, detail='no such token')
    tokens.revoke(conn, token_id)
    audit(conn, user.username, 'token_revoke', f"{row['username']}: {row['name']}")
    return _back(back, notice=f"Revoked {row['username']}'s token {row['name']}")


# ── audit log ──────────────────────────────────────────────────────────────────

@router.get('/audit')
def audit_log(request: Request, who: str = '', action: str = '', q: str = '', before: int = 0, logins: int = 0,
              user: User = Depends(require_admin), conn=Depends(get_db)):
    where, args = [], []
    if not logins and action not in activity.QUIET:
        # sign-ins drown out the changes; picking a login action shows them anyway
        where.append(f"action NOT IN ({','.join('?' * len(activity.QUIET))})")
        args.extend(activity.QUIET)
    if who:
        where.append('username = ?')
        args.append(who)
    if action:
        where.append('action = ?')
        args.append(action)
    if q:
        where.append("detail LIKE ? ESCAPE '\\'")
        args.append('%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    if before:
        where.append('id < ?')
        args.append(before)
    sql = 'SELECT * FROM audit' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY id DESC LIMIT ?'
    rows = conn.execute(sql, (*args, AUDIT_PAGE + 1)).fetchall()
    return templates.TemplateResponse(request, 'audit.html', {
        'user': user, 'rows': rows[:AUDIT_PAGE], 'more': len(rows) > AUDIT_PAGE,
        'filters': {'who': who, 'action': action, 'q': q, 'logins': 1 if logins else ''},
        'who_choices': [r[0] for r in conn.execute(
            'SELECT DISTINCT username FROM audit WHERE username IS NOT NULL ORDER BY username')],
        'actions': sorted(((r[0], activity.label(r[0])) for r in conn.execute('SELECT DISTINCT action FROM audit')),
                          key=lambda a: a[1])})
