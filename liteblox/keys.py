"""TSIG keys: LiteBlox's own (internal), imported from a node's config, and keys for DHCP/ACME clients.

A user key's secret is shown once, right after it is created or replaced,
through a one-time reveal page that only its creator can open for a few
minutes (the DB keeps the secret, since every node's keys.conf needs it).
Grants say what a key may update in which zone; they're written into the
zone's update-policy while the zone is dynamic. Every change is applied to
each taken-over node in turn (bindconf.apply).
"""

import base64
import re
import secrets
import threading
import time

import dns.exception
import dns.name
import dns.rdatatype
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response

from . import db, jobs
from .auth import User, require_admin
from .bindconf.model import UPDATE_KEY, XFR_KEY
from .db import get_db
from .templating import templates

router = APIRouter()

NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}')
ALGORITHMS = {'hmac-sha256': 32, 'hmac-sha512': 64, 'hmac-sha384': 48, 'hmac-sha1': 20}
INTERNAL = (XFR_KEY, UPDATE_KEY)
SCOPES = ('zonesub', 'subdomain', 'name')
REVEAL_SECONDS = 600


class KeyProblem(ValueError):
    pass


# ── one-time reveals (memory only) ─────────────────────────────────────────────

_reveals, _lock = {}, threading.Lock()


def _reveal(name, algorithm, secret, username, job_id):
    token = secrets.token_urlsafe(24)
    with _lock:
        now = time.time()
        for t in [t for t, r in _reveals.items() if r['expires'] < now]:
            del _reveals[t]
        _reveals[token] = {'name': name, 'algorithm': algorithm, 'secret': secret, 'username': username,
                           'job_id': job_id, 'expires': now + REVEAL_SECONDS}
    return token


def _get_reveal(token, username):
    with _lock:
        r = _reveals.get(token)
    if r is None or r['expires'] < time.time() or r['username'] != username:
        raise HTTPException(status_code=404, detail='this key has been shown already, or the link has expired')
    return r


def key_file(name, algorithm, secret):
    return f'key "{name}" {{\n\talgorithm {algorithm};\n\tsecret "{secret}";\n}};\n'


# ── checks and operations ──────────────────────────────────────────────────────

def check_name(name):
    name = (name or '').strip()
    if not NAME_RE.fullmatch(name):
        raise KeyProblem('a key name is letters, digits, dots, - and _')
    if name in INTERNAL:
        raise KeyProblem(f'{name} is LiteBlox\'s own key')
    return name


def new_secret(algorithm):
    if algorithm not in ALGORITHMS:
        raise KeyProblem(f"the algorithm must be one of {', '.join(ALGORITHMS)}")
    return base64.b64encode(secrets.token_bytes(ALGORITHMS[algorithm])).decode()


def check_grant(conn, zone_name, scope, name, types):
    """(zone row, scope, name, types) for a grant, normalized. Raises KeyProblem."""
    zone = conn.execute("SELECT * FROM zones WHERE name = ? AND kind = 'primary'", (zone_name,)).fetchone()
    if zone is None:
        raise KeyProblem(f'no zone {zone_name} with records in LiteBlox')
    if scope not in SCOPES:
        raise KeyProblem('the scope is the whole zone, names under a name, or one name')
    name = (name or '').strip().lower().rstrip('.')
    if scope == 'zonesub':
        name = ''
    else:
        try:
            owner = dns.name.from_text(name + '.')
        except dns.exception.DNSException:
            raise KeyProblem(f'{name!r} is not a domain name')
        if not name or not owner.is_subdomain(dns.name.from_text(zone['name'] + '.')):
            raise KeyProblem(f'{name or "the name"} must be inside {zone["name"]}')
    words = (types or '').upper().replace(',', ' ').split() or ['ANY']
    for word in words:
        try:
            dns.rdatatype.from_text(word)
        except dns.rdatatype.UnknownRdatatype:
            raise KeyProblem(f'{word} is not a record type')
    return zone, scope, name, ' '.join(dict.fromkeys(words))


def references(conn, name):
    """Where a key is used outside grants: node extras and zone lists (as `key NAME`)."""
    from .bindconf.model import NodeOptions
    word = re.compile(r'key\s+"?' + re.escape(name) + r'"?(?![\w.-])')
    out = []
    for n in conn.execute('SELECT * FROM nodes WHERE managed = 1 ORDER BY name'):
        options = NodeOptions.from_json(n['options'])
        texts = [options.extra, n['top_extra'] or ''] + ['\n'.join(getattr(options, f) or [])
                                                          for f in ('allow_query', 'allow_recursion')]
        if any(word.search(t) for t in texts):
            out.append(f"node {n['name']}")
    for z in conn.execute('SELECT * FROM zones ORDER BY name'):
        if any(word.search(z[f] or '') for f in ('allow_transfer', 'allow_query', 'also_notify')):
            out.append(f"zone {z['name']}")
    if conn.execute('SELECT 1 FROM dhcp4_settings s JOIN tsig_keys k ON k.id = s.ddns_key_id WHERE k.name = ?',
                    (name,)).fetchone():
        out.append('DHCP (its DNS registration key)')
    return out


def _apply(settings, conn, change, undo, reason, username, log):
    from .bindconf.apply import apply_nodes
    targets = [r['id'] for r in conn.execute("SELECT id FROM nodes WHERE managed = 1 AND status = 'ready'")]
    if not targets:
        change(conn)
        log('  no taken-over nodes yet: saved in LiteBlox only')
        return
    apply_nodes(settings, conn, targets, change, undo, reason, username, log)


def _key_row(conn, name):
    row = conn.execute('SELECT * FROM tsig_keys WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise KeyProblem(f'no key named {name}')
    return row


def add(settings, name, algorithm, secret, username, log):
    conn = db.connect(settings.db_path)
    try:
        if conn.execute('SELECT 1 FROM tsig_keys WHERE name = ?', (name,)).fetchone():
            raise KeyProblem(f'there is already a key named {name}')

        def change(c):
            with c:
                c.execute("INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES (?, ?, ?, 'user')",
                          (name, algorithm, secret))

        def undo(c):
            with c:
                c.execute('DELETE FROM tsig_keys WHERE name = ?', (name,))
        log(f'Adding key {name} ({algorithm})')
        _apply(settings, conn, change, undo, f'add key {name}', username, log)
        db.audit(conn, username, 'key_add', name)
        log(f'✓ key {name} is on every taken-over node; it can update nothing until you grant it a zone')
    finally:
        conn.close()


def rotate(settings, name, secret, username, log):
    conn = db.connect(settings.db_path)
    try:
        row = _key_row(conn, name)
        if row['name'] in INTERNAL:
            raise KeyProblem(f"{name} is LiteBlox's own key")

        def change(c):
            with c:
                c.execute('UPDATE tsig_keys SET secret = ? WHERE id = ?', (secret, row['id']))

        def undo(c):
            with c:
                c.execute('UPDATE tsig_keys SET secret = ? WHERE id = ?', (row['secret'], row['id']))
        log(f'Replacing the secret of key {name}')
        _apply(settings, conn, change, undo, f'replace key {name}', username, log)
        db.audit(conn, username, 'key_rotate', name)
        log(f'✓ key {name} has its new secret on every taken-over node; the old one no longer works')
        if 'DHCP (its DNS registration key)' in references(conn, name):
            from .nodes.roles import follow_dhcp
            follow_dhcp(conn, settings, log)        # Kea's D2 signs with it
    finally:
        conn.close()


def delete(settings, name, username, log):
    conn = db.connect(settings.db_path)
    try:
        row = _key_row(conn, name)
        if row['name'] in INTERNAL:
            raise KeyProblem(f"{name} is LiteBlox's own key")
        used = references(conn, name)
        if used:
            raise KeyProblem(f"{name} is still used by {'; '.join(used)}")
        grants = conn.execute('SELECT * FROM key_grants WHERE key_id = ?', (row['id'],)).fetchall()

        def change(c):
            with c:
                c.execute('DELETE FROM tsig_keys WHERE id = ?', (row['id'],))       # grants cascade

        def undo(c):
            with c:
                c.execute('INSERT INTO tsig_keys (id, name, algorithm, secret, purpose, created_at) '
                          'VALUES (?, ?, ?, ?, ?, ?)', tuple(row[k] for k in
                                                          ('id', 'name', 'algorithm', 'secret', 'purpose', 'created_at')))
                for g in grants:
                    c.execute('INSERT INTO key_grants (id, key_id, zone_id, scope, name, types) VALUES (?, ?, ?, ?, ?, ?)',
                              tuple(g))
        log(f'Deleting key {name}' + (f' and its {len(grants)} grant(s)' if grants else ''))
        _apply(settings, conn, change, undo, f'delete key {name}', username, log)
        db.audit(conn, username, 'key_delete', name)
        log(f'✓ key {name} deleted')
    finally:
        conn.close()


def grant(settings, name, zone_name, scope, owner, types, username, log):
    conn = db.connect(settings.db_path)
    try:
        row = _key_row(conn, name)
        if row['name'] in INTERNAL:
            raise KeyProblem(f"{name} is LiteBlox's own key")
        zone, scope, owner, types = check_grant(conn, zone_name, scope, owner, types)
        ids = []

        def change(c):
            with c:
                ids.append(c.execute('INSERT INTO key_grants (key_id, zone_id, scope, name, types) VALUES (?, ?, ?, ?, ?)',
                                     (row['id'], zone['id'], scope, owner, types)).lastrowid)

        def undo(c):
            with c:
                c.execute('DELETE FROM key_grants WHERE id = ?', (ids[-1],))
        log(f"Granting {name}: {types} on {owner or 'all of ' + zone['name']}"
            + ('' if zone['dynamic'] else f" (inactive until {zone['name']} is dynamic)"))
        _apply(settings, conn, change, undo, f"grant {name} on {zone['name']}", username, log)
        db.audit(conn, username, 'key_grant', f"{name} {zone['name']} {scope} {owner} {types}")
        log('✓ granted')
    finally:
        conn.close()


def revoke(settings, grant_id, username, log):
    conn = db.connect(settings.db_path)
    try:
        g = conn.execute('SELECT g.*, k.name AS key, z.name AS zone FROM key_grants g JOIN tsig_keys k ON '
                         'k.id = g.key_id JOIN zones z ON z.id = g.zone_id WHERE g.id = ?', (grant_id,)).fetchone()
        if g is None:
            raise KeyProblem('no such grant')

        def change(c):
            with c:
                c.execute('DELETE FROM key_grants WHERE id = ?', (g['id'],))

        def undo(c):
            with c:
                c.execute('INSERT INTO key_grants (id, key_id, zone_id, scope, name, types) VALUES (?, ?, ?, ?, ?, ?)',
                          (g['id'], g['key_id'], g['zone_id'], g['scope'], g['name'], g['types']))
        log(f"Revoking {g['key']}'s grant on {g['zone']}")
        _apply(settings, conn, change, undo, f"revoke {g['key']} on {g['zone']}", username, log)
        db.audit(conn, username, 'key_revoke', f"{g['key']} {g['zone']}")
        log('✓ revoked')
    finally:
        conn.close()


# ── pages ──────────────────────────────────────────────────────────────────────

def _page(request, user, conn, error=None, form=None, status_code=200):
    keys = conn.execute('SELECT * FROM tsig_keys ORDER BY purpose IN (?, ?) DESC, name', INTERNAL).fetchall()
    grants = {}
    for g in conn.execute('SELECT g.*, z.name AS zone, z.dynamic FROM key_grants g JOIN zones z ON z.id = g.zone_id '
                          'ORDER BY z.name'):
        grants.setdefault(g['key_id'], []).append(g)
    zones = conn.execute("SELECT name, dynamic FROM zones WHERE kind = 'primary' ORDER BY name").fetchall()
    return templates.TemplateResponse(request, 'keys.html', {
        'user': user, 'keys': keys, 'grants': grants, 'zones': zones, 'internal': INTERNAL,
        'algorithms': list(ALGORITHMS), 'error': error or request.query_params.get('error'), 'form': form or {}},
        status_code=status_code)


@router.get('/settings/keys')
def keys_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _page(request, user, conn)


def _job(request, fn, username):
    settings = request.app.state.settings
    return jobs.start(settings.db_path, 'TSIG key', fn, username=username)


@router.post('/settings/keys')
def key_add(request: Request, name: str = Form(''), algorithm: str = Form('hmac-sha256'),
            user: User = Depends(require_admin), conn=Depends(get_db)):
    try:
        name = check_name(name)
        if conn.execute('SELECT 1 FROM tsig_keys WHERE name = ?', (name,)).fetchone():
            raise KeyProblem(f'there is already a key named {name}')
        secret = new_secret(algorithm)
    except KeyProblem as e:
        return _page(request, user, conn, error=str(e), form={'name': name, 'algorithm': algorithm}, status_code=422)
    settings, username = request.app.state.settings, user.username
    job_id = _job(request, lambda log: add(settings, name, algorithm, secret, username, log), username)
    return RedirectResponse(f'/settings/keys/reveal/{_reveal(name, algorithm, secret, username, job_id)}',
                            status_code=303)


@router.post('/settings/keys/{name}/rotate')
def key_rotate(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    row = conn.execute('SELECT * FROM tsig_keys WHERE name = ?', (name,)).fetchone()
    if row is None or row['name'] in INTERNAL:
        raise HTTPException(status_code=404, detail='no such key')
    secret = new_secret(row['algorithm'])
    settings, username = request.app.state.settings, user.username
    job_id = _job(request, lambda log: rotate(settings, name, secret, username, log), username)
    return RedirectResponse(f"/settings/keys/reveal/{_reveal(name, row['algorithm'], secret, username, job_id)}",
                            status_code=303)


@router.get('/settings/keys/reveal/{token}')
def key_reveal(request: Request, token: str, user: User = Depends(require_admin)):
    r = _get_reveal(token, user.username)
    return templates.TemplateResponse(request, 'key_reveal.html', {
        'user': user, 'r': r, 'token': token, 'key_file': key_file(r['name'], r['algorithm'], r['secret'])})


@router.get('/settings/keys/reveal/{token}/download')
def key_download(token: str, user: User = Depends(require_admin)):
    r = _get_reveal(token, user.username)
    return Response(key_file(r['name'], r['algorithm'], r['secret']), media_type='text/plain',
                    headers={'Content-Disposition': f'attachment; filename="{r["name"]}.key"'})


@router.post('/settings/keys/reveal/{token}/done')
def key_reveal_done(token: str, user: User = Depends(require_admin)):
    with _lock:
        r = _reveals.get(token)
        if r and r['username'] == user.username:
            del _reveals[token]
    return RedirectResponse('/settings/keys', status_code=303)


@router.post('/settings/keys/{name}/delete')
def key_delete(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    used = references(conn, name)
    if used:
        return RedirectResponse(f"/settings/keys?error={name} is still used by {'; '.join(used)}", status_code=303)
    settings, username = request.app.state.settings, user.username
    return RedirectResponse(f"/jobs/{_job(request, lambda log: delete(settings, name, username, log), username)}",
                            status_code=303)


@router.post('/settings/keys/{name}/grants')
def key_grant(request: Request, name: str, zone: str = Form(''), scope: str = Form('zonesub'),
              owner: str = Form(''), types: str = Form('ANY'), user: User = Depends(require_admin),
              conn=Depends(get_db)):
    try:
        check_grant(conn, zone, scope, owner, types)
    except KeyProblem as e:
        return RedirectResponse(f'/settings/keys?error={e}#key-{name}', status_code=303)
    settings, username = request.app.state.settings, user.username
    job_id = _job(request, lambda log: grant(settings, name, zone, scope, owner, types, username, log), username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/settings/keys/grants/{grant_id}/revoke')
def key_revoke(request: Request, grant_id: int, user: User = Depends(require_admin)):
    settings, username = request.app.state.settings, user.username
    return RedirectResponse(f"/jobs/{_job(request, lambda log: revoke(settings, grant_id, username, log), username)}",
                            status_code=303)
