"""Settings → HTTPS (4.6): turn the HTTPS port on, HTTPS only, a self-signed certificate or an imported one."""

import os
import re
import secrets
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response

from . import web_tls
from .auth import User, require_admin
from .db import audit, get_db
from .templating import templates

router = APIRouter()
PENDING_TTL = 900       # seconds an import waits for Use it
_TOKEN = re.compile(r'[A-Za-z0-9_-]{16,64}')


def _settings(request):
    return request.app.state.settings


def _back(**params):
    params = {k: v for k, v in params.items() if v}
    query = '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
    return RedirectResponse('/settings/https' + (f'?{query}' if query else ''), status_code=303)


def on_https(request):
    """Did this request come in on LiteBlox's own HTTPS port (not a proxy's TLS in front of plain HTTP)?"""
    return request.scope.get('liteblox_listener') == 'https'


def _host(request):
    return request.url.hostname or ''


# ── an import waiting for Use it: the checked pair, kept beside the certificate (0600) ──

def _pending_path(settings, token):
    return web_tls.tls_dir(settings) / f'.import-{token}.pem'


def _sweep_pending(settings):
    folder = web_tls.tls_dir(settings)
    if not folder.is_dir():
        return
    for path in folder.glob('.import-*.pem'):
        try:
            if time.time() - path.stat().st_mtime > PENDING_TTL:
                path.unlink()
        except OSError:
            pass


def _stash(settings, chain_pem, key_pem):
    _sweep_pending(settings)
    folder = web_tls.tls_dir(settings)
    folder.mkdir(mode=0o700, exist_ok=True)
    token = secrets.token_urlsafe(18)
    fd = os.open(_pending_path(settings, token), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key_pem + chain_pem)
    return token


def _unstash(settings, token, remove=False):
    """(chain PEM, key PEM) of a pending import, or None."""
    if not token or not _TOKEN.fullmatch(token):
        return None
    path = _pending_path(settings, token)
    try:
        if time.time() - path.stat().st_mtime > PENDING_TTL:
            path.unlink()
            return None
        data = path.read_bytes()
        if remove:
            path.unlink()
    except OSError:
        return None
    marker = b'-----BEGIN CERTIFICATE-----'
    at = data.find(marker)
    return (data[at:], data[:at]) if at > 0 else None


# ── the page ───────────────────────────────────────────────────────────────────

def _page(request, conn, user, pending=None, errors=None, form=None, status_code=200):
    settings = _settings(request)
    row = web_tls.load(conn)
    info = web_tls.current(settings)
    host = _host(request)
    port = row['port'] or web_tls.https_port()
    q = request.query_params
    preview = None
    if pending:
        pair = _unstash(settings, pending)
        if pair:
            p_info = web_tls.describe(pair[0])
            preview = {'token': pending, 'info': p_info, 'warnings': web_tls.warnings(p_info, host)}
    return templates.TemplateResponse(request, 'settings_https.html', {
        'user': user, 'tab': 'https', 'row': row, 'info': info, 'host': host, 'port': port,
        'warnings': web_tls.warnings(info, host) if info else [],
        'outside': bool(info and row['fingerprint'] and info['fingerprint'] != row['fingerprint']),
        'on_https': on_https(request), 'proxied': bool(request.headers.get('x-forwarded-for')),
        'https_url': f"https://{host if ':' not in host else f'[{host}]'}:{port}/settings/https",
        'names': row['names'] or ', '.join(web_tls.default_names(host)),
        'preview': preview, 'errors': errors or {}, 'form': form or {},
        'error': q.get('error'), 'done': q.get('done'), 'max_upload': web_tls.MAX_UPLOAD // 1024,
    }, status_code=status_code)


@router.get('/settings/https')
def https_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _page(request, conn, user, pending=request.query_params.get('pending'))


@router.post('/settings/https/enabled')
async def https_enabled(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    want = bool(form.get('enabled'))
    row = web_tls.load(conn)
    if want == bool(row['enabled']):
        return _back()
    if want:
        try:
            made = web_tls.enable(conn, _settings(request), user.username, _host(request))
        except web_tls.CertError as e:
            return _back(error=f'HTTPS was not turned on: {e}.')
        audit(conn, user.username, 'https_enable', f"port {row['port'] or web_tls.https_port()}"
              + (f", a self-signed certificate for {', '.join(made['names'])}" if made else ''))
        return _back(done='HTTPS is on: the port opens within a few seconds.'
                     + (' A self-signed certificate was made for it.' if made else ''))
    web_tls.disable(conn, user.username)
    audit(conn, user.username, 'https_disable', 'HTTPS only off with it' if row['https_only'] else None)
    return _back(done='HTTPS is off: the port closes within a few seconds.')


@router.post('/settings/https/only')
async def https_only(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    want = bool(form.get('https_only'))
    row = web_tls.load(conn)
    if want == bool(row['https_only']):
        return _back()
    if want:
        if not row['enabled'] or not row['listening']:
            return _back(error='Turn HTTPS on first, and wait until its port is listening.')
        if not on_https(request):
            return _back(error=f"Open this page over HTTPS (port {row['port'] or web_tls.https_port()}) first: "
                               'HTTPS only can only be turned on from there.')
        web_tls.save(conn, user.username, https_only=1)
        audit(conn, user.username, 'https_only', 'plain HTTP answers with a page saying HTTP is not supported')
        return _back(done='HTTPS only: plain HTTP now answers with a page saying HTTP is not supported.')
    web_tls.save(conn, user.username, https_only=0)
    audit(conn, user.username, 'https_allow_http', 'from the HTTPS tab')
    return _back(done='Plain HTTP works again.')


@router.post('/settings/https/generate')
async def https_generate(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    try:
        names = web_tls.parse_names(form.get('names', ''))
    except web_tls.CertError as e:
        return _page(request, conn, user, errors={'names': str(e)}, form={'names': form.get('names', '')},
                     status_code=422)
    info = web_tls.generate(conn, _settings(request), names, user.username)
    audit(conn, user.username, 'https_generate', f"{', '.join(names)} ({info['fingerprint'][:23]}…)")
    return _back(done='A new self-signed certificate is in place: new connections get it within a few seconds. '
                      'Browsers warn again until they trust it.')


@router.post('/settings/https/import')
async def https_import(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()

    async def data(name):
        f = form.get(name)
        if f is None or isinstance(f, str):
            return b''
        return await f.read(web_tls.MAX_UPLOAD + 1)
    try:
        chain_pem, key_pem = web_tls.read_import(await data('cert'), await data('key'), await data('pfx'),
                                                 form.get('password') or '')
    except web_tls.CertError as e:
        return _page(request, conn, user, errors={'import': str(e)}, status_code=422)
    token = _stash(_settings(request), chain_pem, key_pem)
    return RedirectResponse(f'/settings/https?pending={token}#import', status_code=303)


@router.post('/settings/https/import/use')
async def https_import_use(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    pair = _unstash(_settings(request), form.get('token'), remove=True)
    if pair is None:
        return _back(error='That import is gone (it waits 15 minutes): upload it again.')
    try:
        info = web_tls.install(conn, _settings(request), pair[0], pair[1], 'imported', user.username)
    except web_tls.CertError as e:
        return _back(error=f'Not imported: {e}.')
    audit(conn, user.username, 'https_import',
          f"{info['subject']} from {info['issuer']}, until {info['not_after']:%Y-%m-%d} ({info['fingerprint'][:23]}…)")
    return _back(done='The certificate is in place: new connections get it within a few seconds.')


@router.post('/settings/https/import/cancel')
async def https_import_cancel(request: Request, user: User = Depends(require_admin)):
    form = await request.form()
    _unstash(_settings(request), form.get('token'), remove=True)
    return _back()


@router.get('/settings/https/cert.pem')
def https_cert(request: Request, user: User = Depends(require_admin)):
    try:
        pair = web_tls.read(_settings(request))
    except web_tls.CertError as e:
        return Response(f'{e}\n', status_code=409, media_type='text/plain')
    if pair is None:
        return Response('no certificate yet\n', status_code=404, media_type='text/plain')
    return Response(pair[0], media_type='application/x-pem-file',
                    headers={'Content-Disposition': 'attachment; filename="liteblox-cert.pem"'})
