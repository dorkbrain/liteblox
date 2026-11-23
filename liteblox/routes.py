"""Core pages: health, login/logout, dashboard."""

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response

from . import auth
from .auth import User, current_user
from .dashboard import overview
from .db import audit, get_db
from .templating import asset, has_asset, templates
from .version import __version__

router = APIRouter()


@router.get('/healthz')
def healthz():
    return {'status': 'ok', 'version': __version__}


@router.get('/favicon.ico', include_in_schema=False)
def favicon():
    # browsers ask for /favicon.ico on their own; answer with the SVG when there is one
    if not has_asset('favicon.svg'):
        return Response(status_code=404)
    return RedirectResponse(asset('favicon.svg'), status_code=302)


@router.get('/login')
def login_form(request: Request, conn=Depends(get_db)):
    if request.session.get('user'):
        return RedirectResponse('/', status_code=303)
    return templates.TemplateResponse(request, 'login.html', {
        'no_users': auth.user_count(conn) == 0,
    })


@router.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...),
          conn=Depends(get_db)):
    address = request.client.host if request.client else ''
    minutes = auth.login_throttled(conn, username.strip(), address)
    if minutes:
        return templates.TemplateResponse(request, 'login.html', {
            'error': f"Too many failed logins; try again in {minutes} minute{'s' if minutes != 1 else ''}",
            'username': username,
            'no_users': auth.user_count(conn) == 0,
        }, status_code=429)
    user = auth.authenticate(conn, username.strip(), password)
    if user is None:
        audit(conn, username.strip(), 'login_failed', address)
        return templates.TemplateResponse(request, 'login.html', {
            'error': 'Invalid username or password',
            'username': username,
            'no_users': auth.user_count(conn) == 0,
        }, status_code=401)

    auth.login_session(request, user)
    audit(conn, user.username, 'login', address)
    return RedirectResponse('/', status_code=303)


@router.post('/logout')
def logout(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    auth.logout_session(request)
    audit(conn, user.username, 'logout')
    return RedirectResponse('/login', status_code=303)


@router.get('/')
def dashboard(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    return templates.TemplateResponse(request, 'dashboard.html', {
        'user': user, 'overview': overview(conn, request.app.state.settings)})


@router.get('/dashboard/body')
def dashboard_body(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    """The Dashboard without its frame, which the page fetches every minute."""
    return templates.TemplateResponse(request, 'partials/dashboard_body.html', {
        'user': user, 'overview': overview(conn, request.app.state.settings)})


@router.get('/search')
def search_page(request: Request, q: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    """Every zone's records, the DHCP reservations and leases, the zones and subnets, for one query."""
    from . import search
    from .ipam import seen
    settings = request.app.state.settings
    res = search.search(conn, settings, q) if q.strip() else None
    cfg = seen.settings(conn)
    return templates.TemplateResponse(request, 'search.html', {
        'user': user, 'q': q.strip(), 'res': res, 'mark': search.mark, 'record_link': search.record_link,
        'min_length': search.MIN_LENGTH, 'live_length': search.LIVE_LENGTH, 'keep_days': cfg.keep_days,
        'flap_minutes': cfg.flap_minutes})


# ── moving one address ─────────────────────────────────────────────────────────

def _move_back(value, ip):
    value = (value or '').strip()
    if (value.startswith('/ipam') or value.startswith('/search')) and '//' not in value:
        return value
    return f'/search?q={ip}#address'


def _move_page(request, conn, user, ip, to='', back='', error=None, errors=None, status_code=200):
    from . import move
    plan, problem = None, None
    if to.strip():
        try:
            plan = move.plan(conn, request.app.state.settings, ip, to)
        except move.MoveError as e:
            problem = '; '.join(e.errors.values())
    return templates.TemplateResponse(request, 'address_move.html', {
        'user': user, 'ip': ip, 'to': to.strip(), 'back': _move_back(back, ip), 'plan': plan,
        'ptr_lines': move.ptr_lines(plan) if plan else [], 'error': error or problem, 'errors': errors or {}},
        status_code=status_code if not problem else 422)


@router.get('/addresses/{ip}/move')
def move_page(request: Request, ip: str, to: str = '', back: str = '', user: User = Depends(auth.require_admin),
              conn=Depends(get_db)):
    """Move one address everywhere: the preview, once a new address is given."""
    import ipaddress
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        return Response(status_code=404)
    return _move_page(request, conn, user, ip, to, back)


@router.post('/addresses/{ip}/move')
def move_apply(request: Request, ip: str, to: str = Form(...), token: str = Form(...), back: str = Form(''),
               reservation: str = Form(''), ipam: str = Form(''), user: User = Depends(auth.require_admin),
               conn=Depends(get_db)):
    from . import move
    try:
        done = move.apply(conn, request.app.state.settings, ip, to, token, reservation=bool(reservation),
                          ipam=bool(ipam), username=user.username)
    except move.Changed:
        return _move_page(request, conn, user, ip, to, back, status_code=409,
                          error='Something here changed since the preview: check it again.')
    except move.MoveError as e:
        return _move_page(request, conn, user, ip, to, back, errors=e.errors, status_code=422,
                          error='Nothing was moved: ' + '; '.join(e.errors.values()))
    if done['zones']:
        return RedirectResponse(f"/zones/{done['zones'][0]}/review", status_code=303)
    if done['job']:
        return RedirectResponse(f"/jobs/{done['job']}", status_code=303)
    return RedirectResponse(f'/search?q={to.strip()}#address', status_code=303)
