"""App factory. Run with `liteblox serve` or `uvicorn --factory liteblox.main:create_app`."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import accounts, acls, db, help, https_routes, jobs, keys, modules, routes, scheduler, tools
from .api import ipam as api_ipam
from .api import routes as api_routes
from .backups import routes as backup_routes
from .dhcp import routes as dhcp_routes
from .dhcp import routes6 as dhcp6_routes
from .dns import routes as zone_routes
from .ipam import routes as ipam_routes
from .auth import LoginRequired, verify_csrf
from .config import load_secret, load_settings
from .nodes import routes as node_routes
from .ntp import routes as ntp_routes
from .pki import PKI
from .version import __version__

PACKAGE_DIR = Path(__file__).parent
API_DESCRIPTION = (
    'Every call needs an API token (Users → Tokens, or My account): `Authorization: Bearer lbx_…`. '
    'A read-only token can call the GET endpoints; a full token also writes, if its user is an admin. '
    'Long operations answer `202` with a job id: poll `GET /api/v1/jobs/{id}`.')


def _login_redirect(request: Request, exc: LoginRequired):
    # htmx swaps the response into the page, so ask it to navigate instead
    if request.headers.get('HX-Request'):
        return Response(status_code=204, headers={'HX-Redirect': '/login'})
    return RedirectResponse('/login', status_code=303)


def _module_off(request: Request, exc: Exception):
    """A page or API call of a module that's switched off (Settings → Modules)."""
    if request.url.path.startswith('/api/'):
        return JSONResponse({'detail': str(exc)}, status_code=404)
    from .auth import optional_user
    from .templating import templates
    conn = db.connect(request.app.state.settings.db_path)
    try:
        user = optional_user(request, conn)
    finally:
        conn.close()
    return templates.TemplateResponse(request, 'module_off.html', {'user': user, 'name': modules.LABELS[exc.name]},
                                      status_code=404)


def _dynamic_error(request: Request, exc: Exception):
    """A dynamic zone's primary refused an update, or a prerequisite failed, or it couldn't be read."""
    from html import escape
    from .dns.dynamic import Conflict
    if request.url.path.startswith('/api/'):
        return JSONResponse({'detail': str(exc)}, status_code=409 if isinstance(exc, Conflict) else 502)
    message = escape(str(exc)) + (' <a href="">Reload</a> to see what the server has now.'
                                  if isinstance(exc, Conflict) else '')
    if request.headers.get('HX-Request'):
        return HTMLResponse(f'<p class="error" role="alert">{message}</p>', status_code=409,
                            headers={'HX-Retarget': '#zone-alert', 'HX-Reswap': 'innerHTML'})
    return HTMLResponse(f'<!doctype html><meta charset="utf-8"><title>LiteBlox</title>'
                        f'<link rel="stylesheet" href="/static/app.css"><main class="card" style="margin:24px">'
                        f'<p class="error">{message}</p><p><a href="/zones">Back to zones</a></p></main>',
                        status_code=502)


@asynccontextmanager
async def lifespan(app):
    tasks = [asyncio.create_task(scheduler.run(app.state.settings)),
             asyncio.create_task(scheduler.health(app.state.settings)),
             asyncio.create_task(scheduler.ipam_daily(app.state.settings)),
             asyncio.create_task(scheduler.ipam_sweeps(app.state.settings)),
             asyncio.create_task(scheduler.ddns_reclaim(app.state.settings))]
    yield
    for task in tasks:
        task.cancel()


def _sort_zones(settings):
    """Every static zone kept sorted (3.3.1): one not in order yet becomes a draft to review, e.g. after an
    upgrade from a version that let a zone keep its own order. Never stops the app from starting."""
    from .dns import importer
    from .dns.drafts import Drafts
    conn = db.connect(settings.db_path)
    try:
        if conn.execute("SELECT 1 FROM zones WHERE kind = 'primary' AND dynamic = 0 AND repo_file != ''").fetchone():
            importer.sort_all(conn, Drafts(settings))
    except Exception as e:      # noqa: BLE001 (logged; the Dashboard still lists the zone)
        print(f'ERROR: sorting the zones at startup failed: {e}', flush=True)
    finally:
        conn.close()


class SchemeSessions:
    """The session cookie per scheme (4.6): over HTTPS `__Host-liteblox_session` (Secure), over plain HTTP
    `liteblox_session`. Browsers share cookies across ports, and a Secure cookie would keep the plain-HTTP login
    from setting its own, so the two are kept apart: a login is per scheme."""

    def __init__(self, app, secret_key, max_age, force_secure=False):
        common = {'secret_key': secret_key, 'max_age': max_age, 'same_site': 'lax'}
        self.plain = SessionMiddleware(app, session_cookie='liteblox_session', https_only=force_secure, **common)
        self.secure = SessionMiddleware(app, session_cookie='__Host-liteblox_session', https_only=True, **common)

    async def __call__(self, scope, receive, send):
        chosen = self.secure if scope.get('scheme') in ('https', 'wss') else self.plain
        await chosen(scope, receive, send)


def create_app(settings=None):
    settings = settings or load_settings()
    db.migrate(settings.db_path)
    PKI(settings.pki_dir).ensure()
    jobs.fail_interrupted(settings.db_path)
    _sort_zones(settings)

    # the spec is served by api.routes (logged-in users or token holders), and covers /api/v1 only
    app = FastAPI(title='LiteBlox API', version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None, dependencies=[Depends(verify_csrf), Depends(modules.guard)], lifespan=lifespan,
                  description=API_DESCRIPTION)
    app.state.settings = settings

    app.add_middleware(SchemeSessions, secret_key=load_secret(settings), max_age=settings.web.session_hours * 3600,
                       force_secure=settings.web.secure_cookies)
    app.add_exception_handler(LoginRequired, _login_redirect)
    app.add_exception_handler(modules.ModuleOff, _module_off)
    from .dns.dynamic import DynamicError
    app.add_exception_handler(DynamicError, _dynamic_error)
    app.mount('/static', StaticFiles(directory=PACKAGE_DIR / 'static'), name='static')
    for router in (routes.router, node_routes.router, backup_routes.router, zone_routes.router, dhcp_routes.router,
                   dhcp6_routes.router,
                   help.router, accounts.router, acls.router, keys.router, ntp_routes.router, ipam_routes.router,
                   tools.router, modules.router, https_routes.router, api_routes.docs_router):
        app.include_router(router, include_in_schema=False)
    app.include_router(api_routes.router)
    app.include_router(api_ipam.router)
    return app
