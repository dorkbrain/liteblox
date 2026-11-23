"""The two ports (4.6): plain HTTP on 53530, always, and HTTPS on 53443 while it's on.

`liteblox serve` builds the app once and runs it behind both. The HTTP server owns the lifespan (the scheduler)
and the signals; a supervisor starts, stops and re-keys the HTTPS server as the settings and the certificate
files change, so nothing needs a restart. With HTTPS only, plain HTTP answers every request but /healthz with a
static page, never a redirect.
"""

import asyncio
import json
import logging
import socket
import time

import uvicorn

from . import db, web_tls

log = logging.getLogger('liteblox.https')
CHECK_EVERY = 5         # seconds between looks at the settings and the certificate files
GATE_CACHE = 3          # seconds the HTTP gate trusts its copy of the settings

REFUSED_PAGE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTPS only · LiteBlox</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ margin: 0; font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
        background: #f6f7f9; color: #1c2330; }}
main {{ max-width: 34rem; margin: 15vh auto; padding: 0 16px; }}
h1 {{ font-size: 1.4rem; margin: 0 0 .5rem; }}
p {{ margin: 0 0 .75rem; }}
@media (prefers-color-scheme: dark) {{ body {{ background: #12161d; color: #e4e8ee; }} }}
</style></head>
<body><main>
<h1>HTTP isn't supported here</h1>
<p>This LiteBlox is set to HTTPS only. Open it with <strong>https://</strong> on port <strong>{port}</strong>.</p>
</main></body></html>
'''


class Settings:
    """The HTTPS row, re-read at most every GATE_CACHE seconds (every request on plain HTTP asks)."""

    def __init__(self, settings):
        self.settings = settings
        self._at, self._row = 0.0, None

    def row(self):
        if self._row is None or time.monotonic() - self._at > GATE_CACHE:
            conn = db.connect(self.settings.db_path)
            try:
                self._row = web_tls.load(conn)
            finally:
                conn.close()
            self._at = time.monotonic()
        return self._row


class Listener:
    """The app as one port serves it: requests carry scope['liteblox_listener'] ('http' or 'https'), and with
    HTTPS only, plain HTTP gets the static page (JSON for the API) instead."""

    def __init__(self, app, kind, settings, https_settings=None):
        self.app, self.kind = app, kind
        self.https = https_settings or Settings(settings)

    async def __call__(self, scope, receive, send):
        if scope['type'] in ('http', 'websocket'):
            scope['liteblox_listener'] = self.kind
            if self.kind == 'http' and scope['type'] == 'http' and scope['path'] != '/healthz':
                row = self.https.row()
                if row['enabled'] and row['https_only']:
                    await self._refused(scope, send, row['port'] or web_tls.https_port())
                    return
        await self.app(scope, receive, send)

    @staticmethod
    async def _refused(scope, send, port):
        if scope['path'].startswith('/api/'):
            body = json.dumps({'detail': f'HTTP is not supported: this LiteBlox is HTTPS only (port {port})'})
            kind = b'application/json'
        else:
            body, kind = REFUSED_PAGE.format(port=port), b'text/html; charset=utf-8'
        data = body.encode()
        await send({'type': 'http.response.start', 'status': 403, 'headers': [
            (b'content-type', kind), (b'content-length', str(len(data)).encode()), (b'cache-control', b'no-store')]})
        await send({'type': 'http.response.body', 'body': data})


class Supervisor:
    """Starts the HTTPS server when it's on and its certificate loads, stops it when it's turned off, and keeps
    handing new connections the newest certificate that loads."""

    def __init__(self, app, settings, host, port, https_settings=None):
        self.app, self.settings, self.host, self.port = app, settings, host, port
        self.https = https_settings or Settings(settings)
        self.live = None
        self.server = None
        self.task = None
        self.sock = None
        self._recorded = None

    def _record(self, **fields):
        if fields == self._recorded:
            return
        conn = db.connect(self.settings.db_path)
        try:
            web_tls.record(conn, **fields)
        finally:
            conn.close()
        self._recorded = fields

    def _bind(self):
        family = socket.AF_INET6 if ':' in self.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.host, self.port))
            sock.listen(2048)
        except OSError:
            sock.close()
            raise
        sock.setblocking(False)
        return sock

    async def _start(self):
        # bound here, so a port in use is an error on the page, not uvicorn's sys.exit
        self.sock = self._bind()
        live = self.live
        config = uvicorn.Config(Listener(self.app, 'https', self.settings, self.https), host=self.host,
                                port=self.port, proxy_headers=True, lifespan='off',
                                ssl_context_factory=lambda config, default: live.base)
        self.server = uvicorn.Server(config)
        serve = getattr(self.server, '_serve', self.server.serve)    # no signal handlers: the HTTP server has them
        self.task = asyncio.create_task(serve(sockets=[self.sock]))
        log.info('HTTPS listening on %s:%s (certificate %s)', self.host, self.port, live.fingerprint)

    async def stop(self):
        if self.server is not None:
            self.server.should_exit = True
            try:
                await asyncio.wait_for(self.task, timeout=10)
            except (asyncio.TimeoutError, Exception):      # noqa: BLE001 (shutting down either way)
                self.task.cancel()
            log.info('HTTPS stopped')
        if self.sock is not None:
            self.sock.close()
        self.server = self.task = self.sock = None

    async def check(self):
        """One look: start, stop or re-key, and record what was found."""
        self.https._row = None          # always fresh here
        row = self.https.row()
        if not row['enabled']:
            if self.server is not None:
                await self.stop()
            self.live = None
            self._record(listening=0, port=self.port, serving=None, error=None)
            return
        if self.live is None:
            self.live = web_tls.Live(self.settings)
        if self.live.refresh() and self.server is not None:
            log.info('HTTPS certificate reloaded (%s)', self.live.fingerprint)
        if self.task is not None and self.task.done():     # it stopped on its own
            await self.stop()
        error = self.live.error
        if self.server is None and self.live.base is not None:
            try:
                await self._start()
            except OSError as e:
                error = f'port {self.port} could not be opened ({e.strerror or e})'
                log.error('HTTPS: %s', error)
        self._record(listening=int(self.server is not None), port=self.port, serving=self.live.fingerprint,
                     error=error)

    async def run(self):
        while True:
            try:
                await self.check()
            except asyncio.CancelledError:
                raise
            except Exception:       # noqa: BLE001 (logged; plain HTTP keeps serving)
                log.exception('HTTPS supervisor')
            await asyncio.sleep(CHECK_EVERY)


async def serve(app, settings, host, port, https_port):
    """Both ports until a signal stops the HTTP server."""
    shared = Settings(settings)
    http = uvicorn.Server(uvicorn.Config(Listener(app, 'http', settings, shared), host=host, port=port,
                                         proxy_headers=True, lifespan='on'))
    supervisor = Supervisor(app, settings, host, https_port, shared)
    watch = asyncio.create_task(supervisor.run())
    try:
        await http.serve()
    finally:
        watch.cancel()
        try:
            await watch
        except asyncio.CancelledError:
            pass
        await supervisor.stop()
        conn = db.connect(settings.db_path)
        try:
            web_tls.record(conn, listening=0)
        finally:
            conn.close()
