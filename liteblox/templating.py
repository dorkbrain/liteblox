"""Shared Jinja2 environment for all routers."""

import hashlib
import json
from pathlib import Path

from fastapi.templating import Jinja2Templates

from .auth import csrf_token
from .activity import job_label, label as action_label
from .timefmt import ago, duration, local, offset, reltime
from .version import __version__

STATIC_DIR = Path(__file__).parent / 'static'


def has_asset(path):
    return (STATIC_DIR / path).is_file()


def asset(path):
    """Static URL with a content hash, so browsers fetch a changed file instead of a cached one."""
    digest = hashlib.sha256((STATIC_DIR / path).read_bytes()).hexdigest()[:10]
    return f'/static/{path}?v={digest}'


templates = Jinja2Templates(directory=Path(__file__).parent / 'templates')
templates.env.globals.update(version=__version__, csrf_token=csrf_token, asset=asset, has_asset=has_asset)
templates.env.filters.update(localtime=local, duration=duration, ago=ago, reltime=reltime, offset=offset,
                             job_label=job_label, action_label=action_label, fromjson=lambda s: json.loads(s) if s else None)


def health(request):
    """(level, count) for the top bar's dot: error, warn or ok, and how many problems need an admin."""
    from .status import cached_level
    return cached_level(request.app.state.settings)


templates.env.globals['health'] = health


def modules_on(request):
    """{dns, dhcp, ntp, ipam: bool} for this request (Settings → Modules)."""
    from .modules import for_request
    return for_request(request)


templates.env.globals['modules_on'] = modules_on


def _module_texts():
    from . import modules
    templates.env.globals.update(module_names=modules.NAMES, module_labels=modules.LABELS, module_about=modules.ABOUT)


_module_texts()


def mac_vendor(request, mac):
    """The second line under a MAC: its device label and its vendor from IPAM's list ('' with neither)."""
    from .ipam import devices, oui
    if not mac:
        return ''
    settings = request.app.state.settings
    found = getattr(request.state, 'device_labels', None)
    if found is None:       # read once per page
        from .db import connect
        conn = connect(settings.db_path)
        try:
            found = request.state.device_labels = devices.labels(conn)
            request.state.device_repeaters = devices.repeaters(conn)
        finally:
            conn.close()
    from .ipam.seen import mac_text
    m = mac_text(mac)
    return devices.line(found.get(m, ''), oui.vendor(settings, mac), m in request.state.device_repeaters)


templates.env.globals['vendor'] = mac_vendor
