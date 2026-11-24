"""Modules (4.0): which of DNS, DHCP, Time and IPAM this install runs (Settings → Modules).

A module that's off is hidden everywhere (menus, Dashboard, problems, search, help) and its pages and API answer 404.
One that's in use can't be switched off: what uses it has to go first, so nothing keeps running unseen.
"""

import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .auth import User, require_admin
from .db import audit, connect, get_db

NAMES = ('dns', 'dhcp', 'ntp', 'ipam')
LABELS = {'dns': 'DNS', 'dhcp': 'DHCP', 'ntp': 'Time', 'ipam': 'IPAM'}
ABOUT = {
    'dns': 'BIND9 on your nodes: zones, records, primary and secondaries, dynamic zones and TSIG keys.',
    'dhcp': 'Kea on your nodes: subnets, pools, reservations, leases, a failover pair and DNS registration.',
    'ntp': 'chrony on your nodes: one list of time sources, and the nodes serving time to your network.',
    'ipam': 'Networks and ranges, every address used and free, devices seen, next free addresses and sweeps.',
}
# the pages and API of each module (a node's own sub-pages too)
PATHS = {
    'dns': re.compile(r'^/(zones|settings/(acls|keys)|api/v1/zones|nodes/\d+/(takeover|drift|primary|settings|zones|'
                      r'dns-address|reports))(/|$)'),
    'dhcp': re.compile(r'^/(dhcp|api/v1/dhcp|nodes/\d+/dhcp)(/|$)'),
    'ntp': re.compile(r'^/(settings/time|api/v1/ntp|nodes/\d+/time)(/|$)'),
    'ipam': re.compile(r'^/(ipam|settings/ipam|api/v1/ipam)(/|$)'),
}


class ModuleOff(Exception):
    def __init__(self, name):
        super().__init__(f"the {LABELS[name]} module is off (Settings → Modules)")
        self.name = name


def enabled(conn):
    """{name: bool} for the four modules."""
    row = conn.execute('SELECT * FROM modules WHERE id = 1').fetchone()
    return {n: bool(row[n]) if row else True for n in NAMES}


def chosen(conn):
    row = conn.execute('SELECT chosen_at FROM modules WHERE id = 1').fetchone()
    return bool(row and row['chosen_at'])


def for_request(request):
    """enabled() once per request, for templates and the guard."""
    found = getattr(request.state, 'modules', None)
    if found is None:
        conn = connect(request.app.state.settings.db_path)
        try:
            found = request.state.modules = enabled(conn)
        finally:
            conn.close()
    return found


def _count(conn, sql):
    return conn.execute(sql).fetchone()[0]


def _things(*pairs):
    """'3 zones and 1 node with Kea': each pair is (count, singular) or (count, (singular, plural))."""
    def one(n, what):
        single, plural = what if isinstance(what, tuple) else (what, what + 's')
        return f'{n} {single if n == 1 else plural}'
    return ' and '.join(one(n, what) for n, what in pairs if n)


def in_use(conn, name):
    """What keeps the module on ('3 zones and 2 BIND nodes'), or None when it can go."""
    if name == 'dns':
        return _things((_count(conn, 'SELECT COUNT(*) FROM zones'), 'zone'),
                       (_count(conn, 'SELECT COUNT(*) FROM nodes WHERE bind = 1'), 'BIND node')) or None
    if name == 'dhcp':
        return _things((_count(conn, 'SELECT COUNT(*) FROM nodes WHERE dhcp = 1'), ('node with Kea', 'nodes with Kea')),
                       (_count(conn, 'SELECT COUNT(*) FROM dhcp4_subnets'), 'DHCP subnet'),
                       (_count(conn, 'SELECT COUNT(*) FROM dhcp6_subnets'), 'DHCPv6 subnet')) or None
    if name == 'ntp':
        return _things((_count(conn, 'SELECT COUNT(*) FROM nodes WHERE ntp = 1'), ('node with chrony', 'nodes with chrony'))) or None
    return None     # IPAM only reads what's there


def save(conn, wanted):
    """Switch the modules to wanted ({name: bool}); returns {name: why not} for those that can't go off."""
    current = enabled(conn)
    errors = {}
    for name in NAMES:
        if current[name] and not wanted[name]:
            why = in_use(conn, name)
            if why:
                errors[name] = f'in use: remove {why} first'
    if not any(wanted.values()):
        errors['all'] = 'keep at least one module on'
    if errors:
        return errors
    with conn:
        conn.execute("UPDATE modules SET dns = ?, dhcp = ?, ntp = ?, ipam = ?, chosen_at = datetime('now') "
                     'WHERE id = 1', tuple(int(bool(wanted[n])) for n in NAMES))
    return {}


def describe(found):
    return ', '.join(LABELS[n] for n in NAMES if found[n]) or 'none'


def module_of(path):
    return next((n for n, rx in PATHS.items() if rx.match(path)), None)


async def guard(request: Request):
    """App-wide dependency: a page or API call of a module that's off answers 404."""
    name = module_of(request.url.path)
    if name and not for_request(request)[name]:
        raise ModuleOff(name)


# ── Settings → Modules ──

router = APIRouter()


def _page(request, user, conn, wanted=None, errors=None, done=None, status_code=200):
    from .templating import templates
    current = enabled(conn)
    return templates.TemplateResponse(request, 'settings_modules.html', {
        'user': user, 'tab': 'modules', 'names': NAMES, 'labels': LABELS, 'about': ABOUT,
        'wanted': wanted or current, 'errors': errors or {}, 'done': done, 'chosen': chosen(conn),
        'in_use': {n: in_use(conn, n) for n in NAMES}}, status_code=status_code)


@router.get('/settings/modules')
def modules_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _page(request, user, conn, done=request.query_params.get('done'))


@router.post('/settings/modules')
async def modules_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    wanted = {n: form.get(n) == 'on' for n in NAMES}
    before = enabled(conn)
    errors = save(conn, wanted)
    if errors:
        return _page(request, user, conn, wanted, errors, status_code=422)
    audit(conn, user.username, 'modules', describe(wanted))
    if form.get('next') == 'dashboard':
        return RedirectResponse('/', status_code=303)
    changed = before != wanted
    return RedirectResponse('/settings/modules' + ('?done=Saved.' if changed else ''), status_code=303)
