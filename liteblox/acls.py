"""ACLs: named address-match lists LiteBlox writes into every node's acls.conf.

Every add, change or delete is applied to each taken-over node in turn,
with probes and an all-or-nothing rollback (bindconf.apply). A list that's
still referenced (by node settings, a zone's lists, or another ACL) can't
be deleted.
"""

import json
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from . import db, jobs
from .auth import User, require_admin
from .bindconf.model import Acl, NodeOptions, global_acls
from .db import get_db
from .templating import templates

router = APIRouter()

NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}')
BUILTIN = ('any', 'none', 'localhost', 'localnets')
LIST_FIELDS = ('listen_on', 'listen_on_v6', 'allow_query', 'allow_recursion')
ZONE_LISTS = ('allow_transfer', 'allow_query', 'also_notify')


class AclError(ValueError):
    pass


def check_name(name):
    name = (name or '').strip()
    if not NAME_RE.fullmatch(name):
        raise AclError('an ACL name is letters, digits, - and _ (starting with a letter or digit)')
    if name.lower() in BUILTIN:
        raise AclError(f'{name} is built into BIND')
    return name


def check_items(text):
    from .dns.declare import parse_list
    items = parse_list(text)
    if not items:
        raise AclError('add at least one address, network, ACL name or "key NAME"')
    return items


def _refers(items, name):
    return any(i.lstrip('!').strip() == name for i in items)


def references(conn, name):
    """Where the ACL is used: ['node ns1: allow-query', 'zone example.com: allow-transfer', 'ACL other', ...]."""
    from .dns.declare import parse_list
    word = re.compile(r'(?<![\w.-])' + re.escape(name) + r'(?![\w.-])')
    out = []
    for n in conn.execute('SELECT * FROM nodes WHERE managed = 1 ORDER BY name'):
        options = NodeOptions.from_json(n['options'])
        for field in LIST_FIELDS:
            if _refers(getattr(options, field) or [], name):
                out.append(f"node {n['name']}: {field.replace('_', '-')}")
        if word.search(options.extra) or word.search(n['top_extra'] or ''):
            out.append(f"node {n['name']}: extra statements")
    for z in conn.execute('SELECT * FROM zones ORDER BY name'):
        for field in ZONE_LISTS:
            try:
                if _refers(parse_list(z[field]), name):
                    out.append(f"zone {z['name']}: {field.replace('_', '-')}")
            except ValueError:
                pass
    for a in global_acls(conn):
        if a.name != name and _refers(a.items, name):
            out.append(f'ACL {a.name}')
    return out


def _targets(conn):
    return [r['id'] for r in conn.execute("SELECT id FROM nodes WHERE managed = 1 AND status = 'ready'")]


def _apply(settings, conn, change, undo, reason, username, log):
    from .bindconf.apply import apply_nodes
    targets = _targets(conn)
    if not targets:
        change(conn)
        log('  no taken-over nodes yet: saved in LiteBlox only')
        return
    apply_nodes(settings, conn, targets, change, undo, reason, username, log)


def save(settings, name, items, username, log, create):
    """Add (create=True) or change an ACL, then write acls.conf on every taken-over node."""
    conn = db.connect(settings.db_path)
    try:
        row = conn.execute('SELECT * FROM acls WHERE name = ?', (name,)).fetchone()
        if create and row:
            raise AclError(f'there is already an ACL named {name}')
        if not create and not row:
            raise AclError(f'no ACL named {name}')
        if name in items or _loops(conn, name, items):
            raise AclError(f'{name} would include itself')

        def change(c):
            with c:
                if create:
                    c.execute('INSERT INTO acls (name, items) VALUES (?, ?)', (name, json.dumps(items)))
                else:
                    c.execute('UPDATE acls SET items = ? WHERE name = ?', (json.dumps(items), name))

        def undo(c):
            with c:
                if create:
                    c.execute('DELETE FROM acls WHERE name = ?', (name,))
                else:
                    c.execute('UPDATE acls SET items = ? WHERE name = ?', (row['items'], name))
        log(f"{'Adding' if create else 'Changing'} ACL {name}: {', '.join(items)}")
        _apply(settings, conn, change, undo, f"{'add' if create else 'change'} ACL {name}", username, log)
        db.audit(conn, username, 'acl_add' if create else 'acl_change', name)
        log(f'✓ ACL {name} is on every taken-over node')
    finally:
        conn.close()


def _loops(conn, name, items, seen=None):
    """Would `name` reach itself through the ACLs it names?"""
    acls = {a.name: a.items for a in global_acls(conn)}
    acls[name] = items
    seen = seen or set()
    todo = [i.lstrip('!').strip() for i in items]
    while todo:
        item = todo.pop()
        if item == name:
            return True
        if item in acls and item not in seen:
            seen.add(item)
            todo += [i.lstrip('!').strip() for i in acls[item]]
    return False


def delete(settings, name, username, log):
    conn = db.connect(settings.db_path)
    try:
        row = conn.execute('SELECT * FROM acls WHERE name = ?', (name,)).fetchone()
        if not row:
            raise AclError(f'no ACL named {name}')
        used = references(conn, name)
        if used:
            raise AclError(f"{name} is still used by {'; '.join(used)}")

        def change(c):
            with c:
                c.execute('DELETE FROM acls WHERE name = ?', (name,))

        def undo(c):
            with c:
                c.execute('INSERT INTO acls (name, items) VALUES (?, ?)', (name, row['items']))
        log(f'Deleting ACL {name}')
        _apply(settings, conn, change, undo, f'delete ACL {name}', username, log)
        db.audit(conn, username, 'acl_delete', name)
        log(f'✓ ACL {name} deleted')
    finally:
        conn.close()


# ── pages ──────────────────────────────────────────────────────────────────────

def _page(request, user, conn, error=None, form=None, status_code=200):
    acls = [(a, references(conn, a.name)) for a in global_acls(conn)]
    return templates.TemplateResponse(request, 'acls.html', {
        'user': user, 'acls': acls, 'error': error, 'form': form or {}}, status_code=status_code)


@router.get('/settings')
def settings_index(request: Request, user: User = Depends(require_admin)):
    from .modules import for_request
    on = for_request(request)
    first = '/settings/acls' if on['dns'] else '/settings/time' if on['ntp'] else '/settings/ipam' if on['ipam'] \
        else '/settings/modules'
    return RedirectResponse(first, status_code=303)


@router.get('/settings/acls')
def acls_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _page(request, user, conn, error=request.query_params.get('error'))


def _job(request, kind, fn, username):
    settings = request.app.state.settings
    job_id = jobs.start(settings.db_path, kind, fn, username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/settings/acls')
def acl_save(request: Request, name: str = Form(...), items: str = Form(''), create: bool = Form(False),
             user: User = Depends(require_admin), conn=Depends(get_db)):
    try:
        name = check_name(name)
        values = check_items(items)
    except (AclError, ValueError) as e:
        return _page(request, user, conn, error=str(e), form={'name': name, 'items': items, 'create': create},
                     status_code=422)
    settings, username = request.app.state.settings, user.username
    return _job(request, 'ACL', lambda log: save(settings, name, values, username, log, create), username)


@router.post('/settings/acls/{name}/delete')
def acl_delete(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    used = references(conn, name)
    if used:
        return RedirectResponse(f"/settings/acls?error={name} is still used by {'; '.join(used)}", status_code=303)
    settings, username = request.app.state.settings, user.username
    return _job(request, 'ACL', lambda log: delete(settings, name, username, log), username)
