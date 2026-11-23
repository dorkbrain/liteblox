"""Nodes pages: list, add (host-key pinning), bootstrap wizard, status, zone discovery and import,
config drift and demote reports."""

import json
import re
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from .. import jobs
from ..backups import service as backups
from ..auth import User, current_user, require_admin
from ..db import audit, get_db
from ..dns.drafts import Drafts
from ..templating import templates
from . import service, ssh
from .bootstrap import Credentials, Options
from .client import AgentError

# a node's BIND pages: a node without BIND has none of them
BIND_PAGES = re.compile(r'^/nodes/(\d+)/(takeover|drift|primary|settings|zones|dns-address|reports)(/|$)')


def _bind_pages(request: Request):
    m = BIND_PAGES.match(request.url.path)
    if not m:
        return
    from ..db import connect
    conn = connect(request.app.state.settings.db_path)
    try:
        row = conn.execute('SELECT bind FROM nodes WHERE id = ?', (int(m.group(1)),)).fetchone()
    finally:
        conn.close()
    if row is not None and not row['bind']:
        raise HTTPException(status_code=404, detail="this node doesn't run BIND for LiteBlox")


router = APIRouter(dependencies=[Depends(_bind_pages)])


def _settings(request):
    return request.app.state.settings


def _node_or_404(conn, node_id):
    try:
        return service.get_node(conn, node_id)
    except service.NodeError:
        raise HTTPException(status_code=404, detail='no such node')


def _zone_rows(conn, node_id):
    return {r['name']: r for r in conn.execute(
        'SELECT z.name, z.mode, zn.deployed_sha256, zn.node_id FROM zones z '
        'LEFT JOIN zone_nodes zn ON zn.zone_id = z.id AND zn.node_id = ?', (node_id,))}


# ── list / add ─────────────────────────────────────────────────────────────────

@router.get('/nodes')
def nodes(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    rows = service.list_nodes(conn)
    settings = _settings(request)
    from ..bindconf.apply import differences
    from ..bindconf.model import node_address
    from . import roles
    groups = differences(conn)
    return templates.TemplateResponse(request, 'nodes.html', {
        'differ': groups if len(groups) > 1 else [],
        'user': user, 'nodes': rows, 'upgrade': {n['id']: service.needs_upgrade(n) for n in rows},
        'can_upgrade': [n for n in rows if service.can_upgrade(n)],
        'kinds': {n['id']: service.kind(n) for n in rows}, 'any_bind': any(n['bind'] for n in rows),
        'topology': roles.topology(conn), 'addresses': {n['id']: node_address(n) for n in rows},
        'reports': dict(conn.execute('SELECT node_id, COUNT(*) FROM demote_reports WHERE resolved_at IS NULL '
                                     'GROUP BY node_id').fetchall()),
        'stale': {n['id']: n['status'] != 'new' and backups.is_stale(conn, settings, n['id']) for n in rows},
        'readopt': _readopt_offer(conn)})


def _readopt_offer(conn):
    from ..bindconf import readopt
    found = readopt.candidates(conn)
    return found if found and not readopt.not_fresh(conn) else []


# ── re-adopt (LiteBlox's data lost, its nodes still running) ───────────────────

@router.get('/nodes/readopt')
def node_readopt_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..bindconf import readopt
    return templates.TemplateResponse(request, 'node_readopt.html', {
        'user': user, 'candidates': readopt.candidates(conn), 'not_fresh': readopt.not_fresh(conn)})


@router.post('/nodes/readopt/preview')
async def node_readopt_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..bindconf import readopt
    ids = [int(i) for i in (await request.form()).getlist('node')]
    pv = readopt.preview(conn, _settings(request), ids) if ids else None
    return templates.TemplateResponse(request, 'partials/node_readopt_preview.html', {
        'pv': pv, 'ids': ids, 'summary': readopt.summary(pv.plan) if pv and not pv.blockers else []})


@router.post('/nodes/readopt')
async def node_readopt(request: Request, user: User = Depends(require_admin)):
    from ..bindconf import readopt
    ids = [int(i) for i in (await request.form()).getlist('node')]
    if not ids:
        return RedirectResponse('/nodes/readopt', status_code=303)
    job_id = readopt.start(_settings(request), ids, user.username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


def _dns_on(request):
    from ..modules import for_request
    return for_request(request)['dns']


def _bind_choice(request, services, bind):
    """Runs DNS (BIND)? The form's box when it was shown (services=1), else yes whenever the DNS module is on."""
    if not _dns_on(request):
        return 0
    return int(bind in ('1', 'true', 'on')) if services else 1


@router.get('/nodes/new')
def node_new(request: Request, user: User = Depends(require_admin)):
    return templates.TemplateResponse(request, 'node_new.html', {
        'user': user, 'form': {'bind': _bind_choice(request, '', '')}, 'dns_on': _dns_on(request)})


@router.post('/nodes/new')
def node_new_post(request: Request, name: str = Form(...), host: str = Form(...),
                  ssh_port: int = Form(22), agent_port: int = Form(8530), services: str = Form(''),
                  bind: str = Form(''), user: User = Depends(require_admin), conn=Depends(get_db)):
    form = {'name': name.strip().lower(), 'host': host.strip(), 'ssh_port': ssh_port, 'agent_port': agent_port,
            'bind': _bind_choice(request, services, bind)}
    error = None
    if not service.NAME_RE.fullmatch(form['name']):
        error = 'Name must be lowercase letters, digits, dots or dashes.'
    elif conn.execute('SELECT 1 FROM nodes WHERE name = ?', (form['name'],)).fetchone():
        error = f"A node called {form['name']} already exists."
    else:
        try:
            host_key, fp = ssh.fetch_host_key(form['host'], ssh_port)
            return templates.TemplateResponse(request, 'node_confirm.html', {
                'user': user, 'form': form, 'key_type': host_key.split()[0], 'fingerprint': fp})
        except ssh.SSHError as e:
            error = str(e)
    return templates.TemplateResponse(request, 'node_new.html', {
        'user': user, 'form': form, 'error': error, 'dns_on': _dns_on(request)}, status_code=400)


@router.post('/nodes/confirm')
def node_confirm(request: Request, name: str = Form(...), host: str = Form(...),
                 ssh_port: int = Form(...), agent_port: int = Form(...), fingerprint: str = Form(...),
                 services: str = Form(''), bind: str = Form(''),
                 user: User = Depends(require_admin), conn=Depends(get_db)):
    form = {'name': name, 'host': host, 'ssh_port': ssh_port, 'agent_port': agent_port,
            'bind': _bind_choice(request, services, bind)}
    try:
        # fetch again: pin only the key the user actually looked at
        host_key, fp = ssh.fetch_host_key(host, ssh_port)
        if fp != fingerprint:
            raise service.NodeError('The host key changed since you confirmed it. Start again and check it.')
        node_id = service.add_node(conn, name, host, ssh_port, agent_port, host_key, fp, bind=form['bind'])
    except (ssh.SSHError, service.NodeError) as e:
        return templates.TemplateResponse(request, 'node_new.html', {
            'user': user, 'form': form, 'error': str(e), 'dns_on': _dns_on(request)}, status_code=400)
    audit(conn, user.username, 'node_add', f"{name} {host} key {fp}{'' if form['bind'] else ' (no BIND)'}")
    return RedirectResponse(f'/nodes/{node_id}/bootstrap', status_code=303)


# ── change address / re-pin host key, remove ──────────────────────────────────

@router.get('/nodes/{node_id}/edit')
def node_edit(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    return templates.TemplateResponse(request, 'node_edit.html', {'user': user, 'node': node, 'form': node})


@router.post('/nodes/{node_id}/edit')
def node_edit_post(request: Request, node_id: int, host: str = Form(...), ssh_port: int = Form(22),
                   agent_port: int = Form(8530), user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    form = {'host': host.strip(), 'ssh_port': ssh_port, 'agent_port': agent_port}
    try:
        host_key, fp = ssh.fetch_host_key(form['host'], ssh_port)
    except ssh.SSHError as e:
        return templates.TemplateResponse(request, 'node_edit.html', {
            'user': user, 'node': node, 'form': form, 'error': str(e)}, status_code=400)
    return templates.TemplateResponse(request, 'node_confirm.html', {
        'user': user, 'node': node, 'form': form, 'key_type': host_key.split()[0], 'fingerprint': fp})


@router.post('/nodes/{node_id}/edit/confirm')
def node_edit_confirm(request: Request, node_id: int, host: str = Form(...), ssh_port: int = Form(...),
                      agent_port: int = Form(...), fingerprint: str = Form(...),
                      user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    form = {'host': host, 'ssh_port': ssh_port, 'agent_port': agent_port}
    try:
        host_key, fp = ssh.fetch_host_key(host, ssh_port)
        if fp != fingerprint:
            raise service.NodeError('The host key changed since you confirmed it. Start again and check it.')
        changes = service.update_node(conn, node_id, host, ssh_port, agent_port, host_key, fp)
    except (ssh.SSHError, service.NodeError) as e:
        return templates.TemplateResponse(request, 'node_edit.html', {
            'user': user, 'node': node, 'form': form, 'error': str(e)}, status_code=400)
    if changes:
        audit(conn, user.username, 'node_update', f"{node['name']}: {'; '.join(changes)}")
    return RedirectResponse(f'/nodes/{node_id}', status_code=303)


@router.post('/nodes/{node_id}/dns-address')
def node_dns_address(request: Request, node_id: int, dns_address: str = Form(''),
                     user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    try:
        service.set_dns_address(conn, node['id'], dns_address)
    except service.NodeError as e:
        return RedirectResponse(f'/nodes/{node_id}?error={e}', status_code=303)
    audit(conn, user.username, 'node_dns_address', f"{node['name']}: {dns_address.strip() or '(the address)'}")
    from ..dhcp import apply as dhcp_apply
    if node['role'] == 'primary' and any(dhcp_apply.stale(conn, n) for n in dhcp_apply.dhcp_nodes(conn)):
        # DHCP sends its DNS updates to the primary's address
        settings, username = _settings(request), user.username

        def run(log):
            from .. import db as db_mod
            from .roles import follow_dhcp
            c = db_mod.connect(settings.db_path)
            try:
                follow_dhcp(c, settings, log)
            finally:
                c.close()
        job_id = jobs.start(settings.db_path, 'dhcp config', run, node_id=node['id'], username=username)
        return RedirectResponse(f'/jobs/{job_id}', status_code=303)
    return RedirectResponse(f'/nodes/{node_id}', status_code=303)


@router.post('/nodes/{node_id}/upgrade-agent')
def node_upgrade_agent(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    """The image's agent over mTLS: the node's root installer puts it in place on the agent's restart."""
    node = _node_or_404(conn, node_id)
    if not service.can_upgrade(node):
        return RedirectResponse(f"/nodes/{node_id}?error={quote('This node needs Repair / upgrade agent over SSH')}",
                                status_code=303)
    try:
        job_id = service.start_agent_upgrade(_settings(request), [node['id']], user.username)
    except service.NodeError as e:
        return RedirectResponse(f'/nodes/{node_id}?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/nodes/upgrade-agents')
def nodes_upgrade_agents(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    """Every node whose agent can be upgraded over mTLS, one at a time."""
    ids = [n['id'] for n in service.list_nodes(conn) if service.can_upgrade(n)]
    if not ids:
        return RedirectResponse('/nodes', status_code=303)
    try:
        job_id = service.start_agent_upgrade(_settings(request), ids, user.username)
    except service.NodeError as e:
        return RedirectResponse(f'/nodes?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/nodes/{node_id}/primary')
def node_make_primary(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import roles
    node = _node_or_404(conn, node_id)
    settings, username = _settings(request), user.username
    primary = roles.topology(conn)['primary']
    kind = 'promote' if primary is not None and primary['id'] != node['id'] else 'make primary'
    job_id = jobs.start(settings.db_path, kind,
                        lambda log: roles.make_primary(settings, node['id'], username, log),
                        node_id=node['id'], username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.get('/nodes/{node_id}/remove')
def node_remove_form(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    return templates.TemplateResponse(request, 'node_remove.html', {
        'user': user, 'node': node, 'zones': service.removal_impact(conn, node_id)})


@router.post('/nodes/{node_id}/remove')
def node_remove(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    try:
        service.remove_node(conn, node_id)
    except service.NodeError as e:
        return templates.TemplateResponse(request, 'node_remove.html', {
            'user': user, 'node': node, 'zones': service.removal_impact(conn, node_id), 'error': str(e)},
            status_code=409)
    audit(conn, user.username, 'node_remove', f"{node['name']} {node['host']}")
    return RedirectResponse('/nodes', status_code=303)


# ── detail / status / zones ────────────────────────────────────────────────────

@router.get('/nodes/{node_id}')
def node_detail(request: Request, node_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    recent = conn.execute('SELECT id, kind, status, username, created_at FROM jobs WHERE node_id = ? '
                          'ORDER BY id DESC LIMIT 5', (node_id,)).fetchall()
    zones = conn.execute('SELECT z.name, z.mode, zn.node_file FROM zone_nodes zn JOIN zones z '
                         'ON z.id = zn.zone_id WHERE zn.node_id = ? ORDER BY z.name', (node_id,)).fetchall()
    from ..bindconf.model import node_address
    from . import reports, roles
    return templates.TemplateResponse(request, 'node_detail.html', {
        'user': user, 'node': node, 'jobs': recent, 'zones': zones, 'address': node_address(node),
        'error': request.query_params.get('error'), 'done': request.query_params.get('done'),
        'primary': roles.topology(conn)['primary'], 'reports': reports.open_reports(conn, node_id),
        'drift': json.loads(node['drift'] or '[]'), 'second': json.loads(node['second_primary'] or '[]'),
        'needs_upgrade': service.needs_upgrade(node), 'needs_repair': service.needs_repair(node),
        'can_upgrade': service.can_upgrade(node),
        'clock': service.clock_state(node), 'kind': service.kind(node),
        'stale': node['status'] != 'new' and backups.is_stale(conn, _settings(request), node_id)})


@router.get('/nodes/{node_id}/status')
def node_status(request: Request, node_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    status, error = service.refresh(conn, _settings(request), node)
    return templates.TemplateResponse(request, 'partials/node_status.html', {
        'node': service.get_node(conn, node_id), 'status': status, 'error': error})


@router.get('/nodes/{node_id}/dhcp')
def node_dhcp(request: Request, node_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    """The DHCP card: Kea's state, the node's interfaces, and drift with a diff."""
    import difflib
    from ..bindconf.model import node_address
    from ..dhcp.apply import files_for
    node = _node_or_404(conn, node_id)
    from ..dhcp.model import interfaces_of, subnets
    ctx = {'user': user, 'node': node, 'status': None, 'error': None, 'diff': '',
           'drift': json.loads(node['dhcp_drift'] or '[]'), 'own': {node['host'], node_address(node)},
           'served': interfaces_of(node), 'subnets': subnets(conn)}
    try:
        with service.agent_client(_settings(request), node) as c:
            ctx['status'] = c.status()
            if ctx['drift']:
                now, ours = c.dhcp_files(), files_for(conn, node)
                ctx['diff'] = ''.join(''.join(difflib.unified_diff(
                    service.mask_secrets(ours[r]).splitlines(True), service.mask_secrets(now.get(r)).splitlines(True),
                    f'{r} as LiteBlox wrote it', f'{r} on {node["name"]} now')) for r in ctx['drift'])
    except AgentError as e:
        ctx['error'] = e.message
    return templates.TemplateResponse(request, 'partials/node_dhcp.html', ctx)


@router.post('/nodes/{node_id}/dhcp/rewrite')
def node_dhcp_rewrite(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..dhcp import apply as dhcp_apply
    node = _node_or_404(conn, node_id)
    if not node['dhcp']:
        return RedirectResponse(f"/nodes/{node_id}?error={quote('Kea is not set up on this node')}", status_code=303)
    job_id = dhcp_apply.start_rewrite(_settings(request), node_id, user.username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.get('/nodes/{node_id}/zones')
def node_zones(request: Request, node_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    try:
        with service.agent_client(_settings(request), node) as c:
            cfg = c.config()
    except AgentError as e:
        return templates.TemplateResponse(request, 'partials/node_zones.html', {'error': e.message})
    known = _zone_rows(conn, node_id)
    return templates.TemplateResponse(request, 'partials/node_zones.html', {
        'user': user, 'node': node, 'zones': cfg['zones'], 'known': known,
        'checkconf': service.mask_secrets(cfg['checkconf'])})


@router.get('/nodes/{node_id}/bootstrap')
def node_bootstrap_form(request: Request, node_id: int, user: User = Depends(require_admin),
                        conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    # each box starts from the node's state: what's set up stays ticked (a repair keeps it), ?dhcp=1 / ?ntp=1
    # (the Set up links) tick it for a node without it, and only a fresh node is taken over by default
    q = request.query_params
    return templates.TemplateResponse(request, 'node_bootstrap.html', {
        'user': user, 'node': node, 'insecure': _insecure(request),
        'dhcp': bool(node['dhcp']) or q.get('dhcp') == '1', 'ntp': bool(node['ntp']) or q.get('ntp') == '1',
        'takeover': not node['agent_version'] and not node['managed'],
        # the BIND box: while nothing in LiteBlox needs the node's BIND, and (to add BIND) the DNS module is on
        'bind_fixed': service.bind_change_blocked(conn, node), 'dns_on': _dns_on(request)})


def _insecure(request):
    host = request.url.hostname or ''
    return request.url.scheme != 'https' and host not in ('localhost', '127.0.0.1', '::1')


@router.post('/nodes/{node_id}/bootstrap')
def node_bootstrap(request: Request, node_id: int, ssh_user: str = Form(...), ssh_password: str = Form(...),
                   sudo_password: str = Form(''), install_bind: bool = Form(False),
                   fix_permissions: bool = Form(False),
                   takeover: bool = Form(False), dhcp: bool = Form(False), ntp: bool = Form(False),
                   services: str = Form(''), bind: str = Form(''),
                   user: User = Depends(require_admin),
                   conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    creds = Credentials(ssh_user.strip(), password=ssh_password, sudo_password=sudo_password or None)
    # the box is only on the form while the choice can change; otherwise the node keeps its own
    chosen = None
    if services and not service.bind_change_blocked(conn, node):
        chosen = bind in ('1', 'true', 'on') and (_dns_on(request) or bool(node['bind']))
    options = Options(bind=chosen, install_bind=install_bind, fix_permissions=fix_permissions, takeover=takeover,
                      dhcp=dhcp, ntp=ntp)
    job_id = service.start_bootstrap(_settings(request), node['id'], creds, options, user.username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── server settings ────────────────────────────────────────────────────────────

def _settings_page(request, user, conn, node, values, error=None, chosen=(), status_code=200, source=None,
                   kept=False):
    from ..bindconf import apply
    others = [n for n in service.list_nodes(conn) if n['managed'] and n['id'] != node['id']]
    return templates.TemplateResponse(request, 'node_settings.html', {
        'user': user, 'node': node, 'v': values, 'others': others, 'error': error, 'chosen': chosen,
        'source': source, 'kept': kept, 'choices': apply.CHOICES}, status_code=status_code)


@router.get('/nodes/{node_id}/settings')
def node_settings(request: Request, node_id: int, copy: int = 0, user: User = Depends(current_user),
                  conn=Depends(get_db)):
    from ..bindconf import apply
    from ..bindconf.model import NodeOptions
    node = _node_or_404(conn, node_id)
    source = _node_or_404(conn, copy) if copy else node
    values = apply.form_values(NodeOptions.from_json(source['options']), source['top_extra'])
    return _settings_page(request, user, conn, node, values, source=source if copy else None)


def _settings_targets(conn, node, also):
    ids = [node['id']] + [int(i) for i in also if int(i) != node['id']]
    return [service.get_node(conn, i) for i in ids]


@router.post('/nodes/{node_id}/settings/preview')
async def node_settings_preview(request: Request, node_id: int, user: User = Depends(require_admin),
                                conn=Depends(get_db)):
    from ..bindconf import apply
    node = _node_or_404(conn, node_id)
    form = await request.form()
    try:
        options, top_extra = apply.parse_settings(form)
        results = [(n, apply.preview(conn, _settings(request), n, options, top_extra))
                   for n in _settings_targets(conn, node, form.getlist('also'))]
        error = None
    except (ValueError, service.NodeError) as e:
        results, error = [], str(e)
    return templates.TemplateResponse(request, 'partials/node_settings_preview.html', {
        'results': results, 'error': error,
        'problems': any(pv['problems'] for _, pv in results),
        'changed': any(pv['diff'] for _, pv in results),
        'blocks': any(level == 'block' for _, pv in results for level, _ in pv['findings'])})


@router.post('/nodes/{node_id}/settings')
async def node_settings_post(request: Request, node_id: int, user: User = Depends(require_admin),
                             conn=Depends(get_db)):
    from ..bindconf import apply
    node = _node_or_404(conn, node_id)
    form = await request.form()
    also = form.getlist('also')
    try:
        options, top_extra = apply.parse_settings(form)
        targets = _settings_targets(conn, node, also)
        not_taken = [n['name'] for n in targets if not n['managed']]
        if not_taken:
            raise ValueError(f"{', '.join(not_taken)} is not taken over yet")
        recursion_probe, blocks = {}, []
        for n in targets:
            pv = apply.preview(conn, _settings(request), n, options, top_extra)
            if pv['problems']:
                raise ValueError(f"{n['name']}: " + '; '.join(pv['problems']))
            recursion_probe[n['id']] = pv['recursion_probe']
            blocks += [f"{n['name']}: {msg}" for level, msg in pv['findings'] if level == 'block']
        if blocks and not form.get('apply_anyway'):
            raise ValueError('this would lock LiteBlox out: ' + '; '.join(blocks)
                             + '. Tick "Apply anyway" if you mean it (the probes will roll it back if it breaks).')
    except (ValueError, service.NodeError) as e:
        values = {k: form.get(k, '') for k in apply.form_values(apply.NodeOptions(), '')}
        return _settings_page(request, user, conn, node, values, error=str(e), chosen=also, status_code=422)
    settings, username = _settings(request), user.username
    ids = [n['id'] for n in targets]
    job_id = jobs.start(settings.db_path, 'server settings',
                        lambda log: apply.set_node_settings(settings, ids, options, top_extra, username, log,
                                                            recursion_probe=recursion_probe),
                        node_id=node['id'], username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── takeover ───────────────────────────────────────────────────────────────────

@router.get('/nodes/{node_id}/takeover')
def node_takeover_page(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    return templates.TemplateResponse(request, 'node_takeover.html', {
        'user': user, 'node': _node_or_404(conn, node_id)})


@router.get('/nodes/{node_id}/takeover/preview')
def node_takeover_preview(request: Request, node_id: int, user: User = Depends(require_admin),
                          conn=Depends(get_db)):
    from ..bindconf import takeover
    node = _node_or_404(conn, node_id)
    try:
        pv, error = takeover.preview(conn, _settings(request), node), None
    except takeover.TakeoverError as e:
        pv, error = None, str(e)
    return templates.TemplateResponse(request, 'partials/node_takeover_preview.html', {
        'node': node, 'pv': pv, 'error': error,
        'fields': takeover.option_fields(pv.plan.config.options) if pv else []})


@router.post('/nodes/{node_id}/takeover')
def node_takeover(request: Request, node_id: int, current_sha: str = Form(...),
                  user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..bindconf import takeover
    node = _node_or_404(conn, node_id)
    job_id = takeover.start(_settings(request), node['id'], user.username, expect_sha=current_sha)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── jobs ───────────────────────────────────────────────────────────────────────

def _job_context(conn, job):
    # read on every poll: a create-zone job only learns its zone when it finishes
    node = service.get_node(conn, job['node_id']) if job['node_id'] else None
    zone = conn.execute('SELECT name FROM zones WHERE id = ?', (job['zone_id'],)).fetchone() if job['zone_id'] else None
    return {'job': job, 'node': node, 'zone': zone['name'] if zone else None}


JOBS_PAGE = 50


def _took(job):
    if not job['finished_at']:
        return ''
    seconds = int((datetime.fromisoformat(job['finished_at']) - datetime.fromisoformat(job['created_at'])).total_seconds())
    return f'{seconds} s' if seconds < 60 else f'{seconds // 60} min {seconds % 60} s'


@router.get('/jobs')
def jobs_list(request: Request, kind: str = '', status: str = '', node: str = '', before: int = 0,
              user: User = Depends(current_user), conn=Depends(get_db)):
    """Every job, newest first, filtered by kind, status or node and paged by id."""
    where, args = [], []
    for column, value in (('j.kind', kind), ('j.status', status), ('n.name', node)):
        if value:
            where.append(f'{column} = ?')
            args.append(value)
    if before:
        where.append('j.id < ?')
        args.append(before)
    rows = conn.execute('SELECT j.id, j.kind, j.status, j.username, j.created_at, j.finished_at, j.node_id, '
                        "n.name AS node, z.name AS zone, instr(j.log, '⚠') > 0 AS warned FROM jobs j "
                        'LEFT JOIN nodes n ON n.id = j.node_id LEFT JOIN zones z ON z.id = j.zone_id'
                        + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY j.id DESC LIMIT ?',
                        (*args, JOBS_PAGE + 1)).fetchall()
    return templates.TemplateResponse(request, 'jobs.html', {
        'user': user, 'rows': [{**dict(r), 'took': _took(r)} for r in rows[:JOBS_PAGE]], 'more': len(rows) > JOBS_PAGE,
        'filters': {'kind': kind, 'status': status, 'node': node},
        'kinds': [r[0] for r in conn.execute('SELECT DISTINCT kind FROM jobs ORDER BY kind')],
        'nodes': [r[0] for r in conn.execute('SELECT name FROM nodes ORDER BY name')]})


@router.get('/jobs/{job_id}')
def job_page(request: Request, job_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    job = jobs.get(conn, job_id)
    if job is None:
        return Response('no such job', status_code=404)
    return templates.TemplateResponse(request, 'job.html', {'user': user, **_job_context(conn, job)})


@router.get('/jobs/{job_id}/log')
def job_log(request: Request, job_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    job = jobs.get(conn, job_id)
    if job is None:
        return Response('no such job', status_code=404)
    # htmx stops polling on 286
    return templates.TemplateResponse(request, 'partials/job_log.html', _job_context(conn, job),
                                      status_code=286 if job['status'] != 'running' else 200)


# ── config drift ───────────────────────────────────────────────────────────────

@router.get('/nodes/{node_id}/drift')
def node_drift(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..dns.publish import served_serial
    from ..bindconf.model import node_address
    from . import drift, roles
    node = _node_or_404(conn, node_id)
    try:
        text, error = drift.diff(_settings(request), conn, node), None
    except (AgentError, drift.DriftError) as e:
        text, error = '', getattr(e, 'message', str(e))
    roles_changed = json.loads(node['drift'] or '[]')
    second = json.loads(node['second_primary'] or '[]')
    primary = roles.topology(conn)['primary']
    serials = [(z, served_serial(node_address(primary), z) if primary else None, served_serial(node_address(node), z))
               for z in second]
    return templates.TemplateResponse(request, 'node_drift.html', {
        'user': user, 'node': node, 'diff': text, 'error': error, 'changed': roles_changed, 'second': second,
        'serials': serials, 'primary': primary, 'keepable': bool(roles_changed) and set(roles_changed) <= drift.KEEPABLE})


@router.post('/nodes/{node_id}/drift/overwrite')
def node_drift_overwrite(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import drift
    node = _node_or_404(conn, node_id)
    settings, username = _settings(request), user.username
    job_id = jobs.start(settings.db_path, 'overwrite config',
                        lambda log: drift.overwrite(settings, node['id'], username, log),
                        node_id=node['id'], username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.get('/nodes/{node_id}/drift/keep')
def node_drift_keep(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    """The server settings form filled in from the node's own options.conf / top.conf, to review and apply."""
    from . import drift
    node = _node_or_404(conn, node_id)
    try:
        values = drift.kept_settings(_settings(request), conn, node)
    except (AgentError, drift.DriftError) as e:
        message = getattr(e, 'message', str(e))
        return RedirectResponse(f'/nodes/{node_id}?error={quote(message)}', status_code=303)
    return _settings_page(request, user, conn, node, values, kept=True)


# ── demote reports ─────────────────────────────────────────────────────────────

def _report_or_404(conn, node_id, report_id):
    from . import reports
    report = reports.get(conn, report_id)
    if report is None or report['node_id'] != node_id:
        raise HTTPException(status_code=404, detail='no such report')
    return report


@router.get('/nodes/{node_id}/reports/{report_id}')
def node_report(request: Request, node_id: int, report_id: int, user: User = Depends(current_user),
                conn=Depends(get_db)):
    node = _node_or_404(conn, node_id)
    return templates.TemplateResponse(request, 'node_report.html', {
        'user': user, 'node': node, 'report': _report_or_404(conn, node_id, report_id),
        'error': request.query_params.get('error'), 'done': request.query_params.get('done')})


@router.get('/nodes/{node_id}/reports/{report_id}/old')
def node_report_old(request: Request, node_id: int, report_id: int, user: User = Depends(current_user),
                    conn=Depends(get_db)):
    report = _report_or_404(conn, node_id, report_id)
    return PlainTextResponse(report['old_text'], headers={
        'Content-Disposition': f'attachment; filename="{report["zone"]}.{report["node"]}.old"'})


@router.post('/nodes/{node_id}/reports/{report_id}/reapply')
async def node_report_reapply(request: Request, node_id: int, report_id: int, user: User = Depends(require_admin),
                              conn=Depends(get_db)):
    from ..dns import dynamic
    from . import reports
    _report_or_404(conn, node_id, report_id)
    picks = [int(i) for i in (await request.form()).getlist('pick') if i.isdigit()]
    base = f'/nodes/{node_id}/reports/{report_id}'
    try:
        done = reports.reapply(_settings(request), conn, report_id, picks, user.username)
    except (reports.ReportError, dynamic.DynamicError) as e:
        return RedirectResponse(f'{base}?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'{base}?done={quote(done)}', status_code=303)


@router.post('/nodes/{node_id}/reports/{report_id}/dismiss')
def node_report_dismiss(request: Request, node_id: int, report_id: int, user: User = Depends(require_admin),
                        conn=Depends(get_db)):
    from . import reports
    _report_or_404(conn, node_id, report_id)
    reports.dismiss(conn, report_id, user.username)
    return RedirectResponse(f'/nodes/{node_id}?done={quote("Report dismissed")}', status_code=303)
