"""Settings → Time (the sources every node syncs from) and each node's Time card."""

import difflib
import json
from urllib.parse import quote

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from ..auth import User, current_user, require_admin
from ..db import audit, get_db
from ..nodes import service as nodes
from ..nodes.client import AgentError
from ..templating import templates
from . import apply, validate
from .model import DEFAULT_LOCAL_STRATUM, custom, ntp_nodes, sources, to_json

router = APIRouter()


def _settings(request):
    return request.app.state.settings


def _states(conn):
    return {n['id']: json.loads(n['ntp_state']) if n['ntp_state'] else None for n in ntp_nodes(conn)}


def _serving_values(conn, form=None):
    """{node id: {serve, allow (text), local}} as stored, or as the form sent them."""
    out = {}
    for n in ntp_nodes(conn):
        if form is None:
            out[n['id']] = {'serve': bool(n['ntp_serve']), 'allow': '\n'.join(json.loads(n['ntp_allow'] or '[]')),
                            'local': n['ntp_local'] is not None}
        else:
            out[n['id']] = {'serve': form.get(f"serve_{n['id']}") == '1', 'allow': form.get(f"allow_{n['id']}") or '',
                            'local': form.get(f"local_{n['id']}") == '1'}
    return out


def _change(conn, form):
    """(sources, {node id: (serve, networks, local stratum or 0)}, errors) from the Settings → Time form."""
    parsed, errors = validate.parse_sources(form.get('sources'))
    serving = {}
    for node_id, v in _serving_values(conn, form).items():
        name = nodes.get_node(conn, node_id)['name']
        networks, problems = validate.parse_networks(v['allow'])
        if v['serve'] and not networks and not problems:
            problems.append('name the networks it serves time to')
        problems += validate.guard(networks) if v['serve'] else []
        errors += [f'{name}: {p}' for p in problems]
        serving[node_id] = (v['serve'], networks, DEFAULT_LOCAL_STRATUM if v['serve'] and v['local'] else 0)
    return parsed, serving, errors


def _page(request, user, conn, text=None, errors=None, status_code=200, form=None):
    return templates.TemplateResponse(request, 'settings_time.html', {
        'user': user, 'tab': 'time', 'nodes': ntp_nodes(conn), 'states': _states(conn),
        'text': validate.sources_text(sources(conn)) if text is None else text, 'custom': custom(conn),
        'serving': _serving_values(conn, form), 'errors': errors or [], 'error': request.query_params.get('error'),
        'done': request.query_params.get('done'), 'running': apply.busy(conn)}, status_code=status_code)


@router.get('/settings/time')
def time_page(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _page(request, user, conn)


@router.post('/settings/time/preview')
async def time_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    parsed, serving, errors = _change(conn, form)
    results = [] if errors else [
        apply.preview(conn, _settings(request), n, source_list=parsed, serve=serving[n['id']][0],
                      allow=serving[n['id']][1], local=serving[n['id']][2]) for n in ntp_nodes(conn)]
    for r in results:
        r['notes'] = _off_network(_settings(request), r['node'], serving[r['node']['id']])
    return templates.TemplateResponse(request, 'partials/ntp_review.html', {
        'errors': errors, 'results': results, 'changed': any(r['diff'] for r in results),
        'problems': any(r['problems'] for r in results), 'label': 'Apply to every time server'})


@router.post('/settings/time')
async def time_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    parsed, serving, errors = _change(conn, form)
    if errors:
        return _page(request, user, conn, text=form.get('sources'), errors=errors, status_code=422, form=form)
    if apply.busy(conn):
        return RedirectResponse('/settings/time?error=' + quote('another time change is still running'), status_code=303)
    before = conn.execute('SELECT sources FROM ntp_settings WHERE id = 1').fetchone()[0]
    before_nodes = [(n['id'], n['ntp_serve'], n['ntp_allow'], n['ntp_local']) for n in ntp_nodes(conn)]

    def change(c):
        with c:
            c.execute('UPDATE ntp_settings SET sources = ? WHERE id = 1', (to_json(parsed),))
            for node_id, (serve, networks, local) in serving.items():
                c.execute('UPDATE nodes SET ntp_serve = ?, ntp_allow = ?, ntp_local = ? WHERE id = ?',
                          (int(serve), json.dumps(networks), local or None, node_id))

    def undo(c):
        with c:
            c.execute('UPDATE ntp_settings SET sources = ? WHERE id = 1', (before,))
            for node_id, serve, allow, local in before_nodes:
                c.execute('UPDATE nodes SET ntp_serve = ?, ntp_allow = ?, ntp_local = ? WHERE id = ?',
                          (serve, allow, local, node_id))
    targets = [n['id'] for n in ntp_nodes(conn)]
    if not targets:
        change(conn)
        audit(conn, user.username, 'ntp_sources', ', '.join(s.address for s in parsed))
        return RedirectResponse('/settings/time?done=' + quote('Saved: nodes get these sources when you set time sync up '
                                                                 'on them'), status_code=303)
    job_id = apply.start(_settings(request), targets, 'time sources and serving', user.username, change=change,
                         undo=undo)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


def _off_network(settings, node, serving):
    """Notes for served networks none of the node's interfaces is on (it would serve nobody there)."""
    import ipaddress

    from ..dhcp.ops import node_status
    serve, networks, _ = serving
    if not serve or not networks:
        return []
    status, _ = node_status(settings, node)
    have = [ipaddress.ip_interface(a).network for i in (status or {}).get('interfaces') or [] for a in i['addresses']]
    return [f"{node['name']} has no address in {n}: nobody there would reach it" for n in networks
            if not any(ipaddress.ip_network(n).overlaps(h) for h in have if h.version == ipaddress.ip_network(n).version)]


def serving_addresses(settings, conn, prefix):
    """Addresses of the time-serving nodes in this network that they serve time to (for DHCP's NTP option)."""
    import ipaddress

    from ..dhcp.ops import node_status
    try:
        network = ipaddress.ip_network(prefix)
    except ValueError:
        return []
    out = []
    for n in ntp_nodes(conn):
        allowed = [ipaddress.ip_network(a) for a in json.loads(n['ntp_allow'] or '[]')]
        if not n['ntp_serve'] or not any(a.overlaps(network) for a in allowed if a.version == network.version):
            continue
        status, _ = node_status(settings, n)
        for i in (status or {}).get('interfaces') or []:
            for a in i['addresses']:
                ip = ipaddress.ip_interface(a).ip
                if ip.version == network.version and ip in network and str(ip) not in out:
                    out.append(str(ip))
    return out


# ── the node's Time card ───────────────────────────────────────────────────────

@router.get('/nodes/{node_id}/time')
def node_time(request: Request, node_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    """chrony's state on the node, and drift with a diff."""
    node = nodes.get_node(conn, node_id)
    ctx = {'user': user, 'node': node, 'time': None, 'error': None, 'diff': '',
           'drift': json.loads(node['ntp_drift'] or '[]'), 'stale': apply.stale(conn, node)}
    try:
        with nodes.agent_client(_settings(request), node) as c:
            ctx['time'] = c.status().get('time')
            if ctx['drift']:
                now, ours = c.ntp_files(), apply.files_for(conn, node)
                ctx['diff'] = ''.join(''.join(difflib.unified_diff(
                    (ours[r] or '').splitlines(True), (now.get(r) or '').splitlines(True),
                    f'{r} as LiteBlox wrote it', f'{r} on {node["name"]} now')) for r in ctx['drift'])
    except AgentError as e:
        ctx['error'] = e.message
    return templates.TemplateResponse(request, 'partials/node_time.html', ctx)


@router.post('/nodes/{node_id}/time/rewrite')
def node_time_rewrite(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = nodes.get_node(conn, node_id)
    if not node['ntp']:
        return RedirectResponse(f"/nodes/{node_id}?error={quote('time sync is not set up on this node')}", status_code=303)
    job_id = apply.start_rewrite(_settings(request), node_id, user.username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)
