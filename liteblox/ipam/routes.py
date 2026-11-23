"""The IPAM pages: the network tree, a network's map, utilization and addresses, its settings and ranges."""

import ipaddress
import json
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import csvout, search
from ..auth import User, current_user, require_admin
from ..db import audit, get_db
from ..nodes import service as nodes
from ..nodes.client import AgentError
from ..templating import templates
from . import model, seen, view

router = APIRouter()


def _settings(request):
    return request.app.state.settings


def _back(url, **params):
    params = {k: v for k, v in params.items() if v}
    if not params:
        return RedirectResponse(url, status_code=303)
    url, hash_, fragment = url.partition('#')
    return RedirectResponse(url + ('&' if '?' in url else '?') + '&'.join(f'{k}={quote(str(v))}' for k, v in params.items())
                            + hash_ + fragment, status_code=303)


def _context(request, conn, user, current=None):
    """What every IPAM page shows: the tree (with each network's usage) and the networks not added yet."""
    found = model.networks(conn)
    facts = view.gather(conn, _settings(request))
    use = {}
    for n in found:
        if n.container:
            c = view.container_counts(n)
            use[n.id] = (c['assigned'], n.net.num_addresses)
        else:
            use[n.id] = view.usage(facts, n)
    return {'user': user, 'networks': found, 'facts': facts, 'use': use, 'current': current,
            'suggestions': model.suggestions(conn, found, facts.subnets), 'errors': facts.errors,
            'path': model.path(found, current) if current else []}


def _network(found, network_id):
    n = next((x for x in found if x.id == network_id), None)
    if n is None:
        raise HTTPException(status_code=404, detail='no such network')
    return n


def _node_on(conn, ip):
    from .free import node_on
    return node_on(conn, ip)


def _nodes_on(conn, network):
    out = []
    # scanners first (the sweep node list), then by name
    for node in conn.execute("SELECT * FROM nodes WHERE status = 'ready' ORDER BY (bind = 1 OR dhcp = 1 OR ntp = 1), name"):
        for prefix in json.loads(node['networks'] or '[]'):
            try:
                if ipaddress.IPv4Network(prefix).overlaps(network.net):
                    out.append(node)
                    break
            except ValueError:
                pass
    return out


# ── pages ──────────────────────────────────────────────────────────────────────

@router.get('/ipam')
def ipam_home(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = _context(request, conn, user)
    ctx.update({'roots': model.roots(ctx['networks']), 'form': {}, 'form_errors': {},
                'error': request.query_params.get('error'), 'done': request.query_params.get('done')})
    return templates.TemplateResponse(request, 'ipam.html', ctx)


@router.post('/ipam/networks')
async def network_add(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    try:
        network_id = model.add_network(conn, form.get('prefix', ''), form.get('name', ''), form.get('comment', ''))
    except model.IpamError as e:
        ctx = _context(request, conn, user)
        ctx.update({'roots': model.roots(ctx['networks']), 'form': dict(form), 'form_errors': e.errors,
                    'error': None, 'done': None})
        return templates.TemplateResponse(request, 'ipam.html', ctx, status_code=422)
    n = model.get(conn, network_id)
    audit(conn, user.username, 'ipam_network_add', n.prefix + (f' ({n.name})' if n.name else ''))
    return RedirectResponse(f'/ipam/networks/{network_id}', status_code=303)


@router.get('/ipam/networks/{network_id}')
def network_page(request: Request, network_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    found = model.networks(conn)
    network = _network(found, network_id)
    ctx = _context(request, conn, user, network)
    facts = ctx['facts']
    q = request.query_params
    ctx.update({'network': network, 'error': q.get('error'), 'done': q.get('done'), 'warnings': q.getlist('warning')})
    if network.container:
        counts = view.container_counts(network)
        ctx.update({'cells': view.container_map(facts, network), 'counts': counts, 'children': network.children,
                    'segments': view.svg_donut([('assigned', counts['assigned']), ('free', counts['free'])])})
        return templates.TemplateResponse(request, 'ipam_container.html', ctx)
    ranges = model.all_ranges(conn, network, facts.subnets)
    highlight = None
    page = 0
    if q.get('ip'):
        try:
            highlight = ipaddress.IPv4Address(q['ip'])
            if highlight in network.net:
                page = view.page_of(network, highlight)
        except ValueError:
            highlight = None
    elif q.get('page', '').isdigit():
        page = int(q['page'])
    page = min(max(page, 0), view.pages(network) - 1)
    used_only = q.get('used') == '1'
    notes = model.notes(conn)
    page_rows = view.rows(facts, network, ranges, notes, page)
    counts = view.counts(facts, network)
    from . import ptr
    lo, hi = network.hosts_range()
    ptr.refresh_later(_settings(request), conn, [ipaddress.IPv4Address(n) for n in facts.used_between(int(lo), int(hi))])
    ctx.update({
        'ranges': ranges, 'range_counts': view.range_counts(facts, ranges), 'counts': counts,
        'segments': view.svg_donut([(s, counts[s]) for s in view.STATES]), 'states': view.STATES,
        'page': page, 'pages': view.pages(network), 'bounds': view.page_bounds(network, page),
        'blocks': view.blocks(facts, network), 'cells': view.cells(page_rows, ranges),
        'rows': [r for r in page_rows if r['state'] != 'free'] if used_only else page_rows, 'used_only': used_only,
        'highlight': highlight, 'probe_nodes': _nodes_on(conn, network), 'kinds': model.KINDS,
        'record_link': search.record_link, 'now': int(time.time()), 'resolver': ptr.config(conn)[0],
        'flapping': [f for f in seen.flapping(conn) if ipaddress.IPv4Address(f['ip']) in network.net],
    })
    return templates.TemplateResponse(request, 'ipam_network.html', ctx)


ADDRESS_COLUMNS = ('ip', 'state', 'names', 'ipam_name', 'rdns', 'ptr', 'mac', 'vendor', 'hostname', 'range', 'comment',
                   'comment_from', 'last_seen', 'flapping', 'checks')
EVERY_ADDRESS_UP_TO = 65536        # a bigger leaf exports its used addresses only: millions of free rows help nobody


@router.get('/ipam/networks/{network_id}/addresses.csv')
def network_csv(request: Request, network_id: int, used: str = '', user: User = Depends(current_user),
                conn=Depends(get_db)):
    """The network page's address table, every /24 page of it, as CSV (used=1: the used addresses only)."""
    network = _network(model.networks(conn), network_id)
    if network.container:
        raise HTTPException(status_code=404, detail=f'{network.prefix} holds other networks: export those')
    used_only, notes = used == '1', []
    if not used_only and network.net.num_addresses > EVERY_ADDRESS_UP_TO:
        used_only = True
        notes.append(f'{network.prefix} is bigger than a /16: its used addresses only')
    facts = view.gather(conn, _settings(request))
    ranges, comments = model.all_ranges(conn, network, facts.subnets), model.notes(conn)
    out = []
    for page in range(view.pages(network)):
        for a in view.rows(facts, network, ranges, comments, page, used_only):
            i = view.item(a)
            i['last_seen'] = csvout.when(i['last_seen'])
            i['checks'] = [c['text'] for c in i['checks']]
            out.append([i[c] for c in ADDRESS_COLUMNS])
    return csvout.response(ADDRESS_COLUMNS, out, csvout.filename('ipam', network.prefix, 'used' if used_only else ''),
                           notes=notes + list(facts.errors))


# ── settings and ranges ────────────────────────────────────────────────────────

def _settings_page(request, conn, user, network, status_code=200, **extra):
    ctx = _context(request, conn, user, network)
    q = request.query_params
    ctx.update({'network': network, 'kinds': model.KINDS, 'form': {}, 'form_errors': {}, 'range_form': {},
                'range_errors': {}, 'edit_range': None, 'error': q.get('error'), 'done': q.get('done')})
    ctx['ranges'] = model.all_ranges(conn, network, ctx['facts'].subnets)
    from . import sweep
    ctx.update({'sweep_nodes': _nodes_on(conn, network), 'sweep_problem': sweep.problem(conn, network)})
    ctx.update(extra)
    return templates.TemplateResponse(request, 'ipam_settings.html', ctx, status_code=status_code)


@router.get('/ipam/networks/{network_id}/settings')
def network_settings(request: Request, network_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    network = _network(model.networks(conn), network_id)
    return _settings_page(request, conn, user, network)


@router.post('/ipam/networks/{network_id}/settings')
async def network_save(request: Request, network_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    network = _network(model.networks(conn), network_id)
    form = await request.form()
    node = form.get('sweep_node') or ''
    try:
        model.update_network(conn, network.id, form.get('name', ''), form.get('comment', ''),
                             form.get('sweep', network.sweep), int(node) if node.isdigit() else None)
    except model.IpamError as e:
        return _back(f'/ipam/networks/{network.id}/settings', error='; '.join(e.errors.values()))
    audit(conn, user.username, 'ipam_network_edit', network.prefix)
    return _back(f'/ipam/networks/{network.id}/settings', done='Saved.')


@router.post('/ipam/networks/{network_id}/sweep')
def network_sweep(request: Request, network_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import sweep
    network = _network(model.networks(conn), network_id)
    try:
        job_id = sweep.start(_settings(request), conn, network, user.username)
    except ValueError as e:
        return _back(f'/ipam/networks/{network.id}/settings', error=str(e))
    audit(conn, user.username, 'ipam_sweep', network.prefix)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/ipam/networks/{network_id}/delete')
def network_delete(request: Request, network_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    network = _network(model.networks(conn), network_id)
    model.delete_network(conn, network.id)
    audit(conn, user.username, 'ipam_network_delete', network.prefix)
    return _back('/ipam', done=f'{network.prefix} is no longer in IPAM. Its DNS records and DHCP are unchanged.')


@router.post('/ipam/networks/{network_id}/ranges')
async def range_save(request: Request, network_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    network = _network(model.networks(conn), network_id)
    form = await request.form()
    rid = int(form['range_id']) if (form.get('range_id') or '').isdigit() else None
    from ..dhcp.model import subnets
    try:
        model.save_range(conn, network, form.get('first'), form.get('last'), form.get('kind', 'static'),
                         form.get('name', ''), form.get('comment', ''), range_id=rid, subnets=subnets(conn))
    except model.IpamError as e:
        return _settings_page(request, conn, user, network, 422, range_form=dict(form), range_errors=e.errors,
                              edit_range=rid)
    audit(conn, user.username, 'ipam_range_edit' if rid else 'ipam_range_add',
          f"{network.prefix}: {form.get('first')} – {form.get('last') or form.get('first')}")
    return _back(f'/ipam/networks/{network.id}/settings', done='Range saved.')


@router.post('/ipam/networks/{network_id}/ranges/{range_id}/delete')
def range_delete(request: Request, network_id: int, range_id: int, user: User = Depends(require_admin),
                 conn=Depends(get_db)):
    network = _network(model.networks(conn), network_id)
    r = next((x for x in model.ranges(conn, network.id) if x.id == range_id), None)
    if r is None:
        raise HTTPException(status_code=404, detail='no such range')
    model.delete_range(conn, network.id, range_id)
    audit(conn, user.username, 'ipam_range_delete', f'{network.prefix}: {r.first} – {r.last}')
    return _back(f'/ipam/networks/{network.id}/settings', done='Range deleted.')


# ── one address: its comment, a Check ──────────────────────────────────────────

@router.post('/ipam/comment')
async def comment_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    """An address's one comment, written back to where it lives: the A record in its static zone (a draft, as
    the grid does), its reservation (LiteBlox keeps reservation comments: nothing to write to Kea), or an IPAM
    note."""
    form = await request.form()
    try:
        ip = ipaddress.IPv4Address((form.get('ip') or '').strip())
    except ValueError:
        raise HTTPException(status_code=400, detail='not an IPv4 address')
    text = (form.get('comment') or '').strip()
    back = form.get('back') or '/ipam'
    if not back.startswith('/ipam'):
        back = '/ipam'
    kind = form.get('kind')
    try:
        if kind == 'dns':
            note = _comment_to_record(request, conn, user, form.get('zone', ''), form.get('fqdn', ''), ip, text)
        elif kind == 'reservation':
            note = _comment_to_reservation(conn, user, int(form.get('id') or 0), ip, text)
        elif kind == 'ipam':
            from . import names
            names.set_comment(conn, ip, text)
            audit(conn, user.username, 'ipam_name', f"{ip}: comment {text or 'removed'}")
            note = 'Saved on the IPAM record.'
        else:
            model.set_note(conn, ip, text, user.username)
            audit(conn, user.username, 'ipam_note', f'{ip}: {text}' if text else f'{ip}: removed')
            note = 'Note saved.'
    except ValueError as e:
        return _back(back, ip=str(ip), error=str(e))
    return _back(back, ip=str(ip), done=note)


def _comment_to_record(request, conn, user, zone, fqdn, ip, text):
    from ..dns import editing
    from ..dns.records import RecordError
    with editing.zone_lock(zone):
        try:
            edit = editing.ZoneEdit(_settings(request), conn, zone)
        except editing.ZoneError:
            raise ValueError(f'{zone} is not a zone LiteBlox holds')
        if edit.dynamic or edit.zone is None:
            raise ValueError(f"{zone} can't take a comment here: edit it in the zone")
        rec = next((r for r in edit.zone.records() if r.rtype == 'A' and r.name.to_text().rstrip('.').lower() == fqdn
                    and r.rdata.strip() == str(ip)), None)
        if rec is None:
            raise ValueError(f'the A record {fqdn} → {ip} is no longer in {zone}')
        try:
            editing.apply_row(edit, rec, rec.relative_name(edit.zone.origin), None if rec.ttl is None else str(rec.ttl),
                              'A', rec.rdata, text, False, None, user.username)
        except RecordError as e:
            raise ValueError(str(e))
    audit(conn, user.username, 'record_edit', f'{zone}: {rec.relative_name(edit.zone.origin)} A (comment, from IPAM)')
    return f'Comment saved in the draft of {zone}: publish it there.'


def _comment_to_reservation(conn, user, rid, ip, text):
    row = conn.execute('SELECT * FROM dhcp4_reservations WHERE id = ?', (rid,)).fetchone()
    if row is None or row['ip_address'] != str(ip):
        raise ValueError(f'the reservation for {ip} is gone')
    with conn:
        conn.execute('UPDATE dhcp4_reservations SET comment = ? WHERE id = ?', (text, rid))
    audit(conn, user.username, 'dhcp_reservation_comment', f"{ip} ({row['hw_address']}): {text or 'removed'}")
    return "Saved on the reservation."


@router.post('/ipam/check', response_class=HTMLResponse)
async def check_address(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    """One probe of a free address through a node on its network: does anything answer there?"""
    form = await request.form()
    try:
        ip = ipaddress.IPv4Address((form.get('ip') or '').strip())
    except ValueError:
        raise HTTPException(status_code=400, detail='not an IPv4 address')
    node = _node_on(conn, ip)
    if node is None:
        return HTMLResponse('<span class="muted small">no node on this network to check from</span>')
    try:
        with nodes.agent_client(_settings(request), node, timeout=15.0) as c:
            answer = c.probe([str(ip)], wait=1.5)
    except AgentError as e:
        if e.status == 404:
            return HTMLResponse(f"<span class=\"muted small\">{node['name']}'s agent is too old: upgrade it</span>")
        return HTMLResponse(f'<span class="error-text small">{_esc(e.message)}</span>')
    result = (answer.get('results') or {}).get(str(ip)) or {}
    return templates.TemplateResponse(request, 'partials/ipam_check.html', {'r': result, 'node': node, 'ip': ip,
                                                                             'method': answer.get('method'),
                                                                             'elapsed': answer.get('elapsed') or 0})


def _esc(text):
    from markupsafe import escape
    return str(escape(text))


# ── IPAM records: Name this address ────────────────────────────────────────────

def _name_back(value, ip):
    """Where the name form returns to: an IPAM page or the address card, else the address's network."""
    value = (value or '').strip()
    if (value.startswith('/ipam') or value.startswith('/search')) and '//' not in value:
        return value
    return f'/search?q={ip}#address'


def _name_page(request, conn, user, ip, form=None, errors=None, status_code=200):
    from ..dns import ptr as dns_ptr
    from ..modules import for_request
    from . import names
    ctx = _context(request, conn, user)
    record = names.get(conn, ip)
    zones = [r['name'] for r in conn.execute("SELECT name FROM zones WHERE name LIKE '%.in-addr.arpa'")]
    latest = seen.at_address(conn, ip)
    ctx.update({'ip': ip, 'record': record, 'network': model.leaf_for(ctx['networks'], ipaddress.IPv4Address(ip)),
                'form': form or record or {'name': '', 'mac': '', 'comment': model.notes(conn).get(ip, '')},
                'errors': errors or {}, 'back': _name_back(request.query_params.get('back') or
                                                         (form or {}).get('back'), ip),
                'nameable': dns_ptr.reverse_zone_for(ip, zones) is None,
                'dns_on': for_request(request)['dns'],
                'seen_mac': latest[0]['mac'] if latest else '', 'error': request.query_params.get('error')})
    if ctx['form'].get('mac') is None:
        ctx['form'] = {**ctx['form'], 'mac': ''}
    return templates.TemplateResponse(request, 'ipam_name.html', ctx, status_code=status_code)


@router.get('/ipam/names/{ip}')
def name_page(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _name_page(request, conn, user, _ip_or_400(ip))


@router.post('/ipam/names/{ip}')
async def name_save(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import names
    ip = _ip_or_400(ip)
    form = dict(await request.form())
    try:
        new = names.save(conn, ip, form.get('name'), form.get('mac'), form.get('comment'), user.username)
    except model.IpamError as e:
        return _name_page(request, conn, user, ip, form, e.errors, 422)
    r = names.get(conn, ip)
    audit(conn, user.username, 'ipam_name', f"{ip}: {r['name']}{' ' + r['mac'] if r['mac'] else ''}"
                                            f"{'' if new else ' (changed)'}")
    return _back(_name_back(form.get('back'), ip), done=f"{ip} is named {r['name']} in IPAM.")


@router.post('/ipam/names/{ip}/delete')
async def name_delete(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import names
    ip = _ip_or_400(ip)
    form = await request.form()
    r = names.get(conn, ip)
    if r is None or not names.delete(conn, ip):
        raise HTTPException(status_code=404, detail='no IPAM name at this address')
    audit(conn, user.username, 'ipam_name_delete', f"{ip}: {r['name']}")
    return _back(_name_back(form.get('back'), ip), done=f"{ip}'s IPAM name {r['name']} is removed.")


# ── what the nodes see ─────────────────────────────────────────────────────────

@router.get('/ipam/seen')
def seen_page(request: Request, q: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    """Devices seen: one row per MAC the nodes have seen, like an ARP monitor."""
    from . import oui
    ctx = _context(request, conn, user)
    rows = _seen_rows(request, conn, ctx['facts'], ctx['networks'])
    cfg = seen.settings(conn)
    ctx.update({'rows': rows, 'q': q, 'keep_days': cfg.keep_days, 'flapping': seen.flapping(conn),
                'error': request.query_params.get('error'), 'done': request.query_params.get('done'),
                'oui': oui.info(_settings(request)), 'now': int(time.time())})
    return templates.TemplateResponse(request, 'ipam_seen.html', ctx)


def _seen_rows(request, conn, facts, networks):
    from . import oui
    flapping = {f['ip'] for f in seen.flapping(conn)}
    expected = seen.expected(conn)
    vendors = oui.table(_settings(request))
    known = {r['mac']: r for r in conn.execute('SELECT * FROM devices')}
    rows = []
    for d in seen.devices(conn):
        addr = ipaddress.IPv4Address(d['ip'])
        dev = known.get(d['mac'])
        rows.append({**d, 'addr': addr, 'vendor': oui.vendor(None, d['mac'], vendors),
                     'label': dev['label'] if dev else '', 'comment': dev['comment'] if dev else '',
                     'repeater': bool(dev and dev['repeater']),
                     'expected': d['mac'] in (expected.get(d['ip']) or {}).get('macs', ()),
                     'names': _names_at(facts, addr),
                     'flapping': d['ip'] in flapping,
                     'network': model.leaf_for(networks, addr)})
    rows.sort(key=lambda r: int(r['addr']))
    return rows


def _seen_search(d):
    """What the page's filter box matches, as its data-search attribute has it."""
    return ' '.join([d['ip'], d['mac'], d['vendor'] or '', d['label'] or '', d['comment'] or '',
                     'wi-fi repeater' if d['repeater'] else '', *d['names'], *d['earlier']]).lower()


SEEN_COLUMNS = ('ip', 'mac', 'vendor', 'label', 'comment', 'names', 'network', 'first_seen', 'last_seen', 'node',
                'source', 'earlier_ips', 'flapping', 'expected', 'repeater')


@router.get('/ipam/seen.csv')
def seen_csv(request: Request, q: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    """Devices seen as CSV; q: the page's filter (every word must match)."""
    facts = view.gather(conn, _settings(request))
    words = q.lower().split()
    out = [[d['ip'], d['mac'], d['vendor'], d['label'], d['comment'], d['names'],
            d['network'].prefix if d['network'] else '', csvout.when(d['first_seen']), csvout.when(d['last_seen']),
            d['node'] or '', d['source'] or '', d['earlier'], d['flapping'], d['expected'], d['repeater']]
           for d in _seen_rows(request, conn, facts, model.networks(conn))
           if all(w in _seen_search(d) for w in words)]
    return csvout.response(SEEN_COLUMNS, out, csvout.filename('ipam-devices-seen', dated=True), notes=facts.errors)


def _names_at(facts, addr):
    """An address's names for Devices seen: its A records, its IPAM record, then its PTR at the resolver."""
    out = [h['rec'].fqdn for h in facts.names.get(addr, [])]
    for name in ((facts.ipam.get(addr) or {}).get('name'), (facts.rdns.get(addr) or {}).get('name')):
        if name and name not in out:
            out.append(name)
    return out


@router.post('/ipam/seen/forget')
async def seen_forget(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import seen
    form = await request.form()
    try:
        ip = str(ipaddress.IPv4Address((form.get('ip') or '').strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail='not an IPv4 address')
    mac = (form.get('mac') or '').strip() or None
    seen.forget(conn, ip, mac)
    audit(conn, user.username, 'ipam_forget', f'{ip} {mac}' if mac else ip)
    return _back('/ipam/seen', done=f"Forgotten: {mac + ' on ' if mac else ''}{ip}. It comes back if a node sees it "
                                    'again.')


@router.post('/ipam/flapping/{ip}/ack')
def flapping_ack(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import seen
    try:
        ip = str(ipaddress.IPv4Address(ip))
    except ValueError:
        raise HTTPException(status_code=400, detail='not an IPv4 address')
    seen.ack(conn, ip, user.username)
    audit(conn, user.username, 'ipam_ack', ip)
    return RedirectResponse(f'/search?q={ip}#address', status_code=303)


def _ip_or_400(ip):
    try:
        return str(ipaddress.IPv4Address((ip or '').strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail='not an IPv4 address')


@router.post('/ipam/flapping/{ip}/expect')
async def flapping_expect(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    """These MACs are expected here: the flapping's MACs (and any already expected) stop counting, for good."""
    from . import seen
    ip = _ip_or_400(ip)
    form = await request.form()
    found = next((f for f in seen.flapping(conn) if f['ip'] == ip), None)
    macs = found['macs'] if found else [r['mac'] for r in seen.at_address(conn, ip)]
    macs = seen.expect(conn, ip, macs, form.get('reason') or '', user.username)
    audit(conn, user.username, 'ipam_expect', f"{ip} {' '.join(macs)}")
    return RedirectResponse(f'/search?q={ip}#address', status_code=303)


@router.post('/ipam/flapping/{ip}/unmute')
async def flapping_unmute(request: Request, ip: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import seen
    ip = _ip_or_400(ip)
    form = await request.form()
    seen.unmute(conn, ip)
    audit(conn, user.username, 'ipam_unmute', ip)
    back = (form.get('back') or '').strip()
    if back.startswith('/ipam/seen') and '//' not in back:
        return _back('/ipam/seen', done=f'{ip}: every MAC change counts again.')
    return RedirectResponse(f'/search?q={ip}#address', status_code=303)


# ── devices ────────────────────────────────────────────────────────────────────

def _mac_or_404(mac):
    from ..dhcp.validate import normalize_mac
    m = normalize_mac(mac)
    if m is None:
        raise HTTPException(status_code=404, detail='not a MAC address')
    return m


@router.get('/ipam/devices/{mac}')
def device_page(request: Request, mac: str, user: User = Depends(current_user), conn=Depends(get_db)):
    """One device: its label, vendor, DHCP and DNS, where the nodes saw it, and the steps up and down."""
    from ..dhcp import leases as lease_mod
    from ..dhcp.model import subnets as dhcp_subnets
    from . import devices, oui, seen
    m = _mac_or_404(mac)
    settings = _settings(request)
    found, errors = lease_mod.serving_leases(settings, conn)
    history = [dict(r) for r in conn.execute(
        'SELECT s.*, n.name AS node FROM ipam_seen s LEFT JOIN nodes n ON n.id = s.node_id WHERE s.mac = ? '
        'ORDER BY s.last_seen DESC', (m,))]
    expected = seen.expected(conn)
    for h in history:
        h['expected'] = m in (expected.get(h['ip']) or {}).get('macs', ())
    dev = devices.get(conn, m) or {'label': '', 'comment': '', 'repeater': False}
    ctx = _context(request, conn, user)
    ctx.update({'mac': m, 'device': dev, 'vendor': oui.vendor(settings, m),
                'steps': devices.steps(conn, settings, m, dhcp_subnets(conn), found), 'history': history,
                'suggested': devices.hostname_for(dev['label']), 'lease_errors': errors,
                'keep_days': seen.settings(conn).keep_days,
                'error': request.query_params.get('error'), 'done': request.query_params.get('done')})
    return templates.TemplateResponse(request, 'ipam_device.html', ctx)


@router.post('/ipam/devices/{mac}')
async def device_save(request: Request, mac: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import devices
    m = _mac_or_404(mac)
    form = await request.form()
    label, comment = (form.get('label') or '').strip(), (form.get('comment') or '').strip()
    # only the device page's form has the checkbox; Devices seen's label form leaves the flag as it is
    repeater = form.get('repeater') == '1' if form.get('repeater_shown') else None
    was = devices.get(conn, m)
    saved = devices.save(conn, m, label, comment, repeater)
    flag = bool(saved and saved['repeater'])
    note = '' if flag == bool(was and was['repeater']) else (' (Wi-Fi repeater)' if flag else ' (not a repeater)')
    audit(conn, user.username, 'ipam_device', f"{m} {label}".strip() + note)
    back = (form.get('back') or '').strip()
    url = back if back in ('/ipam/seen',) else f'/ipam/devices/{m}'
    return _back(url, done=f"Saved {m}." if saved else f"Cleared {m}'s label.")


# ── Settings → IPAM ────────────────────────────────────────────────────────────

LIMITS = {'keep_days': (1, 90), 'seen_hours': (1, 90 * 24), 'flap_changes': (2, 20), 'flap_minutes': (1, 120)}


def _ipam_settings_page(request, conn, user, form=None, errors=None, status_code=200):
    from . import oui, ptr, seen
    cfg = seen.settings(conn)
    resolver, hours = ptr.config(conn)
    q = request.query_params
    counts = conn.execute("SELECT COUNT(*) AS n, SUM(name != '') AS named, SUM(error IS NOT NULL) AS failed "
                          "FROM ipam_ptr").fetchone()
    return templates.TemplateResponse(request, 'settings_ipam.html', {
        'user': user, 'tab': 'ipam', 'cfg': cfg,
        'form': form or {**vars(cfg), 'resolver': resolver, 'ptr_hours': hours, 'keep_seen_names': conn.execute(
            'SELECT keep_seen_names FROM ipam_settings WHERE id = 1').fetchone()[0]}, 'errors': errors or {},
        'oui': oui.info(_settings(request)), 'limits': LIMITS, 'ptr_counts': counts, 'resolver': resolver,
        'error': q.get('error'), 'done': q.get('done')}, status_code=status_code)


@router.get('/settings/ipam')
def ipam_settings(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _ipam_settings_page(request, conn, user)


@router.post('/settings/ipam')
async def ipam_settings_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import ptr, seen
    form = dict(await request.form())
    old_resolver, old_hours = ptr.config(conn)
    form.setdefault('ptr_hours', str(old_hours))
    form.setdefault('resolver', old_resolver)
    form.setdefault('seen_hours', str(seen.settings(conn).seen_hours))
    values, errors = {}, {}
    for key, (lo, hi) in {**LIMITS, 'ptr_hours': ptr.HOURS}.items():
        try:
            values[key] = int(form.get(key, ''))
            if not lo <= values[key] <= hi:
                raise ValueError
        except ValueError:
            errors[key] = f'a whole number from {lo} to {hi}'
    # in use can't outlast what's kept
    if 'keep_days' in values and 'seen_hours' in values and values['seen_hours'] > values['keep_days'] * 24:
        errors['seen_hours'] = f"at most {values['keep_days'] * 24} hours (Keep for)"
    resolver = (form.get('resolver') or '').strip()
    try:
        ptr.parse_resolver(resolver)
    except ValueError as e:
        errors['resolver'] = str(e)
    if errors:
        return _ipam_settings_page(request, conn, user, form, errors, 422)
    seen.save_settings(conn, values['keep_days'], values['flap_changes'], values['flap_minutes'], values['seen_hours'])
    ptr.save(conn, resolver, values['ptr_hours'])
    keep_seen = bool(form.get('keep_seen_names'))
    with conn:
        conn.execute('UPDATE ipam_settings SET keep_seen_names = ? WHERE id = 1', (int(keep_seen),))
    audit(conn, user.username, 'ipam_settings',
          f"keep {values['keep_days']} days, in use for {values['seen_hours']} h, flapping {values['flap_changes']} changes in {values['flap_minutes']} min, "
          + (f"PTR lookups at {resolver} every {values['ptr_hours']} h" if resolver else 'no PTR lookups')
          + ('' if keep_seen else ', stale DHCP names go even when seen'))
    return _back('/settings/ipam', done='Saved.')


@router.post('/settings/ipam/vendors')
def ipam_vendors_refresh(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from . import oui
    line = oui.refresh(_settings(request), conn, force=True)
    error = conn.execute('SELECT oui_error FROM ipam_settings WHERE id = 1').fetchone()[0]
    # the label already says what happened: the detail is only the outcome
    audit(conn, user.username, 'ipam_vendors', error or f"{oui.info(_settings(request))['count']} prefixes")
    return _back('/settings/ipam', error=error) if error else _back('/settings/ipam', done=line[0].upper() + line[1:] + '.')
