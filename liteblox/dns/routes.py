"""Zones pages: list, record grid with inline editing, SOA card, raw editor, review, history.

Edits go into the zone's draft. Every edit request carries the draft revision it
was made against; if the draft changed meanwhile (another tab or user), the
edit is refused instead of hitting the wrong row, since record ids are just
positions in the current parse.
"""

from html import escape
from urllib.parse import quote

import dns.exception
import dns.name
import dns.ttl
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import User, current_user, require_admin
from ..db import audit, get_db
from ..db import connect as db_connect
from ..nodes import service as nodes
from ..nodes.client import AgentError
from ..templating import templates
from ..timefmt import duration
from .. import csvout, jobs
from . import declare
from . import editing
from . import many
from . import nameservers
from .canonical import why_unsorted
from . import publish as pub
from . import ptr
from . import records
from .drafts import Drafts, keeps_sorted, rev
from . import dynamic
from .importer import diff, resolve_conflict
from .repo import Repo
from .validate import ToolMissing, named_checkzone
from .validate import check_rdata
from .zonefile import Zone, ZoneParseError, _rdata_tokens

router = APIRouter()


class Ctx(editing.ZoneEdit):
    """editing.ZoneEdit for a page: a missing zone is a 404, a forwarding zone goes to its Settings tab,
    and the page's own zone tells the nav whether it's dynamic."""

    def __init__(self, request, conn, name, forwarding_ok=False):
        try:
            super().__init__(request.app.state.settings, conn, name, forwarding_ok)
        except editing.NoSuchZone:
            raise HTTPException(status_code=404, detail='no such zone')
        except editing.ForwardingZone:
            # no records, history or publish: everything about it lives on its Settings tab
            raise HTTPException(status_code=303, headers={'Location': f'/zones/{name}/settings'})
        if not hasattr(request.state, 'zone_dynamic'):      # the page's own zone, not a linked one
            request.state.zone_forwarding, request.state.zone_dynamic = self.forwarding, self.dynamic


def _changed_ids(ctx, rows):
    """Ids of draft rows that differ from the published copy (highlighted in the grid)."""
    published = ctx.published_zone() if ctx.is_draft else None
    if published is None:
        return set()
    key = lambda r: (r.name, r.ttl, r.rtype, tuple(_rdata_tokens(r.rdata)), r.comment)
    remaining = {}
    for r in published.records():
        remaining[key(r)] = remaining.get(key(r), 0) + 1
    changed = set()
    for r in rows:
        if remaining.get(key(r)):
            remaining[key(r)] -= 1
        else:
            changed.add(r.id)
    return changed


def _grid_context(request, user, ctx, focus=None, warnings=None, notes=None):
    zone = ctx.zone
    # the SOA and the apex NS records have their own cards above the grid
    rows = [r for r in zone.records() if r.rtype != 'SOA' and not (r.rtype == 'NS' and r.name == zone.origin)]
    summary = ctx.summary()
    return {
        'user': user, 'zone_name': ctx.name, 'zone': zone, 'rows': rows, 'rev': ctx.rev,
        'is_draft': ctx.is_draft, 'pending': records.count(summary) if summary else 0,
        'stale': ctx.is_draft and ctx.drafts.is_stale(ctx.row),
        'types': sorted({r.rtype for r in rows}), 'previews': {
            r.id: records.target_preview(r.rtype, r.rdata, r.origin) for r in rows},
        'focus': focus, 'unsupported': zone.unsupported, 'warnings': warnings or [], 'notes': notes or [],
        'linked': sorted(ctx.drafts.linked(ctx.name)), 'auto_ptr': bool(ctx.row['auto_ptr']),
        'changed_ids': _changed_ids(ctx, rows), 'rr': _tokens(ctx, rows),
    }


def _grid(request, user, ctx, focus=None, warnings=None, notes=None):
    # oob: also refresh the SOA form's revision, which lives outside the grid
    return templates.TemplateResponse(request, 'partials/zone_grid.html',
                                      {**_grid_context(request, user, ctx, focus, warnings, notes), 'oob': True})


def _edit_row(request, ctx, rec, form=None, errors=None, after=None, status_code=200, headers=None):
    rtype = (form or {}).get('type') or (rec.rtype if rec else 'A')
    if form is None and rec is not None:
        form = {'name': rec.relative_name(ctx.zone.origin), 'ttl': duration(rec.ttl),
                'type': rec.rtype, 'comment': rec.comment or '', **records.decompose(rec.rtype, rec.rdata)}
    return templates.TemplateResponse(request, 'partials/record_edit.html', {
        'zone_name': ctx.name, 'rec': rec, 'form': form or {'type': rtype}, 'errors': errors or {},
        'rev': ctx.rev, 'after': after, 'fields': records.FIELDS, 'types': records.COMMON_TYPES,
        'rr': (_tokens(ctx, [rec]).get(rec.id, '') if rec else '') if ctx.dynamic else None,
        'auto_ptr': bool(ctx.row['auto_ptr']) if form is None or 'ptr_field' not in form else 'ptr' in form},
        status_code=status_code, headers=headers)


def _conflict(ctx=None, record=False):
    if record:
        what = ('That record changed on the server since you loaded the page (an update from DHCP, ACME, another '
                'tab or user); nothing was written.')
    elif ctx is not None and ctx.dynamic:
        what = ('This zone changed on the server since you loaded it (an update from DHCP, ACME, another tab or '
                'user); nothing was written.')
    else:
        what = 'This zone was changed in another tab or by another user.'
    return HTMLResponse(f'<p class="error" role="alert">{what} <a href="">Reload</a> to see the current version.</p>',
                        status_code=409, headers={'HX-Retarget': '#zone-alert', 'HX-Reswap': 'innerHTML'})


def _stale(ctx, form):
    """Did the zone change since the page was loaded?

    A dynamic zone changes under the editor all the time (DHCP, ACME), so a
    page that sends rr (dynamic.rr_token) is only checked on the RRset it
    edits, by _record; a new record needs no check (the update's
    prerequisites still guard it). Everything else compares the whole zone.
    """
    if ctx.dynamic and 'rr' in form:
        return False
    return form.get('rev') != ctx.rev


def _record(ctx, record_id, rr=None):
    """The record a row points at; None in a dynamic zone when it (or its RRset) changed since the page."""
    if ctx.dynamic and rr:
        rec = dynamic.find_token(ctx.zone, rr)
        if rec is None:
            return None
    else:
        try:
            rec = ctx.zone.get(record_id)
        except KeyError:
            raise HTTPException(status_code=404, detail='no such record')
    if rec.rtype == 'SOA':
        raise HTTPException(status_code=400, detail='edit the SOA in the SOA card')
    return rec


def _tokens(ctx, recs):
    """{record id: rr token} for a dynamic zone's rows (empty for a static zone)."""
    return {r.id: dynamic.rr_token(ctx.zone, r) for r in recs} if ctx.dynamic and ctx.zone else {}


# ── list ───────────────────────────────────────────────────────────────────────

@router.get('/zones')
def zones(request: Request, kind: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    settings = request.app.state.settings
    drafts = Drafts(settings)
    rows = conn.execute('SELECT * FROM zones ORDER BY name').fetchall()
    info = []
    for z in rows:
        if z['kind'] == 'forwarding':
            text, is_draft, serial = '', False, None
        else:
            text, is_draft = drafts.load(z)
            try:
                serial = Zone.parse(drafts.published(z), z['name'] + '.').serial
            except (ZoneParseError, LookupError, ValueError):
                serial = None
        node_names = [r['name'] for r in conn.execute(
            'SELECT n.name FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id WHERE zn.zone_id = ? '
            'ORDER BY n.name', (z['id'],))]
        info.append({'row': z, 'serial': serial, 'is_draft': is_draft, 'nodes': node_names,
                     'kinds': _zone_kinds(z, is_draft)})
    counts = {k: sum(k in z['kinds'] for z in info) for k in ZONE_FILTERS}
    kind = kind if kind in ZONE_FILTERS else None
    shown = [z for z in info if kind is None or kind in z['kinds']]
    return templates.TemplateResponse(request, 'zones.html', {
        'user': user, 'zones': shown, 'any': bool(info), 'kind': kind, 'total': len(info),
        'zone_filters': [(k, label, counts[k]) for k, label in ZONE_FILTERS.items()]})


ZONE_FILTERS = {'forward': 'Forward', 'reverse': 'Reverse', 'dynamic': 'Dynamic', 'forwarding': 'Forwarding',
                'draft': 'Drafts'}


def _zone_kinds(z, is_draft):
    """The Zones list filters a zone falls under."""
    kinds = {'forwarding'} if z['kind'] == 'forwarding' else {'reverse' if z['name'].endswith('.arpa') else 'forward'}
    if z['dynamic'] and z['kind'] != 'forwarding':
        kinds.add('dynamic')
    if is_draft:
        kinds.add('draft')
    return kinds


ALL_COLUMNS = ('zone',) + many.COLUMNS


@router.get('/zones/records.csv')
def all_records_csv(request: Request, kind: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    """Every zone's records in one file (the Zones list's filter applies). Each zone's rows are the ones its
    own export gives, so a zone's rows, without the zone column, import back through Add many."""
    settings = request.app.state.settings
    kind = kind if kind in ZONE_FILTERS else ''
    rows, notes = [], []
    for z in conn.execute("SELECT * FROM zones WHERE kind != 'forwarding' ORDER BY name").fetchall():
        if kind and kind not in _zone_kinds(z, kind == 'draft' and Drafts(settings).load(z)[1]):
            continue
        try:
            edit = editing.ZoneEdit(settings, conn, z['name'])
        except dynamic.DynamicError as e:
            notes.append(f"{z['name']}: left out, {e}")
            continue
        if edit.zone is None:
            notes.append(f"{z['name']}: left out, it doesn't parse ({edit.error})")
            continue
        for r in many.grid_records(edit.zone):
            rows.append([z['name'], r.relative_name(edit.zone.origin), '' if r.ttl is None else r.ttl, r.rtype,
                         r.rdata, r.comment or ''])
    return Response(csvout.text(ALL_COLUMNS, rows, notes, guard=False), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': f'attachment; filename="{csvout.filename("zones", kind)}"'})


@router.get('/zones/serials')
def zone_serials(request: Request, ids: str = '', user: User = Depends(current_user), conn=Depends(get_db)):
    """Serial each node is serving, per zone (fragment loaded after the list; ids: only the zones a filter shows)."""
    settings = request.app.state.settings
    serving, errors = {}, {}
    for node in conn.execute("SELECT * FROM nodes WHERE status != 'new' AND bind = 1 ORDER BY name"):
        try:
            with nodes.agent_client(settings, node, timeout=5.0) as c:
                for z in c.config()['zones']:
                    serving[(z['name'], node['name'])] = z.get('loaded_serial')
        except AgentError as e:
            errors[node['name']] = e.message
    links = conn.execute('SELECT z.id AS zone_id, z.name AS zone, n.name AS node FROM zone_nodes zn '
                         'JOIN zones z ON z.id = zn.zone_id JOIN nodes n ON n.id = zn.node_id '
                         "WHERE z.kind = 'primary' ORDER BY n.name").fetchall()
    only = {int(i) for i in ids.split(',') if i.isdigit()}
    out = {}
    for link in links:
        if only and link['zone_id'] not in only:
            continue
        out.setdefault(link['zone_id'], []).append({
            'node': link['node'], 'serial': serving.get((link['zone'], link['node'])),
            'error': errors.get(link['node'])})
    return templates.TemplateResponse(request, 'partials/zone_serials.html', {'serials': out})


# ── managed zones: create ──────────────────────────────────────────────────────

def _ready_nodes(conn):
    """Ready BIND nodes (a node without BIND never serves zones)."""
    return conn.execute("SELECT * FROM nodes WHERE status = 'ready' AND bind = 1 ORDER BY name").fetchall()


def _zone_targets(conn):
    """Nodes a new zone can go on: ready and taken over."""
    return [n for n in _ready_nodes(conn) if n['managed']]


@router.get('/zones/new')
def zone_new(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return templates.TemplateResponse(request, 'zone_new.html', {
        'user': user, 'nodes': _zone_targets(conn), 'form': {'ttl': '1h'}, 'error': None,
        'recursion_off': {n['id']: declare.recursion_off(n) for n in _zone_targets(conn)}})


@router.get('/zones/new/reverse-name')
def zone_new_reverse_name(network: str = '', user: User = Depends(require_admin)):
    """The zone name for the network typed so far (htmx preview on the new-zone form)."""
    if not network.strip():
        return HTMLResponse('')
    try:
        return HTMLResponse(f'Zone name: <code>{escape(declare.reverse_zone_name(network))}</code>')
    except declare.DeclareError as e:
        return HTMLResponse(f'<span class="error-text">{escape(str(e))}</span>')


@router.post('/zones/new')
async def zone_new_post(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    values = {k: v for k, v in form.items() if k != 'nodes'}
    node_ids = form.getlist('nodes')
    settings = request.app.state.settings
    if values.get('kind') == 'forwarding':
        return _zone_new_forwarding(request, user, conn, values, node_ids, form)
    try:
        if values.get('kind') == 'reverse':
            name = declare.reverse_zone_name(values.get('network'))
        else:
            name = declare.check_zone_name(values.get('name'))
            if name.endswith('.arpa'):
                raise declare.DeclareError('for a reverse zone, choose Reverse and enter the network')
        nameservers = []
        for line in (values.get('nameservers') or '').splitlines():
            parts = line.split()
            if parts:
                nameservers.append((parts[0], parts[1] if len(parts) > 1 else None))
        rname = (values.get('rname') or '').strip() or None
        if rname and not rname.endswith('.'):
            rname += '.'
        try:
            ttl = dns.ttl.from_text((values.get('ttl') or '3600').strip())
        except (dns.ttl.BadTTL, ValueError):
            raise declare.DeclareError('Default TTL must be seconds or like 1h, 1d')
        text = declare.starter_zone(name, nameservers, rname, ttl)
        if not node_ids:
            raise declare.DeclareError('choose at least one node')
        if conn.execute('SELECT 1 FROM zones WHERE name = ?', (name,)).fetchone():
            raise declare.DeclareError(f'{name} is already in LiteBlox')
    except (declare.DeclareError, ValueError) as e:
        return templates.TemplateResponse(request, 'zone_new.html', {
            'user': user, 'nodes': _zone_targets(conn), 'form': values, 'chosen': node_ids, 'error': str(e)},
            status_code=422)
    username = user.username
    def run(log, job_id):
        declare.create_zone(settings, name, node_ids, text, username, log)
        # link the job to the zone it created, so its page offers a way there
        job_conn = db_connect(settings.db_path)
        try:
            with job_conn:
                job_conn.execute('UPDATE jobs SET zone_id = (SELECT id FROM zones WHERE name = ?) WHERE id = ?',
                                 (name, job_id))
        finally:
            job_conn.close()
    job_id = jobs.start(settings.db_path, 'create zone', run, username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


def _zone_new_forwarding(request, user, conn, values, node_ids, form):
    settings = request.app.state.settings
    mode = values.get('forward_mode', 'only')
    try:
        name = declare.check_zone_name(values.get('fwd_name'), forwarding=True)
        declare._forwarding_values(values.get('forwarders'), mode)
        if mode not in ('only', 'first'):
            raise declare.DeclareError('forward must be only or first')
        if not node_ids:
            raise declare.DeclareError('choose at least one node')
        if conn.execute('SELECT 1 FROM zones WHERE name = ?', (name,)).fetchone():
            raise declare.DeclareError(f'{name} is already in LiteBlox')
    except declare.DeclareError as e:
        return templates.TemplateResponse(request, 'zone_new.html', {
            'user': user, 'nodes': _zone_targets(conn), 'form': values, 'chosen': node_ids, 'error': str(e)},
            status_code=422)
    forwarders, validate = values.get('forwarders'), bool(form.get('validate_except'))
    username = user.username

    def run(log, job_id):
        declare.create_forwarding_zone(settings, name, node_ids, forwarders, mode, validate, username, log)
        job_conn = db_connect(settings.db_path)
        try:
            with job_conn:
                job_conn.execute('UPDATE jobs SET zone_id = (SELECT id FROM zones WHERE name = ?) WHERE id = ?',
                                 (name, job_id))
        finally:
            job_conn.close()
    job_id = jobs.start(settings.db_path, 'create zone', run, username=username)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── records grid ───────────────────────────────────────────────────────────────

@router.get('/zones/{name}')
def zone_page(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    if ctx.zone is None:
        return RedirectResponse(f'/zones/{name}/raw', status_code=303)
    published = ctx.published_zone()
    serving = _zone_nodes(conn, ctx.row, pub.sha(ctx.drafts.published(ctx.row)))
    ns, ns_problems, ns_notes = nameservers.check(ctx.zone, serving, _ns_lookup(conn, ctx))
    return templates.TemplateResponse(request, 'zone.html', {
        **_grid_context(request, user, ctx), 'tab': 'records', 'soa': ctx.zone.soa,
        'soa_fields': _soa_fields(ctx.zone), 'soa_help': SOA_HELP, 'published_serial': published.serial if published else None,
        'nodes': serving, 'last_deploy': next(iter(pub.recent_deploys(conn, ctx.row['id'], 1)), None),
        'ns': ns, 'ns_problems': ns_problems, 'ns_notes': ns_notes,
        'ns_error': request.query_params.get('ns_error'), 'failed_ptr': dynamic.failed_ptr(conn, ctx.row['id']),
        'rr': _tokens(ctx, ctx.zone.records()), 'zone_row': ctx.row,      # rr: the grid's rows plus the SOA and NS cards
        'stale_view': _stale_view(conn, ctx) if ctx.dynamic and request.query_params.get('stale') else None,
        'done': request.query_params.get('done')})


def _stale_view(conn, ctx):
    """The zone's DHCP names and which are stale, for its page (?stale=1)."""
    from . import reclaim
    found, errors = reclaim.all_leases(ctx.settings, conn)
    trouble = errors[0] if errors else reclaim.dhcp_trouble(conn)
    # looking starts a name's clock too, so a zone that isn't reclaimed on a schedule still learns its names' age
    items = reclaim.review(conn, ctx.settings, ctx.row, ctx.zone, found, notice=not trouble)
    ptrs, _ = reclaim.review_ptrs(ctx.settings, conn, ctx.row, ctx.zone, found, notice=not trouble)
    if trouble:                     # without trustworthy leases, nothing is called stale
        for i in items + ptrs:
            if i['stale']:
                i['stale'], i['why'] = False, f"can't tell: {trouble}"
    return {'names': items, 'stale': [i for i in items if i['stale']], 'trouble': trouble,
            'ptrs': ptrs, 'stale_ptrs': [i for i in ptrs if i['stale']],
            'grace': reclaim.grace(conn, ctx.row), 'default': reclaim.grace_default(conn, ctx.row)}


@router.post('/zones/{name}/stale')
async def stale_delete(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    """Delete the DHCP names ticked in the zone's stale view (their A, AAAA, DHCID and PTR), and the stale PTRs."""
    from . import reclaim
    ctx = Ctx(request, conn, name)
    form = await request.form()
    names, owners = form.getlist('names'), form.getlist('ptrs')
    if not ctx.dynamic or not (names or owners):
        return RedirectResponse(f'/zones/{name}?stale=1#stale', status_code=303)
    lines = reclaim.delete(ctx.settings, conn, name, names, user.username) if names else []
    stale_lines = reclaim.delete_ptrs(ctx.settings, conn, name, owners, user.username) if owners else []
    with conn:
        conn.executemany('DELETE FROM ddns_names WHERE name = ?', [(n.rstrip('.').lower(),) for n in names])
        # what a held-back pass asked you to look at is dealt with: Needs attention drops it
        conn.execute('UPDATE zones SET reclaim_note = NULL WHERE id = ?', (ctx.row['id'],))
    if names or stale_lines:        # a PTR whose name got its address back (or that went already) stays: not logged
        audit(conn, user.username, 'ddns_delete', f'{name}: ' + ', '.join(
            names + [line.removeprefix('removed ') for line in stale_lines]))
    removed = sum(1 for line in lines if line.startswith('removed ') and ' PTR ' not in line)
    ptrs = sum(1 for line in lines if 'the PTR for' in line)
    parts = []
    if names:
        parts.append(f"{removed} name{'' if removed == 1 else 's'} removed" + (
            f", with {ptrs} PTR record{'' if ptrs == 1 else 's'}" if ptrs else ''))
    if owners and stale_lines:
        parts.append(f"{len(stale_lines)} stale PTR record{'' if len(stale_lines) == 1 else 's'} removed")
    elif owners:
        parts.append('no PTR record removed: its name has that address again, or it was gone already')
    done = '; '.join(parts)
    return RedirectResponse(f'/zones/{name}?stale=1&done={quote(done)}#stale', status_code=303)


def _zone_nodes(conn, row, published_sha=None):
    rows = conn.execute('SELECT n.id, n.name, n.host, n.role, n.managed, zn.node_file, zn.deployed_sha256 '
                        'FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id WHERE zn.zone_id = ? ORDER BY n.name',
                        (row['id'],)).fetchall()
    # a secondary has no file LiteBlox writes; it follows the primary by NOTIFY and IXFR
    if row['kind'] == 'forwarding' or row['dynamic']:
        return [dict(r, in_sync=None) for r in rows]      # nothing LiteBlox publishes to compare
    return [dict(r, in_sync=None if r['role'] == 'secondary' else r['deployed_sha256'] == published_sha)
            for r in rows]


def _candidates(conn, zone_id):
    """Ready, taken-over nodes that don't serve the zone yet."""
    serving = {r['node_id'] for r in conn.execute('SELECT node_id FROM zone_nodes WHERE zone_id = ?', (zone_id,))}
    return [n for n in _ready_nodes(conn) if n['id'] not in serving and n['managed']]


def _ns_lookup(conn, ctx):
    """lookup(name) -> its addresses from whichever LiteBlox zone holds it (drafts first), or None."""
    names = [r['name'] for r in conn.execute("SELECT name FROM zones WHERE kind = 'primary'")]
    parsed = {ctx.name: ctx.zone}

    def lookup(target):
        holder = max((z for z in names if target.is_subdomain(dns.name.from_text(z + '.'))), key=len, default=None)
        if holder is None:
            return None
        if holder not in parsed:
            row = conn.execute('SELECT * FROM zones WHERE name = ?', (holder,)).fetchone()
            try:
                parsed[holder] = Zone.parse(ctx.drafts.load(row)[0], holder + '.')
            except ZoneParseError:
                parsed[holder] = None
        return nameservers.addresses_in(parsed[holder], target) if parsed[holder] else None
    return lookup


# ── nameservers card ───────────────────────────────────────────────────────────

@router.post('/zones/{name}/ns')
async def ns_add(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    if _stale(ctx, form):
        return RedirectResponse(f'/zones/{name}?conflict=1', status_code=303)
    target = (form.get('target') or '').strip()
    try:
        owner, _, _, _ = records.check(ctx.zone, None, '@', None, 'NS', target)
        wanted = dns.name.from_text(target, ctx.zone.origin)
        if any(dns.name.from_text(_rdata_tokens(r.rdata)[0], r.origin) == wanted for r in nameservers.apex_ns(ctx.zone)):
            raise records.RecordError({'value': f'{wanted} is already a nameserver'})
    except records.RecordError as e:
        return RedirectResponse(f"/zones/{name}?ns_error={'; '.join(e.errors.values())}", status_code=303)
    except dns.exception.DNSException as e:
        return RedirectResponse(f'/zones/{name}?ns_error=bad name: {e}', status_code=303)
    ctx.zone.add('@', 'NS', target, after=(nameservers.apex_ns(ctx.zone) or [None])[-1])
    ctx.save(user.username)
    audit(conn, user.username, 'ns_add', f'{name}: {target}')
    return RedirectResponse(f'/zones/{name}', status_code=303)


@router.post('/zones/{name}/ns/{record_id}/delete')
async def ns_delete(request: Request, name: str, record_id: int, user: User = Depends(require_admin),
                    conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    if _stale(ctx, form):
        return RedirectResponse(f'/zones/{name}?conflict=1', status_code=303)
    rec = _record(ctx, record_id, form.get('rr'))
    if rec is None:
        return RedirectResponse(f'/zones/{name}?conflict=1', status_code=303)
    if rec not in nameservers.apex_ns(ctx.zone):
        raise HTTPException(status_code=404, detail='not one of the zone\'s nameservers')
    if len(nameservers.apex_ns(ctx.zone)) == 1:
        return RedirectResponse(f'/zones/{name}?ns_error=a zone needs at least one nameserver', status_code=303)
    ctx.zone.delete(rec)
    ctx.save(user.username)
    audit(conn, user.username, 'ns_delete', f'{name}: {rec.rdata}')
    return RedirectResponse(f'/zones/{name}', status_code=303)


@router.get('/zones/{name}/records/new')
def record_new(request: Request, name: str, after: int = None, type: str = 'A',
               user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    return _edit_row(request, ctx, None, form={'type': type.upper(), 'name': '', 'ttl': ''}, after=after)


@router.get('/zones/{name}/records/{record_id}/edit')
def record_edit(request: Request, name: str, record_id: int, rr: str = None, user: User = Depends(require_admin),
                conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    rec = _record(ctx, record_id, rr)
    if rec is None:
        return _conflict(ctx, record=True)
    return _edit_row(request, ctx, rec)


@router.get('/zones/{name}/records/{record_id}/row')
def record_row(request: Request, name: str, record_id: int, rr: str = None, user: User = Depends(current_user),
               conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    rec = _record(ctx, record_id, rr)
    if rec is None:
        return _conflict(ctx, record=True)
    return templates.TemplateResponse(request, 'partials/record_row.html', {
        'user': user, 'zone_name': name, 'zone': ctx.zone, 'r': rec, 'rev': ctx.rev, 'rr': _tokens(ctx, [rec]),
        'previews': {rec.id: records.target_preview(rec.rtype, rec.rdata, rec.origin)}})


async def _form(request):
    return {k: v for k, v in (await request.form()).items()}


def _ptr_enabled(ctx, form):
    # the edit row sends ptr_field so an unticked box can be told apart from "no checkbox"
    return ('ptr' in form) if 'ptr_field' in form else bool(ctx.row['auto_ptr'])


def _apply(ctx, rec, form, after_id, username):
    """A row form, applied (plus any PTR change). Returns (notes, warnings, focus id) or raises RecordError."""
    rtype = (form.get('type') or '').upper()
    after = ctx.zone.get(after_id) if after_id else None
    notes, warnings, saved = editing.apply_row(ctx, rec, form.get('name', ''), form.get('ttl'), rtype,
                                               records.compose(rtype, form), form.get('comment'),
                                               _ptr_enabled(ctx, form), after, username)
    return notes, warnings, saved.id if saved else None


@router.post('/zones/{name}/records')
async def record_add(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await _form(request)
    with editing.zone_lock(name):
        ctx = Ctx(request, conn, name)
        if _stale(ctx, form):
            return _conflict(ctx)
        # a dynamic zone is AXFR order, re-read since the page: a position from the page means nothing now
        after = int(form['after']) if form.get('after') and not ctx.dynamic else None
        try:
            notes, warnings, focus = _apply(ctx, None, form, after, user.username)
        except records.RecordError as e:
            return _edit_row(request, ctx, None, form=form, errors=e.errors, after=after, status_code=422,
                             headers={'HX-Retarget': '#row-new', 'HX-Reswap': 'outerHTML'})
    audit(conn, user.username, 'record_add', f"{name}: {form.get('name')} {form.get('type')}")
    return _grid(request, user, ctx, focus=focus, warnings=warnings, notes=notes)


# ── many at once: pasted lines, CSV ────────────────────────────────────────────

def _many_page(request, user, ctx, form=None, rows=None, error=None, status_code=200):
    form = form or {}
    return templates.TemplateResponse(request, 'zone_many.html', {
        'user': user, 'zone_name': ctx.name, 'tab': 'records', 'is_draft': ctx.is_draft, 'rev': ctx.rev,
        'text': form.get('text', ''), 'csv_text': form.get('csv_text', ''), 'csv_name': form.get('csv_name', ''),
        'replace': bool(form.get('replace')), 'ptr': ('ptr' in form) if 'ptr_field' in form else bool(ctx.row['auto_ptr']),
        'rows': rows, 'counts': many.counts(rows) if rows is not None else {}, 'error': error,
        'auto_ptr': bool(ctx.row['auto_ptr'])}, status_code=status_code)


async def _many_input(request):
    """The form, with an uploaded CSV read into csv_text (so the preview can carry it to Add)."""
    form = await request.form()
    data = {k: v for k, v in form.items() if isinstance(v, str)}
    if data.get('csv_clear'):
        data.pop('csv_text', None), data.pop('csv_name', None)
    upload = form.get('csv')
    if upload is not None and not isinstance(upload, str) and upload.filename:
        raw = await upload.read()
        try:
            data['csv_text'], data['csv_name'] = raw.decode('utf-8-sig'), upload.filename
        except UnicodeDecodeError:
            data['csv_error'] = f'{upload.filename} is not UTF-8 text'
    return data


def _many_lines(ctx, form):
    if form.get('csv_text', '').strip():
        return many.from_csv(form['csv_text'])
    return many.from_text(form.get('text', ''), ctx.zone.origin)


def _many_ctx(request, conn, name):
    ctx = Ctx(request, conn, name)
    if ctx.dynamic:
        raise HTTPException(status_code=303, headers={'Location': f'/zones/{name}'})
    if ctx.zone is None:
        raise HTTPException(status_code=303, headers={'Location': f'/zones/{name}/raw'})
    return ctx


@router.get('/zones/{name}/records/many')
def many_page(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _many_page(request, user, _many_ctx(request, conn, name))


@router.post('/zones/{name}/records/many/preview')
async def many_preview(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await _many_input(request)
    ctx = _many_ctx(request, conn, name)
    if form.get('csv_error'):
        return _many_page(request, user, ctx, form, error=form['csv_error'], status_code=422)
    lines = _many_lines(ctx, form)
    if not lines:
        return _many_page(request, user, ctx, form, error='Nothing to add: paste some lines or pick a CSV file.',
                          status_code=422)
    return _many_page(request, user, ctx, form, rows=many.preview(ctx, lines, bool(form.get('replace'))))


@router.post('/zones/{name}/records/many')
async def many_add(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await _many_input(request)
    with editing.zone_lock(name):
        ctx = _many_ctx(request, conn, name)
        if form.get('rev') != ctx.rev:
            return _many_page(request, user, ctx, form, rows=many.preview(ctx, _many_lines(ctx, form),
                                                                          bool(form.get('replace'))),
                              error='The zone changed since the preview: check it again, then add.', status_code=409)
        ptr_on = ('ptr' in form) if 'ptr_field' in form else bool(ctx.row['auto_ptr'])
        try:
            rows, notes, warnings = many.add(ctx, _many_lines(ctx, form), bool(form.get('replace')), ptr_on,
                                             user.username)
        except ValueError as e:
            return _many_page(request, user, ctx, form, rows=many.preview(ctx, _many_lines(ctx, form),
                                                                          bool(form.get('replace'))),
                              error=str(e).capitalize() + '.', status_code=422)
    c = many.counts(rows)
    done = ', '.join(f'{c[k]} {label}' for k, label in (('add', 'added'), ('change', 'changed'), ('remove', 'removed'))
                     if c.get(k))
    audit(conn, user.username, 'record_many', f"{name}: {done or 'nothing to change'}"
                                              f"{' from ' + form['csv_name'] if form.get('csv_name') else ''}")
    # the draft's diff is the natural next step; with nothing to change, back to the grid
    return RedirectResponse(f'/zones/{name}/review' if done else f'/zones/{name}', status_code=303)


@router.get('/zones/{name}/records.csv')
def records_csv(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    if ctx.zone is None:
        raise HTTPException(status_code=409, detail="the zone doesn't parse: see its Raw tab")
    return Response(many.to_csv(ctx.zone), media_type='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{name}.csv"'})


@router.get('/zones/{name}/records-template.csv')
def records_template(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    Ctx(request, conn, name)
    forward = next((r['name'] for r in conn.execute(
        "SELECT name FROM zones WHERE kind = 'primary' AND name NOT LIKE '%.arpa' ORDER BY name")), 'example.com')
    return Response(many.template(name, forward), media_type='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="{name}-template.csv"'})


BULK_ACTIONS = {'delete': 'delete', 'ttl': 'set the TTL of', 'comment': 'set the comment of'}


def _alert(text, status_code=422):
    return HTMLResponse(f'<p class="error" role="alert">{escape(text)}</p>', status_code=status_code,
                        headers={'HX-Retarget': '#zone-alert', 'HX-Reswap': 'innerHTML'})


@router.post('/zones/{name}/records/bulk')
async def records_bulk(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    """The selected rows: delete them, or set their TTL or comment, as one change (one draft save, or one update
    for a dynamic zone, where Delete is the only action); the PTRs follow a delete as for one row."""
    form = await request.form()
    action = form.get('action')
    if action not in BULK_ACTIONS:
        raise HTTPException(status_code=400, detail='unknown action')
    with editing.zone_lock(name):
        ctx = Ctx(request, conn, name)
        tokens, ids = form.getlist('rr'), form.getlist('ids')
        if ctx.dynamic and action != 'delete':
            return _alert(f'{name} is dynamic: only Delete works on its rows', 400)
        if not (tokens if ctx.dynamic else ids):
            return _alert('Nothing selected.', 400)
        if not ctx.dynamic and form.get('rev') != ctx.rev:
            return _conflict(ctx)
        try:
            recs = [_record(ctx, None, t) for t in tokens] if ctx.dynamic else [_record(ctx, int(i)) for i in ids]
        except ValueError:
            raise HTTPException(status_code=400, detail='bad selection')
        if any(r is None for r in recs):
            return _conflict(ctx, record=True)
        recs = list({id(r): r for r in recs}.values())
        origin = ctx.zone.origin
        if action == 'delete':
            ops = [editing.Op.removing(r) for r in recs]
        else:
            value = (form.get(action) or '').strip()
            ops = [editing.Op(r, r.relative_name(origin), value if action == 'ttl' else r.ttl, r.rtype, r.rdata,
                              value if action == 'comment' else r.comment) for r in recs]
        try:
            notes, warnings, _ = editing.batch(ctx, ops, action == 'delete' and bool(ctx.row['auto_ptr']),
                                               user.username)
        except records.RecordError as e:
            rec = recs[getattr(e, 'index', 0)]
            return _alert(f"{rec.relative_name(origin)} {rec.rtype}: {'; '.join(e.errors.values())}")
    audit(conn, user.username, 'record_bulk',
          f"{name}: {BULK_ACTIONS[action]} {len(recs)} record{'' if len(recs) == 1 else 's'}")
    return _grid(request, user, ctx, warnings=warnings, notes=notes)


@router.post('/zones/{name}/records/{record_id}')
async def record_save(request: Request, name: str, record_id: int, user: User = Depends(require_admin),
                      conn=Depends(get_db)):
    form = await _form(request)
    with editing.zone_lock(name):
        ctx = Ctx(request, conn, name)
        if _stale(ctx, form):
            return _conflict(ctx)
        rec = _record(ctx, record_id, form.get('rr'))
        if rec is None:
            return _conflict(ctx, record=True)
        try:
            notes, warnings, focus = _apply(ctx, rec, form, None, user.username)
        except records.RecordError as e:
            return _edit_row(request, ctx, rec, form=form, errors=e.errors, status_code=422,
                             headers={'HX-Retarget': f'#row-{record_id}', 'HX-Reswap': 'outerHTML'})
    audit(conn, user.username, 'record_edit', f"{name}: {form.get('name')} {form.get('type')}")
    return _grid(request, user, ctx, focus=focus, warnings=warnings, notes=notes)


@router.post('/zones/{name}/records/{record_id}/delete')
async def record_delete(request: Request, name: str, record_id: int, user: User = Depends(require_admin),
                        conn=Depends(get_db)):
    form = await _form(request)
    with editing.zone_lock(name):
        ctx = Ctx(request, conn, name)
        if _stale(ctx, form):
            return _conflict(ctx)
        rec = _record(ctx, record_id, form.get('rr'))
        if rec is None:
            return _conflict(ctx, record=True)
        notes, warnings = editing.delete_row(ctx, rec, bool(ctx.row['auto_ptr']), user.username)
    audit(conn, user.username, 'record_delete', f'{name}: {rec.relative_name(ctx.zone.origin)} {rec.rtype}')
    return _grid(request, user, ctx, warnings=warnings, notes=notes)


# ── SOA ────────────────────────────────────────────────────────────────────────

SOA_FIELDS = [('mname', 'Primary nameserver'), ('rname', 'Responsible mailbox'), ('serial', 'Serial'),
              ('refresh', 'Refresh'), ('retry', 'Retry'), ('expire', 'Expire'), ('minimum', 'Negative TTL')]


SOA_TIMERS = ('refresh', 'retry', 'expire', 'minimum')
_UNITS_HINT = '<p class="muted small">Seconds, or units: <code>30m</code>, <code>1h</code>, <code>1d</code>, <code>2w</code>.</p>'
SOA_HELP = [
    ('mname', 'Primary nameserver',
     '<p>MNAME: the zone\'s primary server, normally your primary node\'s name (a new zone gets the first '
     'nameserver). BIND doesn\'t send NOTIFY to the server named here, and dynamic update clients such as '
     '<code>nsupdate</code> send their updates to it when they aren\'t given a server. LiteBlox notifies the '
     'secondaries itself and doesn\'t use it.</p>'
     '<p>A host name; end it with a dot when it\'s outside this zone.</p>'),
    ('rname', 'Responsible mailbox',
     '<p>RNAME: the zone admin\'s email address with the <code>@</code> written as a dot, so '
     '<code>hostmaster.example.com.</code> means hostmaster@example.com. A dot before the <code>@</code> '
     'is written <code>\\.</code></p>'),
    ('refresh', 'Refresh',
     '<p>How often a secondary checks the primary\'s serial for changes. The secondaries also get a NOTIFY '
     'whenever the zone changes and transfer it right away, so Refresh is the fallback for a NOTIFY that '
     'went missing.</p><p>Typical: 1h to 1d.</p>' + _UNITS_HINT),
    ('retry', 'Retry',
     '<p>How long a secondary waits to try again after a failed refresh. Keep it shorter than Refresh.</p>'
     '<p>Typical: 15m to 2h.</p>' + _UNITS_HINT),
    ('expire', 'Expire',
     '<p>How long a secondary keeps answering for the zone while it can\'t reach a primary. After that it '
     'stops answering. Must be longer than Refresh plus Retry.</p><p>Typical: 1w to 4w.</p>' + _UNITS_HINT),
    ('minimum', 'Negative TTL',
     '<p>How long resolvers cache a "no such name" or "no such record" answer (RFC 2308). Lower it before '
     'adding a name clients have recently looked up, or they keep getting the old "not found".</p>'
     '<p>Typical: 5m to 1h.</p>' + _UNITS_HINT),
]


def _soa_fields(zone):
    return editing.soa_fields(zone)


@router.post('/zones/{name}/soa')
async def soa_save(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await _form(request)
    with editing.zone_lock(name):
        ctx = Ctx(request, conn, name)
        if _stale(ctx, form) or (ctx.dynamic and 'rr' in form and dynamic.find_token(ctx.zone, form['rr']) is None):
            return RedirectResponse(f'/zones/{name}?conflict=1', status_code=303)
        problem = editing.save_soa(ctx, form, user.username)
    if problem:
        return RedirectResponse(f'/zones/{name}?soa_error={problem}', status_code=303)
    return RedirectResponse(f'/zones/{name}', status_code=303)


# ── raw editor ─────────────────────────────────────────────────────────────────

@router.get('/zones/{name}/raw')
def raw_page(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    return templates.TemplateResponse(request, 'zone_raw.html', {
        'user': user, 'zone_name': name, 'text': ctx.text, 'rev': ctx.rev, 'is_draft': ctx.is_draft,
        'error': ctx.error, 'tab': 'raw', 'dynamic': ctx.dynamic,
        'unsorted': None if ctx.dynamic else why_unsorted(ctx.text, name + '.')})


@router.post('/zones/{name}/raw')
async def raw_save(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await _form(request)
    with editing.zone_lock(name):
        return _raw_save(request, name, user, conn, form)


def _raw_save(request, name, user, conn, form):
    ctx = Ctx(request, conn, name)
    if ctx.dynamic:
        return RedirectResponse(f'/zones/{name}/raw', status_code=303)  # named owns the file: edit in the grid
    if form.get('rev') != ctx.rev:
        return RedirectResponse(f'/zones/{name}/raw', status_code=303)
    # browsers submit textareas with CRLF; keep the zone's own line endings
    text = (form.get('text') or '').replace('\r\n', '\n')
    newline = ctx.zone.newline if ctx.zone else ('\r\n' if '\r\n' in ctx.text else '\n')
    if newline == '\r\n':
        text = text.replace('\n', '\r\n')
    try:
        Zone.parse(text, name + '.').soa
        ctx.drafts.save(ctx.row, text, user.username)
    except (ZoneParseError, LookupError) as e:
        return templates.TemplateResponse(request, 'zone_raw.html', {
            'user': user, 'zone_name': name, 'text': text, 'rev': ctx.rev, 'is_draft': ctx.is_draft,
            'error': str(e), 'tab': 'raw'}, status_code=422)
    audit(conn, user.username, 'zone_raw_edit', name)
    return RedirectResponse(f'/zones/{name}', status_code=303)


# ── review / discard ───────────────────────────────────────────────────────────

@router.get('/zones/{name}/review')
def review(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    if ctx.dynamic:
        return RedirectResponse(f'/zones/{name}', status_code=303)     # edits are live; nothing to review
    published = ctx.drafts.published(ctx.row)
    check = None
    if ctx.is_draft:
        try:
            check = named_checkzone(name, ctx.text)
        except ToolMissing as e:
            check = (None, str(e))
    states = pub.node_states(conn, ctx.settings, ctx.row)
    for st in states:
        if st['state'] == 'drift':
            st['diff'] = diff(published, st['content'], f'{name} (LiteBlox)', f"{st['node']['name']}: {st['node']['node_file']}")
    linked = []
    for other in sorted(ctx.drafts.linked(name)):
        octx = Ctx(request, conn, other)
        opub = octx.drafts.published(octx.row)
        ostates = pub.node_states(conn, ctx.settings, octx.row)
        try:
            ocheck = named_checkzone(other, octx.text)
        except ToolMissing as e:
            ocheck = (None, str(e))
        linked.append({'name': other, 'rev': octx.rev, 'summary': octx.summary(), 'check': ocheck,
                       'stale': octx.drafts.is_stale(octx.row), 'states': ostates,
                       'diff': diff(opub, octx.text, f'{other} (published)', f'{other} (draft)')})
        states_blocked = any(st['state'] in ('drift', 'unreachable') for st in ostates)
        if states_blocked:
            linked[-1]['blocked'] = True
    blocked = any(st['state'] in ('drift', 'unreachable') for st in states) or any(l.get('blocked') for l in linked)
    return templates.TemplateResponse(request, 'zone_review.html', {
        'user': user, 'zone_name': name, 'is_draft': ctx.is_draft, 'summary': ctx.summary(),
        'diff': diff(published, ctx.text, f'{name} (published)', f'{name} (draft)') if ctx.is_draft else '',
        'check': check, 'stale': ctx.is_draft and ctx.drafts.is_stale(ctx.row), 'meta': ctx.drafts.meta(name),
        'tab': 'review', 'states': states, 'blocked': blocked, 'rev': ctx.rev,
        'behind': any(st['state'] == 'behind' for st in states),
        'running': pub.running(conn, ctx.row['id']), 'deploys': pub.recent_deploys(conn, ctx.row['id'], 5),
        'linked': linked, 'linked_bad': any(l['stale'] or (l['check'] and l['check'][0] is False) for l in linked),
        'queued_ptr': dynamic.queued_ptr(conn, ctx.row['id'])})


@router.post('/zones/{name}/publish')
async def publish(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    settings, username, reviewed = ctx.settings, user.username, form.get('rev')
    revs = {k[4:]: v for k, v in form.items() if k.startswith('rev:')}
    message = ' '.join((form.get('message') or '').split())[:200]      # one line for the History list
    if message in ('', f'Publish {name}', f'Republish {name}'):
        message = None                                                  # the default per-zone message
    job_id = jobs.start(settings.db_path, 'publish',
                        lambda log, job_id: pub.publish(settings, name, username, log, rev=reviewed, job_id=job_id,
                                                        linked=True, revs=revs, message=message),
                        username=username, zone_id=ctx.row['id'])
    audit(conn, username, 'publish', name + (f': {message}' if message else ''))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/zones/{name}/nodes/{node_id}/accept')
async def accept_node(request: Request, name: str, node_id: int, user: User = Depends(require_admin),
                      conn=Depends(get_db)):
    """Drift: let the next publish overwrite the node's changed file."""
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    state = next((s for s in pub.node_states(conn, ctx.settings, ctx.row) if s['node']['id'] == node_id), None)
    if state is None or state['sha256'] != form.get('sha256'):
        return RedirectResponse(f'/zones/{name}/review', status_code=303)
    pub.accept_node_file(conn, ctx.row, node_id, state['sha256'])
    audit(conn, user.username, 'drift_overwrite', f"{name} on {state['node']['name']}")
    return RedirectResponse(f'/zones/{name}/review', status_code=303)


@router.post('/zones/{name}/nodes/{node_id}/import')
async def import_node(request: Request, name: str, node_id: int, user: User = Depends(require_admin),
                      conn=Depends(get_db)):
    """Drift: take the node's changed file into LiteBlox as the new published copy."""
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    state = next((s for s in pub.node_states(conn, ctx.settings, ctx.row) if s['node']['id'] == node_id), None)
    if state is None or state['sha256'] != form.get('sha256'):
        return RedirectResponse(f'/zones/{name}/review', status_code=303)
    info = {'name': name, 'file': state['node']['node_file']}
    resolve_conflict(conn, Repo(ctx.settings.repo_dir).ensure(), state['node'], info, state['content'],
                     state['sha256'], 'node', user.username)
    audit(conn, user.username, 'drift_import', f"{name} from {state['node']['name']}")
    return RedirectResponse(f'/zones/{name}/review', status_code=303)


# ── zone declarations: nodes, settings ─────────────────────────────────────────

def _zone_job(request, ctx, kind, fn, username):
    job_id = jobs.start(ctx.settings.db_path, kind, fn, username=username, zone_id=ctx.row['id'])
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/zones/{name}/nodes/add')
async def zone_add_node(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name, forwarding_ok=True)
    node_id = int((await _form(request)).get('node_id') or 0)
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'add node to zone',
                     lambda log: declare.add_node(settings, name, node_id, username, log), username)


@router.post('/zones/{name}/nodes/remove')
async def zone_remove_node(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name, forwarding_ok=True)
    node_id = int((await _form(request)).get('node_id') or 0)
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'remove node from zone',
                     lambda log: declare.remove_node(settings, name, node_id, username, log), username)


@router.get('/zones/{name}/settings')
def zone_settings(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name, forwarding_ok=True)
    return templates.TemplateResponse(request, 'zone_settings.html', {
        'user': user, 'zone_name': name, 'zone_row': ctx.row, 'tab': 'settings', 'is_draft': ctx.is_draft,
        'error': request.query_params.get('error'), 'candidates': _candidates(conn, ctx.row['id']),
        'nodes': _zone_nodes(conn, ctx.row, pub.sha(ctx.drafts.published(ctx.row))),
        'include': None if ctx.forwarding else declare.stanza(conn, ctx.row),
        'dynamic_blocker': _dynamic_blocker(conn, ctx),
        'grants': conn.execute('SELECT g.*, k.name AS key FROM key_grants g JOIN tsig_keys k ON k.id = g.key_id '
                               'WHERE g.zone_id = ? ORDER BY k.name', (ctx.row['id'],)).fetchall(),
        'reclaim_default': _reclaim_default(conn, ctx),
        'forwarding': ctx.forwarding, 'recursion_off': {n['id']: declare.recursion_off(n) for n in _ready_nodes(conn)},
        'recursion': {n['id']: _recursion_text(n) for n in _ready_nodes(conn)} if ctx.forwarding else {}})


def _dynamic_blocker(conn, ctx):
    """Why the zone can't switch to dynamic updates now, or None."""
    if ctx.forwarding or ctx.dynamic:
        return None
    serving = conn.execute('SELECT n.* FROM nodes n JOIN zone_nodes zn ON zn.node_id = n.id WHERE zn.zone_id = ?',
                           (ctx.row['id'],)).fetchall()
    if not any(n['role'] == 'primary' for n in serving):
        return 'Updates go to the primary: pick a primary that serves this zone first (Nodes).'
    if any(n['role'] != 'primary' and n['role'] != 'secondary' for n in serving):
        return "Some of its nodes still hold their own copy: make the primary again so they become secondaries."
    if ctx.is_draft:
        return 'It has a draft: publish or discard it first.'
    return None


@router.post('/zones/{name}/dynamic')
async def zone_dynamic(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    on = (await _form(request)).get('dynamic') == 'on'
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'dynamic updates',
                     lambda log: declare.set_dynamic(settings, name, on, username, log), username)


def _recursion_text(node):
    """Who the node recurses (and so forwards) for, as its settings say."""
    from ..bindconf.model import NodeOptions
    o = NodeOptions.from_json(node['options'])
    if o.recursion is False:
        return 'recursion is off'
    who = ', '.join(o.allow_recursion) if o.allow_recursion is not None else 'localnets, localhost (BIND default)'
    return f'recurses for {who}'


@router.post('/zones/{name}/delete')
async def zone_delete(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name, forwarding_ok=True)
    if (await _form(request)).get('confirm_name', '').strip().lower().rstrip('.') != name:
        return RedirectResponse(f'/zones/{name}/settings?error=Type the zone name to delete it.#danger',
                                status_code=303)
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'delete zone',
                     lambda log: declare.delete_zone(settings, name, username, log), username)


@router.post('/zones/{name}/settings')
async def zone_settings_post(request: Request, name: str, user: User = Depends(require_admin),
                             conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    notify, also, allow = form.get('notify', 'no'), form.get('also_notify', ''), form.get('allow_transfer', '')
    query = form.get('allow_query')         # only taken-over nodes' zones.conf has the field
    try:
        if notify not in declare.NOTIFY_CHOICES:
            raise ValueError('notify must be no, explicit, yes or the BIND default')
        declare.parse_list(also)
        declare.parse_list(allow)
        declare.parse_list(query)
    except ValueError as e:
        return RedirectResponse(f'/zones/{name}/settings?error={e}', status_code=303)
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'zone settings',
                     lambda log: declare.update_settings(settings, name, notify, also, allow, username, log,
                                                         allow_query=query), username)


@router.post('/zones/{name}/forwarders')
async def zone_forwarders_post(request: Request, name: str, user: User = Depends(require_admin),
                               conn=Depends(get_db)):
    ctx = Ctx(request, conn, name, forwarding_ok=True)
    form = await _form(request)
    forwarders, mode = form.get('forwarders', ''), form.get('forward_mode', 'only')
    try:
        declare._forwarding_values(forwarders, mode)
    except declare.DeclareError as e:
        return RedirectResponse(f'/zones/{name}/settings?error={e}', status_code=303)
    settings, username = ctx.settings, user.username
    return _zone_job(request, ctx, 'zone forwarders',
                     lambda log: declare.update_forwarding(settings, name, forwarders, mode, username, log), username)


def _reclaim_default(conn, ctx):
    from . import reclaim
    return reclaim.grace_default(conn, ctx.row) if ctx.dynamic else None


@router.post('/zones/{name}/reclaim')
async def zone_reclaim(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    form = await _form(request)
    on, text = 'reclaim' in form, (form.get('reclaim_after') or '').strip()
    try:
        after = dns.ttl.from_text(text) if text else None
    except (dns.ttl.BadTTL, ValueError):
        after = -1
    if after is not None and not 60 <= after <= 365 * 86400:
        return RedirectResponse(f"/zones/{name}/settings?error={quote('After: a time from 1m to 365d, e.g. 12h or 1d')}#reclaim",
                                status_code=303)
    with conn:
        conn.execute('UPDATE zones SET reclaim = ?, reclaim_after = ?, reclaim_note = NULL WHERE id = ?',
                     (int(on), after, ctx.row['id']))
    audit(conn, user.username, 'zone_reclaim', f"{name}: {'on' if on else 'off'}"
                                               + (f', after {duration(after)}' if after else ''))
    if on:      # what would go now
        return RedirectResponse(f'/zones/{name}?stale=1#stale', status_code=303)
    return RedirectResponse(f'/zones/{name}/settings#reclaim', status_code=303)


@router.post('/zones/{name}/autoptr')
async def zone_autoptr(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    on = 'auto_ptr' in (await _form(request))
    with conn:
        conn.execute('UPDATE zones SET auto_ptr = ? WHERE id = ?', (int(on), ctx.row['id']))
    audit(conn, user.username, 'zone_auto_ptr', f"{name}: {'on' if on else 'off'}")
    return RedirectResponse(f'/zones/{name}/settings', status_code=303)


@router.post('/zones/{name}/notes')
async def zone_notes(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    notes = ((await _form(request)).get('notes') or '').replace('\r\n', '\n').strip()
    if notes != ctx.row['notes']:
        with conn:
            conn.execute('UPDATE zones SET notes = ? WHERE id = ?', (notes, ctx.row['id']))
        audit(conn, user.username, 'zone_notes', name)
    return RedirectResponse(f'/zones/{name}/settings#notes', status_code=303)


@router.get('/zones/{name}/deploys/{deploy_id}')
def deploy_detail(request: Request, name: str, deploy_id: int, user: User = Depends(current_user),
                  conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    row = conn.execute('SELECT * FROM deploys WHERE id = ? AND zone_id = ?', (deploy_id, ctx.row['id'])).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such deploy')
    return templates.TemplateResponse(request, 'deploy.html', {
        'user': user, 'zone_name': name, 'deploy': row, 'nodes': pub.deploy_nodes(conn, deploy_id), 'tab': 'review',
        'job': jobs.get(conn, row['job_id']) if row['job_id'] else None})


@router.post('/zones/{name}/discard')
def discard(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    with editing.zone_lock(name):
        editing.discard(Ctx(request, conn, name), user.username)
    return RedirectResponse(f'/zones/{name}', status_code=303)


@router.post('/zones/{name}/ptr-queue/retry')
def ptr_retry(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    settings, username, zone_id = ctx.settings, user.username, ctx.row['id']

    def run(log):
        c = db_connect(settings.db_path)
        try:
            row = c.execute('SELECT * FROM zones WHERE id = ?', (zone_id,)).fetchone()
            log(f"Sending the PTR changes {name}'s publish left behind")
            failed = dynamic.flush_ptr_queue(settings, c, row, username, log)
            if failed:
                raise RuntimeError(f"not sent to {', '.join(failed)}; they stay queued")
            log('✓ every queued PTR change is sent')
        finally:
            c.close()
    audit(conn, user.username, 'ptr_retry', name)
    return _zone_job(request, ctx, 'send PTR updates', run, user.username)


@router.post('/zones/{name}/ptr-queue/drop')
def ptr_drop(request: Request, name: str, user: User = Depends(require_admin), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    dynamic.drop_ptr_queue(conn, ctx.row['id'], failed=True)
    audit(conn, user.username, 'ptr_drop', name)
    return RedirectResponse(f'/zones/{name}', status_code=303)


# ── history ────────────────────────────────────────────────────────────────────

@router.get('/zones/{name}/history')
def history(request: Request, name: str, user: User = Depends(current_user), conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    repo = Repo(ctx.settings.repo_dir)
    return templates.TemplateResponse(request, 'zone_history.html', {
        'user': user, 'zone_name': name, 'commits': repo.log(ctx.row['repo_file'], limit=200), 'tab': 'history',
        'error': request.query_params.get('error'),
        'is_draft': ctx.is_draft, 'deploys': pub.recent_deploys(conn, ctx.row['id'], 20)})


@router.get('/zones/{name}/compare')
def history_compare(request: Request, name: str, v: list[str] = Query(default=[]),
                    user: User = Depends(current_user), conn=Depends(get_db)):
    """Everything that changed in a zone between two versions (publishes are versions too)."""
    ctx = Ctx(request, conn, name)
    repo = Repo(ctx.settings.repo_dir)
    commits = repo.log(ctx.row['repo_file'], limit=1000)
    index = {c['sha']: i for i, c in enumerate(commits)}        # newest first
    picked = list(dict.fromkeys(v))                             # a publish and its version are one commit
    if len(picked) != 2 or any(sha not in index for sha in picked):
        return RedirectResponse(f'/zones/{name}/history?error=pick-two', status_code=303)
    newer, older = sorted(picked, key=lambda sha: index[sha])
    before, after = repo.show(older, ctx.row['repo_file']), repo.show(newer, ctx.row['repo_file'])
    try:
        summary = records.summarize(Zone.parse(before, name + '.'), Zone.parse(after, name + '.'))
    except ZoneParseError:
        summary = None
    return templates.TemplateResponse(request, 'zone_compare.html', {
        'user': user, 'zone_name': name, 'tab': 'history', 'is_draft': ctx.is_draft,
        'older': commits[index[older]], 'newer': commits[index[newer]],
        'between': commits[index[newer]:index[older] + 1], 'summary': summary,
        'diff': diff(before, after, f'{name} {older[:10]}', f'{name} {newer[:10]}')})


@router.get('/zones/{name}/history/{sha}')
def history_commit(request: Request, name: str, sha: str, user: User = Depends(current_user),
                   conn=Depends(get_db)):
    ctx = Ctx(request, conn, name)
    repo = Repo(ctx.settings.repo_dir)
    commits = repo.log(ctx.row['repo_file'], limit=500)
    idx = next((i for i, c in enumerate(commits) if c['sha'] == sha), None)
    if idx is None:
        raise HTTPException(status_code=404, detail='no such commit for this zone')
    after = repo.show(sha, ctx.row['repo_file'])
    before = repo.show(commits[idx + 1]['sha'], ctx.row['repo_file']) if idx + 1 < len(commits) else ''
    return templates.TemplateResponse(request, 'zone_commit.html', {
        'user': user, 'zone_name': name, 'commit': commits[idx], 'tab': 'history',
        'diff': diff(before, after, 'before', 'after'), 'is_draft': ctx.is_draft,
        'is_current': after == ctx.drafts.published(ctx.row),
        'vs_current': diff(ctx.drafts.published(ctx.row), after, 'published now', f'version {sha[:10]}')})


@router.post('/zones/{name}/history/{sha}/restore')
async def history_restore(request: Request, name: str, sha: str, user: User = Depends(require_admin),
                          conn=Depends(get_db)):
    """Put an old version into the draft. Publishing it bumps the serial past whatever the nodes serve."""
    form = await _form(request)
    with editing.zone_lock(name):
        return _restore(request, name, sha, user, conn, form)


def _restore(request, name, sha, user, conn, form):
    ctx = Ctx(request, conn, name)
    repo = Repo(ctx.settings.repo_dir)
    if not any(c['sha'] == sha for c in repo.log(ctx.row['repo_file'], limit=1000)):
        raise HTTPException(status_code=404, detail='no such commit for this zone')
    if ctx.is_draft and not form.get('replace'):
        return RedirectResponse(f'/zones/{name}/history/{sha}?error=draft', status_code=303)
    text = repo.show(sha, ctx.row['repo_file'])
    if ctx.dynamic:
        # live zone: send the difference as one guarded update (fails if it changed since this page loaded)
        if form.get('rev') and form.get('rev') != ctx.rev:
            return RedirectResponse(f'/zones/{name}/history/{sha}?error=changed', status_code=303)
        try:
            dynamic.send_edit(ctx.settings, conn, ctx.row, ctx.text, text, user.username, f'Restore {sha[:10]}')
        except dynamic.DynamicError as e:
            return RedirectResponse(f'/zones/{name}/history/{sha}?error={e}', status_code=303)
        audit(conn, user.username, 'history_restore', f'{name} to {sha[:10]} (dynamic)')
        return RedirectResponse(f'/zones/{name}', status_code=303)
    try:
        Zone.parse(text, name + '.').soa
    except (ZoneParseError, LookupError):
        return RedirectResponse(f'/zones/{name}/history/{sha}?error=parse', status_code=303)
    for other in ctx.drafts.linked(name):        # a restore replaces edits that made linked PTR changes
        ctx.drafts.discard(other)
    ctx.drafts.discard(name)
    ctx.drafts.save(ctx.row, text, user.username, note={'restored_from': sha})
    audit(conn, user.username, 'history_restore', f'{name} to {sha[:10]}')
    return RedirectResponse(f'/zones/{name}/review', status_code=303)
