"""/api/v1: the JSON API. A thin layer over what the pages use, so it gets the same checks and audit."""

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from ..db import audit, get_db
from ..nodes import service
from . import models
from .deps import api_user, api_writer
from .tokens import ApiUser

router = APIRouter(prefix='/api/v1')


def _settings(request):
    return request.app.state.settings


@router.get('/me', response_model=models.Me, tags=['account'], summary='Who this token belongs to')
def me(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Who this token belongs to, and what it may do."""
    row = conn.execute('SELECT expires_at FROM api_tokens WHERE id = ?', (user.token_id,)).fetchone()
    return {'username': user.username, 'role': user.role,
            'token': {'name': user.token_name, 'scope': user.scope, 'expires_at': row['expires_at'] if row else None}}


@router.get('/status', response_model=models.Status, tags=['status'], summary="What needs attention")
def status_get(request: Request, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """The Dashboard's tiles and its Needs attention list, from what the health check last saw. For
    monitoring: `level` is `ok`, `warn` or `error`."""
    from ..dashboard import overview
    o = overview(conn, _settings(request))
    return {'level': o['level'], 'attention': o['attention'], 'checked_at': o['checked'], 'problems': o['problems'],
            'tiles': [{k: t[k] for k in ('key', 'label', 'level', 'value', 'sub')} for t in o['tiles']],
            'modules': [n for n, v in o['modules'].items() if v]}


# ── nodes ──────────────────────────────────────────────────────────────────────

def _node(n):
    return {
        'name': n['name'], 'host': n['host'], 'dns_address': n['dns_address'], 'role': n['role'],
        'bind': bool(n['bind']), 'managed': bool(n['managed']), 'status': n['status'],
        'status_detail': n['status_detail'],
        'agent_version': n['agent_version'], 'named_version': n['named_version'], 'last_seen_at': n['last_seen_at'],
        'dhcp': bool(n['dhcp']), 'dhcp_interfaces': json.loads(n['dhcp_interfaces'] or '[]'),
        'time': json.loads(n['ntp_state']) if n['ntp'] and n['ntp_state'] else None,
        'install_rev': n['install_rev'], 'can_upgrade': service.can_upgrade(n),
        'flags': {'pending': n['pending'], 'drift': json.loads(n['drift'] or '[]'),
                  'second_primary': json.loads(n['second_primary'] or '[]'),
                  'dhcp_drift': json.loads(n['dhcp_drift'] or '[]'), 'dhcp_ha_state': n['dhcp_ha_state'],
                  'clock_skew': n['clock_skew'],
                  'clock_synced': None if n['clock_synced'] is None else bool(n['clock_synced']),
                  'other_liteblox': bool(n['other_liteblox'])}}


@router.get('/search', response_model=models.Search, tags=['search'], summary='Search zones and DHCP')
def search_get(request: Request, q: str = Query(..., description='a name or part of one, an IPv4 or IPv6 address, a network, a MAC or a DUID'),
               limit: int = Query(200, ge=1, le=5000, description='at most this many items per group'),
               user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """What the Search page shows: records in every zone (a static zone's draft when it has one, a dynamic
    zone as its primary serves it), DHCP and DHCPv6 reservations, leases read live from Kea, zones and subnets
    (`family` tells a DHCPv4 subnet id from a DHCPv6 one). An address (IPv4 or IPv6) also gets `address`: its
    names, PTR, reservation, lease and subnet, and what doesn't add up.
    Queries shorter than 3 characters skip the live reads (`skipped`)."""
    from .. import search
    res = search.search(conn, _settings(request), q, limit=limit)
    if res is None:
        raise HTTPException(status_code=422, detail=f'a query needs at least {search.MIN_LENGTH} characters')
    return search.to_dict(res)


@router.get('/nodes', response_model=list[models.Node], tags=['nodes'], summary='List the nodes')
def nodes_list(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Every node, as the health check last saw it (it asks each one every minute)."""
    return [_node(n) for n in conn.execute('SELECT * FROM nodes ORDER BY name')]


@router.get('/nodes/{name}', response_model=models.Node, tags=['nodes'], summary='Get a node')
def node_get(name: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """One node, as the health check last saw it."""
    row = conn.execute('SELECT * FROM nodes WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such node')
    return _node(row)


@router.post('/nodes/{name}/upgrade-agent', status_code=202, response_model=models.JobStarted, tags=['nodes'],
             summary="Upgrade a node's agent")
def node_upgrade_agent(request: Request, name: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Send this LiteBlox's agent to the node over mutual TLS, as the node page's **Upgrade agent** does. Runs as
    a job: poll `GET /api/v1/jobs/{job}`. Refused (409) when the node can't be upgraded this way (`can_upgrade`
    false: already current, unreachable, or it needs Repair / upgrade agent over SSH first) or a job runs on it."""
    row = conn.execute('SELECT * FROM nodes WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such node')
    if not service.can_upgrade(row):
        raise HTTPException(status_code=409, detail=f'{name} can\'t be upgraded over mTLS: ' + (
            'its agent is already current' if not service.needs_upgrade(row) else
            'it needs Repair / upgrade agent over SSH, or it is unreachable'))
    try:
        job_id = service.start_agent_upgrade(_settings(request), [row['id']], user.username, via=_via(user))
    except service.NodeError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return JSONResponse(status_code=202, content={'job': job_id}, headers={'Location': f'/api/v1/jobs/{job_id}'})


# ── zones ──────────────────────────────────────────────────────────────────────

def _zone_row(conn, name):
    row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such zone')
    return row


def _zone(conn, settings, row):
    from ..dns.drafts import Drafts
    serving = [r[0] for r in conn.execute('SELECT n.name FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id '
                                          'WHERE zn.zone_id = ? ORDER BY n.name', (row['id'],))]
    forwarding = row['kind'] == 'forwarding'
    draft = not forwarding and not row['dynamic'] and Drafts(settings).load(row)[1]
    return {'name': row['name'], 'kind': row['kind'], 'dynamic': bool(row['dynamic']), 'nodes': serving,
            'has_draft': bool(draft)}


@router.get('/zones', response_model=list[models.Zone], tags=['zones'], summary='List the zones')
def zones_list(request: Request, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Every zone, the nodes serving it, and whether a static zone has unpublished changes (a draft)."""
    return [_zone(conn, _settings(request), r) for r in conn.execute('SELECT * FROM zones ORDER BY name')]


@router.get('/zones/{name}', response_model=models.ZoneDetail, tags=['zones'], summary='Get a zone')
def zone_get(request: Request, name: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """A zone's settings and grants, and (static zones) the serial of its published version."""
    from ..dns.drafts import Drafts
    from ..dns.zonefile import Zone, ZoneParseError
    row = _zone_row(conn, name)
    out = _zone(conn, _settings(request), row)

    def lines(text):
        return [i for i in (text or '').split('\n') if i]
    out['settings'] = {'notify': row['notify'] or '', 'also_notify': lines(row['also_notify']),
                       'allow_transfer': lines(row['allow_transfer']), 'allow_query': lines(row['allow_query']),
                       'forwarders': lines(row['forwarders']), 'forward_mode': row['forward_mode'] or '',
                       'auto_ptr': bool(row['auto_ptr']),
                       'sorted': row['kind'] != 'forwarding' and not row['dynamic']}
    out['notes'] = row['notes']
    out['grants'] = [{'key': g['key'], 'scope': g['scope'], 'name': g['name'], 'types': g['types']}
                     for g in conn.execute('SELECT g.*, k.name AS key FROM key_grants g JOIN tsig_keys k '
                                           'ON k.id = g.key_id WHERE g.zone_id = ? ORDER BY k.name, g.id',
                                           (row['id'],))]
    if row['kind'] != 'forwarding' and not row['dynamic']:
        try:
            out['published_serial'] = Zone.parse(Drafts(_settings(request)).published(row), name + '.').serial
        except (ZoneParseError, LookupError, ValueError, IndexError):
            out['published_serial'] = None
    return out


@router.get('/zones/{name}/records', response_model=models.Records, tags=['zones'], summary="List a zone's records")
def records_list(request: Request, response: Response, name: str,
                 published: bool = Query(False, description='the published version instead of the draft'),
                 user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """A zone's records: a static zone's draft when it has one (unless `published`), a dynamic zone as
    its primary serves it now. `rev` (also the ETag) identifies this version of the zone; a dynamic zone's
    records also carry `rr`, which pins just that record's RRset (DHCP changes the rest all the time).
    Either one can go in a write's `If-Match`."""
    from ..dns import dynamic
    from ..dns.drafts import Drafts, rev
    from ..dns.zonefile import Zone, ZoneParseError
    row = _zone_row(conn, name)
    if row['kind'] == 'forwarding':
        raise HTTPException(status_code=409, detail=f'{name} is a forwarding zone: it has no records')
    drafts, is_draft = Drafts(_settings(request)), False
    if row['dynamic']:
        text = dynamic.axfr(conn, row)
    elif published:
        text = drafts.published(row)
    else:
        text, is_draft = drafts.load(row)
    try:
        zone = Zone.parse(text, name + '.')
    except ZoneParseError as e:
        raise HTTPException(status_code=409, detail=f"{name} doesn't parse ({e}); see its Raw tab")
    try:
        serial = zone.serial
    except (LookupError, ValueError, IndexError):
        serial = None
    version = rev(text)
    response.headers['ETag'] = f'"{version}"'
    return {'zone': name, 'rev': version, 'draft': bool(is_draft), 'serial': serial,
            'records': [_record(zone, r, dynamic=bool(row['dynamic'])) for r in zone.records()]}


def _record(zone, r, dynamic=False):
    from ..dns import dynamic as dyn
    return {'id': dyn.record_key(r), 'name': r.relative_name(zone.origin), 'type': r.rtype,
            'ttl': r.ttl if r.ttl is not None else r.default_ttl, 'data': r.rdata, 'comment': r.comment,
            'rr': dyn.rr_token(zone, r) if dynamic else None}


# ── zone text, draft and history ───────────────────────────────────────────────

def _static(conn, request, name):
    """A zone's ZoneEdit, for the draft calls: 404, or 409 for a forwarding or dynamic zone."""
    from ..dns import editing
    try:
        edit = editing.ZoneEdit(_settings(request), conn, name)
    except editing.NoSuchZone:
        raise HTTPException(status_code=404, detail='no such zone')
    except editing.ForwardingZone:
        raise HTTPException(status_code=409, detail=f'{name} is a forwarding zone: it has no records')
    if edit.dynamic:
        raise HTTPException(status_code=409, detail=f'{name} is dynamic: its changes apply at once, there is no draft')
    return edit


@router.get('/zones/{name}/text', response_class=PlainTextResponse, tags=['zones'], summary="A zone's file")
def zone_text(request: Request, name: str, published: bool = Query(False), user: ApiUser = Depends(api_user),
              conn=Depends(get_db)):
    """The zone file as text: the draft (a static zone with one, unless `published`), or what a dynamic zone's
    primary serves now."""
    from ..dns import dynamic
    from ..dns.drafts import Drafts
    row = _zone_row(conn, name)
    if row['kind'] == 'forwarding':
        raise HTTPException(status_code=409, detail=f'{name} is a forwarding zone: it has no records')
    drafts = Drafts(_settings(request))
    text = (dynamic.axfr(conn, row) if row['dynamic'] else drafts.published(row) if published
            else drafts.load(row)[0])
    return PlainTextResponse(text)


@router.get('/zones/{name}/draft', response_model=models.Draft, tags=['zones'], summary="A static zone's draft")
def draft_get(request: Request, name: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """What publishing would change: the records added, removed and changed, the diff, named-checkzone's
    verdict, and the reverse zones whose drafts publish with it."""
    from ..dns.importer import diff
    from ..dns.validate import ToolMissing, named_checkzone
    edit = _static(conn, request, name)
    summary = edit.summary() or {'added': [], 'removed': [], 'changed': []}
    check = None
    if edit.is_draft:
        try:
            ok, output = named_checkzone(name, edit.text)
        except ToolMissing as e:
            ok, output = None, str(e)
        check = {'ok': ok, 'output': output}
    published = edit.drafts.published(edit.row)
    return {'zone': name, 'draft': bool(edit.is_draft), 'rev': edit.rev,
            'stale': bool(edit.is_draft and edit.drafts.is_stale(edit.row)),
            'summary': {'added': summary['added'], 'removed': summary['removed'],
                        'changed': [{'before': b, 'after': a} for b, a in summary['changed']]},
            'diff': diff(published, edit.text, f'{name} (published)', f'{name} (draft)') if edit.is_draft else '',
            'check': check, 'linked': sorted(edit.drafts.linked(name))}


@router.get('/zones/{name}/history', response_model=list[models.Commit], tags=['zones'],
            summary="A zone's versions")
def history_list(request: Request, name: str, limit: int = Query(50, ge=1, le=1000), user: ApiUser = Depends(api_user),
                 conn=Depends(get_db)):
    """Every published version (and a dynamic zone's snapshots), newest first."""
    from ..dns.repo import Repo
    row = _zone_row(conn, name)
    if row['kind'] == 'forwarding':
        return []
    return [{'sha': c['sha'], 'author': c['author'], 'date': c['date'], 'message': c['subject']}
            for c in Repo(_settings(request).repo_dir).log(row['repo_file'], limit=limit)]


@router.get('/zones/{name}/history/{sha}', response_model=models.CommitText, tags=['zones'],
            summary='One version of a zone')
def history_get(request: Request, name: str, sha: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..dns.repo import Repo
    row = _zone_row(conn, name)
    repo = Repo(_settings(request).repo_dir)
    commit = next((c for c in repo.log(row['repo_file'], limit=1000) if c['sha'] == sha), None) \
        if row['kind'] != 'forwarding' else None
    if commit is None:
        raise HTTPException(status_code=404, detail='no such version of this zone')
    return {'sha': sha, 'author': commit['author'], 'date': commit['date'], 'message': commit['subject'],
            'text': repo.show(sha, row['repo_file'])}


# ── zone writes ────────────────────────────────────────────────────────────────

def _via(user):
    return f' (token {user.token_name})'


def _editable(request, conn, name):
    """The zone to change: 404, or 409 for a forwarding zone or one that doesn't parse."""
    from ..dns import editing
    try:
        edit = editing.ZoneEdit(_settings(request), conn, name)
    except editing.NoSuchZone:
        raise HTTPException(status_code=404, detail='no such zone')
    except editing.ForwardingZone:
        raise HTTPException(status_code=409, detail=f'{name} is a forwarding zone: it has no records')
    if edit.zone is None:
        raise HTTPException(status_code=409, detail=f"{name} doesn't parse ({edit.error}); fix it on its Raw tab")
    return edit


def _if_match(request, edit, rec=None):
    """412 unless the zone (its rev) or, in a dynamic zone, the record's RRset (its rr) is as the caller saw it."""
    from ..dns import dynamic
    header = request.headers.get('If-Match')
    if not header:
        return
    tags = {t.strip().removeprefix('W/').strip('"') for t in header.split(',')}
    if '*' in tags or edit.rev in tags:
        return
    if edit.dynamic and rec is not None and dynamic.rr_token(edit.zone, rec) in tags:
        return
    raise HTTPException(status_code=412, detail='the zone changed since you read it (If-Match); read it again')


def _invalid(e):
    return JSONResponse(status_code=422, content={'detail': 'the record is not valid', 'errors': e.errors})


def _result(edit, saved=None, notes=(), warnings=()):
    return {'zone': edit.name, 'rev': edit.rev, 'draft': bool(edit.is_draft),
            'record': _record(edit.zone, saved, edit.dynamic) if saved is not None else None,
            'notes': list(notes), 'warnings': list(warnings)}


def _ttl(value):
    return None if value is None or str(value).strip() == '' else str(value)


def _ptr(edit, wanted):
    return bool(edit.row['auto_ptr']) if wanted is None else wanted


def _find(edit, record_id):
    from ..dns import editing
    rec = editing.find(edit, key=record_id)
    if rec is None:
        raise HTTPException(status_code=404, detail='no such record (it may have changed: read the records again)')
    if rec.rtype == 'SOA':
        raise HTTPException(status_code=409, detail='change the SOA with PUT /zones/{name}/soa')
    return rec


@router.post('/zones/{name}/records', status_code=201, response_model=models.WriteResult, tags=['zones'],
             summary='Add a record', responses={422: {'description': 'the record is not valid (per-field errors)'}})
def record_add(request: Request, name: str, body: models.RecordIn, user: ApiUser = Depends(api_writer),
               conn=Depends(get_db)):
    """A static zone's new record goes into its draft (publish it with POST …/publish); a dynamic zone's
    is sent to its primary at once. An A/AAAA record also gets its PTR unless `ptr` is false."""
    from ..dns import editing, records
    with editing.zone_lock(name):
        edit = _editable(request, conn, name)
        _if_match(request, edit)
        try:
            notes, warnings, saved = editing.apply_row(edit, None, body.name, _ttl(body.ttl), body.type.upper(),
                                                       body.data.strip(), body.comment, _ptr(edit, body.ptr), None,
                                                       user.username, _via(user))
        except records.RecordError as e:
            return _invalid(e)
    audit(conn, user.username, 'record_add', f'{name}: {body.name} {body.type.upper()}{_via(user)}')
    return _result(edit, saved, notes, warnings)


def _batch_ops(edit, body):
    """The batch's ops as editing.Ops, and [{index, errors}] for the ones that can't be: a missing field, an
    unknown id, the same record twice, the SOA."""
    from ..dns import editing
    ops, problems, seen = [], [], set()
    for i, o in enumerate(body.ops):
        errors = {}
        if o.op == 'add':
            errors.update({f: 'needed to add a record' for f in ('name', 'type', 'data') if not getattr(o, f)})
            ops.append(None if errors else editing.Op(None, o.name, _ttl(o.ttl), o.type.upper(), o.data.strip(),
                                                      o.comment))
        else:
            rec = editing.find(edit, key=o.id) if o.id else None
            if not o.id:
                errors['id'] = f'needed to {o.op} a record'
            elif rec is None:
                errors['id'] = 'no such record (it may have changed: read the records again)'
            elif rec.rtype == 'SOA':
                errors['id'] = 'change the SOA with PUT /zones/{name}/soa'
            elif o.id in seen:
                errors['id'] = 'this record is already in an earlier op'
            if errors:
                ops.append(None)
            elif o.op == 'delete':
                ops.append(editing.Op.removing(rec))
            else:
                sent = o.model_fields_set
                ops.append(editing.Op(rec, o.name if o.name is not None else rec.relative_name(edit.zone.origin),
                                      _ttl(o.ttl) if 'ttl' in sent else _ttl(rec.ttl), (o.type or rec.rtype).upper(),
                                      o.data.strip() if o.data is not None else rec.rdata,
                                      o.comment if 'comment' in sent else rec.comment))
            seen.add(o.id)
        if errors:
            problems.append({'index': i, 'errors': errors})
    return ops, problems


def _if_match_all(request, edit, ops):
    """_if_match for a batch: the zone's rev, or in a dynamic zone the rr of every record it changes or deletes."""
    from ..dns import dynamic
    header = request.headers.get('If-Match')
    if not header:
        return
    tags = {t.strip().removeprefix('W/').strip('"') for t in header.split(',')}
    if '*' in tags or edit.rev in tags:
        return
    touched = [op.rec for op in ops if op is not None and op.rec is not None]
    if edit.dynamic and touched and all(dynamic.rr_token(edit.zone, r) in tags for r in touched):
        return
    raise HTTPException(status_code=412, detail='the zone changed since you read it (If-Match); read it again')


@router.post('/zones/{name}/records/batch', response_model=models.BatchResult, tags=['zones'],
             summary='Add, change and delete many records at once',
             responses={422: {'description': 'one or more ops are not valid; nothing was changed'}})
def records_batch(request: Request, name: str, body: models.BatchIn, user: ApiUser = Depends(api_writer),
                  conn=Depends(get_db)):
    """All or nothing: each op is checked against the zone as the ops before it left it, and only when every
    one is good is the zone changed, once. A static zone's draft gets them all (publish it with POST …/publish);
    a dynamic zone gets one update. Ids are the records' ids before the batch. PTRs follow A/AAAA changes
    unless `ptr` is false."""
    from ..dns import editing, records
    with editing.zone_lock(name):
        edit = _editable(request, conn, name)
        ops, problems = _batch_ops(edit, body)
        _if_match_all(request, edit, ops)
        staged, warnings = [], []
        for i, op in enumerate(ops):
            if op is None:
                continue
            try:
                old, new, op_warnings = editing._stage(edit, op)
            except records.RecordError as e:
                problems.append({'index': i, 'errors': e.errors})
                continue
            staged.append((i, old, new))
            warnings += op_warnings
        if problems:
            editing.unstage(edit)
            problems.sort(key=lambda p: p['index'])
            return JSONResponse(status_code=422, content={
                'detail': f"{len(problems)} of {len(ops)} ops are not valid; nothing was changed", 'errors': problems})
        notes, more, saved = editing.commit(edit, [(old, new) for _, old, new in staged], _ptr(edit, body.ptr),
                                            user.username, _via(user))
    became = [None] * len(ops)
    for (i, _, _), rec in zip(staged, saved):
        became[i] = _record(edit.zone, rec, edit.dynamic) if rec is not None else None
    counts = {done: sum(1 for o in body.ops if o.op == op)
              for op, done in (('add', 'added'), ('change', 'changed'), ('delete', 'deleted'))}
    audit(conn, user.username, 'record_batch',
          f"{name}: " + ', '.join(f'{n} {done}' for done, n in counts.items() if n) + _via(user))
    return {'zone': name, 'rev': edit.rev, 'draft': bool(edit.is_draft), 'records': became,
            'notes': notes, 'warnings': warnings + more}


@router.patch('/zones/{name}/records/{record_id}', response_model=models.WriteResult, tags=['zones'],
              summary='Change a record', responses={422: {'description': 'the record is not valid (per-field errors)'}})
def record_patch(request: Request, name: str, record_id: str, body: models.RecordPatch,
                 user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Only the fields sent change. The record's id changes with it (ids are by content): the answer has the new one."""
    from ..dns import editing, records
    sent = body.model_fields_set
    with editing.zone_lock(name):
        edit = _editable(request, conn, name)
        rec = _find(edit, record_id)
        _if_match(request, edit, rec)
        try:
            notes, warnings, saved = editing.apply_row(
                edit, rec, body.name if body.name is not None else rec.relative_name(edit.zone.origin),
                _ttl(body.ttl) if 'ttl' in sent else _ttl(rec.ttl), (body.type or rec.rtype).upper(),
                body.data.strip() if body.data is not None else rec.rdata,
                body.comment if 'comment' in sent else rec.comment, _ptr(edit, body.ptr), None,
                user.username, _via(user))
        except records.RecordError as e:
            return _invalid(e)
    audit(conn, user.username, 'record_edit', f'{name}: {saved.relative_name(edit.zone.origin) if saved else record_id} '
                                              f'{(body.type or rec.rtype).upper()}{_via(user)}')
    return _result(edit, saved, notes, warnings)


@router.delete('/zones/{name}/records/{record_id}', response_model=models.WriteResult, tags=['zones'],
               summary='Delete a record')
def record_delete(request: Request, name: str, record_id: str,
                  ptr: bool = Query(None, description="also remove its PTR (default: the zone's auto-PTR setting)"),
                  user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..dns import editing
    with editing.zone_lock(name):
        edit = _editable(request, conn, name)
        rec = _find(edit, record_id)
        _if_match(request, edit, rec)
        label = f'{rec.relative_name(edit.zone.origin)} {rec.rtype}'
        notes, warnings = editing.delete_row(edit, rec, _ptr(edit, ptr), user.username, _via(user))
    audit(conn, user.username, 'record_delete', f'{name}: {label}{_via(user)}')
    return _result(edit, None, notes, warnings)


@router.put('/zones/{name}/soa', response_model=models.WriteResult, tags=['zones'], summary="Change a zone's SOA")
def soa_put(request: Request, name: str, body: models.SoaIn, user: ApiUser = Depends(api_writer),
            conn=Depends(get_db)):
    """The primary nameserver, the mailbox and the timers; fields left out stay as they are."""
    from ..dns import editing
    with editing.zone_lock(name):
        edit = _editable(request, conn, name)
        _if_match(request, edit, edit.zone.soa)
        fields = editing.soa_fields(edit.zone)
        fields.update({k: str(v) for k, v in body.model_dump().items() if v is not None})
        problem = editing.save_soa(edit, fields, user.username, _via(user))
    if problem:
        return JSONResponse(status_code=422, content={'detail': problem, 'errors': {'soa': problem}})
    soa = edit.zone.soa
    return _result(edit, soa)


@router.put('/zones/{name}/notes', status_code=204, tags=['zones'], summary="Replace a zone's notes")
def notes_put(request: Request, name: str, body: models.NotesIn, user: ApiUser = Depends(api_writer),
              conn=Depends(get_db)):
    """Plain text kept in LiteBlox only (never in the zone file); comment lines a sort takes out land here."""
    row = _zone_row(conn, name)
    notes = body.notes.replace('\r\n', '\n').strip()
    if notes != row['notes']:
        with conn:
            conn.execute('UPDATE zones SET notes = ? WHERE id = ?', (notes, row['id']))
        audit(conn, user.username, 'zone_notes', name + _via(user))
    return Response(status_code=204)


@router.delete('/zones/{name}/draft', status_code=204, tags=['zones'], summary="Discard a static zone's draft")
def draft_delete(request: Request, name: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """The draft, the reverse zones' drafts linked to it, and the PTR updates waiting for its publish."""
    from ..dns import editing
    with editing.zone_lock(name):
        editing.discard(_static(conn, request, name), user.username, _via(user))
    return Response(status_code=204)


@router.post('/zones/{name}/publish', status_code=202, response_model=models.JobStarted, tags=['zones'],
             summary='Publish a static zone')
def publish(request: Request, name: str, body: models.PublishIn = None, user: ApiUser = Depends(api_writer),
            conn=Depends(get_db)):
    """Publish the draft (with the reverse zones' drafts linked to it), or republish the zone as it is. Runs as
    a job: poll `GET /api/v1/jobs/{job}`. With `If-Match` (the `rev` you reviewed), it refuses a draft that
    changed since."""
    from .. import jobs
    from ..dns import publish as pub
    from ..nodes import roles
    edit = _static(conn, request, name)
    if pub.running(conn, edit.row['id']):
        raise HTTPException(status_code=409, detail=f'a publish of {name} is already running')
    if roles.busy():
        raise HTTPException(status_code=409, detail='a role change (promote, demote) is running; publish after it')
    header = request.headers.get('If-Match')
    reviewed = header.strip().removeprefix('W/').strip('"') if header and header.strip() != '*' else None
    message = ' '.join(((body.message if body else None) or '').split())[:200] or None
    settings, username = _settings(request), user.username
    job_id = jobs.start(settings.db_path, 'publish',
                        lambda log, job_id: pub.publish(settings, name, username, log, rev=reviewed, job_id=job_id,
                                                        linked=True, message=message),
                        username=username, zone_id=edit.row['id'])
    audit(conn, username, 'publish', name + (f': {message}' if message else '') + _via(user))
    return JSONResponse(status_code=202, content={'job': job_id}, headers={'Location': f'/api/v1/jobs/{job_id}'})


# ── DHCP ───────────────────────────────────────────────────────────────────────

@router.get('/dhcp', response_model=models.Dhcp, tags=['dhcp'], summary='DHCP servers, the failover pair, settings')
def dhcp_get(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """As LiteBlox last saw them (the health check asks every minute). The registration key's secret is never shown."""
    from ..dhcp import apply
    from ..dhcp.model import ha_pair, interfaces_of
    from ..dhcp.model import settings as load_settings
    pair = ha_pair(conn)
    servers = []
    for n in apply.dhcp_nodes(conn):
        role = pair.role_of(n['id']) if pair.active else None
        servers.append({'node': n['name'], 'interfaces': interfaces_of(n), 'ha_state': n['dhcp_ha_state'],
                        'does': {'primary': 'failover primary', 'standby': 'standby'}.get(role)
                        or ('serving' if interfaces_of(n) else 'serves nothing'),
                        'kea_config_changed': bool(n['dhcp_drift']), 'config_behind': apply.stale(conn, n)})
    s = load_settings(conn)
    return {'servers': servers,
            'pair': {'primary': pair.primary_name, 'standby': pair.standby_name, 'primary_address': pair.primary_address,
                     'standby_address': pair.standby_address, 'port': pair.port,
                     'interfaces': pair.interface_map} if pair.active else None,
            'settings': {'valid_lifetime': s.valid_lifetime, 'renew_timer': s.renew_timer,
                         'rebind_timer': s.rebind_timer, 'options': s.options, 'extra_options': s.extra_options,
                         'authoritative': s.authoritative, 'ddns_key': s.ddns_key['name'] if s.ddns_key else None,
                         'ddns_mode': s.ddns_mode, 'ddns_server': s.ddns_server if s.ddns_mode == 'external' else None,
                         'ddns_port': s.ddns_port if s.ddns_mode == 'external' else None}}


def _subnet(s):
    from ..dhcp.render import reservation_order
    return {'id': s.id, 'prefix': s.prefix, 'interface': s.interface, 'pools': s.pools, 'options': s.options,
            'extra_options': s.extra_options, 'extra': s.extra, 'valid_lifetime': s.valid_lifetime,
            'renew_timer': s.renew_timer, 'rebind_timer': s.rebind_timer, 'comment': s.comment,
            'ddns': {'zone': s.ddns_domain, 'suffix': s.qualifying_suffix} if s.registers else None,
            'reservations': [_reservation(r) for r in sorted(s.reservations, key=reservation_order)]}


def _reservation(r):
    return {'id': r.id, 'hw_address': r.hw_address, 'ip_address': r.ip_address, 'hostname': r.hostname,
            'options': r.options, 'comment': r.comment}


def _dhcp_subnet(conn, subnet_id):
    from ..dhcp.model import subnets
    s = next((x for x in subnets(conn) if x.id == subnet_id), None)
    if s is None:
        raise HTTPException(status_code=404, detail='no such subnet')
    return s


@router.get('/dhcp/subnets', response_model=list[models.Subnet], tags=['dhcp'], summary='List the DHCP subnets')
def dhcp_subnets(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..dhcp.model import subnets
    return [_subnet(s) for s in subnets(conn)]


@router.get('/dhcp/subnets/{subnet_id}', response_model=models.Subnet, tags=['dhcp'], summary='Get a DHCP subnet')
def dhcp_subnet(subnet_id: int, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """A subnet with its pools, options and reservations."""
    return _subnet(_dhcp_subnet(conn, subnet_id))


@router.get('/dhcp/leases', response_model=models.Leases, tags=['dhcp'], summary='List the leases')
def dhcp_leases(request: Request, subnet: int = Query(None, description='only this subnet (its id)'),
                user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Read live from Kea. A failover pair's come from its primary, or from the standby when the primary doesn't
    answer (`errors` then says why)."""
    from datetime import datetime, timezone

    from ..dhcp import leases
    from ..dhcp.model import subnets
    found, errors = leases.serving_leases(_settings(request), conn)
    every = subnets(conn)
    reserved = {(r.hw_address, r.ip_address) for s in every for r in s.reservations}
    named = {(s.id, r.hw_address) for s in every for r in s.reservations if not r.ip_address}
    rows = [{'ip': lease['ip'], 'mac': lease['mac'], 'hostname': lease['hostname'], 'subnet_id': lease['subnet_id'],
             'state': lease['state'], 'expires_in': lease['expires_in'],
             'expires': datetime.fromtimestamp(lease['expires'], timezone.utc).isoformat(timespec='seconds'),
             'registered': lease['registered'], 'reserved': ((lease['mac'], lease['ip']) in reserved
                                                    or (lease['subnet_id'], lease['mac']) in named),
             'node': node['name']}
            for node, lease in found if subnet is None or lease['subnet_id'] == subnet]
    return {'leases': rows, 'read_from': found[0][0]['name'] if found else None, 'errors': errors}


def _dhcp_job(request, conn, start, user, warnings=()):
    from ..dhcp import ops
    try:
        job_id = start()
    except ops.Busy as e:
        raise HTTPException(status_code=409, detail=str(e))
    return JSONResponse(status_code=202, content={'job': job_id, 'warnings': list(warnings)},
                        headers={'Location': f'/api/v1/jobs/{job_id}'})


def _reservation_invalid(errors):
    return JSONResponse(status_code=422, content={
        'detail': 'the reservation is not valid',
        'errors': {k.replace('opt_', 'options.', 1) if k.startswith('opt_') else k: v for k, v in errors.items()}})


def _save_reservation(request, conn, user, subnet, r, rid):
    from ..dhcp import ops
    errors, warnings, _ = ops.reservation_change(_settings(request), conn, subnet, r, rid)
    if errors:
        return _reservation_invalid(errors)
    settings = _settings(request)
    return _dhcp_job(request, conn, lambda: ops.start_reservation(settings, conn, r, rid, user.username, _via(user)),
                     user, warnings)


@router.post('/dhcp/subnets/{subnet_id}/reservations', status_code=202, response_model=models.DhcpJob, tags=['dhcp'],
             summary='Add a reservation', responses={422: {'description': 'not valid (per-field errors)'}})
def reservation_add(request: Request, subnet_id: int, body: models.ReservationIn, user: ApiUser = Depends(api_writer),
                    conn=Depends(get_db)):
    """Written to every DHCP node (the standby first) as a job; `warnings` says if another client holds the
    address right now (it keeps it until its lease ends, or you delete the lease)."""
    from ..dhcp.model import Reservation
    subnet = _dhcp_subnet(conn, subnet_id)
    r = Reservation(None, subnet.id, body.hw_address.strip(), (body.ip_address or '').strip(), body.hostname.strip(),
                    body.options or {}, body.comment.strip())
    return _save_reservation(request, conn, user, subnet, r, None)


def _existing_reservation(subnet, rid):
    r = next((x for x in subnet.reservations if x.id == rid), None)
    if r is None:
        raise HTTPException(status_code=404, detail='no such reservation in this subnet')
    return r


@router.patch('/dhcp/subnets/{subnet_id}/reservations/{reservation_id}', status_code=202,
              response_model=models.DhcpJob, tags=['dhcp'], summary='Change a reservation',
              responses={422: {'description': 'not valid (per-field errors)'}})
def reservation_patch(request: Request, subnet_id: int, reservation_id: int, body: models.ReservationPatch,
                      user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Only the fields sent change; written to every DHCP node as a job."""
    from dataclasses import replace
    subnet = _dhcp_subnet(conn, subnet_id)
    old = _existing_reservation(subnet, reservation_id)
    changes = {k: (v.strip() if isinstance(v, str) else v) for k, v in body.model_dump().items()
               if k in body.model_fields_set and v is not None}
    return _save_reservation(request, conn, user, subnet, replace(old, **changes), reservation_id)


@router.delete('/dhcp/subnets/{subnet_id}/reservations/{reservation_id}', status_code=202,
               response_model=models.DhcpJob, tags=['dhcp'], summary='Delete a reservation')
def reservation_delete(request: Request, subnet_id: int, reservation_id: int, user: ApiUser = Depends(api_writer),
                       conn=Depends(get_db)):
    """Taken off every DHCP node as a job. The client keeps its address until its lease ends."""
    from ..dhcp import ops
    r = _existing_reservation(_dhcp_subnet(conn, subnet_id), reservation_id)
    settings = _settings(request)
    return _dhcp_job(request, conn, lambda: ops.start_reservation_delete(settings, conn, r, user.username, _via(user)),
                     user)


@router.delete('/dhcp/leases/{ip}', response_model=models.LeaseDeleted, tags=['dhcp'], summary='Delete a lease')
def lease_delete(request: Request, ip: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """At once, on the server that holds it and its failover partner. Its DNS names go with it; the client asks
    again at its next renewal."""
    from ..dhcp import leases, ops
    found, errors = leases.serving_leases(_settings(request), conn)
    node = next((n for n, lease in found if lease['ip'] == ip), None)
    if node is None:
        raise HTTPException(status_code=404, detail=f'no lease on {ip}' + (f" ({'; '.join(errors)})" if errors else ''))
    try:
        partner = ops.delete_lease(_settings(request), conn, node, ip)
    except leases.LeaseError as e:
        raise HTTPException(status_code=502, detail=str(e))
    audit(conn, user.username, 'dhcp_lease_delete', f"{ip} on {node['name']}{_via(user)}")
    return {'ip': ip, 'node': node['name'], 'partner': partner}


# ── DHCPv6 ─────────────────────────────────────────────────────────────────────

@router.get('/dhcp6', response_model=models.Dhcp6, tags=['dhcp'], summary='DHCPv6 servers and settings')
def dhcp6_get(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Which DHCP nodes run kea-dhcp6 (a node from before 6.0 needs one Repair), each one's DHCPv6 failover state,
    and the DHCPv6 settings every subnet starts from."""
    from ..dhcp import apply
    from ..dhcp.model import ha_pair, has_dhcp6, settings6
    pair = ha_pair(conn)
    s = settings6(conn)
    return {'servers': [{'node': n['name'], 'runs_dhcp6': has_dhcp6(n), 'ha_state': n['dhcp6_ha_state']}
                        for n in apply.dhcp_nodes(conn)],
            'port6': pair.port6 if pair.active else None,
            'settings': {'preferred_lifetime': s.preferred_lifetime, 'valid_lifetime': s.valid_lifetime,
                         'renew_timer': s.renew_timer, 'rebind_timer': s.rebind_timer, 'options': s.options,
                         'extra_options': s.extra_options}}


def _subnet6(s):
    return {'id': s.id, 'prefix': s.prefix, 'interface': s.interface, 'pools': s.pools, 'pd_pools': s.pd_pools,
            'options': s.options, 'extra_options': s.extra_options, 'extra': s.extra,
            'preferred_lifetime': s.preferred_lifetime, 'valid_lifetime': s.valid_lifetime,
            'renew_timer': s.renew_timer, 'rebind_timer': s.rebind_timer, 'comment': s.comment,
            'ddns': {'zone': s.ddns_domain, 'suffix': s.qualifying_suffix} if s.registers else None,
            'ra': s.ra, 'ra_slaac': s.ra_slaac,
            'reservations': [_reservation6(r) for r in sorted(s.reservations, key=_reservation6_order)]}


def _reservation6_order(r):
    from ..addrs import sort_key
    return (not r.ip_address, sort_key(r.ip_address) if r.ip_address else (0, 0), r.prefix, r.duid or r.hw_address)


def _reservation6(r):
    return {'id': r.id, 'duid': r.duid, 'hw_address': r.hw_address, 'ip_address': r.ip_address, 'prefix': r.prefix,
            'hostname': r.hostname, 'options': r.options, 'comment': r.comment}


def _dhcp6_subnet(conn, subnet_id):
    from ..dhcp.model import subnets6
    s = next((x for x in subnets6(conn) if x.id == subnet_id), None)
    if s is None:
        raise HTTPException(status_code=404, detail='no such DHCPv6 subnet')
    return s


@router.get('/dhcp6/subnets', response_model=list[models.Subnet6], tags=['dhcp'], summary='List the DHCPv6 subnets')
def dhcp6_subnets(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..dhcp.model import subnets6
    return [_subnet6(s) for s in subnets6(conn)]


@router.get('/dhcp6/subnets/{subnet_id}', response_model=models.Subnet6, tags=['dhcp'],
            summary='Get a DHCPv6 subnet')
def dhcp6_subnet(subnet_id: int, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """A subnet with its pools, delegated-prefix pools, options, router advertisement setting and reservations."""
    return _subnet6(_dhcp6_subnet(conn, subnet_id))


@router.get('/dhcp6/leases', response_model=models.Leases6, tags=['dhcp'], summary='List the DHCPv6 leases')
def dhcp6_leases(request: Request, subnet: int = Query(None, description='only this DHCPv6 subnet (its id)'),
                 user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Read live from kea-dhcp6: addresses, then delegated prefixes (`type`). A failover pair's come from its
    primary, or from the standby when the primary doesn't answer."""
    from datetime import datetime, timezone

    from ..dhcp import leases
    from ..dhcp.model import subnets6
    found, errors = leases.serving_leases(_settings(request), conn, family=6)
    every = {s.id: s for s in subnets6(conn)}

    def reserved(lease):
        s = every.get(lease['subnet_id'])
        key = lease['prefix'] if lease['type'] == 'prefix' else lease['ip']
        return bool(s) and any((key in (r.ip_address, r.prefix) and leases._matches(r, lease))
                               or (not r.ip_address and not r.prefix and lease['type'] == 'address'
                                   and leases._matches(r, lease)) for r in s.reservations)
    rows = [{'ip': lease['ip'], 'type': lease['type'], 'prefix': lease['prefix'], 'duid': lease['duid'],
             'iaid': lease['iaid'], 'mac': lease['mac'], 'hostname': lease['hostname'],
             'subnet_id': lease['subnet_id'], 'state': lease['state'], 'expires_in': lease['expires_in'],
             'expires': datetime.fromtimestamp(lease['expires'], timezone.utc).isoformat(timespec='seconds'),
             'registered': lease['registered'], 'reserved': reserved(lease), 'node': node['name']}
            for node, lease in found if subnet is None or lease['subnet_id'] == subnet]
    return {'leases': rows, 'read_from': found[0][0]['name'] if found else None, 'errors': errors}


def _save_reservation6(request, conn, user, subnet, r, rid):
    from ..dhcp import ops
    settings = _settings(request)
    errors, warnings, _ = ops.reservation6_change(settings, conn, subnet, r, rid)
    if errors:
        return _reservation_invalid(errors)
    return _dhcp_job(request, conn, lambda: ops.start_reservation6(settings, conn, r, rid, user.username, _via(user)),
                     user, warnings)


@router.post('/dhcp6/subnets/{subnet_id}/reservations', status_code=202, response_model=models.DhcpJob,
             tags=['dhcp'], summary='Add a DHCPv6 reservation',
             responses={422: {'description': 'not valid (per-field errors)'}})
def reservation6_add(request: Request, subnet_id: int, body: models.Reservation6In,
                     user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """By DUID (or MAC): an address, a delegated prefix, both, or a name only. Written to every DHCP node as a job."""
    from ..dhcp.model import Reservation6
    subnet = _dhcp6_subnet(conn, subnet_id)
    r = Reservation6(None, subnet.id, body.duid.strip(), body.hw_address.strip(), body.ip_address.strip(),
                     body.prefix.strip(), body.hostname.strip(), body.options or {}, body.comment.strip())
    return _save_reservation6(request, conn, user, subnet, r, None)


def _existing_reservation6(subnet, rid):
    r = next((x for x in subnet.reservations if x.id == rid), None)
    if r is None:
        raise HTTPException(status_code=404, detail='no such reservation in this subnet')
    return r


@router.patch('/dhcp6/subnets/{subnet_id}/reservations/{reservation_id}', status_code=202,
              response_model=models.DhcpJob, tags=['dhcp'], summary='Change a DHCPv6 reservation',
              responses={422: {'description': 'not valid (per-field errors)'}})
def reservation6_patch(request: Request, subnet_id: int, reservation_id: int, body: models.Reservation6Patch,
                       user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Only the fields sent change; written to every DHCP node as a job."""
    from dataclasses import replace
    subnet = _dhcp6_subnet(conn, subnet_id)
    old = _existing_reservation6(subnet, reservation_id)
    changes = {k: (v.strip() if isinstance(v, str) else v) for k, v in body.model_dump().items()
               if k in body.model_fields_set and v is not None}
    return _save_reservation6(request, conn, user, subnet, replace(old, **changes), reservation_id)


@router.delete('/dhcp6/subnets/{subnet_id}/reservations/{reservation_id}', status_code=202,
               response_model=models.DhcpJob, tags=['dhcp'], summary='Delete a DHCPv6 reservation')
def reservation6_delete(request: Request, subnet_id: int, reservation_id: int, user: ApiUser = Depends(api_writer),
                        conn=Depends(get_db)):
    from ..dhcp import ops
    r = _existing_reservation6(_dhcp6_subnet(conn, subnet_id), reservation_id)
    settings = _settings(request)
    return _dhcp_job(request, conn,
                     lambda: ops.start_reservation6_delete(settings, conn, r, user.username, _via(user)), user)


@router.delete('/dhcp6/leases/{ip:path}', response_model=models.Lease6Deleted, tags=['dhcp'],
               summary='Delete a DHCPv6 lease')
def lease6_delete(request: Request, ip: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """An address, or a delegated prefix as `prefix/len`. At once, on the server that holds it and its failover
    partner; its DNS names go with it."""
    from ..dhcp import leases, ops
    found, errors = leases.serving_leases(_settings(request), conn, family=6)
    kind = 'prefix' if '/' in ip else 'address'
    node = next((n for n, lease in found if (lease['prefix'] if kind == 'prefix' else lease['ip']) == ip
                 and lease['type'] == kind), None)
    if node is None:
        raise HTTPException(status_code=404, detail=f'no lease on {ip}' + (f" ({'; '.join(errors)})" if errors else ''))
    try:
        partner = ops.delete_lease6(_settings(request), conn, node, ip, kind)
    except leases.LeaseError as e:
        raise HTTPException(status_code=502, detail=str(e))
    audit(conn, user.username, 'dhcp_lease_delete', f"{ip} on {node['name']}{_via(user)}")
    return {'ip': ip, 'type': kind, 'node': node['name'], 'partner': partner}


# ── time ───────────────────────────────────────────────────────────────────────

@router.get('/ntp', response_model=models.Time, tags=['time'], summary='Time sources and time servers')
def ntp_get(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """The sources every node set up for time sync uses, and each one's serving settings and chrony's last state."""
    from ..ntp.model import custom, ntp_nodes, sources
    return {'sources': [s.line() for s in sources(conn)], 'default': not custom(conn),
            'nodes': [{'node': n['name'], 'serves': bool(n['ntp_serve']), 'networks': json.loads(n['ntp_allow'] or '[]'),
                       'keeps_serving': n['ntp_local'] is not None,
                       'state': json.loads(n['ntp_state']) if n['ntp_state'] else None} for n in ntp_nodes(conn)]}


# ── jobs ───────────────────────────────────────────────────────────────────────

def _job(row, log=False):
    out = {k: row[k] for k in ('id', 'kind', 'status', 'username', 'created_at', 'finished_at')}
    out.update(node=row['node'], zone=row['zone'])
    if log:
        out['log'] = row['log'].splitlines()
    return out


JOBS = ('SELECT j.*, n.name AS node, z.name AS zone FROM jobs j LEFT JOIN nodes n ON n.id = j.node_id '
        'LEFT JOIN zones z ON z.id = j.zone_id')


@router.get('/jobs', response_model=list[models.JobSummary], tags=['jobs'], summary='List recent jobs')
def jobs_list(limit: int = Query(50, ge=1, le=500), status: str = Query(None, pattern='^(running|ok|failed)$'),
              user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """The newest jobs first (publishes, config changes, promotes, DHCP applies…)."""
    sql = JOBS + (' WHERE j.status = ?' if status else '') + ' ORDER BY j.id DESC LIMIT ?'
    return [_job(r) for r in conn.execute(sql, ((status,) if status else ()) + (limit,))]


@router.get('/jobs/{job_id}', response_model=models.Job, tags=['jobs'], summary='Get a job and its log')
def job_get(job_id: int, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """One job with its log; poll it until `status` isn't `running`."""
    row = conn.execute(JOBS + ' WHERE j.id = ?', (job_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such job')
    return _job(row, log=True)


# ── the spec and the Swagger page (not part of the spec) ───────────────────────

docs_router = APIRouter(include_in_schema=False)


def _session_user(request: Request, conn=Depends(get_db)):
    from ..auth import current_user
    return current_user(request, conn)


def _reader(request: Request, conn=Depends(get_db)):
    """The spec is for logged-in users (the docs page) or any token holder."""
    from ..auth import LoginRequired, current_user
    try:
        return current_user(request, conn)
    except LoginRequired:
        pass
    header = request.headers.get('Authorization', '')
    if header.startswith('Bearer '):
        from . import tokens
        found = tokens.authenticate(conn, header[7:].strip(), request.client.host if request.client else None)
        if found:
            return found
    raise HTTPException(status_code=401, detail='log in, or send an API token', headers={'WWW-Authenticate': 'Bearer'})


@docs_router.get('/api/v1/openapi.json')
def openapi_spec(request: Request, who=Depends(_reader)):
    return request.app.openapi()


@docs_router.get('/api/docs')
def api_docs(request: Request, user=Depends(_session_user)):
    from ..templating import templates
    return templates.TemplateResponse(request, 'api_docs.html', {'user': user})
