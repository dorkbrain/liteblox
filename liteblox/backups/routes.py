"""Backups pages: per-node list, back up now, details with file-level changes, download, view a file."""

import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse

from ..auth import User, current_user, require_admin
from ..db import audit, get_db
from ..nodes import service as nodes
from ..templating import templates
from . import service

router = APIRouter()


def _settings(request):
    return request.app.state.settings


def _node(conn, node_id):
    try:
        return nodes.get_node(conn, node_id)
    except nodes.NodeError:
        raise HTTPException(status_code=404, detail='no such node')


def _backup(conn, backup_id):
    row = conn.execute('SELECT * FROM backups WHERE id = ?', (backup_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='no such backup')
    return row


@router.get('/nodes/{node_id}/backups')
def node_backups(request: Request, node_id: int, kind: str = '', user: User = Depends(current_user),
                 conn=Depends(get_db)):
    node = _node(conn, node_id)
    rows = conn.execute('SELECT * FROM backups WHERE node_id = ? ORDER BY created_at DESC, id DESC',
                        (node_id,)).fetchall()
    changes = {}
    for r in rows:
        if r['status'] == 'ok' and r['manifest']:
            prev = service.previous_ok(conn, r)
            if prev is not None:
                c = service.manifest_changes(json.loads(prev['manifest']), json.loads(r['manifest']))
                changes[r['id']] = sum(len(v) for v in c.values())
    kind = kind if kind in service.KINDS else None
    # Changes stay against the previous backup of any kind, so a filter doesn't change them
    counts = {k: sum(r['kind'] == k for r in rows) for k in service.KINDS}
    return templates.TemplateResponse(request, 'backups.html', {
        'user': user, 'node': node, 'backups': [r for r in rows if kind is None or r['kind'] == kind],
        'changes': changes, 'kind': kind, 'total': len(rows),
        'kind_filters': [(k, k.capitalize(), counts[k]) for k in service.KINDS],
        'stale': service.is_stale(conn, _settings(request), node_id),
        'settings': _settings(request).backups})


@router.post('/nodes/{node_id}/backups')
def node_backup_now(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node(conn, node_id)
    settings = _settings(request)
    result = service.backup_node(conn, settings, node, 'manual', username=user.username)
    service.prune(conn, settings, node_id)
    audit(conn, user.username, 'backup', f"{node['name']}: {result['action']}")
    if result['action'] == 'failed':
        return RedirectResponse(f'/nodes/{node_id}/backups', status_code=303)
    return RedirectResponse(f"/backups/{result['id']}", status_code=303)


@router.post('/nodes/{node_id}/backups/settings')
def node_backup_settings(request: Request, node_id: int, include_keys: bool = Form(False),
                         user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _node(conn, node_id)
    with conn:
        conn.execute('UPDATE nodes SET backup_keys = ? WHERE id = ?', (int(include_keys), node_id))
    audit(conn, user.username, 'backup_settings', f"{node['name']}: keys {'included' if include_keys else 'excluded'}")
    return RedirectResponse(f'/nodes/{node_id}/backups', status_code=303)


@router.get('/backups/{backup_id}')
def backup_detail(request: Request, backup_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    row = _backup(conn, backup_id)
    node = _node(conn, row['node_id'])
    manifest = json.loads(row['manifest']) if row['manifest'] else None
    prev = service.previous_ok(conn, row) if manifest else None
    changes = (service.manifest_changes(json.loads(prev['manifest']), manifest)
               if prev is not None else None)
    return templates.TemplateResponse(request, 'backup_detail.html', {
        'user': user, 'node': node, 'backup': row, 'manifest': manifest, 'previous': prev,
        'changes': changes})


@router.get('/backups/{backup_id}/download')
def backup_download(request: Request, backup_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    row = _backup(conn, backup_id)
    if not row['file']:
        raise HTTPException(status_code=404, detail='this backup has no file')
    path = _settings(request).backups_dir / row['file']
    if not path.exists():
        raise HTTPException(status_code=410, detail='the archive file is missing from the backups folder')
    audit(conn, user.username, 'backup_download', row['file'])
    return FileResponse(path, media_type='application/gzip', filename=path.name)


@router.get('/backups/{backup_id}/view')
def backup_view(request: Request, backup_id: int, path: str, user: User = Depends(require_admin),
                conn=Depends(get_db)):
    row = _backup(conn, backup_id)
    manifest = json.loads(row['manifest']) if row['manifest'] else {}
    if path not in manifest.get('files', {}):
        raise HTTPException(status_code=404, detail='that file is not in this backup')
    text = service.read_file(_settings(request), row, path)
    if text is None:
        raise HTTPException(status_code=404, detail='that file is not in this backup')
    return templates.TemplateResponse(request, 'backup_file.html', {
        'user': user, 'node': _node(conn, row['node_id']), 'backup': row, 'path': path, 'text': text})
