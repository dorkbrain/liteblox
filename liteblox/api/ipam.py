"""/api/v1/ipam: networks, ranges, addresses, what the nodes saw, devices, IPAM names, next free, assign and
unassign."""

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from ..addrs import sort_key
from ..db import audit, get_db
from ..ipam import model
from ..ipam.free import FreeError
from . import models
from .deps import api_user, api_writer
from .tokens import ApiUser

router = APIRouter(prefix='/api/v1/ipam', tags=['ipam'])


def _settings(request):
    return request.app.state.settings


def _via(user):
    return f' (token {user.token_name})'


def _iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='seconds') if t else None


def _error(e):
    return JSONResponse(status_code=e.status, content={'detail': e.message})


def _invalid(e):
    return JSONResponse(status_code=422, content={'detail': 'not valid', 'errors': e.errors})


# ── networks and ranges ────────────────────────────────────────────────────────

def _range(r):
    return {'id': r.id if not r.dhcp else None, 'first': str(r.first), 'last': str(r.last),
            'kind': 'dhcp' if r.dhcp else r.kind, 'name': r.name, 'comment': r.comment, 'dhcp_subnet': r.subnet_id}


def _network(n, facts=None, known6=()):
    """facts: IPv4's (view.gather); known6: every IPv6 address IPAM knows of (an IPv6 network's used = those in it)."""
    from ..ipam import view
    used = None
    if facts is not None and not n.container:
        used = sum(1 for a in known6 if a in n.net) if n.version == 6 else view.usage(facts, n)[0]
    return {'id': n.id, 'prefix': n.prefix, 'name': n.name, 'comment': n.comment, 'sweep': n.sweep,
            'swept_at': n.swept_at, 'parent': n.parent_id, 'container': n.container,
            'children': [c.id for c in n.children], 'usable': n.usable, 'used': used}


def _known6(request, conn, found):
    """Every IPv6 address IPAM knows of, when there's an IPv6 network to count them for."""
    from ..ipam import view6
    if not any(n.version == 6 and not n.container for n in found):
        return []
    facts6, _ = view6.gather(conn, _settings(request))
    return view6.known(facts6, model.Network(None, '::/0'), model.notes(conn))


def _get_network(conn, network_id):
    found = model.networks(conn)
    n = next((x for x in found if x.id == network_id), None)
    if n is None:
        raise HTTPException(status_code=404, detail='no such network')
    return n


@router.get('/networks', response_model=list[models.IpamNetwork], summary='List the networks')
def networks_list(request: Request, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Every network, its parent and children (worked out from the prefixes) and how many addresses are used."""
    from ..ipam import view
    facts = view.gather(conn, _settings(request))
    found = model.networks(conn)
    known6 = _known6(request, conn, found)
    return [_network(n, facts, known6) for n in found]


@router.get('/networks/{network_id}', response_model=models.IpamNetworkDetail, summary='Get a network')
def network_get(request: Request, network_id: int, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..ipam import view
    from ..dhcp.model import subnets6
    n = _get_network(conn, network_id)
    facts = view.gather(conn, _settings(request))
    out = _network(n, facts, _known6(request, conn, [n]))
    dhcp = subnets6(conn) if n.version == 6 else facts.subnets
    out['ranges'] = [] if n.container else [_range(r) for r in model.all_ranges(conn, n, dhcp)]
    return out


@router.post('/networks', status_code=201, response_model=models.IpamNetwork, summary='Add a network',
             responses={422: {'description': 'not valid (per-field errors)'}})
def network_add(body: models.IpamNetworkIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    try:
        nid = model.add_network(conn, body.prefix, body.name, body.comment, body.sweep)
    except model.IpamError as e:
        return _invalid(e)
    n = _get_network(conn, nid)
    audit(conn, user.username, 'ipam_network_add', f'{n.prefix}{_via(user)}')
    return _network(n)


@router.patch('/networks/{network_id}', response_model=models.IpamNetwork, summary='Change a network')
def network_patch(network_id: int, body: models.IpamNetworkPatch, user: ApiUser = Depends(api_writer),
                  conn=Depends(get_db)):
    n = _get_network(conn, network_id)
    try:
        model.update_network(conn, n.id, n.name if body.name is None else body.name,
                             n.comment if body.comment is None else body.comment,
                             n.sweep if body.sweep is None else body.sweep, n.sweep_node_id)
    except model.IpamError as e:
        return _invalid(e)
    audit(conn, user.username, 'ipam_network_edit', f'{n.prefix}{_via(user)}')
    return _network(_get_network(conn, network_id))


@router.delete('/networks/{network_id}', status_code=204, summary='Take a network out of IPAM')
def network_delete(network_id: int, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Its ranges go too; networks inside it move up a level. Records, DHCP and notes stay."""
    n = _get_network(conn, network_id)
    model.delete_network(conn, n.id)
    audit(conn, user.username, 'ipam_network_delete', f'{n.prefix}{_via(user)}')
    return Response(status_code=204)


def _leaf(conn, network_id):
    n = _get_network(conn, network_id)
    if n.container:
        raise HTTPException(status_code=409, detail=f'{n.prefix} holds other networks, so it has no ranges')
    return n


@router.post('/networks/{network_id}/ranges', status_code=201, response_model=models.IpamRange,
             summary='Add a range', responses={422: {'description': 'not valid (per-field errors)'}})
def range_add(network_id: int, body: models.IpamRangeIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..dhcp.model import subnets
    n = _leaf(conn, network_id)
    try:
        rid = model.save_range(conn, n, body.first, body.last, body.kind, body.name, body.comment,
                               subnets=subnets(conn))
    except model.IpamError as e:
        return _invalid(e)
    audit(conn, user.username, 'ipam_range_add', f'{n.prefix}: {body.first}-{body.last}{_via(user)}')
    return _range(next(r for r in model.ranges(conn, n.id) if r.id == rid))


def _get_range(conn, n, range_id):
    r = next((x for x in model.ranges(conn, n.id) if x.id == range_id), None)
    if r is None:
        raise HTTPException(status_code=404, detail='no such range in this network')
    return r


@router.patch('/networks/{network_id}/ranges/{range_id}', response_model=models.IpamRange, summary='Change a range')
def range_patch(network_id: int, range_id: int, body: models.IpamRangePatch, user: ApiUser = Depends(api_writer),
                conn=Depends(get_db)):
    from ..dhcp.model import subnets
    n = _leaf(conn, network_id)
    r = _get_range(conn, n, range_id)
    v = {k: getattr(body, k) if getattr(body, k) is not None else getattr(r, k)
         for k in ('first', 'last', 'kind', 'name', 'comment')}
    try:
        model.save_range(conn, n, str(v['first']), str(v['last']), v['kind'], v['name'], v['comment'],
                         range_id=r.id, subnets=subnets(conn))
    except model.IpamError as e:
        return _invalid(e)
    audit(conn, user.username, 'ipam_range_edit', f"{n.prefix}: {v['first']}-{v['last']}{_via(user)}")
    return _range(_get_range(conn, n, range_id))


@router.delete('/networks/{network_id}/ranges/{range_id}', status_code=204, summary='Delete a range')
def range_delete(network_id: int, range_id: int, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    n = _leaf(conn, network_id)
    r = _get_range(conn, n, range_id)
    model.delete_range(conn, n.id, r.id)
    audit(conn, user.username, 'ipam_range_delete', f'{n.prefix}: {r.first}-{r.last}{_via(user)}')
    return Response(status_code=204)


@router.get('/networks/{network_id}/addresses', response_model=models.IpamAddresses,
            summary="A network's addresses")
def addresses(request: Request, network_id: int, page: int = Query(0, ge=0, description='one /24 per page'),
              used_only: bool = Query(False, description='leave the free addresses out'),
              user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """The network page's table: every address (or the used ones) of one /24 page, with its state, names, MAC,
    comment and checks. An IPv6 network has one page: the addresses LiteBlox knows of there."""
    from ..ipam import view, view6
    n = _leaf(conn, network_id)
    if n.version == 6:
        from ..dhcp.model import subnets6
        if page:
            raise HTTPException(status_code=404, detail=f'{n.prefix} has 1 page')
        facts, _ = view6.gather(conn, _settings(request), n)
        rows = view6.rows(facts, n, model.all_ranges(conn, n, subnets6(conn)), model.notes(conn))
        return {'network': n.prefix, 'page': 0, 'pages': 1,
                'items': [{**view.item(a), 'last_seen': _iso(a['seen']['last_seen']) if a['seen'] else None}
                          for a in rows]}
    if page >= view.pages(n):
        raise HTTPException(status_code=404, detail=f'{n.prefix} has {view.pages(n)} pages')
    facts = view.gather(conn, _settings(request))
    rows = view.rows(facts, n, model.all_ranges(conn, n, facts.subnets), model.notes(conn), page, used_only)
    return {'network': n.prefix, 'page': page, 'pages': view.pages(n),
            'items': [{**view.item(a), 'last_seen': _iso(a['seen']['last_seen']) if a['seen'] else None} for a in rows]}


# ── what the nodes saw, flapping, devices ──────────────────────────────────────

def _seen_row(r, settings, repeaters=frozenset()):
    from ..ipam import oui
    return {'ip': r['ip'], 'mac': r['mac'], 'vendor': oui.vendor(settings, r['mac']),
            'first_seen': _iso(r['first_seen']), 'last_seen': _iso(r['last_seen']), 'node': r['node'],
            'source': r['source'], 'repeater': r['mac'] in repeaters}


@router.get('/seen', response_model=list[models.IpamSeen], summary='What the nodes saw')
def seen_list(request: Request, network: str = Query(None, description='only inside this prefix'),
              mac: str = Query(None, description='only this MAC'), user: ApiUser = Depends(api_user),
              conn=Depends(get_db)):
    """Every address and MAC the nodes have seen in their neighbour tables (or by a sweep or probe), newest first."""
    from ..ipam.seen import mac_text
    sql, args = ('SELECT s.*, n.name AS node FROM ipam_seen s LEFT JOIN nodes n ON n.id = s.node_id', [])
    if mac:
        sql, args = sql + ' WHERE s.mac = ?', [mac_text(mac)]
    rows = conn.execute(sql + ' ORDER BY s.last_seen DESC', args).fetchall()
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise HTTPException(status_code=422, detail=f'{network} is not a network')
        rows = [r for r in rows if ipaddress.ip_address(r['ip']) in net]
    from ..ipam.devices import repeaters
    behind = repeaters(conn)
    return [_seen_row(r, _settings(request), behind) for r in rows]


def _ip(ip):
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise HTTPException(status_code=422, detail=f'{ip} is not an IP address')


@router.delete('/seen/{ip}', status_code=204, summary='Forget what was seen on an address')
def seen_forget(ip: str, mac: str = Query(None, description='only this MAC'), user: ApiUser = Depends(api_writer),
                conn=Depends(get_db)):
    from ..ipam import seen
    ip = _ip(ip)
    seen.forget(conn, ip, mac)
    audit(conn, user.username, 'ipam_forget', f"{ip}{' ' + mac if mac else ''}{_via(user)}")
    return Response(status_code=204)


@router.get('/flapping', response_model=list[models.IpamFlapping], summary='Addresses flapping between MACs')
def flapping_list(user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..ipam import seen
    return [{**f, 'last_at': _iso(f['last_at'])} for f in seen.flapping(conn)]


@router.post('/flapping/{ip}/ack', status_code=204, summary='Acknowledge a flapping address')
def flapping_ack(ip: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """It comes back only if the address flaps again after this."""
    from ..ipam import seen
    ip = _ip(ip)
    seen.ack(conn, ip, user.username)
    audit(conn, user.username, 'ipam_ack', f'{ip}{_via(user)}')
    return Response(status_code=204)


def _mac(mac):
    from ..dhcp.validate import normalize_mac
    m = normalize_mac(mac)
    if m is None:
        raise HTTPException(status_code=422, detail=f'{mac} is not a MAC address')
    return m


def _device(conn, settings, m, row=None):
    from ..ipam import devices, oui
    row = row or devices.get(conn, m) or {'label': '', 'comment': '', 'repeater': False}
    rows = conn.execute('SELECT s.*, n.name AS node FROM ipam_seen s LEFT JOIN nodes n ON n.id = s.node_id '
                        'WHERE s.mac = ? ORDER BY s.last_seen DESC', (m,)).fetchall()
    repeater = bool(row['repeater'])
    return {'mac': m, 'label': row['label'], 'comment': row['comment'], 'repeater': repeater,
            'vendor': oui.vendor(settings, m),
            'seen': [_seen_row(r, settings, {m} if repeater else frozenset()) for r in rows]}


@router.get('/devices', response_model=list[models.IpamDevice], summary='List the labelled devices (and repeaters)')
def devices_list(request: Request, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    rows = conn.execute('SELECT * FROM devices ORDER BY label, mac').fetchall()
    return [_device(conn, _settings(request), r['mac'], r) for r in rows]


@router.get('/devices/{mac}', response_model=models.IpamDevice, summary='Get a device')
def device_get(request: Request, mac: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    """Its label and comment (empty without one), vendor, and where the nodes saw it."""
    return _device(conn, _settings(request), _mac(mac))


@router.put('/devices/{mac}', response_model=models.IpamDevice,
            summary="Set a device's label and comment, and whether it's a Wi-Fi repeater")
def device_put(request: Request, mac: str, body: models.IpamDeviceIn, user: ApiUser = Depends(api_writer),
               conn=Depends(get_db)):
    """A label shows with the MAC everywhere and search finds it. It changes nothing in DNS or DHCP. `repeater`
    marks a Wi-Fi repeater's MAC, which stands in for the devices connected through it: it then isn't flapping, and
    raises no "reserved for" or "IPAM has it for" warning where it shows. Left out, it stays as it was."""
    from ..ipam import devices
    m = _mac(mac)
    saved = devices.save(conn, m, body.label, body.comment, body.repeater)
    flag = ' (Wi-Fi repeater)' if body.repeater and saved else ' (not a repeater)' if body.repeater is False else ''
    audit(conn, user.username, 'ipam_device', f'{m} {body.label}'.strip() + flag + _via(user))
    return _device(conn, _settings(request), m)


@router.delete('/devices/{mac}', status_code=204, summary="Clear a device's label, comment and repeater mark")
def device_delete(mac: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..ipam import devices
    m = _mac(mac)
    devices.save(conn, m, '', '', repeater=False)
    audit(conn, user.username, 'ipam_device', f'{m}{_via(user)}')
    return Response(status_code=204)


# ── IPAM names: names kept in IPAM only ────────────────────────────────────────

def _name(r):
    return {'ip': r['ip'], 'name': r['name'], 'mac': r['mac'] or '', 'comment': r['comment'],
            'username': r['username'], 'created_at': _iso(r['created_at'])}


@router.get('/names', response_model=list[models.IpamName], summary='List the IPAM names')
def names_list(network: str = Query(None, description='only inside this prefix'), user: ApiUser = Depends(api_user),
               conn=Depends(get_db)):
    """Names kept in IPAM only (Name this address, or assign with the DNS module off or `target: "ipam"`)."""
    from ..ipam import names
    found = names.records(conn)
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise HTTPException(status_code=422, detail=f'{network} is not a network')
        found = {ip: r for ip, r in found.items() if ip in net}
    return [_name(r) for _, r in sorted(found.items(), key=lambda kv: sort_key(kv[0]))]


@router.get('/names/{ip}', response_model=models.IpamName, summary="Get an address's IPAM name")
def name_get(ip: str, user: ApiUser = Depends(api_user), conn=Depends(get_db)):
    from ..ipam import names
    r = names.get(conn, _ip(ip))
    if r is None:
        raise HTTPException(status_code=404, detail='no IPAM name at this address')
    return _name(r)


@router.put('/names/{ip}', response_model=models.IpamName, summary="Set an address's IPAM name",
            responses={422: {'description': 'not valid (per-field errors)'}})
def name_put(ip: str, body: models.IpamNameIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """Nothing goes to DNS or DHCP. An address `assign` made a record or reservation for is refused."""
    from ..ipam import names
    ip = _ip(ip)
    try:
        new = names.save(conn, ip, body.name, body.mac, body.comment, user.username)
    except model.IpamError as e:
        return _invalid(e)
    r = names.get(conn, ip)
    audit(conn, user.username, 'ipam_name', f"{ip}: {r['name']}{'' if new else ' (changed)'}{_via(user)}")
    return _name(r)


@router.delete('/names/{ip}', status_code=204, summary="Remove an address's IPAM name")
def name_delete(ip: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..ipam import names
    ip = _ip(ip)
    r = names.get(conn, ip)
    if r is None or not names.delete(conn, ip):
        raise HTTPException(status_code=404, detail='no IPAM name at this address')
    audit(conn, user.username, 'ipam_name_delete', f"{ip}: {r['name']}{_via(user)}")
    return Response(status_code=204)


# ── next free, holds, assign ───────────────────────────────────────────────────

@router.post('/next-free', response_model=models.NextFree, summary='Find (and hold) the next free addresses',
             responses={404: {'description': 'no such network, range or subnet'},
                        409: {'description': 'nothing free (left)'}})
def next_free(request: Request, body: models.NextFreeIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """The first address (or `count` in a row) that nothing uses on paper and nothing answers on the network,
    held for `minutes` so another caller doesn't get it. Assign it with `POST /ipam/assign`, or release the hold.
    `checked` is false when no node is on the network: then nobody probed it."""
    from ..ipam import free
    try:
        tgt = free.target(conn, body.network, body.range, body.subnet)
        out = free.next_free(conn, _settings(request), tgt, body.count, body.align, body.hold, body.minutes,
                             user.username, body.note)
    except FreeError as e:
        return _error(e)
    return {**out, 'hold_until': _iso(out['hold_until'])}


@router.delete('/holds/{ip}', response_model=models.Released, summary='Release a held address')
def hold_release(ip: str, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..ipam import free
    return {'released': free.release(conn, ip=_ip(ip))}


@router.delete('/holds', response_model=models.Released, summary="Release a block's holds")
def holds_release(hold_id: str = Query(..., description='the hold_id next-free gave'),
                  user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    from ..ipam import free
    return {'released': free.release(conn, hold_id=hold_id)}


@router.post('/assign', response_model=models.Assigned, summary='Put a name on addresses',
             responses={409: {'description': 'already assigned, or a DHCP change is running'}})
def assign(request: Request, body: models.AssignIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """With a MAC in a DHCP subnet: a reservation (its hostname is the name; a DHCP job). Without: an A record (and
    its PTR) in the zone, then a publish job unless `publish` is false. With `target: "ipam"` (the default when the
    DNS module is off): an IPAM record instead of the A record, nothing in DNS (a MAC outside the DHCP subnets
    stays on the record). A block takes `ips` and a name with `{n}`. Each address's hold is released. `unassign`
    removes exactly what this made."""
    from ..ipam import assign as mod
    ips = body.ips or ([body.ip] if body.ip else [])
    macs = body.macs or ([body.mac] if body.mac else None)
    try:
        return mod.assign(conn, _settings(request), ips, body.name, body.zone, macs, body.comment, body.group,
                          body.publish, user.username, _via(user), target=body.target)
    except FreeError as e:
        return _error(e)


@router.post('/unassign', response_model=models.Unassigned, summary='Remove what assign made')
def unassign(request: Request, body: models.UnassignIn, user: ApiUser = Depends(api_writer), conn=Depends(get_db)):
    """By addresses, a range (`192.168.1.80-192.168.1.83`) or a group. Only what `assign` made goes; anything else
    at those addresses is listed in `skipped` and left alone."""
    from ..ipam import assign as mod
    try:
        ips = body.ips or (mod.expand(body.range) if body.range else None)
        if not ips and not body.group:
            raise FreeError('give ips, range or group')
        return mod.unassign(conn, _settings(request), ips, body.group, body.publish, user.username, _via(user))
    except FreeError as e:
        return _error(e)
