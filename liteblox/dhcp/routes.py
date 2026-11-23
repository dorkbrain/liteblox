"""The DHCP tab: servers and the interfaces they serve, subnets, and the global DHCPv4 settings.

Every change is previewed first (the config diff and Kea's own check on each node),
then applied as a job: the rows are saved, each node is backed up, staged, committed
and checked, and a failure rolls back the nodes and the rows together.
"""

import ipaddress
import json
from typing import Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import User, current_user, require_admin
from .. import csvout
from ..bindconf.model import node_address
from ..db import get_db
from ..nodes import service as nodes
from ..templating import templates
from . import apply, ops, store, validate
from . import leases as lease_mod
from .model import (DDNS_MODES, LIFETIMES, Dhcp4Settings, HaPair, Reservation, Subnet, dns_primary,
                    dynamic_reverse_zones, ha_pair, interfaces_of, serves, settings as load_settings,
                    subnets as load_subnets)
from .render import derived_reverse_zones, reverse_zones_for, subnet_reverse_zones

router = APIRouter()


def _settings(request):
    return request.app.state.settings


def _status(request, node):
    return ops.node_status(_settings(request), node)


def _serving(conn):
    return lease_mod.serving(conn)


def _placements(request, conn):
    """(served, not served yet): the DHCP nodes' live interfaces a subnet may go on. A pair's standby is left out:
    subnets carry the primary's interface names, and the standby's own are matched to them by network."""
    pair = ha_pair(conn)
    found = [i for i in ops.dhcp_interfaces(_settings(request), conn)
             if not (pair.active and i.get('node_id') == pair.standby_id)]
    return [i for i in found if i['served']], [i for i in found if not i['served']]


# ── form parsing ───────────────────────────────────────────────────────────────

def _int(form, key, errors):
    raw = (form.get(key) or '').strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        errors[key] = 'a number of seconds'
        return None


def _json(form, key, default, errors):
    raw = (form.get(key) or '').strip()
    if not raw:
        return default
    try:
        return json.loads(raw)
    except ValueError as e:
        errors[key] = f'not JSON: {e}'
        return default


def parse_subnet(form, subnet_id):
    errors = {}
    s = Subnet(subnet_id, (form.get('prefix') or '').strip(), '',
               [p.strip() for p in (form.get('pools') or '').splitlines() if p.strip()],
               validate.parse_options(form), _json(form, 'extra_options', [], errors), _json(form, 'extra', {}, errors),
               *[_int(form, k, errors) for k in LIFETIMES], comment=(form.get('comment') or '').strip(),
               ddns=bool(form.get('ddns')), ddns_zone_id=_int(form, 'ddns_zone_id', errors),
               ddns_suffix=(form.get('ddns_suffix') or '').strip(), ddns_reverse=(form.get('ddns_reverse') or '').strip())
    return s, errors


def user_keys(conn):
    from ..keys import INTERNAL
    return [r for r in conn.execute('SELECT * FROM tsig_keys ORDER BY name') if r['name'] not in INTERNAL]


def parse_settings(form, conn):
    """The DHCP settings from the form. DNS registration: ddns_mode liteblox (a key from tsig_keys; none = off),
    external (server, port and key; an empty secret keeps the one saved) or off. A form without ddns_mode (older
    scripts) is liteblox when it names a key."""
    from ..modules import enabled
    from .ddnstest import check_key
    errors = {}
    s = Dhcp4Settings(*[_int(form, k, errors) for k in LIFETIMES], validate.parse_options(form),
                      _json(form, 'extra_options', [], errors), bool(form.get('authoritative')))
    saved = load_settings(conn)
    key_id = _int(form, 'ddns_key_id', errors)
    mode = (form.get('ddns_mode') or ('liteblox' if key_id else 'off')).strip()
    if mode not in DDNS_MODES:
        errors['ddns_mode'] = 'liteblox, external or off'
        mode = 'off'
    if mode == 'liteblox' and not enabled(conn)['dns']:
        errors['ddns_mode'] = "the DNS module is off, so there's no LiteBlox DNS primary: register at another DNS server"
    s.ddns_mode = mode
    if key_id:
        row = next((k for k in user_keys(conn) if k['id'] == key_id), None)
        if row is None:
            errors['ddns_key_id'] = 'not a client key'
        else:
            s.ddns_key_id = key_id
            if mode == 'liteblox':
                s.ddns_key = {'name': row['name'], 'algorithm': row['algorithm'], 'secret': row['secret']}
    if mode == 'liteblox' and not s.ddns_key:
        s.ddns_mode = 'off'         # no key: nothing registers, as before 4.0
    # the other server's fields are kept whatever the mode, so switching back and forth loses nothing
    s.ddns_server = (form.get('ddns_server', saved.ddns_server) or '').strip()
    port = (form.get('ddns_port') or str(saved.ddns_port or 53)).strip()
    s.ddns_port = int(port) if port.isdigit() and 1 <= int(port) <= 65535 else None
    old = saved.ddns_external_key or {}
    name = (form.get('ddns_key_name', old.get('name', '')) or '').strip().rstrip('.')
    algorithm = (form.get('ddns_key_algorithm', old.get('algorithm', 'hmac-sha256')) or '').strip()
    secret = (form.get('ddns_key_secret') or '').strip() or (old.get('secret', '') if name == old.get('name') else '')
    s.ddns_external_key = {'name': name, 'algorithm': algorithm, 'secret': secret} if name or secret else None
    if mode == 'external':
        try:
            ipaddress.IPv4Address(s.ddns_server)
        except ValueError:
            errors['ddns_server'] = "the DNS server's IPv4 address: the primary of the zones clients go in"
        if s.ddns_port is None:
            errors['ddns_port'] = 'a port from 1 to 65535'
        errors.update(check_key(s.ddns_external_key or {}))
        s.ddns_key = s.ddns_external_key
    s.ddns_port = s.ddns_port or 53
    return s, errors


def subnet_values(s):
    """A Subnet as the form shows it."""
    o = s.options
    return {'prefix': s.prefix, 'pools': '\n'.join(s.pools), 'routers': ', '.join(o.get('routers', [])),
            'dns': ', '.join(o.get('dns', [])), 'domain': o.get('domain', ''), 'search': ', '.join(o.get('search', [])),
            'ntp': ', '.join(o.get('ntp', [])),
            'extra_options': json.dumps(s.extra_options, indent=2) if s.extra_options else '',
            'extra': json.dumps(s.extra, indent=2) if s.extra else '', 'comment': s.comment,
            'ddns': s.ddns, 'ddns_zone_id': s.ddns_zone_id or '', 'ddns_suffix': s.ddns_suffix,
            'ddns_reverse': s.ddns_reverse,
            **{k: '' if getattr(s, k) is None else str(getattr(s, k)) for k in LIFETIMES}}


def settings_values(s):
    o = s.options
    return {'routers': ', '.join(o.get('routers', [])), 'dns': ', '.join(o.get('dns', [])),
            'domain': o.get('domain', ''), 'search': ', '.join(o.get('search', [])), 'ntp': ', '.join(o.get('ntp', [])),
            'extra_options': json.dumps(s.extra_options, indent=2) if s.extra_options else '',
            'authoritative': s.authoritative, 'ddns_key_id': s.ddns_key_id or '', 'ddns_mode': s.ddns_mode,
            'ddns_server': s.ddns_server, 'ddns_port': str(s.ddns_port or 53),
            'ddns_key_name': (s.ddns_external_key or {}).get('name', ''),
            'ddns_key_algorithm': (s.ddns_external_key or {}).get('algorithm', 'hmac-sha256'), 'ddns_key_secret': '',
            **{k: '' if getattr(s, k) is None else str(getattr(s, k)) for k in LIFETIMES}}


def _suggested_ntp(request, conn, prefix):
    """The time-serving nodes' addresses in this subnet (Settings → Time), for the NTP servers field."""
    from ..ntp.routes import serving_addresses
    return serving_addresses(_settings(request), conn, prefix) if prefix else []


def suggested_dns(conn, prefix):
    """LiteBlox's DNS nodes with an address in this network (their DNS address, or their host)."""
    try:
        network = ipaddress.ip_network(prefix)
    except ValueError:
        return []
    out = []
    for n in nodes.list_nodes(conn):
        addr = node_address(n)
        if addr and n['managed'] and ipaddress.ip_address(addr) in network:
            out.append(addr)
    return out


# ── previews ───────────────────────────────────────────────────────────────────

def _previews(request, conn, targets, **overrides):
    return [apply.preview(conn, _settings(request), n, **overrides) for n in targets]


def _review(request, results, error=None, action=None, label='Apply', ddns=None, saves=None, granted=None,
            notes=()):
    """saves: why this change is saved without reaching Kea (a subnet not served yet); it can still be applied.
    granted: the job that just added the key's missing grants (the review runs again after it). notes: worth
    knowing before applying, never blocking."""
    blocked = bool(ddns and ddns.get('grants'))
    return templates.TemplateResponse(request, 'partials/dhcp_review.html', {
        'results': results, 'error': error, 'action': action, 'label': label, 'ddns': ddns, 'saves': saves,
        'granted': granted, 'notes': list(notes),
        'problems': blocked or any(r['problems'] for r in results), 'changed': any(r['diff'] for r in results)})


def _subnet_change(request, conn, form, subnet_id):
    """(subnet, errors, subnet list after the change) for a subnet form."""
    s, errors = parse_subnet(form, subnet_id)
    s.ddns_mode = load_settings(conn).ddns_mode
    subnets = load_subnets(conn)
    others = [o for o in subnets if o.id != subnet_id]
    # the form doesn't carry the reservations, and saving it keeps them: so must the review and its check
    s.reservations = next((o.reservations for o in subnets if o.id == subnet_id), [])
    if not errors:
        errors.update(validate.check_subnet(s, others, *_placements(request, conn)))
    if not errors:
        errors.update(validate.check_ddns(conn, s, load_settings(conn)))
    return s, errors, sorted(others + [s], key=lambda x: x.id)


def ddns_summary(conn, subnet, test=False):
    """What a registering subnet's review shows: the zones, where updates go, and grants still missing (LiteBlox's
    DNS), or what the other DNS server answers for them (test: ask it now)."""
    if not subnet.registers:
        return None
    s = load_settings(conn)
    key = s.ddns_key
    if subnet.ddns_mode == 'external':
        from . import ddnstest
        from .model import KeaConfig
        reverse = subnet_reverse_zones(subnet, KeaConfig())
        return {'zone': subnet.ddns_domain, 'suffix': subnet.qualifying_suffix, 'reverse': reverse,
                'primary': s.ddns_server if s.ddns_port == 53 else f'{s.ddns_server} port {s.ddns_port}',
                'key': key['name'] if key else None, 'external': True, 'grants': [],
                'test': ddnstest.run(s, [subnet]) if test and key else None}
    reverse = reverse_zones_for(subnet.prefix, dynamic_reverse_zones(conn))
    return {'zone': subnet.ddns_zone, 'suffix': subnet.qualifying_suffix, 'reverse': reverse,
            'primary': dns_primary(conn), 'key': key['name'] if key else None,
            'grants': validate.missing_grants(conn, key['name'] if key else None, subnet, reverse)}


def mode_notes(conn, s):
    """Subnets that ask to register clients but won't under the new DNS registration settings s."""
    out = []
    for sub in load_subnets(conn):
        if not sub.ddns:
            continue
        sub.ddns_mode = s.ddns_mode
        if s.ddns_mode == 'off':
            out.append(f'{sub.prefix} stops registering its clients in DNS (names already registered stay: '
                       'nothing removes them when their leases end).')
        elif not sub.registers:
            what = 'LiteBlox zone' if s.ddns_mode == 'liteblox' else 'domain at the DNS server'
            out.append(f"{sub.prefix} has no {what} to register in yet, so it registers nothing until you set one on "
                       'its Settings.')
    return out


# ── overview: servers and their interfaces ─────────────────────────────────────

@router.get('/dhcp')
def overview(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    servers = []
    pair = ha_pair(conn)
    for n in apply.dhcp_nodes(conn):
        status, error = _status(request, n)
        ha = (((status or {}).get('kea') or {}).get('services') or {}).get('dhcp4', {}).get('ha')
        addresses = [a.split('/')[0] for i in (status or {}).get('interfaces') or [] for a in i['addresses']
                     if ':' not in a]
        servers.append({'node': n, 'status': status, 'error': error, 'served': interfaces_of(n),
                        'own': {n['host'], node_address(n)}, 'role': pair.role_of(n['id']), 'ha': ha,
                        'addresses': addresses,
                        # a standby's own interface name: the primary's it stands in for, where they differ
                        'stands_for': {v: k for k, v in pair.interface_map.items()}
                        if pair.role_of(n['id']) == 'standby' else {}})
    serving = {n['id'] for n in _serving(conn)}
    counts, _ = lease_mod.counts(_settings(request), conn)
    return templates.TemplateResponse(request, 'dhcp.html', {
        'user': user, 'servers': servers, 'subnets': load_subnets(conn), 'serving': serving, 'counts': counts,
        'served_names': {i for s in servers for i in s['served']},
        'pair': pair,
        'others_set_up': [n for n in nodes.list_nodes(conn) if nodes.set_up(n) and not n['dhcp']],
        'error': request.query_params.get('error')})


def _interfaces_change(request, conn, node, form):
    """(chosen names, errors, the pair's new interface map or None)."""
    chosen = sorted(set(form.getlist('interfaces')))
    status, error = _status(request, node)
    if error:
        return chosen, {'interfaces': f"{node['name']} is unreachable: {error}"}, None
    pair = ha_pair(conn)
    if pair.role_of(node['id']) == 'standby':
        return chosen, {'interfaces': f'{node["name"]} is the standby: it serves what {pair.primary_name} serves; '
                                      f'change the interfaces on {pair.primary_name}'}, None
    others = [n for n in _serving(conn) if n['id'] not in (node['id'], pair.partner_of(node['id']))]
    errors = validate.check_interfaces(node, chosen, status.get('interfaces'), others)
    mapping = None
    if pair.active and not errors:
        # the standby serves the same networks under its own names
        standby = nodes.get_node(conn, pair.standby_id)
        theirs, error = _status(request, standby)
        if error:
            return chosen, {'interfaces': f"{standby['name']} (the standby) is unreachable: {error}"}, None
        mapping, problem = validate.match_interfaces(node, standby, status.get('interfaces'),
                                                     theirs.get('interfaces'), chosen)
        if problem:
            errors['interfaces'] = problem
    return chosen, errors, mapping


def _with_map(pair, mapping):
    """The pair as it will be with `mapping` (for previews)."""
    from dataclasses import replace
    return replace(pair, interface_map={k: v for k, v in (mapping or {}).items() if k != v})


def _map_note(pair, mapping):
    differ = {k: v for k, v in (mapping or {}).items() if k != v}
    if not differ:
        return None
    return (f'{pair.standby_name} serves ' + ', '.join(f"{v} for {pair.primary_name}'s {k}" for k, v in sorted(differ.items()))
            + ' (matched by network)')


@router.post('/dhcp/nodes/{node_id}/interfaces/preview')
async def interfaces_preview(request: Request, node_id: int, user: User = Depends(require_admin),
                             conn=Depends(get_db)):
    node = _dhcp_node(conn, node_id)
    chosen, errors, mapping = _interfaces_change(request, conn, node, await request.form())
    if errors:
        return _review(request, [], '; '.join(errors.values()))
    results = _previews(request, conn, [node], interfaces=chosen)
    pair = ha_pair(conn)
    if mapping is not None:
        standby = nodes.get_node(conn, pair.standby_id)
        results += [apply.preview(conn, _settings(request), standby, pair=_with_map(pair, mapping), interfaces=chosen)]
    notes = []
    for s in load_subnets(conn):
        was, now = s.interface in interfaces_of(node), s.interface in chosen
        if was and not now:
            notes.append(f"{s.prefix} won't be served any more (its interface is unticked)")
        elif now and not was:
            count = len(s.reservations)
            notes.append(f"Kea starts answering for {s.prefix} on {s.interface} (pools {', '.join(s.pools)}; "
                         f"{count} reservation{'' if count == 1 else 's'})")
    note = _map_note(pair, mapping) if mapping is not None else None
    if note:
        notes.append(note)
    if notes:
        results[0]['notes'] = notes
    return _review(request, results, label=f"Serve on {', '.join(chosen) or 'no interface'}")


@router.post('/dhcp/nodes/{node_id}/interfaces')
async def interfaces_apply(request: Request, node_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    node = _dhcp_node(conn, node_id)
    chosen, errors, mapping = _interfaces_change(request, conn, node, await request.form())
    if errors:
        return RedirectResponse(f"/dhcp?error={quote('; '.join(errors.values()))}", status_code=303)
    snap = store.snapshot(conn)
    partner = ha_pair(conn).partner_of(node['id'])
    targets = [node['id']] + ([partner] if partner else [])

    def change(c):
        store.set_interfaces(c, node['id'], chosen)
        if partner:
            store.set_interface_map(c, mapping)
            store.set_interfaces(c, partner, [(mapping or {}).get(n, n) for n in chosen])
    job_id = apply.start(_settings(request), targets, f"serve DHCP on {', '.join(chosen) or 'no interface'}",
                         user.username, change=change, undo=lambda c: store.restore(c, snap), node_id=node['id'])
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


def _dhcp_node(conn, node_id):
    node = nodes.get_node(conn, node_id)
    if node is None or not node['dhcp']:
        raise HTTPException(status_code=404, detail='no such DHCP node')
    return node


# ── subnets ────────────────────────────────────────────────────────────────────

def _subnet_page(request, user, conn, subnet_id, values, errors=None, status_code=200):
    zones = conn.execute("SELECT id, name FROM zones WHERE dynamic = 1 AND kind = 'primary' AND name NOT LIKE '%.arpa' "
                         'ORDER BY name').fetchall()
    s = load_settings(conn)
    derived = []
    if s.ddns_mode == 'external' and values.get('prefix'):
        try:
            derived = derived_reverse_zones(values['prefix'])
        except ValueError:
            pass
    return templates.TemplateResponse(request, 'dhcp_subnet_settings.html', {
        'user': user, 'subnet_id': subnet_id, 'v': values, 'errors': errors or {}, 'tab': 'settings',
        'suggested': suggested_dns(conn, values.get('prefix', '')), 'serving': _serving(conn),
        'suggested_ntp': _suggested_ntp(request, conn, values.get('prefix', '')),
        'ddns_zones': zones, 'ddns_key': s.ddns_key, 'ddns_mode': s.ddns_mode, 'ddns_server': s.ddns_server,
        'derived_reverse': derived}, status_code=status_code)


@router.get('/dhcp/subnets/new')
def subnet_new(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _subnet_page(request, user, conn, None, subnet_values(Subnet(None, '', '')))


@router.get('/dhcp/subnets/{subnet_id}')
def subnet_overview(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    """The subnet at a glance, from the DB and the health check's samples (no Kea read)."""
    from .. import stats
    s = _subnet_or_404(conn, subnet_id)
    size = lease_mod.pool_size(s)
    active = stats.latest(conn, 'leases_active', subnet_id=s.id)
    in_pool = stats.latest(conn, 'leases_in_pool', subnet_id=s.id)
    graphs = [(label, hours, stats.spark(stats.series(conn, 'leases_active', subnet_id=s.id, hours=hours), hours=hours))
              for label, hours in (('last day', 24), ('last week', 7 * 24))]
    pair = ha_pair(conn)
    return templates.TemplateResponse(request, 'dhcp_subnet.html', {
        'user': user, 'subnet': s, 'tab': 'overview', 'size': size, 'active': active, 'in_pool': in_pool,
        'pct': 100.0 * in_pool / size if size and in_pool is not None else None, 'graphs': graphs,
        'servers': [n for n in _serving(conn) if serves(pair, n, s)], 'pair': pair,
        'ddns': ddns_summary(conn, s), 'globals': load_settings(conn)})


@router.get('/dhcp/subnets/{subnet_id}/addresses')
def subnet_addresses(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    """Leases and reservations in one table, the leases read live from Kea."""
    s = _subnet_or_404(conn, subnet_id)
    found, errors = lease_mod.serving_leases(_settings(request), conn)
    rows = _address_rows(conn, s, found)
    return templates.TemplateResponse(request, 'dhcp_subnet_addresses.html', {
        'user': user, 'subnet': s, 'tab': 'addresses', 'rows': rows, 'tally': lease_mod.tally(rows),
        'errors': errors, 'serving': _serving(conn),
        'done': request.query_params.get('done'), 'error': request.query_params.get('error')})


@router.get('/dhcp/subnets/{subnet_id}/settings')
def subnet_settings(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    s = _subnet_or_404(conn, subnet_id)
    return _subnet_page(request, user, conn, subnet_id, {**subnet_values(s), 'interface': s.interface})


def _address_rows(conn, subnet, found):
    """addresses() for a subnet, each row with the node holding its lease and the zone its name is in."""
    nodes_of = {lease['ip']: node for node, lease in found if lease['subnet_id'] == subnet.id}
    rows = lease_mod.addresses(subnet, [lease for _, lease in found])
    for row in rows:
        lease = row['lease']
        row['node'] = nodes_of.get(row['ip']) if lease else None
        row['zone'] = (lease_mod.dns_zone(conn, lease['hostname'])
                       if lease and lease['registered'] and lease['hostname'] else None)
    return rows


@router.post('/dhcp/subnets/preview')
async def subnet_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    subnet_id = int(form['id']) if form.get('id') else store.next_subnet_id(conn)
    s, errors, after = _subnet_change(request, conn, form, subnet_id)
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    note = ops.not_served_note(conn, s)
    granted = form.get('granted')
    return _review(request, _previews(request, conn, apply.dhcp_nodes(conn), subnet_list=after),
                   label='Save (not served yet)' if note else 'Apply', ddns=ddns_summary(conn, s, test=True), saves=note,
                   granted=int(granted) if granted and granted.isdigit() else None)


@router.post('/dhcp/subnets')
async def subnet_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    existing = int(form['id']) if form.get('id') else None
    subnet_id = existing or store.next_subnet_id(conn)
    s, errors, _ = _subnet_change(request, conn, form, subnet_id)
    if not errors:
        summary = ddns_summary(conn, s)
        if summary and summary['grants']:
            errors['ddns'] = (f"key {summary['key']} may not register these names yet: review, then "
                              '"Add the missing grants"')
    if errors:
        return _subnet_page(request, user, conn, existing, {k: form.get(k, '') for k in subnet_values(s)}, errors, 422)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)],
                         f"{'change' if existing else 'add'} subnet {s.prefix}", user.username,
                         change=lambda c: store.save_subnet(c, s), undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/dhcp/subnets/{subnet_id}/delete')
async def subnet_delete(request: Request, subnet_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    s = store.get_subnet(conn, subnet_id)
    if s is None:
        raise HTTPException(status_code=404, detail='no such subnet')
    form = await request.form()
    if (form.get('confirm') or '').strip() != s.prefix:
        return RedirectResponse(f"/dhcp/subnets/{subnet_id}/settings?error={quote('type the subnet to confirm')}",
                                status_code=303)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)], f'delete subnet {s.prefix}',
                         user.username, change=lambda c: store.delete_subnet(c, subnet_id),
                         undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── global settings ────────────────────────────────────────────────────────────

def _settings_page(request, user, values, errors=None, status_code=200, conn=None):
    from ..keys import ALGORITHMS
    from ..modules import for_request
    saved = load_settings(conn) if conn else None
    return templates.TemplateResponse(request, 'dhcp_settings.html', {
        'user': user, 'v': values, 'errors': errors or {}, 'keys': user_keys(conn) if conn else [],
        'dns_on': for_request(request)['dns'], 'algorithms': list(ALGORITHMS),
        'has_secret': bool(saved and (saved.ddns_external_key or {}).get('secret'))}, status_code=status_code)


@router.get('/dhcp/settings')
def settings_page(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    return _settings_page(request, user, settings_values(load_settings(conn)), conn=conn)


def _settings_change(form, conn):
    s, errors = parse_settings(form, conn)
    if not errors:
        errors.update(validate.check_settings(s))
    return s, errors


@router.post('/dhcp/settings/preview')
async def settings_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    s, errors = _settings_change(await request.form(), conn)
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    return _review(request, _previews(request, conn, apply.dhcp_nodes(conn), dhcp_settings=s),
                   notes=mode_notes(conn, s))


@router.post('/dhcp/settings/ddns-test', response_class=HTMLResponse)
async def settings_ddns_test(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    """Test: a TSIG-signed SOA query to the other DNS server for each zone the registering subnets update."""
    from . import ddnstest
    form = dict(await request.form())
    form['ddns_mode'] = 'external'
    s, errors = parse_settings(form, conn)
    errors = {k: v for k, v in errors.items() if k.startswith('ddns_')}
    results = [] if errors else ddnstest.run(s, load_subnets(conn))
    return templates.TemplateResponse(request, 'partials/dhcp_ddns_test.html', {
        'errors': errors, 'results': results, 'tested': not errors})


@router.post('/dhcp/settings')
async def settings_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    s, errors = _settings_change(form, conn)
    if errors:
        return _settings_page(request, user, {**settings_values(s), **{k: form.get(k, '') for k in form}}, errors, 422,
                              conn)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)], 'DHCP settings', user.username,
                         change=lambda c: store.save_settings(c, s), undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── grants the DDNS key needs ──────────────────────────────────────────────────

@router.post('/dhcp/grants')
async def add_grants(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    """The grants a subnet's review found missing, added as one job (each reapplies BIND on the nodes)."""
    from .. import jobs, keys
    form = await request.form()
    key = load_settings(conn).ddns_key
    try:
        wanted = [tuple(g) for g in json.loads(form.get('grants') or '[]')]
    except ValueError:
        wanted = []
    if not key or not wanted:
        raise HTTPException(status_code=400, detail='no grants to add')
    settings, username = _settings(request), user.username

    def run(log):
        for zone, scope, owner, types in wanted:
            log(f"Granting key {key['name']}: {scope} {owner + ' ' if owner else ''}{types} in {zone}")
            keys.grant(settings, key['name'], zone, scope, owner, types, username, log)
        log(f"✓ key {key['name']} may register DHCP clients; review the subnet again and apply it")
    job_id = jobs.start(settings.db_path, 'grant', run, username=username)
    # shown under the button: the form stays as it is, and Review runs again once the grants are in
    return templates.TemplateResponse(request, 'partials/dhcp_grant_job.html', {'job': jobs.get(conn, job_id)})


@router.get('/dhcp/grants/{job_id}')
def grant_job(request: Request, job_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    """The grant job's log, polled from the review; 286 stops htmx polling once it's done."""
    from .. import jobs
    job = jobs.get(conn, job_id)
    if job is None or job['kind'] != 'grant':
        raise HTTPException(status_code=404, detail='no such grant job')
    return templates.TemplateResponse(request, 'partials/dhcp_grant_job.html', {'job': job, 'poll': True},
                                      status_code=286 if job['status'] != 'running' else 200)


# ── reservations ───────────────────────────────────────────────────────────────

def _subnet_or_404(conn, subnet_id):
    s = next((x for x in load_subnets(conn) if x.id == subnet_id), None)
    if s is None:
        raise HTTPException(status_code=404, detail='no such subnet')
    return s


def parse_reservation(form, subnet_id, reservation_id):
    options = validate.parse_options(form, prefix='opt_')
    return Reservation(reservation_id, subnet_id, (form.get('hw_address') or '').strip(),
                       (form.get('ip_address') or '').strip(), (form.get('hostname') or '').strip(), options,
                       (form.get('comment') or '').strip())


def reservation_values(r):
    o = r.options
    return {'hw_address': r.hw_address, 'ip_address': r.ip_address, 'hostname': r.hostname, 'comment': r.comment,
            'opt_routers': ', '.join(o.get('routers', [])), 'opt_dns': ', '.join(o.get('dns', [])),
            'opt_domain': o.get('domain', ''), 'opt_ntp': ', '.join(o.get('ntp', []))}


def _reservation_change(request, conn, subnet, form, reservation_id):
    """(reservation, errors, warnings, subnet list after the change)."""
    r = parse_reservation(form, subnet.id, reservation_id)
    errors, warnings, after = ops.reservation_change(_settings(request), conn, subnet, r, reservation_id)
    return r, errors, warnings, after


def _reservation_page(request, user, conn, subnet, reservation_id, values, errors=None, status_code=200):
    return templates.TemplateResponse(request, 'dhcp_reservation.html', {
        'user': user, 'subnet': subnet, 'reservation_id': reservation_id, 'v': values, 'errors': errors or {}},
        status_code=status_code)


@router.get('/dhcp/subnets/{subnet_id}/reservations/new')
def reservation_new(request: Request, subnet_id: int, mac: str = '', ip: str = '', hostname: str = '',
                    user: User = Depends(require_admin), conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    name = hostname.split('.')[0] if hostname else ''
    return _reservation_page(request, user, conn, subnet, None,
                             reservation_values(Reservation(None, subnet_id, mac, ip, name)))


@router.get('/dhcp/subnets/{subnet_id}/reservations/{reservation_id}')
def reservation_page(request: Request, subnet_id: int, reservation_id: int, ip: Optional[str] = None,
                     user: User = Depends(current_user), conn=Depends(get_db)):
    """ip: a new address to review (IPAM's device page: fix its address, or '' to back down to the name only)."""
    subnet = _subnet_or_404(conn, subnet_id)
    r = store.get_reservation(conn, reservation_id)
    if r is None or r.subnet_id != subnet_id:
        raise HTTPException(status_code=404, detail='no such reservation')
    values = reservation_values(r)
    if ip is not None:
        values['ip_address'] = ip.strip()
    return _reservation_page(request, user, conn, subnet, reservation_id, values)


@router.post('/dhcp/subnets/{subnet_id}/reservations/preview')
async def reservation_preview(request: Request, subnet_id: int, user: User = Depends(require_admin),
                              conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    form = await request.form()
    rid = int(form['id']) if form.get('id') else None
    r, errors, warnings, after = _reservation_change(request, conn, subnet, form, rid)
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    results = _previews(request, conn, apply.dhcp_nodes(conn), subnet_list=after)
    for res in results:
        res['notes'] = warnings
    note = ops.not_served_note(conn, subnet)
    return _review(request, results, label='Save (not served yet)' if note else 'Apply', saves=note)


@router.post('/dhcp/subnets/{subnet_id}/reservations')
async def reservation_save(request: Request, subnet_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    form = await request.form()
    rid = int(form['id']) if form.get('id') else None
    r, errors, _, _ = _reservation_change(request, conn, subnet, form, rid)
    if errors:
        return _reservation_page(request, user, conn, subnet, rid, {k: form.get(k, '') for k in reservation_values(r)},
                                 errors, 422)
    try:
        job_id = ops.start_reservation(_settings(request), conn, r, rid, user.username)
    except ops.Busy as e:
        return RedirectResponse(f'/dhcp/subnets/{subnet_id}/addresses?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/dhcp/subnets/{subnet_id}/reservations/{reservation_id}/delete')
def reservation_delete(request: Request, subnet_id: int, reservation_id: int, user: User = Depends(require_admin),
                       conn=Depends(get_db)):
    r = store.get_reservation(conn, reservation_id)
    if r is None or r.subnet_id != subnet_id:
        raise HTTPException(status_code=404, detail='no such reservation')
    try:
        job_id = ops.start_reservation_delete(_settings(request), conn, r, user.username)
    except ops.Busy as e:
        return RedirectResponse(f'/dhcp/subnets/{subnet_id}/addresses?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── leases ─────────────────────────────────────────────────────────────────────

@router.get('/dhcp/leases')
def leases_page(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    """Every subnet's addresses, leases and reservations merged (the subnets' Addresses tabs on one page)."""
    found, errors = lease_mod.serving_leases(_settings(request), conn)
    subnets = load_subnets(conn)
    groups = [(s, _address_rows(conn, s, found)) for s in subnets]
    return templates.TemplateResponse(request, 'dhcp_leases.html', {
        'user': user, 'groups': [g for g in groups if g[1]], 'strays': _strays(subnets, found),
        'tally': lease_mod.tally, 'errors': errors, 'serving': _serving(conn), 'done': request.query_params.get('done'),
        'error': request.query_params.get('error')})


def _strays(subnets, found):
    """[(subnet id, rows)] for leases in a subnet Kea has but LiteBlox doesn't (a config edited on the node),
    listed as they are."""
    known = {s.id for s in subnets}
    strays = {}
    for node, lease in found:
        if lease['subnet_id'] not in known:
            strays.setdefault(lease['subnet_id'], []).append(
                {'ip': lease['ip'], 'mac': lease['mac'], 'hostname': lease['hostname'], 'lease': lease,
                 'reservation': None, 'state': lease['state'], 'label': lease['state'], 'node': node, 'zone': None,
                 'pill': 'ready' if lease['state'] == 'active' else '', 'in_pool': False})
    return sorted(strays.items(), key=lambda x: x[0] or 0)


CSV_COLUMNS = ('subnet', 'ip', 'state', 'mac', 'hostname', 'reserved', 'lease_state', 'expires', 'node', 'in_pool',
               'dns_zone')


def _csv_rows(subnet, rows):
    """An addresses table's rows for csvout: subnet is its prefix (or "subnet N" for a stray)."""
    for a in rows:
        r, lease = a['reservation'], a['lease']
        yield [subnet, a['ip'] or '', a['label'], a['mac'], a['hostname'],
               ('address' if r.ip_address else 'name only') if r else '',
               lease['state'] if lease else '', csvout.when(lease['expires']) if lease else '',
               a['node']['name'] if a.get('node') else '', a['in_pool'], a.get('zone') or '']


@router.get('/dhcp/subnets/{subnet_id}/addresses.csv')
def subnet_addresses_csv(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    s = _subnet_or_404(conn, subnet_id)
    found, errors = lease_mod.serving_leases(_settings(request), conn)
    return csvout.response(CSV_COLUMNS, _csv_rows(s.prefix, _address_rows(conn, s, found)),
                           csvout.filename('dhcp', s.prefix, dated=True), notes=errors)


@router.get('/dhcp/leases.csv')
def leases_csv(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    """The Leases page as one file: every subnet's addresses, then the leases in subnets LiteBlox doesn't have."""
    found, errors = lease_mod.serving_leases(_settings(request), conn)
    subnets = load_subnets(conn)
    rows = [row for s in subnets for row in _csv_rows(s.prefix, _address_rows(conn, s, found))]
    rows += [row for sid, stray in _strays(subnets, found) for row in _csv_rows(f'subnet {sid}', stray)]
    return csvout.response(CSV_COLUMNS, rows, csvout.filename('dhcp-leases', dated=True), notes=errors)


def _back(form, default='/dhcp/leases'):
    """Where a form asks to go back to: a DHCP page of this site only."""
    back = (form.get('back') or '').strip()
    return back if back.startswith('/dhcp/') and '//' not in back and '?' not in back else default


@router.post('/dhcp/leases/delete')
async def lease_delete(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..db import audit
    form = await request.form()
    ip = (form.get('ip') or '').strip()
    node = nodes.get_node(conn, int(form.get('node_id') or 0))
    if node is None or not node['dhcp']:
        raise HTTPException(status_code=404, detail='no such DHCP node')
    back = _back(form)
    try:
        ops.delete_lease(_settings(request), conn, node, ip)
    except lease_mod.LeaseError as e:
        return RedirectResponse(f'{back}?error={quote(str(e))}', status_code=303)
    audit(conn, user.username, 'dhcp_lease_delete', f"{ip} on {node['name']}")
    return RedirectResponse(f"{back}?done={quote(f'Deleted the lease on {ip}; its DNS name goes with it')}",
                            status_code=303)


# ── the failover pair ──────────────────────────────────────────────────────────

def _pair_change(request, conn, form):
    """(primary row, standby row, values, errors) from the pair form."""
    def node(key):
        try:
            return nodes.get_node(conn, int(form.get(key) or 0))
        except ValueError:
            return None
    primary, standby = node('primary'), node('standby')
    try:
        port = int(form.get('port') or 8001)
    except ValueError:
        port = None
    values = {'primary_address': (form.get('primary_address') or '').strip(),
              'standby_address': (form.get('standby_address') or '').strip(), 'port': port}
    live = {}
    for n in (primary, standby):
        if n:
            status, error = _status(request, n)
            if error:
                return primary, standby, values, {'nodes': f"{n['name']} is unreachable: {error}"}
            live[n['id']] = status.get('interfaces') or []
    served = interfaces_of(primary) if primary else []
    errors = validate.check_pair(primary, standby, values['primary_address'], values['standby_address'], port,
                                 live, served)
    if not errors:
        values['interface_map'], _ = validate.match_interfaces(primary, standby, live.get(primary['id']),
                                                               live.get(standby['id']), served)
    return primary, standby, values, errors


def _pair_of(primary, standby, values):
    return HaPair(primary['id'], standby['id'], primary['name'], standby['name'], values['primary_address'],
                  values['standby_address'], values['port'],
                  {k: v for k, v in (values.get('interface_map') or {}).items() if k != v})


def _subnets_for_pair(conn, primary_id):
    """The subnets as they'll be once `primary_id` is the primary: renamed to its interface names when it's the
    current standby (store.set_pair does the same)."""
    from dataclasses import replace
    old, subnets = ha_pair(conn), load_subnets(conn)
    if old.active and primary_id == old.standby_id:
        subnets = [replace(x, interface=old.standby_name_for(x.interface)) for x in subnets]
    return subnets


@router.post('/dhcp/ha/preview')
async def pair_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..pki import PKI
    primary, standby, values, errors = _pair_change(request, conn, await request.form())
    if errors:
        return _review(request, [], '; '.join(errors.values()))
    pair = _pair_of(primary, standby, values)
    # the review renders with throwaway certificates: the real ones are issued when it's applied
    pki = PKI(_settings(request).pki_dir)
    results = []
    for n, address in ((standby, values['standby_address']), (primary, values['primary_address'])):
        key, cert = pki.issue_peer_cert(f"{n['name']}-dhcp", [address])
        row = {**dict(n), 'kea_tls': json.dumps({'address': address, 'cert': cert.decode(), 'key': key.decode(),
                                                 'ca': pki.ca_pem().decode()})}
        served = interfaces_of(primary)
        results.append(apply.preview(conn, _settings(request), row, pair=pair, interfaces=served,
                                     subnet_list=_subnets_for_pair(conn, primary['id'])))
    for gone in store.leaving_pair(ha_pair(conn), primary['id'], standby['id']):
        row = nodes.get_node(conn, gone)
        results.insert(0, apply.preview(conn, _settings(request), row, pair=pair, interfaces=[]))
        results[0]['notes'] = [f"{row['name']} leaves the pair and serves nothing"]
    note = _map_note(pair, values.get('interface_map'))
    if note:        # on the standby's review (it follows any node leaving the pair)
        standby_result = results[-2]
        standby_result['notes'] = [*standby_result.get('notes', []), note]
    return _review(request, results, label=f"Pair {primary['name']} (primary) with {standby['name']} (standby)")


@router.post('/dhcp/ha')
async def pair_apply(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..pki import PKI
    primary, standby, values, errors = _pair_change(request, conn, await request.form())
    if errors:
        return RedirectResponse(f"/dhcp?error={quote('; '.join(errors.values()))}", status_code=303)
    snap = store.snapshot(conn)
    pki = PKI(_settings(request).pki_dir)
    gone = store.leaving_pair(ha_pair(conn), primary['id'], standby['id'])     # stops serving first
    job_id = apply.start(_settings(request), [*gone, standby['id'], primary['id']],
                         f"pair {primary['name']} (primary) with {standby['name']} (standby)", user.username,
                         change=lambda c: store.set_pair(c, pki, primary['id'], standby['id'], values['primary_address'],
                                                         values['standby_address'], values['port'],
                                                         values.get('interface_map')),
                         undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post('/dhcp/ha/unpair')
async def pair_remove(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    pair = ha_pair(conn)
    form = await request.form()
    keep = int(form.get('keep') or 0)
    if not pair.active or keep not in (pair.primary_id, pair.standby_id):
        return RedirectResponse(f"/dhcp?error={quote('pick the node that keeps serving')}", status_code=303)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [pair.primary_id, pair.standby_id], 'end the failover pair', user.username,
                         change=lambda c: store.unpair(c, keep), undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)
