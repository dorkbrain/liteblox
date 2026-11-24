"""DHCPv6 pages (6.0): subnets with their pools and delegated-prefix pools, reservations by DUID or MAC, leases and
the DHCPv6 settings. Changes are reviewed and applied the way the DHCPv4 pages do it (routes.py), in one job for both
families' files."""

import json
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from ..auth import User, current_user, require_admin
from .. import csvout
from ..db import get_db
from ..nodes import service as nodes
from ..templating import templates
from . import apply, ops, store, validate, validate6
from . import ra as ra_mod
from . import leases as lease_mod
from .model import (LIFETIMES6, Dhcp6Settings, Reservation6, Subnet6, ha_pair, has_dhcp6, serves,
                    settings as load_settings, settings6 as load_settings6, subnets6 as load_subnets6)
from .render import derived_reverse_zones
from .routes import (_int, _json, _placements, _previews, _review, _serving, _settings, _suggested_ntp, ddns_summary,
                     suggested_dns)

router = APIRouter()
BASE = '/dhcp/v6'


# ── form parsing ───────────────────────────────────────────────────────────────

def parse_subnet6(form, subnet_id):
    errors = {}
    pd = []
    for line in (form.get('pd_pools') or '').splitlines():
        if line.strip():
            try:
                pd.append(validate6.parse_pd_pool(line))
            except ValueError as e:
                errors['pd_pools'] = str(e)
    s = Subnet6(subnet_id, (form.get('prefix') or '').strip(), '',
                [p.strip() for p in (form.get('pools') or '').splitlines() if p.strip()], pd,
                validate6.parse_options6(form), _json(form, 'extra_options', [], errors), _json(form, 'extra', {}, errors),
                *[_int(form, k, errors) for k in LIFETIMES6], comment=(form.get('comment') or '').strip(),
                ddns=bool(form.get('ddns')), ddns_zone_id=_int(form, 'ddns_zone_id', errors),
                ddns_suffix=(form.get('ddns_suffix') or '').strip(), ddns_reverse=(form.get('ddns_reverse') or '').strip(),
                ra=bool(form.get('ra')), ra_slaac=bool(form.get('ra')) and bool(form.get('ra_slaac')))
    return s, errors


def subnet6_values(s):
    o = s.options
    return {'prefix': s.prefix, 'pools': '\n'.join(s.pools), 'pd_pools': '\n'.join(validate6.pd_text(p) for p in s.pd_pools),
            'dns': ', '.join(o.get('dns', [])), 'search': ', '.join(o.get('search', [])), 'ntp': ', '.join(o.get('ntp', [])),
            'extra_options': json.dumps(s.extra_options, indent=2) if s.extra_options else '',
            'extra': json.dumps(s.extra, indent=2) if s.extra else '', 'comment': s.comment,
            'ddns': s.ddns, 'ddns_zone_id': s.ddns_zone_id or '', 'ddns_suffix': s.ddns_suffix,
            'ddns_reverse': s.ddns_reverse, 'ra': '1' if s.ra else '', 'ra_slaac': '1' if s.ra_slaac else '',
            **{k: '' if getattr(s, k) is None else str(getattr(s, k)) for k in LIFETIMES6}}


def settings6_values(s):
    o = s.options
    return {'dns': ', '.join(o.get('dns', [])), 'search': ', '.join(o.get('search', [])), 'ntp': ', '.join(o.get('ntp', [])),
            'extra_options': json.dumps(s.extra_options, indent=2) if s.extra_options else '',
            **{k: '' if getattr(s, k) is None else str(getattr(s, k)) for k in LIFETIMES6}}


def parse_settings6(form):
    errors = {}
    s = Dhcp6Settings(*[_int(form, k, errors) for k in LIFETIMES6], validate6.parse_options6(form),
                      _json(form, 'extra_options', [], errors))
    return s, errors


def parse_reservation6(form, subnet_id, reservation_id):
    return Reservation6(reservation_id, subnet_id, (form.get('duid') or '').strip(), (form.get('hw_address') or '').strip(),
                        (form.get('ip_address') or '').strip(), (form.get('prefix') or '').strip(),
                        (form.get('hostname') or '').strip(), validate6.parse_options6(form, prefix='opt_'),
                        (form.get('comment') or '').strip())


def reservation6_values(r):
    o = r.options
    return {'duid': r.duid, 'hw_address': r.hw_address, 'ip_address': r.ip_address, 'prefix': r.prefix,
            'hostname': r.hostname, 'comment': r.comment, 'opt_dns': ', '.join(o.get('dns', [])),
            'opt_search': ', '.join(o.get('search', [])), 'opt_ntp': ', '.join(o.get('ntp', []))}


# ── shared ─────────────────────────────────────────────────────────────────────

def without_dhcp6(conn):
    """DHCP nodes that don't run kea-dhcp6 yet (before their 6.0 Repair)."""
    return [n for n in apply.dhcp_nodes(conn) if not has_dhcp6(n)]


def notes6(conn, subnet=None, served=()):
    out = []
    missing = without_dhcp6(conn)
    if missing:
        out.append(f"{', '.join(n['name'] for n in missing)} {'doesn' if len(missing) == 1 else 'don'}'t run kea-dhcp6 "
                   "yet: Repair each once (its page) and it serves DHCPv6 too. Until then it isn't written there.")
    if subnet is not None:
        off = validate6.check_interface_ipv6(subnet, served)
        if off:
            out.append(off)
    return out + ra_mod.notes(conn)


def _subnet_or_404(conn, subnet_id):
    s = next((x for x in load_subnets6(conn) if x.id == subnet_id), None)
    if s is None:
        raise HTTPException(status_code=404, detail='no such DHCPv6 subnet')
    return s


def _subnet6_change(request, conn, form, subnet_id):
    """(subnet, errors, v6 subnet list after the change, live interfaces it may go on)."""
    s, errors = parse_subnet6(form, subnet_id)
    s.ddns_mode = load_settings(conn).ddns_mode
    subnets = load_subnets6(conn)
    others = [o for o in subnets if o.id != subnet_id]
    old = next((o for o in subnets if o.id == subnet_id), None)
    s.reservations = old.reservations if old else []
    # when RA was turned on: kept while it stays on (LITEBLOX_DEV_RA_MAX_MINUTES counts from it)
    s.ra_since = (old.ra_since if old and old.ra else ra_mod.now()) if s.ra else None
    served, unserved = _placements(request, conn)
    if not errors:
        errors.update(validate6.check_subnet6(s, others, served, unserved))
    if not errors:
        errors.update(ra_mod.check(conn, s))
    if not errors:
        errors.update(validate.check_ddns(conn, s, load_settings(conn)))
    return s, errors, sorted(others + [s], key=lambda x: x.id), served


def not_served_note(conn, subnet):
    if ops.served(conn, subnet):
        return None
    pair = ha_pair(conn)
    where = f' on {pair.primary_name}' if pair.active else ''
    return (f"{subnet.prefix} isn't served yet, so Kea's config doesn't change: this is saved now, and Kea answers "
            f"for it once you tick {subnet.interface}{where} (Servers → Change interfaces).")


def _address_rows(conn, subnet, found):
    nodes_of = {(lease['prefix'] or lease['ip']): node for node, lease in found if lease['subnet_id'] == subnet.id}
    rows = lease_mod.addresses6(subnet, [lease for _, lease in found])
    for row in rows:
        lease = row['lease']
        row['node'] = nodes_of.get(row['ip']) if lease else None
        row['zone'] = (lease_mod.dns_zone(conn, lease['hostname'])
                       if lease and lease['registered'] and lease['hostname'] else None)
    return rows


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
    return templates.TemplateResponse(request, 'dhcp6_subnet_settings.html', {
        'user': user, 'subnet_id': subnet_id, 'v': values, 'errors': errors or {}, 'tab': 'settings',
        'suggested': suggested_dns(conn, values.get('prefix', '')), 'serving': _serving(conn),
        'suggested_ntp': _suggested_ntp(request, conn, values.get('prefix', '')),
        'ddns_zones': zones, 'ddns_key': s.ddns_key, 'ddns_mode': s.ddns_mode, 'ddns_server': s.ddns_server,
        'derived_reverse': derived, 'record': 'AAAA', 'missing': without_dhcp6(conn),
        'ra_max': ra_mod.max_minutes()}, status_code=status_code)


@router.get(BASE + '/subnets/new')
def subnet_new(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    return _subnet_page(request, user, conn, None, subnet6_values(Subnet6(None, '', '')))


@router.get(BASE + '/subnets/{subnet_id}')
def subnet_overview(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    """The subnet at a glance, from the DB and the health check's samples (no Kea read)."""
    from .. import stats
    s = _subnet_or_404(conn, subnet_id)
    size = lease_mod.pool_size6(s)
    active = stats.latest(conn, 'leases6_active', subnet6_id=s.id)
    in_pool = stats.latest(conn, 'leases6_in_pool', subnet6_id=s.id)
    prefixes = stats.latest(conn, 'prefixes6_active', subnet6_id=s.id)
    graphs = [(label, hours, stats.spark(stats.series(conn, 'leases6_active', subnet6_id=s.id, hours=hours), hours=hours))
              for label, hours in (('last day', 24), ('last week', 7 * 24))]
    pair = ha_pair(conn)
    return templates.TemplateResponse(request, 'dhcp6_subnet.html', {
        'user': user, 'subnet': s, 'tab': 'overview', 'size': size, 'active': active, 'in_pool': in_pool,
        'prefixes': prefixes, 'pd_size': lease_mod.pd_size(s),
        'pct': 100.0 * in_pool / size if size and in_pool is not None else None, 'graphs': graphs,
        'servers': [n for n in _serving(conn) if serves(pair, n, s) and has_dhcp6(n)], 'pair': pair,
        'ddns': ddns_summary(conn, s), 'globals': load_settings6(conn), 'notes': notes6(conn)})


@router.get(BASE + '/subnets/{subnet_id}/addresses')
def subnet_addresses(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    s = _subnet_or_404(conn, subnet_id)
    found, errors = lease_mod.serving_leases(_settings(request), conn, family=6)
    rows = _address_rows(conn, s, found)
    return templates.TemplateResponse(request, 'dhcp6_subnet_addresses.html', {
        'user': user, 'subnet': s, 'tab': 'addresses', 'rows': rows, 'tally': lease_mod.tally(rows),
        'errors': errors, 'serving': _serving(conn),
        'done': request.query_params.get('done'), 'error': request.query_params.get('error')})


@router.get(BASE + '/subnets/{subnet_id}/settings')
def subnet_settings(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    s = _subnet_or_404(conn, subnet_id)
    return _subnet_page(request, user, conn, subnet_id, {**subnet6_values(s), 'interface': s.interface,
                                                         'ra_since': s.ra_since})


@router.post(BASE + '/subnets/preview')
async def subnet_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    subnet_id = int(form['id']) if form.get('id') else store.next_subnet6_id(conn)
    s, errors, after, served = _subnet6_change(request, conn, form, subnet_id)
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    note = not_served_note(conn, s)
    granted = form.get('granted')
    return _review(request, _previews(request, conn, apply.dhcp_nodes(conn), subnet6_list=after),
                   label='Save (not served yet)' if note else 'Apply', ddns=ddns_summary(conn, s, test=True), saves=note,
                   granted=int(granted) if granted and granted.isdigit() else None, notes=notes6(conn, s, served))


@router.post(BASE + '/subnets')
async def subnet_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    existing = int(form['id']) if form.get('id') else None
    subnet_id = existing or store.next_subnet6_id(conn)
    s, errors, _, _ = _subnet6_change(request, conn, form, subnet_id)
    if not errors:
        summary = ddns_summary(conn, s)
        if summary and summary['grants']:
            errors['ddns'] = (f"key {summary['key']} may not register these names yet: review, then "
                              '"Add the missing grants"')
    if errors:
        return _subnet_page(request, user, conn, existing, {k: form.get(k, '') for k in subnet6_values(s)}, errors, 422)
    snap = store.snapshot(conn)
    old = store.get_subnet6(conn, existing) if existing else None
    turned = '' if bool(old and old.ra) == s.ra else ('; router advertisements on' if s.ra else
                                                       '; router advertisements off')
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)],
                         f"{'change' if existing else 'add'} IPv6 subnet {s.prefix}{turned}", user.username,
                         change=lambda c: store.save_subnet6(c, s), undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post(BASE + '/subnets/{subnet_id}/delete')
async def subnet_delete(request: Request, subnet_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    s = store.get_subnet6(conn, subnet_id)
    if s is None:
        raise HTTPException(status_code=404, detail='no such DHCPv6 subnet')
    form = await request.form()
    if (form.get('confirm') or '').strip() != s.prefix:
        return RedirectResponse(f"{BASE}/subnets/{subnet_id}/settings?error={quote('type the subnet to confirm')}",
                                status_code=303)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)], f'delete IPv6 subnet {s.prefix}',
                         user.username, change=lambda c: store.delete_subnet6(c, subnet_id),
                         undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── settings ───────────────────────────────────────────────────────────────────

def _settings_page(request, user, values, errors=None, status_code=200):
    return templates.TemplateResponse(request, 'dhcp6_settings.html', {'user': user, 'v': values, 'errors': errors or {}},
                                      status_code=status_code)


@router.get(BASE + '/settings')
def settings_page(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    return _settings_page(request, user, settings6_values(load_settings6(conn)))


def _settings_change(form):
    s, errors = parse_settings6(form)
    if not errors:
        errors.update(validate6.check_settings6(s))
    return s, errors


@router.post(BASE + '/settings/preview')
async def settings_preview(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    s, errors = _settings_change(await request.form())
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    return _review(request, _previews(request, conn, apply.dhcp_nodes(conn), dhcp6_settings=s), notes=notes6(conn))


@router.post(BASE + '/settings')
async def settings_save(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    form = await request.form()
    s, errors = _settings_change(form)
    if errors:
        return _settings_page(request, user, {k: form.get(k, '') for k in settings6_values(s)}, errors, 422)
    snap = store.snapshot(conn)
    job_id = apply.start(_settings(request), [n['id'] for n in apply.dhcp_nodes(conn)], 'DHCPv6 settings',
                         user.username, change=lambda c: store.save_settings6(c, s), undo=lambda c: store.restore(c, snap))
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── reservations ───────────────────────────────────────────────────────────────

def _reservation_page(request, user, subnet, reservation_id, values, errors=None, status_code=200):
    return templates.TemplateResponse(request, 'dhcp6_reservation.html', {
        'user': user, 'subnet': subnet, 'reservation_id': reservation_id, 'v': values, 'errors': errors or {}},
        status_code=status_code)


@router.get(BASE + '/subnets/{subnet_id}/reservations/new')
def reservation_new(request: Request, subnet_id: int, duid: str = '', mac: str = '', ip: str = '', prefix: str = '',
                    hostname: str = '', user: User = Depends(require_admin), conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    name = hostname.split('.')[0] if hostname else ''
    return _reservation_page(request, user, subnet, None, reservation6_values(
        Reservation6(None, subnet_id, duid, '' if duid else mac, ip, prefix, name)))


@router.get(BASE + '/subnets/{subnet_id}/reservations/{reservation_id}')
def reservation_page(request: Request, subnet_id: int, reservation_id: int, user: User = Depends(current_user),
                     conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    r = store.get_reservation6(conn, reservation_id)
    if r is None or r.subnet_id != subnet_id:
        raise HTTPException(status_code=404, detail='no such reservation')
    return _reservation_page(request, user, subnet, reservation_id, reservation6_values(r))


@router.post(BASE + '/subnets/{subnet_id}/reservations/preview')
async def reservation_preview(request: Request, subnet_id: int, user: User = Depends(require_admin),
                              conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    form = await request.form()
    rid = int(form['id']) if form.get('id') else None
    r = parse_reservation6(form, subnet.id, rid)
    errors, warnings, after = ops.reservation6_change(_settings(request), conn, subnet, r, rid)
    if errors:
        return _review(request, [], '; '.join(f'{k}: {v}' for k, v in errors.items()))
    results = _previews(request, conn, apply.dhcp_nodes(conn), subnet6_list=after)
    for res in results:
        res['notes'] = warnings
    note = not_served_note(conn, subnet)
    return _review(request, results, label='Save (not served yet)' if note else 'Apply', saves=note, notes=notes6(conn))


@router.post(BASE + '/subnets/{subnet_id}/reservations')
async def reservation_save(request: Request, subnet_id: int, user: User = Depends(require_admin), conn=Depends(get_db)):
    subnet = _subnet_or_404(conn, subnet_id)
    form = await request.form()
    rid = int(form['id']) if form.get('id') else None
    r = parse_reservation6(form, subnet.id, rid)
    errors, _, _ = ops.reservation6_change(_settings(request), conn, subnet, r, rid)
    if errors:
        return _reservation_page(request, user, subnet, rid, {k: form.get(k, '') for k in reservation6_values(r)},
                                 errors, 422)
    try:
        job_id = ops.start_reservation6(_settings(request), conn, r, rid, user.username)
    except ops.Busy as e:
        return RedirectResponse(f'{BASE}/subnets/{subnet_id}/addresses?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


@router.post(BASE + '/subnets/{subnet_id}/reservations/{reservation_id}/delete')
def reservation_delete(request: Request, subnet_id: int, reservation_id: int, user: User = Depends(require_admin),
                       conn=Depends(get_db)):
    r = store.get_reservation6(conn, reservation_id)
    if r is None or r.subnet_id != subnet_id:
        raise HTTPException(status_code=404, detail='no such reservation')
    try:
        job_id = ops.start_reservation6_delete(_settings(request), conn, r, user.username)
    except ops.Busy as e:
        return RedirectResponse(f'{BASE}/subnets/{subnet_id}/addresses?error={quote(str(e))}', status_code=303)
    return RedirectResponse(f'/jobs/{job_id}', status_code=303)


# ── leases ─────────────────────────────────────────────────────────────────────

CSV_COLUMNS = ('subnet', 'address_or_prefix', 'kind', 'state', 'duid', 'mac', 'hostname', 'reserved', 'lease_state',
               'expires', 'node', 'in_pool', 'dns_zone')


def csv_rows(subnet, rows):
    for a in rows:
        r, lease = a['reservation'], a['lease']
        yield [subnet, a['ip'] or '', a['kind'], a['label'], a['duid'], a['mac'], a['hostname'],
               ('prefix' if r.prefix and not r.ip_address else 'address' if r.ip_address else 'name only') if r else '',
               lease['state'] if lease else '', csvout.when(lease['expires']) if lease else '',
               a['node']['name'] if a.get('node') else '', a['in_pool'], a.get('zone') or '']


@router.get(BASE + '/subnets/{subnet_id}/addresses.csv')
def subnet_addresses_csv(request: Request, subnet_id: int, user: User = Depends(current_user), conn=Depends(get_db)):
    s = _subnet_or_404(conn, subnet_id)
    found, errors = lease_mod.serving_leases(_settings(request), conn, family=6)
    return csvout.response(CSV_COLUMNS, csv_rows(s.prefix, _address_rows(conn, s, found)),
                           csvout.filename('dhcp6', s.prefix, dated=True), notes=errors)


@router.get(BASE + '/leases.csv')
def leases_csv(request: Request, user: User = Depends(current_user), conn=Depends(get_db)):
    """Every DHCPv6 subnet's addresses and delegated prefixes (its table), read from Kea again."""
    found, errors = lease_mod.serving_leases(_settings(request), conn, family=6)
    rows = [row for s in load_subnets6(conn) for row in csv_rows(s.prefix, _address_rows(conn, s, found))]
    return csvout.response(CSV_COLUMNS, rows, csvout.filename('dhcp6-leases', dated=True), notes=errors)


def _back(form, default):
    back = (form.get('back') or '').strip()
    return back if back.startswith('/dhcp/') and '//' not in back and '?' not in back else default


@router.post(BASE + '/leases/delete')
async def lease_delete(request: Request, user: User = Depends(require_admin), conn=Depends(get_db)):
    from ..db import audit
    form = await request.form()
    ip = (form.get('ip') or '').strip()
    kind = 'prefix' if form.get('kind') == 'prefix' else 'address'
    node = nodes.get_node(conn, int(form.get('node_id') or 0))
    if node is None or not node['dhcp'] or not has_dhcp6(node):
        raise HTTPException(status_code=404, detail='no such DHCPv6 node')
    back = _back(form, '/dhcp')
    try:
        ops.delete_lease6(_settings(request), conn, node, ip, kind)
    except lease_mod.LeaseError as e:
        return RedirectResponse(f'{back}?error={quote(str(e))}', status_code=303)
    audit(conn, user.username, 'dhcp_lease_delete', f"{ip} on {node['name']}")
    what = 'delegated prefix' if kind == 'prefix' else 'lease'
    return RedirectResponse(f"{back}?done={quote(f'Deleted the {what} {ip}; its DNS name goes with it')}",
                            status_code=303)


def overview_rows(request, conn):
    """The DHCP page's DHCPv6 subnets with their active lease counts (from the health check's samples)."""
    from .. import stats
    out = []
    for s in load_subnets6(conn):
        out.append({'subnet': s, 'active': stats.latest(conn, 'leases6_active', subnet6_id=s.id),
                    'prefixes': stats.latest(conn, 'prefixes6_active', subnet6_id=s.id)})
    return out
