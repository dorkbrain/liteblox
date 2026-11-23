"""Move one address everywhere: its A records in every static zone, their PTRs, and optionally its DHCP
reservation and what IPAM keeps for it (its IPAM record or assignment, and its comment).

plan() reads what holds the old address (and what already uses the new one) without changing anything;
apply() makes the changes. Every static zone's records are staged first and saved only when all are good,
then the drafts are linked, so one Review shows them all and one publish sends them. A dynamic zone's names
belong to DHCP (or whoever updates it): they're listed, never changed. A reservation change is a DHCP job
started at once; DNS waits for the publish.
"""

import contextlib
import hashlib
import ipaddress

from .db import audit


class MoveError(Exception):
    def __init__(self, errors):
        super().__init__('; '.join(errors.values()))
        self.errors = errors


class Changed(Exception):
    """Something the preview showed changed before the move was made."""


def _ip(text, field):
    try:
        return ipaddress.IPv4Address(str(text or '').strip())
    except ValueError:
        raise MoveError({field: f'{text or "(empty)"} is not an IPv4 address'})


def _ttl(rec):
    return None if rec.ttl is None else str(rec.ttl)


def _held(conn):
    """{name: row} of the zones whose records LiteBlox edits."""
    return {r['name']: r for r in conn.execute("SELECT * FROM zones WHERE kind = 'primary'")}


def _a_records(edit, ip):
    return [r for r in edit.zone.records() if r.rtype == 'A' and r.rdata.strip() == str(ip)]


def _ptr_records(edit, ip):
    import dns.reversename
    owner = dns.reversename.from_address(str(ip))
    return [r for r in edit.zone.records() if r.rtype == 'PTR' and r.name == owner]


def _target(rec):
    import dns.exception
    import dns.name
    try:
        return dns.name.from_text(rec.rdata.strip(), rec.origin)
    except dns.exception.DNSException:
        return None


def plan(conn, settings, old, new):
    """What moving old to new would do. Raises MoveError for addresses that can't be used."""
    from . import search
    from .dhcp import model as dhcp_model
    from .dns import editing, ptr
    old, new = _ip(old, 'old'), _ip(new, 'new')
    if old == new:
        raise MoveError({'new': 'that is the address it has now'})
    held = _held(conn)
    reverse_names = [n for n in held if n.endswith('.in-addr.arpa')]
    old_rzone, new_rzone = ptr.reverse_zone_for(str(old), reverse_names), ptr.reverse_zone_for(str(new), reverse_names)

    forward, ptr_moves, revs, edits = [], [], {}, {}
    for name, row in sorted(held.items()):
        if row['dynamic']:
            continue
        edit = editing.ZoneEdit(settings, conn, name)
        if edit.zone is None:
            continue
        edits[name], revs[name] = edit, edit.rev
        recs = _a_records(edit, old)
        if recs:
            forward.append({'zone': name, 'recs': recs, 'draft': edit.is_draft})
    moved_targets = {r.name for f in forward for r in f['recs']}
    # a moved name gets the new address's PTR, so an old PTR to another name only goes
    remove_only = any(ptr.is_host_name(t) for t in moved_targets)
    for name, edit in edits.items():
        if not name.endswith('.in-addr.arpa'):
            continue
        for rec in _ptr_records(edit, old):
            target = _target(rec)
            if target is not None and target not in moved_targets:
                ptr_moves.append({'zone': name, 'rec': rec, 'target': target, 'remove_only': remove_only})

    found_old = search.search(conn, settings, str(old))
    found_new = search.search(conn, settings, str(new))
    a_old, a_new = found_old.address, found_new.address
    moved_names = {t.to_text().rstrip('.').lower() for t in moved_targets}
    # a PTR to a moved name in a dynamic reverse zone follows anyway (sent when the forward zone is published)
    dynamic = [h for h in found_old.records.hits if h['dynamic'] and h['rec'].address == old
               and not (h['rec'].rtype == 'PTR' and h['rec'].target in moved_names)]

    subnets = dhcp_model.subnets(conn)
    by_id = {s.id: s for s in subnets}
    to_subnet = next((s for s in subnets if new in ipaddress.IPv4Network(s.prefix, strict=False)), None)
    reservations = []
    for r in a_old['reservations']:
        if r.ip_address != str(old):
            continue
        item = {'r': r, 'subnet': by_id.get(r.subnet_id), 'to_subnet': to_subnet, 'errors': {}, 'warnings': []}
        if to_subnet is None:
            item['errors'] = {'ip_address': f'{new} is in no DHCP subnet, so the reservation can\'t follow it'}
        else:
            from dataclasses import replace
            from .dhcp import ops
            moved = replace(r, ip_address=str(new), id=r.id if to_subnet.id == r.subnet_id else None,
                            subnet_id=to_subnet.id)
            errors, warnings, _ = ops.reservation_change(settings, conn, to_subnet, moved,
                                                         r.id if to_subnet.id == r.subnet_id else None)
            item.update(moved=moved, errors=errors, warnings=warnings)
        reservations.append(item)

    assignment = conn.execute('SELECT * FROM ipam_assignments WHERE ip = ?', (str(old),)).fetchone()
    note = conn.execute('SELECT note FROM ipam_notes WHERE ip = ?', (str(old),)).fetchone()
    ipam = {'assignment': dict(assignment) if assignment else None, 'note': note['note'] if note else None,
            'blocked': None}
    if assignment and conn.execute('SELECT 1 FROM ipam_assignments WHERE ip = ?', (str(new),)).fetchone():
        ipam['blocked'] = f'{new} already has an IPAM record or assignment'
    elif note and conn.execute('SELECT 1 FROM ipam_notes WHERE ip = ?', (str(new),)).fetchone():
        ipam['blocked'] = f'{new} already has an IPAM comment'

    in_use = []
    for h in a_new['names']:
        in_use.append(f"{h['rec'].fqdn} has it (in {h['zone']})")
    for r in a_new['reservations']:
        if r.ip_address == str(new):
            in_use.append(f'it is reserved for {r.hw_address}' + (f' ({r.hostname})' if r.hostname else ''))
    if a_new['lease'] and a_new['lease']['state'] == 'active':
        in_use.append(f"{a_new['lease']['mac']} holds a lease on it")
    if a_new.get('ipam'):
        in_use.append(f"IPAM names it {a_new['ipam']['name']}")
    if a_new.get('seen'):
        in_use.append(f"the nodes saw {a_new['seen'][0]['mac']} on it")
    if a_new['subnet'] and a_new['in_pool']:
        in_use.append(f"it is in a DHCP pool of {a_new['subnet'].prefix}: DHCP can lease it to another client")

    zones = sorted({f['zone'] for f in forward} | {m['zone'] for m in ptr_moves}
                   | ({old_rzone} if old_rzone and forward else set())
                   | ({new_rzone} if new_rzone and (forward or ptr_moves) else set()))
    pending = [z for z in zones if z in edits and edits[z].is_draft]
    token = hashlib.sha256(repr((sorted(revs.items()), [(r['r'].id, r['r'].ip_address) for r in reservations],
                                 ipam['assignment'], ipam['note'])).encode()).hexdigest()[:16]
    return {'old': old, 'new': new, 'forward': forward, 'ptr_moves': ptr_moves, 'dynamic': dynamic,
            'old_rzone': old_rzone, 'new_rzone': new_rzone, 'held': held, 'reservations': reservations,
            'ipam': ipam, 'in_use': in_use, 'lease': a_old['lease'], 'pending': pending, 'zones': zones,
            'token': token,
            'nothing': not (forward or ptr_moves or reservations or ipam['assignment'] or ipam['note'])}


def ptr_lines(p):
    """What happens to the PTRs, in words, for the preview."""
    from .dns import ptr
    out = []
    held = p['held']
    for f in p['forward']:
        for rec in f['recs']:
            target = rec.name.to_text()
            if not ptr.is_host_name(rec.name):
                continue
            if p['old_rzone']:
                when = 'is removed when you publish' if held[p['old_rzone']]['dynamic'] else 'goes'
                out.append(f"the PTR for {p['old']} → {target} in {p['old_rzone']} {when}, if it's there")
            if p['new_rzone'] is None:
                out.append(f"no reverse zone for {p['new']} in LiteBlox, so no PTR is added")
            elif held[p['new_rzone']]['dynamic']:
                out.append(f"PTR {p['new']} → {target} in {p['new_rzone']} is sent when you publish")
            else:
                out.append(f"PTR {p['new']} → {target} is added in {p['new_rzone']}")
    for m in p['ptr_moves']:
        where = p['new_rzone']
        if m['remove_only']:
            out.append(f"PTR {p['old']} → {m['target']} in {m['zone']} goes: {p['new']}'s PTR names the moved record")
        elif where and not held[where]['dynamic']:
            out.append(f"PTR {p['old']} → {m['target']} in {m['zone']} moves to {p['new']}")
        else:
            out.append(f"PTR {p['old']} → {m['target']} in {m['zone']} goes ("
                       + ('no reverse zone for the new address' if not where else f'{where} is dynamic: add it there')
                       + ')')
    return out


def apply(conn, settings, old, new, token, reservation=True, ipam=True, username=None):
    """Make the move. Returns {zones (the static zones now with drafts), job (a DHCP job id or None), notes,
    warnings}. Raises Changed when the plan's token differs, MoveError when something can't be done (nothing is
    changed then)."""
    from .dhcp import ops
    from .dns import editing, ptr, records
    p = plan(conn, settings, old, new)
    if p['token'] != token:
        raise Changed('something changed since the preview')
    old, new = p['old'], p['new']
    move_reservations = [r for r in p['reservations'] if reservation]
    if any(r['errors'] for r in move_reservations):
        raise MoveError({'reservation': '; '.join(e for r in move_reservations for e in r['errors'].values())})
    if move_reservations and ops.busy(conn):
        raise MoveError({'reservation': 'another DHCP change is still running; try again when its job has finished'})
    if ipam and p['ipam']['blocked'] and (p['ipam']['assignment'] or p['ipam']['note']):
        raise MoveError({'ipam': p['ipam']['blocked']})

    notes, warnings, touched = [], [], set()
    with contextlib.ExitStack() as stack:
        for name in p['zones']:
            stack.enter_context(editing.zone_lock(name))
        staged = []
        for f in p['forward']:
            edit = editing.ZoneEdit(settings, conn, f['zone'])
            ops_ = [editing.Op(rec, rec.relative_name(edit.zone.origin), _ttl(rec), 'A', str(new), rec.comment)
                    for rec in _a_records(edit, old)]
            try:
                pairs, more = editing.stage_all(edit, ops_)
            except records.RecordError as e:
                for other, _ in staged:
                    editing.unstage(other)
                raise MoveError({f['zone']: '; '.join(e.errors.values())})
            staged.append((edit, pairs))
            warnings += more
        for edit, pairs in staged:
            n, w, _ = editing.commit(edit, pairs, True, username, ' (move)')
            notes += n
            warnings += w
            touched.add(edit.name)
        for m in p['ptr_moves']:
            redit = editing.ZoneEdit(settings, conn, m['zone'])
            changed, message = ptr.apply(redit.zone, 'remove', str(old), m['target'])
            if changed:
                redit.save(username)
                touched.add(m['zone'])
                notes.append(message)
            where = p['new_rzone']
            if where and not p['held'][where]['dynamic'] and not m['remove_only']:
                with editing.zone_lock(where):
                    nedit = editing.ZoneEdit(settings, conn, where)
                    changed, message = ptr.apply(nedit.zone, 'add', str(new), m['target'])
                    if changed:
                        nedit.save(username)
                        touched.add(where)
                    if message:
                        (notes if changed else warnings).append(message)
        drafts = [z for z in sorted(touched | set(p['zones'])) if not p['held'][z]['dynamic']
                  and editing.ZoneEdit(settings, conn, z).is_draft]
        if len(drafts) > 1:
            from .dns.drafts import Drafts
            Drafts(settings).link(*drafts)

    moved_ipam = []
    if ipam and (p['ipam']['assignment'] or p['ipam']['note']):
        with conn:
            if p['ipam']['assignment']:
                to_subnet = p['reservations'][0]['to_subnet'] if move_reservations else None
                conn.execute('UPDATE ipam_assignments SET ip = ?, subnet_id = COALESCE(?, subnet_id) WHERE ip = ?',
                             (str(new), to_subnet.id if to_subnet else None, str(old)))
                moved_ipam.append('IPAM record' if p['ipam']['assignment']['kind'] == 'ipam' else 'IPAM assignment')
            if p['ipam']['note']:
                conn.execute('UPDATE ipam_notes SET ip = ? WHERE ip = ?', (str(new), str(old)))
                moved_ipam.append('IPAM comment')

    job = None
    if move_reservations:
        moving = move_reservations
        same = [r for r in moving if r['moved'].id is not None]
        if len(moving) == 1 and same:
            job = ops.start_reservation(settings, conn, same[0]['moved'], same[0]['r'].id, username, ' (move)')
        else:
            job = ops.start_reservations(settings, conn, add=[r['moved'] for r in moving],
                                         delete=[r['r'] for r in moving if r['moved'].id is None],
                                         username=username, reason=f'move reservation {old} → {new}')

    what = [f"{sum(len(f['recs']) for f in p['forward'])} A in {', '.join(f['zone'] for f in p['forward'])}"
            if p['forward'] else '', f"{len(p['ptr_moves'])} PTR" if p['ptr_moves'] else '',
            'reservation' if move_reservations else '', *moved_ipam]
    audit(conn, username, 'address_move', f"{old} → {new}: " + (', '.join(w for w in what if w) or 'nothing'))
    return {'zones': drafts, 'job': job, 'notes': notes, 'warnings': warnings}
