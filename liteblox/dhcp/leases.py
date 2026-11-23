"""Leases, read live from the serving Kea node (its lease file is the truth; LiteBlox keeps no copy)."""

import ipaddress
import time

from ..nodes import service as nodes
from ..nodes.client import AgentError

PAGE = 500
STATES = {0: 'active', 1: 'declined', 2: 'expired-reclaimed', 3: 'released'}


class LeaseError(RuntimeError):
    pass


def leases(settings, node, subnet_id=None, now=None):
    """Every lease on the node (or in one subnet), oldest IP first, as dicts for the page."""
    now = now or time.time()
    try:
        return _leases(settings, node, subnet_id, now)
    except AgentError as e:
        raise LeaseError(f"{node['name']}: {e.message}")


def serving(conn):
    """The DHCP nodes that serve on at least one interface."""
    from .model import interfaces_of
    return [n for n in nodes.list_nodes(conn) if n['dhcp'] and interfaces_of(n)]


def serving_leases(settings, conn):
    """([(node, lease), ...] from every serving node, [errors]). A pair holds the same leases on both
    servers: read the primary's, or the standby's when the primary doesn't answer."""
    from .model import ha_pair
    out, errors = [], []
    pair = ha_pair(conn)
    found = serving(conn)
    if pair.active:
        for n in [n for i in (pair.primary_id, pair.standby_id) for n in found if n['id'] == i]:
            try:
                return [(n, lease) for lease in leases(settings, n)], errors
            except LeaseError as e:
                errors.append(str(e))
        return out, errors
    for n in found:
        try:
            out += [(n, lease) for lease in leases(settings, n)]
        except LeaseError as e:
            errors.append(str(e))
    return out, errors


def counts(settings, conn):
    """{subnet id: active leases}, [errors]."""
    found, errors = serving_leases(settings, conn)
    out = {}
    for _, lease in found:
        if lease['state'] == 'active':
            out[lease['subnet_id']] = out.get(lease['subnet_id'], 0) + 1
    return out, errors


def pool_ranges(subnet):
    """[(first, last) ip_address pairs] of a subnet's pools (a pool that doesn't parse is left out)."""
    from .validate import pool_range
    network = ipaddress.ip_network(subnet.prefix)
    out = []
    for p in subnet.pools:
        try:
            out.append(pool_range(p, network))
        except ValueError:
            pass
    return out


def pool_size(subnet):
    return sum(int(last) - int(first) + 1 for first, last in pool_ranges(subnet))


# lease states that keep an address from other clients: a declined one (a client found it already in
# use) is held back for a while, so it counts as taken in the pools
TAKEN = ('active', 'declined')


def pool_use(conn, found):
    """{subnet id: {active, in_pool, outside, size}} for every subnet LiteBlox has, from serving_leases()'s
    leases: active leases, the addresses inside the pools that are taken (active or declined), the active
    leases outside the pools (reservations there), and the pools' size."""
    from .model import subnets
    out = {}
    for s in subnets(conn):
        ranges = pool_ranges(s)
        mine = [lease for _, lease in found if lease['subnet_id'] == s.id]
        inside = lambda ip: any(first <= ip <= last for first, last in ranges)
        taken = {ipaddress.ip_address(lease['ip']) for lease in mine if lease['state'] in TAKEN}
        active = [ipaddress.ip_address(lease['ip']) for lease in mine if lease['state'] == 'active']
        out[s.id] = {'active': len(active), 'in_pool': sum(1 for ip in taken if inside(ip)),
                     'outside': sum(1 for ip in active if not inside(ip)), 'size': pool_size(s)}
    return out


def tally(rows):
    """[(count, label)] for an addresses() table's heading: active leases always, then the other lease
    states that occur (declined, expired-reclaimed, released), then reservations."""
    states = {}
    for row in rows:
        if row['lease']:
            states[row['lease']['state']] = states.get(row['lease']['state'], 0) + 1
    out = [(states.pop('active', 0), 'active')]
    out += [(states.pop(state), state) for state in ('declined', 'expired-reclaimed', 'released') if state in states]
    out += sorted(((n, state) for state, n in states.items()), key=lambda x: x[1])
    reserved = sum(1 for row in rows if row['reservation'])
    out.append((reserved, 'reservation' if reserved == 1 else 'reservations'))
    return out


# an address's state, from its lease and its reservation: (label, pill class)
STATES_SHOWN = {
    'leased': ('leased', 'ready'),
    'outside': ('leased outside the pools', 'ready'),
    'online': ('reserved, online', 'ready'),
    'offline': ('reserved, offline', ''),
    'taken': ('reserved, held by another client', 'warn'),
    'named': ('named, online', 'ready'),
    'named-offline': ('named, offline', ''),
    'declined': ('declined', 'warn'),
}


def addresses(subnet, found):
    """One row per address in a subnet, its lease and its reservation merged, by IP:
    [{ip, mac, hostname, lease, reservation, state, label, pill, in_pool}].

    found: this subnet's leases (dicts from leases()). A reservation with no active lease at its address is
    offline; one whose address another client holds (leased before the reservation) is taken. A lease that
    isn't active (expired, released, declined) shows its own state. A name-only reservation (no address) joins
    its MAC's active lease (named), or is listed last with no address (named-offline)."""
    ranges = pool_ranges(subnet)
    by_ip = {}
    for lease in found:
        if lease['subnet_id'] == subnet.id:
            # Kea can keep an expired lease and a new one for the same address: the active one wins
            held = by_ip.get(lease['ip'])
            if held is None or (lease['state'] == 'active' and held['state'] != 'active'):
                by_ip[lease['ip']] = lease
    reserved = {r.ip_address: r for r in subnet.reservations if r.ip_address}
    named, offline = {}, []
    active_by_mac = {lease['mac'].lower(): ip for ip, lease in by_ip.items() if lease['state'] == 'active'}
    for r in subnet.reservations:
        if not r.ip_address:
            ip = active_by_mac.get(r.hw_address.lower())
            if ip and ip not in reserved:
                named[ip] = r
            else:
                offline.append(r)
    rows = []
    for ip in sorted(set(by_ip) | set(reserved), key=ipaddress.ip_address):
        lease, r = by_ip.get(ip), reserved.get(ip) or named.get(ip)
        active = lease is not None and lease['state'] == 'active'
        addr = ipaddress.ip_address(ip)
        in_pool = any(first <= addr <= last for first, last in ranges)
        if r is not None and not r.ip_address:
            state = 'named'
        elif r is not None:
            if not active:
                state = 'offline'
            elif lease['mac'].lower() == r.hw_address.lower():
                state = 'online'
            else:
                state = 'taken'
        elif active:
            state = 'leased' if in_pool else 'outside'
        else:
            state = lease['state']
        label, pill = STATES_SHOWN.get(state, (state, ''))
        rows.append({'ip': ip, 'mac': r.hw_address if r else lease['mac'],
                     'hostname': (r.hostname if r and r.hostname else lease['hostname'] if lease else ''),
                     'lease': lease, 'reservation': r, 'state': state, 'label': label, 'pill': pill,
                     'in_pool': in_pool})
    for r in sorted(offline, key=lambda r: r.hw_address):
        label, pill = STATES_SHOWN['named-offline']
        rows.append({'ip': '', 'mac': r.hw_address, 'hostname': r.hostname, 'lease': None, 'reservation': r,
                     'state': 'named-offline', 'label': label, 'pill': pill, 'in_pool': False})
    return rows


def _leases(settings, node, subnet_id, now):
    out, start = [], 'start'
    with nodes.agent_client(settings, node, timeout=30.0) as c:
        while True:
            try:
                answer = c.dhcp_command('dhcp4', 'lease4-get-page', {'from': start, 'limit': PAGE})
            except AgentError as e:
                raise LeaseError(f"{node['name']}: {e.message}")
            if answer.get('result') == 3:          # no (more) leases
                break
            if answer.get('result') != 0:
                raise LeaseError(f"{node['name']}: {answer.get('text')}")
            page = (answer.get('arguments') or {}).get('leases') or []
            out += [_lease(row, now) for row in page]
            if len(page) < PAGE:
                break
            start = page[-1]['ip-address']
    if subnet_id is not None:
        out = [lease for lease in out if lease['subnet_id'] == subnet_id]
    return sorted(out, key=lambda lease: ipaddress.ip_address(lease['ip']))


def _lease(row, now):
    expires = row.get('cltt', 0) + row.get('valid-lft', 0)
    return {'ip': row['ip-address'], 'mac': row.get('hw-address', ''), 'hostname': (row.get('hostname') or '').rstrip('.'),
            'client_id': row.get('client-id', ''), 'subnet_id': row.get('subnet-id'),
            'state': STATES.get(row.get('state', 0), str(row.get('state'))), 'expires': expires,
            'expires_in': int(expires - now), 'registered': bool(row.get('fqdn-fwd'))}


def delete(settings, node, ip, update_ddns=True):
    """Delete a lease; Kea's D2 removes the DNS records it registered for it (update_ddns)."""
    with nodes.agent_client(settings, node, timeout=30.0) as c:
        try:
            answer = c.dhcp_command('dhcp4', 'lease4-del', {'ip-address': ip, 'update-ddns': update_ddns})
        except AgentError as e:
            raise LeaseError(f"{node['name']}: {e.message}")
    if answer.get('result') != 0:
        raise LeaseError(answer.get('text') or f'Kea did not delete the lease on {ip}')
    return answer


def dns_zone(conn, hostname):
    """The LiteBlox zone a registered name lives in (the longest match), or None."""
    name = hostname.rstrip('.').lower()
    best = None
    for (zone,) in conn.execute("SELECT name FROM zones WHERE kind = 'primary'"):
        if (name == zone or name.endswith('.' + zone)) and (best is None or len(zone) > len(best)):
            best = zone
    return best
