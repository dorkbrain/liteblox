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


def serving_leases(settings, conn, family=4):
    """([(node, lease), ...] from every serving node, [errors]). A pair holds the same leases on both
    servers: read the primary's, or the standby's when the primary doesn't answer."""
    from .model import ha_pair, has_dhcp6
    out, errors = [], []
    pair = ha_pair(conn)
    found = serving(conn)
    read = leases
    if family == 6:
        found, read = [n for n in found if has_dhcp6(n)], leases6
    if pair.active:
        for n in [n for i in (pair.primary_id, pair.standby_id) for n in found if n['id'] == i]:
            try:
                return [(n, lease) for lease in read(settings, n)], errors
            except LeaseError as e:
                errors.append(str(e))
        return out, errors
    for n in found:
        try:
            out += [(n, lease) for lease in read(settings, n)]
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


# ── DHCPv6 ─────────────────────────────────────────────────────────────────────

TYPES6 = {'IA_NA': 'address', 'IA_PD': 'prefix', 0: 'address', 2: 'prefix'}


def leases6(settings, node, subnet_id=None, now=None):
    """Every DHCPv6 lease on the node (or in one subnet): addresses by IP, then delegated prefixes."""
    now = now or time.time()
    out, start = [], 'start'
    try:
        with nodes.agent_client(settings, node, timeout=30.0) as c:
            while True:
                answer = c.dhcp_command('dhcp6', 'lease6-get-page', {'from': start, 'limit': PAGE})
                if answer.get('result') == 3:
                    break
                if answer.get('result') != 0:
                    raise LeaseError(f"{node['name']}: {answer.get('text')}")
                page = (answer.get('arguments') or {}).get('leases') or []
                out += [_lease6(row, now) for row in page]
                if len(page) < PAGE:
                    break
                start = page[-1]['ip-address']
    except AgentError as e:
        raise LeaseError(f"{node['name']}: {e.message}")
    if subnet_id is not None:
        out = [lease for lease in out if lease['subnet_id'] == subnet_id]
    return sorted(out, key=lease6_order)


def lease6_order(lease):
    return (lease['type'] == 'prefix', int(ipaddress.ip_address(lease['ip'])), lease.get('prefix_len') or 128)


def _lease6(row, now):
    expires = row.get('cltt', 0) + row.get('valid-lft', 0)
    kind = TYPES6.get(row.get('type', 'IA_NA'), 'address')
    length = row.get('prefix-len', 128)
    return {'ip': row['ip-address'], 'type': kind, 'prefix_len': length,
            'prefix': f"{row['ip-address']}/{length}" if kind == 'prefix' else '',
            'duid': row.get('duid', ''), 'iaid': row.get('iaid'), 'mac': row.get('hw-address', ''),
            'hostname': (row.get('hostname') or '').rstrip('.'), 'subnet_id': row.get('subnet-id'),
            'state': STATES.get(row.get('state', 0), str(row.get('state'))), 'expires': expires,
            'expires_in': int(expires - now), 'registered': bool(row.get('fqdn-fwd'))}


def pool_ranges6(subnet):
    from .validate6 import pool_range6
    network = ipaddress.ip_network(subnet.prefix)
    out = []
    for p in subnet.pools:
        try:
            out.append(pool_range6(p, network))
        except ValueError:
            pass
    return out


def pool_size6(subnet):
    return sum(int(last) - int(first) + 1 for first, last in pool_ranges6(subnet))


def pd_size(subnet):
    """How many prefixes the subnet's delegated-prefix pools hold."""
    return sum(2 ** (int(p['delegated_len']) - ipaddress.ip_network(p['prefix']).prefixlen) for p in subnet.pd_pools)


def pool_use6(conn, found):
    """{subnet id: {addresses, in_pool, prefixes, size}} for every DHCPv6 subnet, from serving_leases(..., 6): active
    address leases, the pool addresses taken (active or declined), and delegated prefixes."""
    from .model import subnets6
    out = {}
    for s in subnets6(conn):
        ranges = pool_ranges6(s)
        mine = [lease for _, lease in found if lease['subnet_id'] == s.id]
        taken = {ipaddress.ip_address(x['ip']) for x in mine if x['type'] == 'address' and x['state'] in TAKEN}
        out[s.id] = {'addresses': sum(1 for x in mine if x['type'] == 'address' and x['state'] == 'active'),
                     'in_pool': sum(1 for ip in taken if any(f <= ip <= l for f, l in ranges)),
                     'prefixes': sum(1 for x in mine if x['type'] == 'prefix' and x['state'] == 'active'),
                     'size': pool_size6(s)}
    return out


def counts6(found):
    """{subnet id: {addresses, prefixes}} of active DHCPv6 leases, from serving_leases(..., family=6)."""
    out = {}
    for _, lease in found:
        if lease['state'] == 'active':
            mine = out.setdefault(lease['subnet_id'], {'addresses': 0, 'prefixes': 0})
            mine['prefixes' if lease['type'] == 'prefix' else 'addresses'] += 1
    return out


def _matches(r, lease):
    """Is this lease the reserved client's (by DUID, or by the MAC Kea learned)?"""
    if r.duid:
        return (lease.get('duid') or '').lower() == r.duid
    return bool(lease.get('mac')) and lease['mac'].lower() == r.hw_address


def addresses6(subnet, found):
    """One row per address and delegated prefix in a DHCPv6 subnet, its lease and reservation merged, as
    addresses() does for DHCPv4: [{ip, kind, duid, mac, hostname, lease, reservation, state, label, pill,
    in_pool}]. kind: 'address' or 'prefix' (ip is then 'prefix/len')."""
    ranges = pool_ranges6(subnet)
    by_key = {}
    for lease in found:
        if lease['subnet_id'] != subnet.id:
            continue
        key = lease['prefix'] if lease['type'] == 'prefix' else lease['ip']
        held = by_key.get(key)
        if held is None or (lease['state'] == 'active' and held['state'] != 'active'):
            by_key[key] = lease
    reserved = {}
    for r in subnet.reservations:
        if r.ip_address:
            reserved[r.ip_address] = r
        if r.prefix:
            reserved[r.prefix] = r
    named, offline = {}, []
    for r in subnet.reservations:
        if not r.ip_address and not r.prefix:
            key = next((k for k, lease in by_key.items() if lease['state'] == 'active' and lease['type'] == 'address'
                        and _matches(r, lease)), None)
            if key and key not in reserved:
                named[key] = r
            else:
                offline.append(r)

    def order(key):
        net = ipaddress.ip_network(key, strict=False)
        return ('/' in key, int(net.network_address), net.prefixlen)
    rows = []
    for key in sorted(set(by_key) | set(reserved), key=order):
        lease, r = by_key.get(key), reserved.get(key) or named.get(key)
        kind = 'prefix' if '/' in key else 'address'
        active = lease is not None and lease['state'] == 'active'
        in_pool = kind == 'address' and any(first <= ipaddress.ip_address(key) <= last for first, last in ranges)
        if r is not None and not r.ip_address and not r.prefix:
            state = 'named'
        elif r is not None:
            state = 'offline' if not active else 'online' if _matches(r, lease) else 'taken'
        elif active:
            state = 'leased' if in_pool or kind == 'prefix' else 'outside'
        else:
            state = lease['state']
        label, pill = STATES_SHOWN.get(state, (state, ''))
        if kind == 'prefix' and state == 'leased':
            label = 'delegated'
        rows.append({'ip': key, 'kind': kind, 'duid': (r.duid if r else '') or (lease or {}).get('duid', ''),
                     'mac': (r.hw_address if r else '') or (lease or {}).get('mac', ''),
                     'hostname': (r.hostname if r and r.hostname else lease['hostname'] if lease else ''),
                     'lease': lease, 'reservation': r, 'state': state, 'label': label, 'pill': pill,
                     'in_pool': in_pool})
    for r in sorted(offline, key=lambda r: r.duid or r.hw_address):
        label, pill = STATES_SHOWN['named-offline']
        rows.append({'ip': '', 'kind': 'address', 'duid': r.duid, 'mac': r.hw_address, 'hostname': r.hostname,
                     'lease': None, 'reservation': r, 'state': 'named-offline', 'label': label, 'pill': pill,
                     'in_pool': False})
    return rows


def delete6(settings, node, ip, kind='address', update_ddns=True):
    """Delete a DHCPv6 lease (an address, or a delegated prefix by its 'prefix/len' or address)."""
    address = ip.split('/', 1)[0]
    with nodes.agent_client(settings, node, timeout=30.0) as c:
        try:
            answer = c.dhcp_command('dhcp6', 'lease6-del', {'ip-address': address,
                                                            'type': 'IA_PD' if kind == 'prefix' else 'IA_NA',
                                                            'update-ddns': update_ddns})
        except AgentError as e:
            raise LeaseError(f"{node['name']}: {e.message}")
    if answer.get('result') != 0:
        raise LeaseError(answer.get('text') or f'Kea did not delete the lease on {ip}')
    return answer
