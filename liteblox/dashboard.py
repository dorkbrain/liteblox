"""The Dashboard's figures, from the DB alone: tiles, services per node, pools, activity, setup steps.

The health check keeps the DB current every minute (status, drift, clocks, samples), so building
this costs a few queries and the page can refresh itself as often.
"""

import json
import time

from . import activity, modules, stats, status
from .backups import service as backups
from .nodes.service import needs_upgrade
from .timefmt import offset

SPARK_HOURS = 24


def _worst(found, area):
    return status.level([p for p in found if p['area'] == area])


def _sweepers(conn):
    """{node id: [prefixes]}: the node IPAM sweeps and checks each network from (the picked one, else the first on it)."""
    from .ipam import model, sweep
    found = {}
    for network in model.networks(conn):
        if not network.container:
            node = sweep.node_for(conn, network)
            if node is not None:
                found.setdefault(node['id'], []).append(network.prefix)
    return found


def _dhcp_pill(n, down, sockets, ha_state, role):
    """(label, colour, tooltip) for a DHCP node: its failover role (or 'serving' alone), coloured by its health."""
    label = role or 'serving'
    if down:
        return label, '', "unknown: the node doesn't answer"
    if sockets:
        state = 'not running' if sockets['status'] == 'down' else 'not listening'
        return label, 'warn' if sockets['status'] == 'retrying' else 'error', f"{state}: {'; '.join(sockets['errors'])}"
    if ha_state:
        if ha_state == 'hot-standby':           # a standby looks like a DNS secondary: plain, not green
            return label, '' if role == 'standby' else 'ready', ha_state
        return label, 'error' if ha_state == 'terminated' else 'warn', ha_state
    return label, 'ready', 'serving'


def _node_rows(conn, settings, nodes, now, on):
    pair = _pair(conn)
    sweepers = _sweepers(conn) if on.get('ipam') else {}
    zones = dict(conn.execute('SELECT node_id, COUNT(*) FROM zone_nodes GROUP BY node_id').fetchall())
    rows = []
    for n in nodes:
        last = backups.last_ok(conn, n['id'])
        # a node that doesn't answer shows nothing it last said, not old values that look current
        down = n['status'] == 'error'
        ntp = json.loads(n['ntp_state']) if n['ntp'] and n['ntp_state'] and not down else None
        figures = {m: None if down else stats.latest(conn, m, node_id=n['id'], now=now)
                   for m in ('load1', 'mem_used_pct', 'disk_used_pct', 'dns_qpm')}
        sockets = json.loads(n['dhcp_sockets']) if n['dhcp_sockets'] and not down else None
        ha_state = None if down else n['dhcp_ha_state']
        dhcp_role = (pair.role_of(n['id']) if pair.active else None) if n['dhcp'] else None
        rows.append({
            'node': n, 'zones': zones.get(n['id'], 0), 'ntp': ntp, 'down': down,
            'ha_state': ha_state, 'skew': None if down else n['clock_skew'], 'sockets': sockets, 'dhcp_role': dhcp_role,
            'dhcp': _dhcp_pill(n, down, sockets, ha_state, dhcp_role) if n['dhcp'] else None,
            'modules': [m for m, used in (('DNS', on.get('dns') and n['bind']), ('DHCP', on.get('dhcp') and n['dhcp']),
                                          ('NTP', on.get('ntp') and n['ntp'])) if used]
                       + (['IPAM'] if n['id'] in sweepers else []),
            'sweeps': sweepers.get(n['id'], []),
            'backup': last['created_at'] if last else None,
            'backup_stale': n['status'] != 'new' and backups.is_stale(conn, settings, n['id']),
            'upgrade': needs_upgrade(n), 'figures': figures,
            'qpm': stats.spark(stats.series(conn, 'dns_qpm', node_id=n['id'], hours=SPARK_HOURS, now=now),
                               hours=SPARK_HOURS, now=now)})
    return rows


def _pair(conn):
    from .dhcp.model import ha_pair
    return ha_pair(conn)


def _pools(conn, now):
    from .dhcp.leases import pool_size, serving
    from .dhcp.model import interfaces_of, subnets
    out = []
    served = {i for n in serving(conn) for i in interfaces_of(n)}
    for s in subnets(conn):
        active = stats.latest(conn, 'leases_active', subnet_id=s.id, now=now)
        in_pool = stats.latest(conn, 'leases_in_pool', subnet_id=s.id, now=now)
        outside = stats.latest(conn, 'leases_outside', subnet_id=s.id, now=now)
        size = pool_size(s)
        out.append({'subnet': s, 'size': size, 'active': active, 'in_pool': in_pool, 'served': s.interface in served,
                    'outside': None if outside is None else int(outside),
                    'pct': 100.0 * in_pool / size if size and in_pool is not None else None,
                    'reserved': len(s.reservations),
                    'spark': stats.spark(stats.series(conn, 'leases_active', subnet_id=s.id, hours=SPARK_HOURS,
                                                      now=now), hours=SPARK_HOURS, now=now)})
    return out


def _setup(conn, nodes, zones, on):
    """The first-run steps for the modules this install runs, each {what, done, link, optional}; None once the
    required ones are done. DNS leads when it's on; else DHCP, else Time; IPAM's first network comes last."""
    def step(what, done, link, optional=False):
        return {'what': what, 'done': bool(done), 'link': link, 'optional': optional}

    steps = []
    agent = step('Set up its agent', any(n['status'] != 'new' for n in nodes), '/nodes')
    if on['dns']:
        steps += [step('Add a BIND node', nodes, '/nodes/new'), agent,
                  step('Take it over', any(n['managed'] for n in nodes), '/nodes'),
                  step('Make one node the primary', any(n['role'] == 'primary' for n in nodes), '/nodes'),
                  step('Add or import zones', zones > 0, '/zones')]
        if on['dhcp']:
            steps.append(step('DHCP (optional)', any(n['dhcp'] for n in nodes), '/help/dhcp', True))
        if on['ntp']:
            steps.append(step('Time sync (optional)', any(n['ntp'] for n in nodes), '/settings/time', True))
    elif on['dhcp']:
        subnets = conn.execute('SELECT COUNT(*) FROM dhcp4_subnets').fetchone()[0]
        steps += [step('Add a node for DHCP', nodes, '/nodes/new'), agent,
                  step('Set up DHCP on it', any(n['dhcp'] for n in nodes), '/nodes'),
                  step('Add a subnet', subnets, '/dhcp')]
        if on['ntp']:
            steps.append(step('Time sync (optional)', any(n['ntp'] for n in nodes), '/settings/time', True))
    elif on['ntp']:
        steps += [step('Add a node', nodes, '/nodes/new'), agent,
                  step('Set up time sync on it', any(n['ntp'] for n in nodes), '/settings/time')]
    if on['ipam']:
        networks = conn.execute('SELECT COUNT(*) FROM ipam_networks').fetchone()[0]
        only = not (on['dns'] or on['dhcp'] or on['ntp'])
        steps.append(step('Add a network to IPAM' + ('' if only else ' (optional)'), networks, '/ipam', not only))
        if only:
            steps.append(step('Add a node on a network to scan from (optional)', nodes, '/nodes/new', True))
    if all(s['done'] for s in steps if not s['optional']):
        return None
    return steps


def _first_run(conn, nodes, zones):
    """Ask what to run until it's chosen, on an install that has nothing in it yet."""
    if modules.chosen(conn) or nodes or zones:
        return False
    return not conn.execute('SELECT 1 FROM ipam_networks UNION ALL SELECT 1 FROM dhcp4_subnets LIMIT 1').fetchone()


def _ipam_tile(conn, found, now):
    from .ipam import seen
    networks = conn.execute('SELECT COUNT(*) FROM ipam_networks').fetchone()[0]
    devices = conn.execute('SELECT COUNT(DISTINCT ip) FROM ipam_seen WHERE last_seen > ?',
                           (int(now) - 86400,)).fetchone()[0]
    flapping = len(seen.flapping(conn, int(now)))
    sub = f"{devices} address{'' if devices == 1 else 'es'} seen today"
    named = conn.execute("SELECT COUNT(*) FROM ipam_assignments WHERE kind = 'ipam'").fetchone()[0]
    if named:
        sub += f' · {named} named'
    if flapping:
        sub += f' · {flapping} flapping'
    return {'key': 'ipam', 'label': 'IPAM networks', 'link': '/ipam', 'level': _worst(found, 'ipam'),
            'value': str(networks), 'sub': sub}


def overview(conn, settings, now=None):
    """Everything the Dashboard shows, and GET /api/v1/status's tiles and problems."""
    now = now or time.time()
    on = modules.enabled(conn)
    found = status.problems(conn, settings)
    nodes = conn.execute('SELECT * FROM nodes ORDER BY name').fetchall()
    zone_count = conn.execute('SELECT COUNT(*) FROM zones').fetchone()[0]
    drafts = sum(1 for p in found if p['area'] == 'dns' and p['link'].endswith('/review'))
    attention = sum(1 for p in found if p['severity'] != 'info')
    primary = next((n['name'] for n in nodes if n['role'] == 'primary'), None)
    pools = _pools(conn, now) if on['dhcp'] and any(n['dhcp'] for n in nodes) else []
    pair = _pair(conn)

    tiles = [{'key': 'nodes', 'label': 'Nodes', 'link': '/nodes', 'level': _worst(found, 'node'),
              'value': f"{sum(1 for n in nodes if n['status'] == 'ready')} / {len(nodes)}",
              'sub': ('ready' if not on['dns'] else f'ready · {primary} primary' if primary else 'ready · no primary')}]
    if on['dns']:
        tiles.append({'key': 'dns', 'label': 'DNS zones', 'link': '/zones', 'level': _worst(found, 'dns'),
                      'value': str(zone_count),
                      'sub': f"{drafts} unpublished draft{'' if drafts == 1 else 's'}" if drafts else 'all published'})
    if on['dhcp'] and any(n['dhcp'] for n in nodes):
        known = [p for p in pools if p['active'] is not None]
        counted = [p for p in pools if p['in_pool'] is not None]
        sub = (f"{sum(p['in_pool'] for p in counted):.0f} of {sum(p['size'] for p in counted)} in the pools"
               if counted else 'no lease counts yet' if any(p['served'] for p in pools) else 'no subnet served yet')
        if pair.active:
            states = {n['dhcp_ha_state'] for n in nodes
                      if n['id'] in (pair.primary_id, pair.standby_id) and n['status'] != 'error'}
            sub += ' · pair ' + (', '.join(sorted(s or 'unknown' for s in states)))
        tiles.append({'key': 'dhcp', 'label': 'DHCP leases', 'link': '/dhcp/leases', 'level': _worst(found, 'dhcp'),
                      'value': f"{sum(p['active'] for p in known):.0f}" if known else '–', 'sub': sub})
    elif on['dhcp']:
        tiles.append({'key': 'dhcp', 'label': 'DHCP', 'link': '/dhcp', 'level': 'off', 'value': 'off',
                      'sub': 'not set up'})
    timed = [json.loads(n['ntp_state']) for n in nodes if n['ntp'] and n['ntp_state'] and n['status'] != 'error']
    if on['ntp'] and any(n['ntp'] for n in nodes):
        synced = sum(1 for s in timed if s.get('synced'))
        offsets = [abs(s['offset']) for s in timed if isinstance(s.get('offset'), (int, float))]
        ntp_nodes = sum(1 for n in nodes if n['ntp'])
        tiles.append({'key': 'time', 'label': 'Time', 'link': '/settings/time', 'level': _worst(found, 'time'),
                      'value': 'synced' if synced == ntp_nodes else f'{synced} / {ntp_nodes}',
                      'sub': f"{ntp_nodes} node{'' if ntp_nodes == 1 else 's'}"
                             + (f' · worst offset {offset(max(offsets), sign=False)}' if offsets else '')})
    elif on['ntp'] or nodes:        # with time sync off and no nodes there's no clock to compare
        skews = [abs(n['clock_skew']) for n in nodes
                 if isinstance(n['clock_skew'], (int, float)) and n['status'] != 'error']
        tiles.append({'key': 'time', 'label': 'Clocks', 'link': '/settings/time' if on['ntp'] else '/nodes',
                      'level': _worst(found, 'time'), 'value': f'{max(skews):.0f} s' if skews else '–',
                      'sub': 'largest gap to LiteBlox' + (' · time sync off' if on['ntp'] else '')})
    if on['ipam']:
        tiles.append(_ipam_tile(conn, found, now))
    tiles.append({'key': 'attention', 'label': 'Attention', 'link': '#attention', 'level': status.level(found),
                  'value': str(attention), 'sub': 'all good' if not attention else 'see below'})

    checked = max((n['last_seen_at'] for n in nodes if n['last_seen_at']), default=None)
    return {'tiles': tiles, 'problems': found, 'attention': attention, 'level': status.level(found),
            'nodes': _node_rows(conn, settings, nodes, now, on), 'pools': pools, 'pair': pair,
            'activity': activity.recent(conn), 'setup': _setup(conn, nodes, zone_count, on), 'checked': checked,
            'modules': on, 'first_run': _first_run(conn, nodes, zone_count)}

