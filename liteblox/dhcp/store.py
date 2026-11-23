"""Saving DHCP settings, subnets and served interfaces, and putting them back when an apply fails."""

import json

from .model import Reservation, Subnet


def snapshot(conn):
    """Everything an apply may change, for undo()."""
    return {'settings': [dict(r) for r in conn.execute('SELECT * FROM dhcp4_settings')],
            'subnets': [dict(r) for r in conn.execute('SELECT * FROM dhcp4_subnets')],
            'reservations': [dict(r) for r in conn.execute('SELECT * FROM dhcp4_reservations')],
            'ha': [dict(r) for r in conn.execute('SELECT * FROM dhcp4_ha')],
            'tls': [(r['id'], r['kea_tls']) for r in conn.execute('SELECT id, kea_tls FROM nodes')],
            'interfaces': [(r['id'], r['dhcp_interfaces']) for r in conn.execute('SELECT id, dhcp_interfaces FROM nodes')]}


def restore(conn, snap):
    tables = {'dhcp4_settings': 'settings', 'dhcp4_subnets': 'subnets', 'dhcp4_reservations': 'reservations',
              'dhcp4_ha': 'ha'}
    with conn:
        conn.execute('DELETE FROM dhcp4_reservations')
        for table, key in tables.items():
            conn.execute(f'DELETE FROM {table}')
            for row in snap[key]:
                cols = list(row)
                conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                             [row[c] for c in cols])
        for node_id, value in snap['interfaces']:
            conn.execute('UPDATE nodes SET dhcp_interfaces = ? WHERE id = ?', (value, node_id))
        for node_id, value in snap['tls']:
            conn.execute('UPDATE nodes SET kea_tls = ? WHERE id = ?', (value, node_id))


def next_subnet_id(conn):
    """The subnet-id a new subnet gets (ids are never reused, so Kea never mixes an old subnet's leases in)."""
    row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'dhcp4_subnets'").fetchone()
    top = conn.execute('SELECT MAX(id) FROM dhcp4_subnets').fetchone()[0]
    return max(row[0] if row else 0, top or 0) + 1


def _subnet_values(s):
    return (s.prefix, s.interface, '\n'.join(s.pools), json.dumps(s.options, sort_keys=True),
            json.dumps(s.extra_options), json.dumps(s.extra, sort_keys=True), s.valid_lifetime, s.renew_timer,
            s.rebind_timer, s.comment, int(s.ddns), s.ddns_zone_id if s.ddns else None, s.ddns_suffix if s.ddns else '',
            s.ddns_reverse if s.ddns else '')


def save_subnet(conn, s):
    with conn:
        if conn.execute('SELECT 1 FROM dhcp4_subnets WHERE id = ?', (s.id,)).fetchone():
            conn.execute('UPDATE dhcp4_subnets SET prefix = ?, interface = ?, pools = ?, options = ?, extra_options = ?, '
                         'extra = ?, valid_lifetime = ?, renew_timer = ?, rebind_timer = ?, comment = ?, ddns = ?, '
                         'ddns_zone_id = ?, ddns_suffix = ?, ddns_reverse = ? WHERE id = ?', (*_subnet_values(s), s.id))
        else:
            conn.execute('INSERT INTO dhcp4_subnets (id, prefix, interface, pools, options, extra_options, extra, '
                         'valid_lifetime, renew_timer, rebind_timer, comment, ddns, ddns_zone_id, ddns_suffix, '
                         'ddns_reverse) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (s.id, *_subnet_values(s)))


def delete_subnet(conn, subnet_id):
    with conn:
        conn.execute('DELETE FROM dhcp4_subnets WHERE id = ?', (subnet_id,))


def save_settings(conn, s):
    with conn:
        conn.execute('UPDATE dhcp4_settings SET valid_lifetime = ?, renew_timer = ?, rebind_timer = ?, options = ?, '
                     'extra_options = ?, authoritative = ?, ddns_key_id = ?, ddns_mode = ?, ddns_server = ?, '
                     'ddns_port = ?, ddns_external_key = ? WHERE id = 1',
                     (s.valid_lifetime, s.renew_timer, s.rebind_timer, json.dumps(s.options, sort_keys=True),
                      json.dumps(s.extra_options), int(s.authoritative), s.ddns_key_id, s.ddns_mode, s.ddns_server,
                      s.ddns_port, json.dumps(s.ddns_external_key, sort_keys=True) if s.ddns_external_key else None))


def set_interfaces(conn, node_id, names):
    with conn:
        conn.execute('UPDATE nodes SET dhcp_interfaces = ? WHERE id = ?', (json.dumps(sorted(names)), node_id))


def get_subnet(conn, subnet_id):
    row = conn.execute('SELECT s.*, z.name AS ddns_zone FROM dhcp4_subnets s LEFT JOIN zones z ON z.id = s.ddns_zone_id '
                       'WHERE s.id = ?', (subnet_id,)).fetchone()
    if row is None:
        return None
    s = Subnet.from_row(row)
    from .model import ddns_mode
    s.ddns_mode = ddns_mode(conn)
    return s


def save_reservation(conn, r):
    with conn:
        values = (r.subnet_id, r.hw_address, r.ip_address, r.hostname, json.dumps(r.options, sort_keys=True), r.comment)
        if r.id and conn.execute('SELECT 1 FROM dhcp4_reservations WHERE id = ?', (r.id,)).fetchone():
            conn.execute('UPDATE dhcp4_reservations SET subnet_id = ?, hw_address = ?, ip_address = ?, hostname = ?, '
                         'options = ?, comment = ? WHERE id = ?', (*values, r.id))
        else:
            r.id = conn.execute('INSERT INTO dhcp4_reservations (subnet_id, hw_address, ip_address, hostname, options, '
                                'comment) VALUES (?, ?, ?, ?, ?, ?)', values).lastrowid


def delete_reservation(conn, reservation_id):
    with conn:
        conn.execute('DELETE FROM dhcp4_reservations WHERE id = ?', (reservation_id,))


def get_reservation(conn, reservation_id):
    row = conn.execute('SELECT * FROM dhcp4_reservations WHERE id = ?', (reservation_id,)).fetchone()
    return Reservation.from_row(row) if row else None


def ensure_tls(conn, pki, node_id, address):
    """The node's peer-link certificate from LiteBlox's CA, issued again when its address changed."""
    row = conn.execute('SELECT name, kea_tls FROM nodes WHERE id = ?', (node_id,)).fetchone()
    have = json.loads(row['kea_tls']) if row['kea_tls'] else None
    if have and have.get('address') == address:
        return
    key, cert = pki.issue_peer_cert(f"{row['name']}-dhcp", [address])
    with conn:
        conn.execute('UPDATE nodes SET kea_tls = ? WHERE id = ?', (json.dumps(
            {'address': address, 'cert': cert.decode(), 'key': key.decode(), 'ca': pki.ca_pem().decode()}), node_id))


def _differing(mapping):
    return {k: v for k, v in (mapping or {}).items() if k != v}


def rename_subnet_interfaces(conn, mapping):
    """Give every subnet the name `mapping` has for its interface (one pass, so a swap of two names works)."""
    for row in conn.execute('SELECT id, interface FROM dhcp4_subnets').fetchall():
        if row['interface'] in mapping:
            conn.execute('UPDATE dhcp4_subnets SET interface = ? WHERE id = ?', (mapping[row['interface']], row['id']))


def set_interface_map(conn, mapping):
    with conn:
        conn.execute('UPDATE dhcp4_ha SET interface_map = ? WHERE id = 1', (json.dumps(_differing(mapping), sort_keys=True),))


def leaving_pair(old, primary_id, standby_id):
    """The nodes of the current pair (`old`, model.HaPair) that the new one leaves out."""
    return [n for n in (old.primary_id, old.standby_id) if old.active and n not in (primary_id, standby_id)]


def set_pair(conn, pki, primary_id, standby_id, primary_address, standby_address, port, interface_map=None):
    """Pair the two nodes: the standby serves the primary's interfaces, under its own names (interface_map,
    {primary's name: standby's}); each gets its peer certificate. Subnets always carry the primary's names, so when
    the old standby becomes the primary they're renamed through the old map."""
    from .model import ha_pair
    ensure_tls(conn, pki, primary_id, primary_address)
    ensure_tls(conn, pki, standby_id, standby_address)
    old = ha_pair(conn)
    mapping = _differing(interface_map)
    served = json.loads(conn.execute('SELECT dhcp_interfaces FROM nodes WHERE id = ?', (primary_id,)).fetchone()[0]
                        or '[]')
    with conn:
        if old.active and primary_id == old.standby_id:
            rename_subnet_interfaces(conn, old.interface_map)
        for gone in leaving_pair(old, primary_id, standby_id):
            # out of the pair, it serves nothing (as after unpair): never a second server beside the new pair
            conn.execute("UPDATE nodes SET dhcp_interfaces = '[]' WHERE id = ?", (gone,))
        conn.execute('UPDATE dhcp4_ha SET primary_node_id = ?, standby_node_id = ?, primary_address = ?, '
                     'standby_address = ?, port = ?, interface_map = ? WHERE id = 1',
                     (primary_id, standby_id, primary_address, standby_address, port,
                      json.dumps(mapping, sort_keys=True)))
        conn.execute('UPDATE nodes SET dhcp_interfaces = ? WHERE id = ?',
                     (json.dumps(sorted(mapping.get(n, n) for n in served)), standby_id))


def unpair(conn, keep_id):
    """Back to one server: `keep_id` keeps serving (under its own interface names), its former partner serves
    nothing."""
    from .model import ha_pair
    pair = ha_pair(conn)
    other = pair.standby_id if keep_id == pair.primary_id else pair.primary_id
    served = json.loads(conn.execute('SELECT dhcp_interfaces FROM nodes WHERE id = ?', (pair.primary_id,)).fetchone()[0]
                        or '[]')
    with conn:
        if keep_id == pair.standby_id:
            rename_subnet_interfaces(conn, pair.interface_map)
            served = [pair.standby_name_for(n) for n in served]
        conn.execute("UPDATE dhcp4_ha SET primary_node_id = NULL, standby_node_id = NULL, interface_map = '{}' "
                     'WHERE id = 1')
        conn.execute('UPDATE nodes SET dhcp_interfaces = ? WHERE id = ?', (json.dumps(sorted(served)), keep_id))
        conn.execute("UPDATE nodes SET dhcp_interfaces = '[]' WHERE id = ?", (other,))
