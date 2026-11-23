"""DHCP operations the pages and the API share: live checks on the nodes, reservations as jobs, lease deletes."""

from dataclasses import replace

from ..nodes import service as nodes
from ..nodes.client import AgentError
from . import apply, leases, store, validate
from .model import ha_pair, interfaces_of, subnets


class Busy(RuntimeError):
    """Another DHCP change is still running."""


def node_status(settings, node):
    """(the agent's /status, None) or (None, why it didn't answer)."""
    try:
        with nodes.agent_client(settings, node, timeout=8.0) as c:
            return c.status(), None
    except AgentError as e:
        return None, e.message


def dhcp_interfaces(settings, conn):
    """Every live interface (with its addresses) of the nodes running Kea, each with 'node' (the node's name)
    and 'served' (ticked for DHCP there)."""
    out = []
    for n in apply.dhcp_nodes(conn):
        status, _ = node_status(settings, n)
        names = interfaces_of(n)
        out += [{**i, 'node': n['name'], 'served': i['name'] in names} for i in (status or {}).get('interfaces') or []]
    return out


def served_interfaces(settings, conn):
    """The live interfaces (with addresses) the serving nodes serve on."""
    return [i for i in dhcp_interfaces(settings, conn) if i['served']]


def served(conn, subnet):
    """Does any node serve the interface this subnet is on (so Kea answers for it)?"""
    return any(subnet.interface in interfaces_of(n) for n in apply.dhcp_nodes(conn))


def not_served_note(conn, subnet):
    """For a review whose change doesn't reach Kea because the subnet isn't served yet; None when it is."""
    if served(conn, subnet):
        return None
    pair = ha_pair(conn)
    where = f' on {pair.primary_name}' if pair.active else ''
    return (f"{subnet.prefix} isn't served yet, so Kea's config doesn't change: this is saved now, and Kea answers "
            f"for it once you tick {subnet.interface}{where} (Servers → Change interfaces).")


def lease_warnings(settings, conn, r):
    """Another client holding the reserved address right now."""
    out = []
    if not r.ip_address:
        return out
    for n in leases.serving(conn):
        try:
            with nodes.agent_client(settings, n, timeout=10.0) as c:
                answer = c.dhcp_command('dhcp4', 'lease4-get', {'ip-address': r.ip_address})
        except AgentError:
            continue
        lease = answer.get('arguments') or {}
        if answer.get('result') == 0 and lease.get('hw-address') and lease['hw-address'] != r.hw_address:
            out.append(f"{lease['hw-address']} ({lease.get('hostname') or 'no name'}) has a lease on {r.ip_address} "
                       'now: it keeps it until it expires or you delete it on the Leases page')
    return out


def reservation_change(settings, conn, subnet, r, reservation_id):
    """(errors, warnings, every subnet as it would be after the change) for reservation r in subnet."""
    errors, warnings = validate.check_reservation(r, subnet, dhcp_interfaces(settings, conn))
    if not errors:
        from ..ipam.checks import reservation_warnings
        warnings += lease_warnings(settings, conn, r) + reservation_warnings(conn, settings, r)
    changed = replace(subnet, reservations=[x for x in subnet.reservations if x.id != reservation_id] + [r])
    after = [changed if x.id == subnet.id else x for x in subnets(conn)]
    return errors, warnings, after


def busy(conn):
    return conn.execute("SELECT 1 FROM jobs WHERE kind = 'dhcp config' AND status = 'running'").fetchone() is not None


def _start(settings, conn, reason, username, change):
    if busy(conn):
        raise Busy('another DHCP change is still running; try again when its job has finished')
    snap = store.snapshot(conn)
    return apply.start(settings, [n['id'] for n in apply.dhcp_nodes(conn)], reason, username,
                       change=change, undo=lambda c: store.restore(c, snap))


def start_reservation(settings, conn, r, reservation_id, username, via=''):
    """Save the reservation and write it to every DHCP node (the standby first), as a job. Returns its id.
    via: added to the job's reason (and so its audit entry), e.g. the API token's name."""
    return _start(settings, conn, f"{'change' if reservation_id else 'add'} reservation {_what(r)} for "
                                  f'{r.hw_address}{via}', username, lambda c: store.save_reservation(c, r))


def _what(r):
    return r.ip_address or f'name {r.hostname}'


def start_reservation_delete(settings, conn, r, username, via=''):
    return _start(settings, conn, f'delete reservation {_what(r)} for {r.hw_address}{via}', username,
                  lambda c: store.delete_reservation(c, r.id))


def delete_lease(settings, conn, node, ip):
    """Delete a lease (its DNS names go too), and the partner's copy. Returns the partner's name, or None."""
    leases.delete(settings, node, ip)
    partner = ha_pair(conn).partner_of(node['id'])
    if not partner:
        return None
    partner = nodes.get_node(conn, partner)
    try:     # Kea's HA doesn't pass deletes made by command on to the partner
        leases.delete(settings, partner, ip, update_ddns=False)
    except leases.LeaseError:
        pass
    return partner['name']


def start_reservations(settings, conn, add=(), delete=(), username=None, reason=''):
    """Add and delete several reservations in one job (IPAM's assign and unassign of a block)."""
    def change(c):
        for r in delete:
            store.delete_reservation(c, r.id)
        for r in add:
            store.save_reservation(c, r)
    return _start(settings, conn, reason, username, change)
