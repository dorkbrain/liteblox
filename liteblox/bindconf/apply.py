"""Apply server-wide config changes (node settings, ACLs) one node at a time, with probes.

Before touching a node, LiteBlox notes which probes pass: each zone it serves
answers its SOA over DNS, and (when recursion stays on and LiteBlox may use
it) a recursive lookup works. After the commit it asks again. A probe that
passed before and fails now rolls the change back on that node and on every
node this job already changed, and puts the stored settings back. Secondaries
go first, the primary last, so a bad setting breaks a node nothing depends on.
"""

import difflib
import time

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from .. import db, jobs
from ..nodes import service as nodes
from ..nodes.client import AgentError
from .importconf import check_allow_lists
from .lockout import check as lockout_check
from .model import NodeOptions, for_node, global_acls, node_address
from .render import record_commit, render, set_sha256


class ApplyError(RuntimeError):
    pass


def recursive_ok(host, timeout=3.0):
    """Does the node resolve a name for LiteBlox (a recursive query for the root's NS)?"""
    try:
        r = dns.query.udp(dns.message.make_query('.', dns.rdatatype.NS), host, timeout=timeout)
    except (dns.exception.DNSException, OSError):
        return False
    return r.rcode() == dns.rcode.NOERROR and bool(r.answer)


def _served(host, zone):
    from ..dns.publish import served_serial
    return served_serial(host, zone) is not None


def _zones(conn, node_id):
    return [r['name'] for r in conn.execute(
        "SELECT z.name FROM zones z JOIN zone_nodes zn ON zn.zone_id = z.id "
        "WHERE zn.node_id = ? AND z.kind = 'primary' ORDER BY z.name", (node_id,))]


def probe(conn, node, recursion, dns_serving=None, dns_recursive=None):
    """{probe label: passed} for the node now."""
    dns_serving, dns_recursive = dns_serving or _served, dns_recursive or recursive_ok
    host = node_address(node) or node['host']
    results = {f'{z} answers': dns_serving(host, z) for z in _zones(conn, node['id'])}
    if recursion:
        results['recursion works'] = dns_recursive(host)
    return results


def _ordered(rows):
    """Secondaries and other nodes first, the primary last."""
    return sorted(rows, key=lambda n: (n['role'] == 'primary', n['name']))


def _client_address(settings, node):
    try:
        with nodes.agent_client(settings, node, timeout=10.0) as c:
            return c.status().get('client_address')
    except AgentError:
        return None


def _acl_map(acls):
    return {a.name: a.items for a in acls}


def preview(conn, settings, node, options=None, top_extra=None, acls=None):
    """What the change would write on one node: {diff, problems, findings, recursion_probe}."""
    old = render(for_node(conn, node))
    new = render(for_node(conn, node, options=options, top_extra=top_extra, acls=acls))
    diff = ''.join(''.join(difflib.unified_diff(old[r].splitlines(True), new[r].splitlines(True),
                                                f'{node["name"]} {r} now', f'{node["name"]} {r} after'))
                   for r in ('acls.conf', 'options.conf', 'top.conf', 'zones.conf'))
    problems = check_allow_lists(new)
    if not problems and diff:
        try:
            with nodes.agent_client(settings, node, timeout=30.0) as c:
                c.check_config(new)
        except AgentError as e:
            out = e.details.get('output')
            problems.append(f"{node['name']}'s named-checkconf: {e.message}" + (f'\n{out}' if out else ''))
    effective = options or NodeOptions.from_json(node['options'])
    findings, recursion = lockout_check(effective, node_address(node), _client_address(settings, node),
                                        _acl_map(acls if acls is not None else global_acls(conn)))
    return {'diff': diff, 'problems': problems, 'findings': findings, 'recursion_probe': recursion}


def apply_nodes(settings, conn, node_ids, change, undo, reason, username, log, recursion_probe=None,
                dns_serving=None, dns_recursive=None, settle=5):
    """Write `change` (a DB update) to each node in turn; all or nothing.

    change(conn) / undo(conn) update and restore the DB. recursion_probe: {node id: bool}
    whether LiteBlox may check recursion on that node afterwards (default: unless recursion is off).
    """
    from ..backups import service as backups
    rows = _ordered([nodes.get_node(conn, int(i)) for i in node_ids])
    waiting = [n['name'] for n in rows if not n['managed']]
    if waiting:
        raise ApplyError(f"{', '.join(waiting)} {'is' if len(waiting) == 1 else 'are'} not taken over yet")
    before = {n['id']: probe(conn, n, NodeOptions.from_json(n['options']).recursion is not False,
                             dns_serving, dns_recursive) for n in rows}
    change(conn)
    done = []

    def give_up(message):
        for n in reversed(done):
            try:
                with nodes.agent_client(settings, n, timeout=60.0) as c:
                    c.rollback_config()
                log(f"  ✓ {n['name']}: rolled back")
            except AgentError as e:
                log(f"  ✗ {n['name']}: rollback failed: {e.message}")
        undo(conn)
        with conn:
            for n in done:
                conn.execute('UPDATE nodes SET config_sha256 = ?, config_files = ? WHERE id = ?',
                             (n['config_sha256'], n['config_files'], n['id']))
        raise ApplyError(message)

    for n in rows:
        node = nodes.get_node(conn, n['id'])
        recursion = NodeOptions.from_json(node['options']).recursion is not False
        if recursion_probe is not None:
            recursion = recursion and recursion_probe.get(node['id'], True)
        log(f"{node['name']}:")
        try:
            backups.snapshot_before_change(conn, settings, node, reason, username)
        except backups.BackupError as e:
            give_up(f"{node['name']}: {e}")
        files = render(for_node(conn, node))
        try:
            with nodes.agent_client(settings, node, timeout=60.0) as c:
                c.commit_config(c.stage_config(files)['stage_id'])
        except AgentError as e:
            detail = e.details.get('output')
            log(f"  ✗ refused: {e.message}" + (f'\n{detail}' if detail else ''))
            give_up(f"{node['name']} refused the change: {e.message}; nothing was changed")
        done.append(n)
        log('  ✓ backed up, committed (rndc reconfig done)')
        failing = []
        for attempt in range(settle):
            after = probe(conn, node, recursion, dns_serving, dns_recursive)
            failing = [label for label, ok in after.items() if not ok and before[node['id']].get(label)]
            if not failing:
                break
            time.sleep(1)
        if failing:
            log(f"  ✗ after the change: {'; '.join(f'{label}: no' for label in failing)}")
            give_up(f"{node['name']} stopped working after the change ({', '.join(failing)}); "
                    'every node this change touched was rolled back')
        checked = [label for label, ok in before[node['id']].items() if ok]
        log(f"  ✓ still fine: {', '.join(checked)}" if checked else '  (nothing LiteBlox could check here)')
        record_commit(conn, node['id'], files)
    return [n['name'] for n in rows]


def stale(conn, node):
    """Would LiteBlox write something else to this node now than it last did (a new LiteBlox version that
    renders something new, like the statistics channel)? Not for a node with a pending role change."""
    if not node['managed'] or not node['config_sha256'] or node['pending']:
        return False
    return set_sha256(render(for_node(conn, node))) != node['config_sha256']


def rewrite(settings, node_id, username, reason, log):
    """Write a node's config again as LiteBlox renders it now (with the probes and rollback)."""
    conn = db.connect(settings.db_path)
    try:
        node = nodes.get_node(conn, int(node_id))
        apply_nodes(settings, conn, [node['id']], lambda c: None, lambda c: None, reason, username, log)
        db.audit(conn, username, 'node_rewrite', f"{node['name']}: {reason}")
        log(f"✓ {node['name']} has LiteBlox's current BIND config")
    finally:
        conn.close()


def start_rewrite(settings, node_id, username, reason, background=True):
    return jobs.start(settings.db_path, 'bind config',
                      lambda log: rewrite(settings, node_id, username, reason, log),
                      node_id=node_id, username=username, background=background)


def set_node_settings(settings, targets, options, top_extra, username, log, recursion_probe=None, **kw):
    """Give every node in `targets` the same options and top-level extras."""
    conn = db.connect(settings.db_path)
    try:
        old = {i: (nodes.get_node(conn, i)['options'], nodes.get_node(conn, i)['top_extra']) for i in targets}

        def change(c):
            with c:
                for i in targets:
                    c.execute('UPDATE nodes SET options = ?, top_extra = ? WHERE id = ?',
                              (options.to_json(), top_extra, i))

        def undo(c):
            with c:
                for i, (o, t) in old.items():
                    c.execute('UPDATE nodes SET options = ?, top_extra = ? WHERE id = ?', (o, t, i))
        names = apply_nodes(settings, conn, targets, change, undo, 'change server settings', username, log,
                            recursion_probe=recursion_probe, **kw)
        db.audit(conn, username, 'node_settings', ', '.join(names))
        log(f"✓ Server settings applied to {', '.join(names)}")
    finally:
        conn.close()


# ── the Server settings form ───────────────────────────────────────────────────

LIST_FIELDS = ('listen_on', 'listen_on_v6', 'allow_query', 'allow_recursion')
CHOICES = {'recursion': ('', 'yes', 'no'), 'forward': ('', 'first', 'only'),
           'dnssec_validation': ('', 'auto', 'yes', 'no')}


def form_values(options, top_extra):
    """The form's field texts for stored options (lists one item per line, '' = not set)."""
    o = options
    values = {f: '\n'.join(getattr(o, f) or []) for f in LIST_FIELDS + ('forwarders', 'validate_except')}
    values.update(recursion='' if o.recursion is None else ('yes' if o.recursion else 'no'),
                  forward=o.forward or '', dnssec_validation=o.dnssec_validation or '',
                  extra=o.extra, top_extra=top_extra or '')
    return values


def parse_settings(form):
    """(NodeOptions, top_extra) from the form. Raises ValueError naming the field."""
    import dns.name
    from ..dns.declare import parse_forwarders, parse_list
    o = NodeOptions()
    for field in LIST_FIELDS:
        try:
            setattr(o, field, parse_list(form.get(field, '')) or None)
        except ValueError as e:
            raise ValueError(f"{field.replace('_', '-')}: {e}")
    try:
        o.forwarders = parse_forwarders(form.get('forwarders', '')) or None
    except ValueError as e:
        raise ValueError(f'forwarders: {e}')
    names = []
    for line in (form.get('validate_except') or '').split():
        try:
            names.append(dns.name.from_text(line.rstrip('.') + '.').to_text(omit_final_dot=True).lower())
        except dns.exception.DNSException:
            raise ValueError(f'validate-except: {line!r} is not a domain name')
    o.validate_except = names or None
    for field, allowed in CHOICES.items():
        value = form.get(field, '')
        if value not in allowed:
            raise ValueError(f"{field.replace('_', '-')}: choose one of {', '.join(a or 'not set' for a in allowed)}")
        if field == 'recursion':
            o.recursion = None if value == '' else value == 'yes'
        else:
            setattr(o, field, value or None)
    o.extra = (form.get('extra') or '').strip()
    return o, (form.get('top_extra') or '').strip()


def differences(conn):
    """Taken-over nodes grouped by identical server settings; more than one group = they differ."""
    groups = {}
    for n in conn.execute('SELECT * FROM nodes WHERE managed = 1 ORDER BY name'):
        key = (NodeOptions.from_json(n['options']).to_json(), (n['top_extra'] or '').strip())
        groups.setdefault(key, []).append(n['name'])
    return list(groups.values())
