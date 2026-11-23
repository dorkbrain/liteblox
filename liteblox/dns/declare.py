"""Zone declarations: which nodes serve which zones, and how.

Every change to that (new zone, add or remove a node, change a zone's
notify/transfer/query settings, delete a zone) goes through apply(): back up
each node first, stage the node's whole generated config (bindconf) plus any
new zone files on every node, and only then commit everywhere, the primary
first so a secondary's first transfer finds it ready. The agent checks the
whole config with named-checkconf and runs `rndc reconfig`, rolling back on
failure. LiteBlox only changes nodes it has taken over.
"""

import contextlib
import hashlib
import ipaddress
import re

import dns.exception
import dns.name

from .. import db
from ..backups import service as backups
from ..bindconf.model import DEBIAN, node_address
from ..nodes import service as nodes
from ..nodes.client import AgentError
from .publish import is_secondary, wait_for_serial, SECONDARY_ATTEMPTS

MANAGED_DIR = '/etc/bind/liteblox'
NOTIFY_CHOICES = ('no', 'explicit', 'yes', '')     # '': not written (BIND's default, yes)
_KEY_RE = re.compile(r'key\s+[A-Za-z0-9_.-]+')
_WORD_RE = re.compile(r'[A-Za-z0-9_.-]+')


class DeclareError(RuntimeError):
    pass


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def managed_file(zone_name):
    return f'{MANAGED_DIR}/db.{zone_name}'


def parse_list(text):
    """Address-match list items from user input (one per line or ';'-separated). Raises ValueError."""
    items = [i.strip() for i in re.split(r'[;\n]', text or '') if i.strip()]
    for item in items:
        bare = item.lstrip('!').strip()
        if bare in ('any', 'none') or _KEY_RE.fullmatch(bare):
            continue
        try:
            ipaddress.ip_network(bare, strict=False)
        except ValueError:
            if not _WORD_RE.fullmatch(bare):
                raise ValueError(f'{item!r} is not an address, network, "key NAME" or ACL name')
    return items


def parse_forwarders(text):
    """Forwarders from user input, one per line (or ';'-separated): an IP, optionally `port N`. Raises ValueError."""
    out = []
    for item in [i.strip() for i in re.split(r'[;\n]', text or '') if i.strip()]:
        words = item.split()
        try:
            addr = str(ipaddress.ip_address(words[0]))
        except ValueError:
            raise ValueError(f'{item!r}: a forwarder is an IP address, optionally followed by "port N"')
        if len(words) == 1:
            out.append(addr)
        elif len(words) == 3 and words[1] == 'port' and words[2].isdigit() and 0 < int(words[2]) < 65536:
            out.append(f'{addr} port {int(words[2])}')
        else:
            raise ValueError(f'{item!r}: a forwarder is an IP address, optionally followed by "port N"')
    return out


def is_forwarding(zone):
    return zone['kind'] == 'forwarding'


def recursion_off(node):
    """The node is set not to recurse, so a forwarding zone on it answers nobody."""
    from ..bindconf.model import NodeOptions
    return NodeOptions.from_json(node['options']).recursion is False


def _set_validate_except(conn, node_ids, name, add):
    """Add (or drop) name in the nodes' validate-except. Returns {node id: old options} for _restore_options."""
    from ..bindconf.model import NodeOptions
    old = {}
    for node_id in node_ids:
        row = nodes.get_node(conn, node_id)
        options = NodeOptions.from_json(row['options'])
        items = list(options.validate_except or [])
        if add == (name in items):
            continue
        old[node_id] = row['options']
        items = items + [name] if add else [i for i in items if i != name]
        options.validate_except = items or None
        with conn:
            conn.execute('UPDATE nodes SET options = ? WHERE id = ?', (options.to_json(), node_id))
    return old


def _restore_options(conn, old):
    with conn:
        for node_id, options in old.items():
            conn.execute('UPDATE nodes SET options = ? WHERE id = ?', (options, node_id))


def _probe_forwarding(log, node, name):
    """Ask the node for the zone's SOA with recursion, to show whether the domain answers (never fails the job)."""
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    host = node_address(node) or node['host']
    try:
        r = dns.query.udp(dns.message.make_query(name + '.', dns.rdatatype.SOA), host, timeout=5.0)
        log(f"  {node['name']}: a recursive query for {name} SOA answers {dns.rcode.to_text(r.rcode())}")
    except (dns.exception.DNSException, OSError) as e:
        log(f"  {node['name']}: a recursive query for {name} got no answer ({e.__class__.__name__}); "
            "check the forwarders and that the node allows recursion for you")


def managed_zones_for(conn, node_id):
    """Zones the node serves (LiteBlox declares all of them once the node is taken over)."""
    return [dict(r) for r in conn.execute(
        "SELECT z.*, zn.node_file FROM zones z JOIN zone_nodes zn ON zn.zone_id = z.id "
        "WHERE zn.node_id = ? ORDER BY z.name", (node_id,))]


def check_zone_name(name, forwarding=False):
    """A zone name; forwarding zones may be a single label (corp) or under .arpa."""
    name = (name or '').strip().lower().rstrip('.')
    try:
        parsed = dns.name.from_text(name + '.')
    except dns.exception.DNSException as e:
        raise DeclareError(f'bad zone name: {e}')
    if len(parsed.labels) < (2 if forwarding else 3):
        raise DeclareError('enter a domain such as corp.example' if forwarding
                           else 'use a full zone name such as example.lab')
    return name


def reverse_zone_name(network):
    """The reverse zone for a network: 192.168.1.0/24 → 1.168.192.in-addr.arpa, 2001:db8::/32 → 8.b.d.0.1.0.0.2.ip6.arpa."""
    text = (network or '').strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise DeclareError(f'{text!r} is not a network such as 192.168.1.0/24')
    if '/' not in text:
        raise DeclareError(f'add the prefix length, for example {net.network_address}/24')
    step = 8 if net.version == 4 else 4
    if net.prefixlen == 0 or net.prefixlen % step:
        if net.version == 4:
            hint = ('split it into /24 zones' if net.prefixlen < 24
                    else 'classless delegation is not supported; create the whole /24')
            raise DeclareError(f'reverse zones follow octet boundaries (/8, /16, /24): {hint}')
        raise DeclareError('IPv6 reverse zones need a prefix length that is a multiple of 4')
    labels = net.network_address.reverse_pointer.split('.')
    return '.'.join(labels[-(net.prefixlen // step + 2):])


def default_rname(name, nameservers):
    """hostmaster@ the zone itself, or for reverse zones the domain of the first nameserver."""
    if name.endswith(('.in-addr.arpa', '.ip6.arpa')) and nameservers:
        labels = nameservers[0][0].rstrip('.').split('.')
        if len(labels) > 2:
            return f"hostmaster.{'.'.join(labels[1:])}."
    return f'hostmaster.{name}.'


def starter_zone(name, nameservers, rname=None, ttl=3600, serial=None):
    """A minimal valid zone: SOA, NS records, and addresses for in-zone nameservers.

    nameservers: [(hostname, ip or None)]; in-zone hostnames need an ip.
    """
    from datetime import date
    origin = dns.name.from_text(name + '.')
    serial = serial or int(date.today().strftime('%Y%m%d')) * 100 + 1
    ns_lines, glue = [], []
    for host, ip in nameservers:
        target = dns.name.from_text(host if host.endswith('.') else host + '.')
        ns_lines.append(f'@\tIN\tNS\t{target}')
        if target.is_subdomain(origin):
            if not ip:
                raise DeclareError(f'{target} is inside {name}, so it needs an address')
            rtype = 'AAAA' if ':' in ip else 'A'
            ipaddress.ip_address(ip)
            glue.append(f"{target.relativize(origin)}\tIN\t{rtype}\t{ip}")
    if not ns_lines:
        raise DeclareError('add at least one nameserver')
    mname = dns.name.from_text(nameservers[0][0].rstrip('.') + '.')
    rname = rname or default_rname(name, nameservers)
    return '\n'.join([
        f'$TTL {ttl}',
        f'@\tIN\tSOA\t{mname} {rname} (',
        f'\t\t{serial}\t; serial',
        '\t\t3600\t\t; refresh',
        '\t\t900\t\t; retry',
        '\t\t1209600\t\t; expire',
        '\t\t300 )\t\t; negative TTL',
        *ns_lines, *([''] + glue if glue else [])]) + '\n'


def _primary(conn):
    return conn.execute("SELECT * FROM nodes WHERE role = 'primary'").fetchone()


def _require_taken_over(node_rows):
    waiting = [n['name'] for n in node_rows if not n['managed']]
    if waiting:
        raise DeclareError(f"{', '.join(waiting)} {'is' if len(waiting) == 1 else 'are'} not taken over yet: "
                           "take over first (the node's page → Take over)")


def _ordered(node_rows):
    """The primary first, then nodes holding primary copies, then secondaries."""
    rank = {'primary': 0, None: 1, 'secondary': 2}
    return sorted(node_rows, key=lambda n: (rank.get(n['role'], 1), n['name']))


def _zones_for(conn, node, zone, serving):
    """The zones node declares once `zone` is served by the node ids in `serving`."""
    zones = [z for z in managed_zones_for(conn, node['id']) if z['name'] != zone['name']]
    if node['id'] in serving:
        changed = {k: v for k, v in dict(zone).items() if k != 'node_file'}
        zones.append(dict(changed, _nodes=list(serving)))
    return zones


def node_file_for(node, name):
    return f'{DEBIAN.sec_dir}/db.{name}' if is_secondary(node) else managed_file(name)


def apply(conn, settings, plan, reason, username, log):
    """Apply new zone declarations. plan: [(node row, zone rows it should declare, {zone: file text} to create)].

    Each node gets its whole generated config. Backs up every node, stages on all,
    commits on all in plan order (put the primary first). A stage failure aborts
    everywhere; a commit failure leaves that node on its old config and is reported.
    """
    from ..bindconf.model import for_node
    from ..bindconf.render import record_commit, render as render_config
    if not plan:
        return []
    _require_taken_over([node for node, _, _ in plan])
    targets = [(node, render_config(for_node(conn, node, zones)), files) for node, zones, files in plan]
    for node, _, _ in targets:
        log(f"  backing up {node['name']} before the change")
        backups.snapshot_before_change(conn, settings, node, reason, username)
    with contextlib.ExitStack() as stack:
        clients = {n['id']: stack.enter_context(nodes.agent_client(settings, n, timeout=60.0)) for n, _, _ in targets}
        staged = []
        for node, config, files in targets:
            try:
                sid = clients[node['id']].stage_config(config, files)['stage_id']
            except AgentError as e:
                for other, _, other_sid in staged:
                    with contextlib.suppress(AgentError):
                        clients[other['id']].abort_config(other_sid)
                detail = e.details.get('output')
                raise DeclareError(f"{node['name']} rejected the change: {e.message}" + (f'\n{detail}' if detail else ''))
            staged.append((node, config, sid))
            log(f"  ✓ {node['name']}: staged")
        done, failed = [], []
        for node, config, sid in staged:
            try:
                clients[node['id']].commit_config(sid)
            except AgentError as e:
                failed.append(node['name'])
                log(f"  ✗ {node['name']}: {e.message} (rolled back to its previous config)")
                continue
            done.append(node)
            record_commit(conn, node['id'], config)
            log(f"  ✓ {node['name']}: named-checkconf passed, rndc reconfig done")
    if failed:
        raise DeclareError(f"the change failed on {', '.join(failed)}; those nodes kept their previous config")
    return done


def _verify_served(log, node, zone_name, serial, verify):
    host = node_address(node) or node['host']
    seen = (verify(host, zone_name, serial, attempts=SECONDARY_ATTEMPTS) if is_secondary(node)
            else verify(host, zone_name, serial))
    if seen is None or seen < serial:
        raise DeclareError(f"{node['name']} answers with serial {seen} for {zone_name}, expected {serial}")
    log(f"  ✓ {node['name']}: serving {zone_name} at serial {seen}"
        + (' (transferred from the primary)' if is_secondary(node) else ''))


def _zone(conn, name):
    row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
    if row is None:
        raise DeclareError(f'no such zone {name}')
    return dict(row)


def _ready_nodes(conn, node_ids):
    rows = [nodes.get_node(conn, int(i)) for i in node_ids]
    for n in rows:
        if n['status'] != 'ready':
            raise DeclareError(f"{n['name']} is not ready (status {n['status']})")
    return rows


def _serving(conn, zone_id):
    return [nodes.get_node(conn, r['node_id']) for r in
            conn.execute('SELECT node_id FROM zone_nodes WHERE zone_id = ?', (zone_id,))]


def _serial(text, name):
    from .zonefile import Zone
    return Zone.parse(text, name + '.').serial


def stanza(conn, zone_row):
    """The zone's declaration as its primary (or first serving node) writes it, for display."""
    from ..bindconf.model import for_node
    from ..bindconf.render import zone_stanza
    serving = _serving(conn, zone_row['id'])
    node = next((n for n in _ordered(serving)), None)
    if node is None or not node['managed']:
        return None
    decl = next((z for z in for_node(conn, node).zones if z.name == zone_row['name']), None)
    return zone_stanza(decl) if decl else None


# ── operations (each runs as a job: fn(log)) ───────────────────────────────────

def create_zone(settings, name, node_ids, text, username, log, verify=wait_for_serial):
    """Create a zone: commit the starter file, declare it on the chosen nodes (and the primary)."""
    from .repo import Repo, zone_file
    from .validate import ToolMissing, named_checkzone
    conn = db.connect(settings.db_path)
    try:
        if conn.execute('SELECT 1 FROM zones WHERE name = ?', (name,)).fetchone():
            raise DeclareError(f'{name} is already in LiteBlox')
        targets = _ready_nodes(conn, node_ids)
        if not targets:
            raise DeclareError('choose at least one node')
        primary = _primary(conn)
        if primary and primary['id'] not in [n['id'] for n in targets]:
            targets.insert(0, primary)
            log(f"  {primary['name']} is the primary, so it serves {name} too")
        _require_taken_over(targets)
        from .canonical import sorted_text
        text = sorted_text(text, name + '.')        # zones LiteBlox creates are kept sorted
        try:
            ok, out = named_checkzone(name, text)
            if not ok:
                raise DeclareError(f'named-checkzone rejected the new zone:\n{out}')
        except ToolMissing:
            log('  named-checkzone is not installed here; relying on each node\'s check')
        targets = _ordered(targets)
        log(f"Creating {name} on {', '.join(n['name'] for n in targets)}")
        new_zone = {'name': name, 'notify': 'no', 'also_notify': '', 'allow_transfer': '', 'allow_query': ''}
        ids = [n['id'] for n in targets]
        plan = [(n, _zones_for(conn, n, new_zone, ids), {} if is_secondary(n) else {name: text}) for n in targets]
        apply(conn, settings, plan, f'create zone {name}', username, log)

        Repo(settings.repo_dir).ensure().write(zone_file(name), text, f'Create {name}', username)
        with conn:
            zone_id = conn.execute("INSERT INTO zones (name, mode, repo_file, sorted) VALUES (?, 'managed', ?, 1)",
                                   (name, zone_file(name))).lastrowid
            for n in targets:
                conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?)',
                             (zone_id, n['id'], node_file_for(n, name), None if is_secondary(n) else sha(text)))
        db.audit(conn, username, 'zone_create', name)
        serial = _serial(text, name)
        for n in targets:
            _verify_served(log, n, name, serial, verify)
    finally:
        conn.close()


def add_node(settings, name, node_id, username, log, verify=wait_for_serial):
    """Serve a zone on one more node: a secondary transfers it, a primary copy gets the published file."""
    from .drafts import Drafts
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        (node,) = _ready_nodes(conn, [node_id])
        serving = _serving(conn, zone['id'])
        if node['id'] in [n['id'] for n in serving]:
            raise DeclareError(f"{node['name']} already serves {name}")
        _require_taken_over(serving + [node])
        ids = [n['id'] for n in serving] + [node['id']]
        if is_forwarding(zone):
            # it forwards like the others; their validate-except for it comes along
            from ..bindconf.model import NodeOptions
            if any(name in (NodeOptions.from_json(n['options']).validate_except or []) for n in serving):
                old = _set_validate_except(conn, [node['id']], name, True)
            else:
                old = {}
            log(f"Adding {node['name']} to {name}")
            try:
                apply(conn, settings, [(node, _zones_for(conn, node, zone, ids), {})], f'add {name}', username, log)
            except Exception:
                _restore_options(conn, old)
                raise
            with conn:
                conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (?, ?, '')",
                             (zone['id'], node['id']))
            db.audit(conn, username, 'zone_add_node', f"{name} on {node['name']}")
            _probe_forwarding(log, node, name)
            return
        primary = _primary(conn)
        if is_secondary(node) and not (primary and primary['id'] in [n['id'] for n in serving]):
            raise DeclareError(f"{node['name']} is a secondary, but the primary doesn't serve {name}")
        if zone['dynamic'] and not is_secondary(node):
            raise DeclareError(f'{name} is dynamic: only secondaries of its primary can serve it')
        text = Drafts(settings).published(zone)
        # the primary's also-notify lists its secondaries, so it changes too
        affected = _ordered([node] + ([primary] if primary and is_secondary(node) else []))
        log(f"Adding {node['name']} to {name}")
        apply(conn, settings, [(n, _zones_for(conn, n, zone, ids),
                                {name: text} if n['id'] == node['id'] and not is_secondary(n) else {})
                               for n in affected], f'add {name}', username, log)
        with conn:
            conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?)',
                         (zone['id'], node['id'], node_file_for(node, name), None if is_secondary(node) else sha(text)))
        db.audit(conn, username, 'zone_add_node', f"{name} on {node['name']}")
        _verify_served(log, node, name, _serial(text, name), verify)
    finally:
        conn.close()


def remove_node(settings, name, node_id, username, log, verify=wait_for_serial):
    """Stop serving a zone on a node (its file stays on disk). The primary can't stop serving a zone."""
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        node = nodes.get_node(conn, int(node_id))
        primary = _primary(conn)
        forwarding = is_forwarding(zone)
        if primary and primary['id'] == node['id'] and not forwarding:
            raise DeclareError(f"{node['name']} is the primary, which serves every zone; make another node the "
                               f"primary first, or delete {name}")
        serving = _serving(conn, zone['id'])
        _require_taken_over(serving)
        ids = [n['id'] for n in serving if n['id'] != node['id']]
        affected = _ordered([node] + ([primary] if primary and primary['id'] in ids and not forwarding else []))
        old = _set_validate_except(conn, [node['id']], name, False) if forwarding else {}
        log(f"Removing {name} from {node['name']}")
        try:
            apply(conn, settings, [(n, _zones_for(conn, n, zone, ids), {}) for n in affected],
                  f'remove {name}', username, log)
        except Exception:
            _restore_options(conn, old)
            raise
        with conn:
            conn.execute('DELETE FROM zone_nodes WHERE zone_id = ? AND node_id = ?', (zone['id'], node['id']))
        db.audit(conn, username, 'zone_remove_node', f"{name} from {node['name']}")
        if forwarding:
            log(f"  ✓ {node['name']} no longer forwards {name}")
            return
        seen = verify(node_address(node) or node['host'], name, 1, attempts=1)
        log(f"  {node['name']} {'no longer serves' if seen is None else 'still answers for'} {name}"
            + ('' if seen is None else f' (serial {seen}; it may be answering from another zone or view)'))
    finally:
        conn.close()


def _not_registering(conn, zone, doing):
    """Refuse to break a zone DHCP registers its clients in."""
    used = [r['prefix'] for r in conn.execute('SELECT prefix FROM dhcp4_subnets WHERE ddns = 1 AND ddns_zone_id = ?',
                                              (zone['id'],))]
    if used:
        raise DeclareError(f"DHCP subnet {', '.join(used)} registers its clients in {zone['name']}: turn that off "
                           f'(DHCP → the subnet → DNS registration) before {doing}')


def delete_zone(settings, name, username, log, verify=wait_for_serial):
    """Delete a zone from LiteBlox: it is first undeclared on every taken-over node serving it.

    The zone's files stay on the nodes, and its history stays in the repository.
    """
    from .drafts import Drafts
    from .repo import Repo
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        _not_registering(conn, zone, 'deleting it')
        served = _serving(conn, zone['id'])
        log(f'Deleting {name}')
        declaring = _ordered([n for n in served if n['managed']])
        forwarding = is_forwarding(zone)
        if declaring:
            # a forwarding zone takes its validate-except entry with it
            old = _set_validate_except(conn, [n['id'] for n in declaring], name, False) if forwarding else {}
            plan = [(n, [z for z in managed_zones_for(conn, n['id']) if z['name'] != name], {}) for n in declaring]
            try:
                apply(conn, settings, plan, f'delete zone {name}', username, log)
            except (DeclareError, backups.BackupError) as e:
                _restore_options(conn, old)
                raise DeclareError(f'{e}\nNothing was deleted. A node that is gone for good can be removed '
                                   'from LiteBlox first (its page → Remove node).') from e
        by_hand = [n for n in served if not n['managed']]
        if by_hand:
            log(f"  {', '.join(n['name'] for n in by_hand)} {'is' if len(by_hand) == 1 else 'are'} not taken over, "
                "so LiteBlox doesn't change them: they keep serving it until you remove it from their config")
        Drafts(settings).discard(name)
        if zone['repo_file']:
            Repo(settings.repo_dir).ensure().delete(zone['repo_file'], f'Delete {name}', username)
        with conn:
            conn.execute('DELETE FROM zones WHERE id = ?', (zone['id'],))
        db.audit(conn, username, 'zone_delete', name)
        log(f'  ✓ {name} deleted from LiteBlox' + ('' if forwarding else '; its history is kept'))
        for n in ([] if forwarding else declaring):
            seen = verify(node_address(n) or n['host'], name, 1, attempts=1)
            log(f"  {n['name']} {'no longer serves' if seen is None else 'still answers for'} {name}"
                + ('' if seen is None else f' (serial {seen}; it may be answering from another zone or view)'))
    finally:
        conn.close()


def update_settings(settings, name, notify, also_notify, allow_transfer, username, log, allow_query=None):
    """Change notify/also-notify/allow-transfer/allow-query for a zone on every node serving it.

    allow_query None keeps the current value.
    """
    if notify not in NOTIFY_CHOICES:
        raise DeclareError('notify must be no, explicit, yes or the BIND default')
    parse_list(also_notify)
    parse_list(allow_transfer)
    parse_list(allow_query)
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        if is_forwarding(zone):
            raise DeclareError(f'{name} is a forwarding zone: change its forwarders instead')
        allow_query = zone['allow_query'] if allow_query is None else allow_query
        new = dict(zone, notify=notify, also_notify=also_notify, allow_transfer=allow_transfer, allow_query=allow_query)
        targets = _ordered(_serving(conn, zone['id']))
        ids = [n['id'] for n in targets]
        log(f'Updating {name} settings on {len(targets)} node(s)')
        apply(conn, settings, [(n, _zones_for(conn, n, new, ids), {}) for n in targets],
              f'change {name} settings', username, log)
        with conn:
            conn.execute('UPDATE zones SET notify = ?, also_notify = ?, allow_transfer = ?, allow_query = ? WHERE id = ?',
                         (notify, also_notify, allow_transfer, allow_query, zone['id']))
        db.audit(conn, username, 'zone_settings', name)
    finally:
        conn.close()


def create_forwarding_zone(settings, name, node_ids, forwarders, mode, validate_except, username, log):
    """Create a forwarding-only zone: queries for it go to `forwarders` on the chosen nodes."""
    conn = db.connect(settings.db_path)
    try:
        if conn.execute('SELECT 1 FROM zones WHERE name = ?', (name,)).fetchone():
            raise DeclareError(f'{name} is already in LiteBlox')
        targets = _ready_nodes(conn, node_ids)
        if not targets:
            raise DeclareError('choose at least one node')
        _require_taken_over(targets)
        items = _forwarding_values(forwarders, mode)
        zone = {'name': name, 'kind': 'forwarding', 'forwarders': '\n'.join(items), 'forward_mode': mode,
                'notify': '', 'also_notify': '', 'allow_transfer': '', 'allow_query': ''}
        ids = [n['id'] for n in targets]
        log(f"Creating forwarding zone {name} on {', '.join(n['name'] for n in _ordered(targets))}: "
            f"forward {mode} to {', '.join(items)}")
        old = _set_validate_except(conn, ids, name, True) if validate_except else {}
        if old:
            log(f"  adding {name} to validate-except on {', '.join(nodes.get_node(conn, i)['name'] for i in old)}")
        try:
            apply(conn, settings, [(n, _zones_for(conn, n, zone, ids), {}) for n in _ordered(targets)],
                  f'create forwarding zone {name}', username, log)
        except Exception:
            _restore_options(conn, old)
            raise
        with conn:
            zone_id = conn.execute(
                "INSERT INTO zones (name, mode, repo_file, kind, forwarders, forward_mode) "
                "VALUES (?, 'managed', '', 'forwarding', ?, ?)", (name, zone['forwarders'], mode)).lastrowid
            for n in targets:
                conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (?, ?, '')", (zone_id, n['id']))
        db.audit(conn, username, 'zone_create', f'{name} (forwarding)')
        for n in targets:
            if recursion_off(n):
                log(f"  note: {n['name']} has recursion off, so it won't forward queries for anyone")
            _probe_forwarding(log, n, name)
    finally:
        conn.close()


def _forwarding_values(forwarders, mode):
    try:
        items = parse_forwarders(forwarders)
    except ValueError as e:
        raise DeclareError(str(e))
    if not items:
        raise DeclareError('add at least one forwarder')
    if mode not in ('only', 'first', ''):
        raise DeclareError('forward must be only or first')
    return items


def update_forwarding(settings, name, forwarders, mode, username, log):
    """Change a forwarding zone's forwarders and mode on every node serving it."""
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        if not is_forwarding(zone):
            raise DeclareError(f'{name} is not a forwarding zone')
        items = _forwarding_values(forwarders, mode)
        new = dict(zone, forwarders='\n'.join(items), forward_mode=mode)
        targets = _ordered(_serving(conn, zone['id']))
        ids = [n['id'] for n in targets]
        log(f"Updating {name}: forward {mode or '(BIND default: first)'} to {', '.join(items)}")
        apply(conn, settings, [(n, _zones_for(conn, n, new, ids), {}) for n in targets],
              f'change {name} forwarders', username, log)
        with conn:
            conn.execute('UPDATE zones SET forwarders = ?, forward_mode = ? WHERE id = ?',
                         (new['forwarders'], mode, zone['id']))
        db.audit(conn, username, 'zone_forwarders', name)
        for n in targets:
            _probe_forwarding(log, n, name)
    finally:
        conn.close()


def set_dynamic(settings, name, on, username, log, verify=None, transfer=None):
    """Switch a zone to dynamic updates (named owns the file from then on) or back to a static file.

    On: the published copy moves to the primary's dyn dir and update-policy lets LiteBlox's key (and
    any granted keys) update it. Off: what named serves now (AXFR) becomes the published copy.
    """
    from . import dynamic
    from .drafts import Drafts
    from .repo import Repo
    from ..nodes.roles import ensure_keys
    verify = verify or wait_for_serial
    conn = db.connect(settings.db_path)
    try:
        zone = _zone(conn, name)
        if is_forwarding(zone):
            raise DeclareError(f'{name} is a forwarding zone')
        if bool(zone['dynamic']) == on:
            raise DeclareError(f"{name} is {'already' if on else 'not'} dynamic")
        if not on:
            _not_registering(conn, zone, 'switching it off dynamic')
        serving = _serving(conn, zone['id'])
        _require_taken_over(serving)
        primary = _primary(conn)
        if primary is None or primary['id'] not in [n['id'] for n in serving]:
            raise DeclareError('dynamic updates go to the primary: pick a primary that serves this zone first '
                               '(Nodes → Make … the primary)')
        stray = [n['name'] for n in serving if n['id'] != primary['id'] and n['role'] != 'secondary']
        if stray:
            raise DeclareError(f"{', '.join(stray)} still hold their own copy: make {primary['name']} the primary "
                               'again so they become its secondaries')
        drafts = Drafts(settings)
        if on and drafts.load(zone)[1]:
            raise DeclareError(f'{name} has a draft: publish or discard it first')
        ensure_keys(conn)
        origin = name + '.'
        if on:
            text = drafts.published(zone)
            log(f"Switching {name} to dynamic updates: its file moves to {DEBIAN.dyn_dir} on {primary['name']}")
        else:
            text = dynamic.axfr(conn, zone, transfer)
            log(f"Switching {name} back to a static file: serial {dynamic.serial(text, origin)}, as named serves it now")
        new = dict(zone, dynamic=1 if on else 0)
        ids = [n['id'] for n in serving]
        plan = [(n, _zones_for(conn, n, new, ids), {name: text} if n['id'] == primary['id'] else {})
                for n in _ordered(serving)]
        apply(conn, settings, plan, f"{'dynamic updates on' if on else 'dynamic updates off'} for {name}",
              username, log)
        path = f'{DEBIAN.dyn_dir}/db.{name}' if on else managed_file(name)
        with conn:
            conn.execute('UPDATE zones SET dynamic = ? WHERE id = ?', (1 if on else 0, zone['id']))
            conn.execute('UPDATE zone_nodes SET node_file = ?, deployed_sha256 = ? WHERE zone_id = ? AND node_id = ?',
                         (path, None if on else sha(text), zone['id'], primary['id']))
        zone = _zone(conn, name)
        if on:
            now = dynamic.axfr(conn, zone, transfer)
            dynamic.snapshot(settings, zone, now, username, f'Dynamic from now on (serial {dynamic.serial(now, origin)})')
        else:
            Repo(settings.repo_dir).ensure().write(zone['repo_file'], text,
                                                   f'Static again (serial {dynamic.serial(text, origin)})', username)
        db.audit(conn, username, 'zone_dynamic', f"{name} {'on' if on else 'off'}")
        serial = dynamic.serial(text, origin)
        for n in _ordered(serving):
            _verify_served(log, n, name, serial, verify)
        log(f"✓ {name} is {'dynamic: edits in the grid, and updates with a granted key, apply at once' if on else 'a static file again'}")
    finally:
        conn.close()
