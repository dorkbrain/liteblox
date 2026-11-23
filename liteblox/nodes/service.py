"""Node records and the operations the UI and CLI share."""

import json
import re
from datetime import datetime, timezone

from .. import db, jobs
from ..pki import PKI
from ..version import __version__
from . import agent_sha256
from .bootstrap import bootstrap
from .client import AgentClient, AgentError

NAME_RE = re.compile(r'[a-z0-9][a-z0-9.-]{0,62}')


class NodeError(ValueError):
    pass


def list_nodes(conn):
    return conn.execute('SELECT * FROM nodes ORDER BY name').fetchall()


def get_node(conn, key):
    col = 'id' if isinstance(key, int) else 'name'
    row = conn.execute(f'SELECT * FROM nodes WHERE {col} = ?', (key,)).fetchone()
    if row is None:
        raise NodeError(f'no such node: {key}')
    return row


def is_scanner(node):
    """A node without BIND, Kea or chrony from LiteBlox: only the agent, which IPAM reads and sweeps through."""
    return not node['bind'] and not node['dhcp'] and not node['ntp']


def set_up(node):
    """Ready for DHCP or Time to be set up: a BIND node LiteBlox has taken over, or a node without BIND with its agent."""
    return bool(node['managed'] if node['bind'] else node['agent_version'])


def kind(node):
    """'DNS', 'DHCP + Time', 'scanner'…: what LiteBlox runs on the node (the Nodes list, its page)."""
    if is_scanner(node):
        return 'scanner'
    return ' + '.join(label for on, label in ((node['bind'], 'DNS'), (node['dhcp'], 'DHCP'), (node['ntp'], 'Time'))
                      if on)


def bind_change_blocked(conn, node):
    """Why a node's BIND choice can't change now (None when it can): LiteBlox runs its BIND config or zones."""
    if node['managed']:
        return f"LiteBlox manages {node['name']}'s BIND config"
    zones = conn.execute('SELECT COUNT(*) FROM zone_nodes WHERE node_id = ?', (node['id'],)).fetchone()[0]
    if zones:
        return f"{node['name']} serves {zones} zone{'' if zones == 1 else 's'} in LiteBlox"
    return None


def set_bind(conn, node_id, bind):
    """Whether the node runs BIND for LiteBlox (only while nothing in LiteBlox depends on it)."""
    node = get_node(conn, node_id)
    if bool(node['bind']) == bool(bind):
        return node
    why = bind_change_blocked(conn, node)
    if why:
        raise NodeError(f'{why}: it stays a BIND node')
    with conn:
        conn.execute('UPDATE nodes SET bind = ? WHERE id = ?', (int(bool(bind)), node['id']))
    return get_node(conn, node_id)


def add_node(conn, name, host, ssh_port, agent_port, host_key, host_key_fp, bind=True):
    name = name.strip().lower()
    if not NAME_RE.fullmatch(name):
        raise NodeError('name must be lowercase letters, digits, dots or dashes')
    if conn.execute('SELECT 1 FROM nodes WHERE name = ?', (name,)).fetchone():
        raise NodeError(f'node {name} already exists')
    with conn:
        return conn.execute(
            'INSERT INTO nodes (name, host, ssh_port, agent_port, host_key, host_key_fp, bind) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (name, host.strip(), ssh_port, agent_port, host_key, host_key_fp, int(bool(bind)))).lastrowid


def update_node(conn, node_id, host, ssh_port, agent_port, host_key, host_key_fp):
    """Change where a node is reached and pin the SSH host key read there.

    The agent's certificate names the old address and its config the old port, so
    either change drops the certificate until "Repair / upgrade agent" issues a new one.
    Returns the list of changes (empty when nothing changed).
    """
    node = get_node(conn, node_id)
    host = host.strip()
    if not host:
        raise NodeError('the address is empty')
    changes = [f'{label} {old} → {new}' for label, old, new in (
        ('address', node['host'], host), ('SSH port', node['ssh_port'], ssh_port),
        ('agent port', node['agent_port'], agent_port), ('host key', node['host_key_fp'], host_key_fp))
        if old != new]
    with conn:
        conn.execute('UPDATE nodes SET host = ?, ssh_port = ?, agent_port = ?, host_key = ?, host_key_fp = ? '
                     'WHERE id = ?', (host, ssh_port, agent_port, host_key, host_key_fp, node['id']))
        if host != node['host'] or agent_port != node['agent_port']:
            conn.execute('UPDATE nodes SET cert_fingerprint = NULL, cert_not_after = NULL WHERE id = ?',
                         (node['id'],))
    return changes


def set_dns_address(conn, node_id, address):
    """The IP the other nodes use for transfers and NOTIFY ('' = the node's address, when that's an IP)."""
    import ipaddress
    node = get_node(conn, node_id)
    address = (address or '').strip()
    if address:
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            raise NodeError(f'{address!r} is not an IP address')
    with conn:
        conn.execute('UPDATE nodes SET dns_address = ? WHERE id = ?', (address or None, node['id']))
    return node


def mask_secrets(conf_text):
    """Hide key secrets in config shown on a page: BIND's `secret "…";` (agents before 1.0.1 send it unmasked)
    and Kea's JSON `"secret": "…"` (the TSIG keys in kea-dhcp-ddns.conf)."""
    text = re.sub(r'(\bsecret\s+)"[^"]*"', r'\1"????????"', conf_text or '')
    return re.sub(r'("secret"\s*:\s*)"[^"]*"', r'\1"????????"', text)


def needs_repair(node):
    """Set up once, but the agent's certificate no longer matches the node's address or port."""
    return bool(node['agent_version']) and not node['cert_fingerprint']


def remove_node(conn, node_id):
    """Forget a node. Nothing on the node changes, and its backup files stay on disk."""
    node = get_node(conn, node_id)
    if conn.execute("SELECT 1 FROM jobs WHERE node_id = ? AND status = 'running'", (node['id'],)).fetchone():
        raise NodeError(f"a job is still running on {node['name']}; wait for it to finish")
    with conn:
        conn.execute('DELETE FROM nodes WHERE id = ?', (node['id'],))
    return node


def removal_impact(conn, node_id):
    """Zones served by the node, each with how many other nodes serve it."""
    return conn.execute(
        'SELECT z.name, z.mode, (SELECT COUNT(*) FROM zone_nodes o WHERE o.zone_id = z.id AND o.node_id != ?) '
        'AS others FROM zone_nodes zn JOIN zones z ON z.id = zn.zone_id WHERE zn.node_id = ? ORDER BY z.name',
        (node_id, node_id)).fetchall()


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def record_status(conn, node_id, status=None, error=None, extra=None):
    """Store the outcome of talking to a node's agent."""
    if error is not None:
        with conn:
            conn.execute("UPDATE nodes SET status = 'error', status_detail = ? WHERE id = ?",
                         (error, node_id))
        return
    fields = {
        'status': 'ready', 'status_detail': None, 'last_seen_at': _now(),
        'agent_version': status['agent_version'], 'agent_sha256': status['agent_sha256'],
        'install_rev': status.get('install_rev') or 0,
        'named_version': status['named_version'], 'networks': json.dumps(own_networks(status)),
        'addresses': json.dumps(own_addresses(status)), **(extra or {}),
    }
    kea, chrony = status.get('kea') or {}, status.get('time') or {}
    if kea.get('installed') and kea.get('version'):
        fields['kea_version'] = kea['version']      # which spelling its config needs (dhcp.model.KeaLayout)
    if chrony.get('installed') and chrony.get('version'):
        fields['chrony_version'] = chrony['version']    # which directives (ntp.render.leap_line)
    with conn:
        conn.execute(f"UPDATE nodes SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?",
                     (*fields.values(), node_id))
        # generated by a LiteBlox that lost its data (or another one): offered for Re-adopt
        conn.execute('UPDATE nodes SET other_liteblox = (? AND managed = 0) WHERE id = ?',
                     (int(other_liteblox(conn, node_id, status)), node_id))


def other_liteblox(conn, node_id, status):
    """Does the node run what another LiteBlox wrote? A BIND node: its BIND config is LiteBlox's (taken over).
    Without BIND: a Kea config a LiteBlox wrote, serving subnets this one doesn't have, or LiteBlox's chrony
    config on a node not set up for time here. (A fresh Kea config has no subnets, so it's never offered.)"""
    node = conn.execute('SELECT bind, dhcp, ntp FROM nodes WHERE id = ?', (node_id,)).fetchone()
    if node is None or node['bind']:
        return bool(status.get('taken_over'))
    kea = status.get('kea') or {}
    if kea.get('liteblox') and kea.get('subnets') and not conn.execute('SELECT 1 FROM dhcp4_subnets').fetchone():
        return True
    return bool((status.get('time') or {}).get('managed') and not node['ntp'])


def own_addresses(status):
    """The node's own IPv4 addresses, from its status: ['192.168.0.213', ...] (next free skips them)."""
    import ipaddress
    out = []
    for i in (status or {}).get('interfaces') or []:
        for cidr in i.get('addresses') or []:
            try:
                a = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            if a.version == 4 and not a.is_loopback and str(a.ip) not in out:
                out.append(str(a.ip))
    return out


def own_networks(status):
    """The IPv4 networks a node's interfaces are on, from its status: ['192.168.0.0/24', ...]."""
    import ipaddress
    out = []
    for i in (status or {}).get('interfaces') or []:
        for cidr in i.get('addresses') or []:
            try:
                net = ipaddress.ip_interface(cidr).network
            except ValueError:
                continue
            if net.version == 4 and not net.is_loopback and str(net) not in out:
                out.append(str(net))
    return out


def agent_client(settings, node, timeout=10.0):
    return AgentClient(node['host'], PKI(settings.pki_dir), port=node['agent_port'], timeout=timeout)


# clock skew: Kea's HA peers give up at about 60s apart, TSIG (transfers, updates, DDNS) fails at 300s
SKEW_WARN, SKEW_ERROR = 30, 120


def clock_fields(status, received):
    """nodes columns for the agent's clock: it reads its time last, right before answering, so the
    skew is measured against when the answer arrived (off by the transfer time, a few ms)."""
    clock = (status or {}).get('clock')
    if not clock or clock.get('time') is None:
        return {}
    synced = clock.get('synchronized')
    return {'clock_skew': round(clock['time'] - received, 1), 'clock_synced': None if synced is None else int(synced),
            'clock_checked_at': _now()}


def clock_state(node):
    """(level, message) for a node's clock: level None (fine), 'warn' or 'error'."""
    skew, synced = node['clock_skew'], node['clock_synced']
    if skew is not None and abs(skew) >= SKEW_ERROR:
        return 'error', (f"{node['name']}'s clock is {abs(skew):.0f}s {'ahead' if skew > 0 else 'behind'}: signed "
                         'transfers and updates (DDNS) fail at 300s. Fix its time sync (timedatectl).')
    if skew is not None and abs(skew) >= SKEW_WARN:
        return 'warn', (f"{node['name']}'s clock is {abs(skew):.0f}s {'ahead' if skew > 0 else 'behind'}; "
                        'DHCP failover pairs stop at 60s apart and signed updates at 300s.')
    if synced == 0:
        return 'warn', f"{node['name']}'s clock isn't synchronized by NTP (timedatectl): it will drift."
    return None, None


def refresh(conn, settings, node):
    """Ask the agent for its status and record it. Returns (status or None, error or None)."""
    import time
    try:
        with agent_client(settings, node) as c:
            status = c.status()
            received = time.time()
    except AgentError as e:
        record_status(conn, node['id'], error=e.message)
        return None, e.message
    record_status(conn, node['id'], status, extra=clock_fields(status, received))
    return status, None


def needs_upgrade(node):
    return bool(node['agent_sha256']) and node['agent_sha256'] != agent_sha256()


def can_upgrade(node):
    """Its agent can be upgraded over mTLS: it needs one, and Repair last put this image's install layout (the
    unit and the root installer) on it. Anything else needs Repair over SSH."""
    from .bootstrap import INSTALL_REV
    return (needs_upgrade(node) and not needs_repair(node) and node['status'] == 'ready'
            and (node['install_rev'] or 0) == INSTALL_REV)


UPGRADE_WAIT = 90           # seconds for the agent to restart on the new code (or roll back)


def _upgrade_one(conn, settings, node, source, digest, log, sleep=None, clock=None):
    """Stage the image's agent on one node and wait for it to run it. Raises NodeError when it doesn't."""
    import time
    sleep, clock = sleep or time.sleep, clock or time.time
    with agent_client(settings, node, timeout=30.0) as c:
        try:
            # what the installer said last, so its next word is told apart (the node's clock may differ)
            before = c.status().get('last_upgrade')
            c.upgrade_agent(__version__, digest, source.decode('utf-8'))
        except AgentError as e:
            raise NodeError(f"{node['name']}: the agent refused the upgrade: {e.message}")
    log(f"{node['name']}: agent {__version__} staged; the agent restarts and its installer puts it in place")
    deadline = clock() + UPGRADE_WAIT
    last = None
    while clock() < deadline:
        sleep(3)
        try:
            with agent_client(settings, node, timeout=10.0) as c:
                status = c.status()
        except AgentError as e:
            last = e.message
            continue
        outcome = status.get('last_upgrade') or {}
        fresh = bool(outcome) and outcome != before
        if status.get('agent_sha256') == digest:
            record_status(conn, node['id'], status)
            log(f"{node['name']}: ✓ running agent {status.get('agent_version')}")
            return status
        if fresh and outcome.get('result') in ('refused', 'rolled back', 'failed'):
            record_status(conn, node['id'], status)
            raise NodeError(f"{node['name']}: {outcome['result']}: {outcome.get('detail') or 'no reason given'}")
    raise NodeError(f"{node['name']}: the agent didn't come back on the new code within {UPGRADE_WAIT} s"
                    + (f' ({last})' if last else '') + ': check it on the node, or run Repair / upgrade agent')


def start_agent_upgrade(settings, node_ids, username, background=True, sleep=None, clock=None, via=''):
    """Upgrade the agents of node_ids over mTLS, one at a time, as a job. Returns the job id."""
    import ast
    import hashlib
    from . import agent_dir
    conn = db.connect(settings.db_path)
    try:
        for node_id in node_ids:
            if conn.execute("SELECT 1 FROM jobs WHERE node_id = ? AND status = 'running'", (node_id,)).fetchone():
                raise NodeError(f"a job is still running on {get_node(conn, node_id)['name']}; wait for it to finish")
    finally:
        conn.close()

    def run(log):
        source = (agent_dir() / 'liteblox_agent.py').read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        if digest != agent_sha256():
            raise NodeError("the image's agent changed while reading it")
        ast.parse(source.decode('utf-8'), feature_version=(3, 9))   # never send what a node can't run
        c = db.connect(settings.db_path)
        failed = []
        try:
            for node_id in node_ids:
                node = get_node(c, node_id)
                if not can_upgrade(node):
                    log(f"{node['name']}: skipped: " + ('already on this agent' if not needs_upgrade(node) else
                                                        'it needs Repair / upgrade agent over SSH'))
                    continue
                try:
                    _upgrade_one(c, settings, node, source, digest, log, sleep, clock)
                    db.audit(c, username, 'node_agent_upgrade', f"{node['name']} {__version__}{via}")
                except NodeError as e:
                    log(f'ERROR: {e}')
                    failed.append(node['name'])
        finally:
            c.close()
        if failed:
            raise NodeError(f"not upgraded: {', '.join(failed)}")
    return jobs.start(settings.db_path, 'agent upgrade', run, node_id=node_ids[0] if len(node_ids) == 1 else None,
                      username=username, background=background)


def start_bootstrap(settings, node_id, creds, options, username, background=True, echo=None):
    """Bootstrap as a job; returns the job id."""
    def run(log):
        from ..bindconf import takeover
        conn = db.connect(settings.db_path)
        try:
            if getattr(options, 'bind', None) is not None and bool(get_node(conn, node_id)['bind']) != options.bind:
                set_bind(conn, node_id, options.bind)
                log(f"{'Runs' if options.bind else 'No longer runs'} DNS (BIND) for LiteBlox from now on")
        except NodeError:
            conn.close()
            raise
        node = dict(get_node(conn, node_id))
        if getattr(options, 'ntp', False):
            from ..ntp.apply import files_for
            node['ntp_conf'] = files_for(conn, node)['chrony.conf']
            # once bootstrap knows the chrony it installed: the config for that version
            node['ntp_render'] = lambda version: files_for(conn, {**node, 'chrony_version': version})['chrony.conf']
        try:
            try:
                status = bootstrap(node, creds, options, PKI(settings.pki_dir), settings.backups_dir,
                                   __version__, log)
                record_status(conn, node_id, status, extra={
                    'cert_fingerprint': node['cert_fingerprint'], 'cert_not_after': node['cert_not_after'],
                    **node.get('dhcp_setup', {}), **node.get('ntp_setup', {})})
                db.audit(conn, username, 'node_bootstrap', node['name'])
            except Exception as e:
                record_status(conn, node_id, error=f'bootstrap failed: {e}')
                raise
            finally:
                if node.get('prebootstrap_backup'):
                    from ..backups.service import record_file
                    record_file(conn, settings, node_id, node['prebootstrap_backup'], 'pre-bootstrap',
                                'snapshot of /etc/bind taken over SSH before bootstrap', username)
            node = get_node(conn, node_id)
            if not node['bind']:
                if node['other_liteblox']:
                    log('A LiteBlox set up Kea or time sync on this node, but not this one (its data lost?): '
                        'Nodes → Re-adopt rebuilds LiteBlox\'s data from its nodes')
                elif is_scanner(node):
                    log('A scanner node: IPAM reads its neighbours every minute and sweeps the networks it is on')
            elif node['managed']:
                log('LiteBlox already manages the whole BIND config on this node')
            elif node['other_liteblox']:
                log('A LiteBlox generated the BIND config on this node, but not this one (its data lost?): '
                    'Nodes → Re-adopt rebuilds LiteBlox\'s data from its nodes')
            elif not options.takeover:
                log("Not taking over the BIND config: LiteBlox changes nothing on this node until you take it "
                    "over (its page → Take over)")
            else:
                try:
                    takeover.takeover(conn, settings, node, username, log, require_fresh=True)
                except takeover.NotFresh as e:
                    log(f'Not taking over: {e}')
        finally:
            conn.close()
    return jobs.start(settings.db_path, 'bootstrap', run, node_id=node_id, username=username,
                      background=background, echo=echo)
