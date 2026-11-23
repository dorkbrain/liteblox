"""Install liteblox-agent on a node over SSH.

Idempotent: re-running it repairs or upgrades an existing install. It never
stores the temporary credentials and never logs them. Every step is logged to
the job so the wizard can stream it.
"""

import json
import posixpath
import shlex
import time
from dataclasses import dataclass, replace
from datetime import datetime

from . import agent_dir, agent_module
from .client import AgentClient, AgentError
from .ssh import Remote, RemoteError
from .. import pki as pki_mod

AGENT_USER = 'liteblox-agent'
AGENT_LIB = '/usr/local/lib/liteblox-agent'
AGENT_STATE = '/var/lib/liteblox-agent'
# the install layout Repair puts on a node: the unit, the root installer and where they live. Bump it when any
# of those change: a node on another revision is upgraded by Repair over SSH, not over mTLS
INSTALL_REV = 1
AGENT_ETC = '/etc/liteblox-agent'
UNIT_PATH = '/etc/systemd/system/liteblox-agent.service'
BIND_DIR = '/etc/bind'
VAR_BIND = '/var/lib/bind'
BIND_PACKAGES = 'bind9 bind9-utils bind9-dnsutils'
KEA_PACKAGES = 'kea-dhcp4-server kea-dhcp-ddns-server'
APT = 'DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300'
APT_LOCK_WAIT = 300        # seconds to wait for another apt run (Debian's daily update, just after boot)
KEA_UNITS = 'kea-dhcp4-server kea-dhcp-ddns-server'
KEA_DIR = '/etc/kea'
KEA_GROUP = '_kea'
# Kea makes its control sockets 0750 _kea (CVE-2025-32803), so the agent can't connect to them: a
# systemd-socket-proxyd running as _kea serves each one on a socket only the agent's group may use
KEA_PROXIES = {'kea4': '/run/kea/kea4-ctrl-socket', 'kea-ddns': '/run/kea/kea-ddns-ctrl-socket'}
PROXY_SOCKET = """# Installed by LiteBlox: the agent's access to {target}
[Unit]
Description=LiteBlox agent access to {target}

[Socket]
ListenStream=/run/liteblox-kea/{name}-ctrl-socket
SocketUser=_kea
SocketGroup=liteblox-agent
SocketMode=0660
DirectoryMode=0755

[Install]
WantedBy=sockets.target
"""
PROXY_SERVICE = """# Installed by LiteBlox: the agent's access to {target}
[Unit]
Description=LiteBlox agent access to {target}
Requires=liteblox-{name}-ctrl.socket

[Service]
User=_kea
ExecStart=/usr/lib/systemd/systemd-socket-proxyd --exit-idle-time=60 {target}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
"""


# IPAM's probes and sweeps ping through an unprivileged ICMP socket, which needs the agent's group inside
# net.ipv4.ping_group_range: systemd's default covers every group (Debian), Ubuntu's "1 0" covers none
PING_SYSCTL = '/etc/sysctl.d/60-liteblox-agent-ping.conf'

CHRONY_DIR = '/etc/chrony'
CHRONY_CONF = '/etc/chrony/chrony.conf'
# the agent never runs sudo: when it replaces chrony.conf, systemd restarts chrony for it
CHRONY_PATH_UNIT = """# Installed by LiteBlox: restart chrony when LiteBlox writes its config
[Unit]
Description=Restart chrony when LiteBlox writes its config

[Path]
PathChanged=/etc/chrony/chrony.conf
Unit=liteblox-chrony.service

[Install]
WantedBy=multi-user.target
"""
CHRONY_RESTART_UNIT = """# Installed by LiteBlox: restart chrony when LiteBlox writes its config
[Unit]
Description=Restart chrony for LiteBlox

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart chrony.service
"""


class BootstrapError(RuntimeError):
    pass


@dataclass
class Options:
    bind: bool = None               # None: the node's own choice (nodes.bind); False: no BIND (a scanner, DHCP/Time only)
    install_bind: bool = False      # apt install BIND when it's missing
    fix_permissions: bool = True    # make /etc/bind and zone files group-writable for bind
    takeover: bool = True           # then let LiteBlox generate the whole BIND config (fresh nodes)
    dhcp: bool = False              # install Kea (DHCP) with a config that serves nothing yet
    ntp: bool = False               # install chrony (replacing systemd-timesyncd) with LiteBlox's time config


@dataclass
class Credentials:
    username: str
    password: str = None
    sudo_password: str = None
    use_local_keys: bool = False    # CLI only: ssh-agent / ~/.ssh keys of the user running LiteBlox

    def __repr__(self):     # keep secrets out of tracebacks and logs
        return f'Credentials(username={self.username!r})'


def q(value):
    return shlex.quote(str(value))


def primary_zones(checkconf_output):
    """Writable primary zones (default view, not built-in) from `named-checkconf -p`."""
    agent = agent_module()
    zones = agent.zones_from_conf(agent.parse_conf(checkconf_output))
    return [z for z in zones if z['type'] == 'primary' and z['file'] and not z['builtin'] and not z['view']]


def unit_text(zone_dirs, kea=False, ntp=False, bind=True):
    """The shipped unit with ReadWritePaths set to /etc/bind, /var/lib/bind and this node's other zone directories
    (and, on a node with Kea, group _kea and /etc/kea, where the agent writes Kea's config; with chrony, /etc/chrony).
    Without BIND: no BIND paths and no group bind (systemd refuses to start a unit naming a group that doesn't exist)."""
    text = (agent_dir() / 'liteblox-agent.service').read_text()
    base = [BIND_DIR, VAR_BIND] if bind else []
    paths = base + sorted(d for d in zone_dirs if not any(d == b or d.startswith(b + '/') for b in base))
    if kea:
        paths.append(KEA_DIR)
    if ntp:
        paths.append(CHRONY_DIR)
    groups = (['bind'] if bind else []) + ([KEA_GROUP] if kea else [])
    lines = []
    for line in text.splitlines():
        if line.startswith('ReadWritePaths='):
            if not paths:
                continue
            line = 'ReadWritePaths=' + ' '.join(paths)
        elif line.startswith('SupplementaryGroups='):
            if not groups:
                continue
            line = 'SupplementaryGroups=' + ' '.join(groups)
        elif line.startswith('# /etc/bind:') and not bind:
            continue
        elif line.startswith('After=') and not bind:
            line = 'After=network-online.target'
        lines.append(line)
    return '\n'.join(lines) + '\n'


def agent_config(node, version, bind=True):
    cfg = json.loads((agent_dir() / 'config.example.json').read_text())
    cfg.update(port=node['agent_port'], version=version, install_rev=INSTALL_REV)
    if not bind:
        cfg['bind'] = False
    return json.dumps(cfg, indent=2) + '\n'


def bootstrap(node, creds, options, pki, backups_dir, version, log, connect=Remote):
    """Run the whole bootstrap; returns the agent's /status. `connect` is swappable for tests."""
    if options.bind is None:
        options = replace(options, bind=bool(node.get('bind', 1)))
    log(f"Connecting to {node['host']}:{node['ssh_port']} as {creds.username} "
        f"(host key {node['host_key_fp']})")
    with connect(node['host'], node['ssh_port'], node['host_key'], creds.username,
                 password=creds.password, sudo_password=creds.sudo_password,
                 use_local_keys=creds.use_local_keys) as r:
        _preflight(r, options, log)
        if options.bind:
            _backup_bind(r, node, backups_dir, log)
            zones = _discover(r, log)
        else:
            zones = []
            log('No BIND on this node: LiteBlox leaves DNS here alone')
        _agent_user(r, log, options.bind)
        _ping_group(r, log)
        if options.bind:
            _permissions(r, zones, options, log)
        kea = _kea(r, node, options, log)
        ntp = _ntp(r, node, options, log)
        _install(r, node, zones, pki, version, log, kea, ntp, options.bind)
    return _verify(node, pki, log)


def _preflight(r, options, log):
    log('Checking the node')
    _, os_release = r.run('. /etc/os-release && echo "$PRETTY_NAME"', label='os-release')
    log(f'  OS: {os_release}')
    code, _ = r.run('true', sudo=True, check=False)
    if code != 0:
        raise BootstrapError('sudo failed: the account needs sudo rights (check the sudo password)')
    log('  sudo: ok')

    code, out = r.run("python3 -c 'import sys; print(sys.version.split()[0]); "
                      "sys.exit(sys.version_info < (3, 9))'", check=False)
    if code == 0:
        log(f'  python3: {out}')
    else:
        log('  python3 >= 3.9 missing: installing python3-minimal')
        _apt(r, 'python3-minimal', log, update=False)

    if not options.bind:
        # what the agent itself needs: systemd for its unit, ip for interfaces, neighbours and DHCP's choices
        code, out = r.run('systemctl --version | head -1', check=False)
        if code != 0 or not out.startswith('systemd'):
            raise BootstrapError('systemd is missing: the agent runs as a systemd service')
        log(f'  {out}')
        code, _ = r.run('test -x /usr/sbin/ip || test -x /sbin/ip', check=False)
        if code != 0:
            log('  ip missing: installing iproute2')
            _apt(r, 'iproute2', log)
        return

    code, out = r.run('/usr/sbin/named -v', check=False)
    if code != 0:
        if not options.install_bind:
            raise BootstrapError('BIND is not installed (tick "Install BIND" to install it)')
        log(f'  BIND missing: installing {BIND_PACKAGES}')
        _apt(r, BIND_PACKAGES, log)
        _, out = r.run('/usr/sbin/named -v')
    log(f'  BIND: {out}')
    r.run('/usr/bin/named-checkconf', sudo=True, label='named-checkconf')
    log('  named-checkconf: ok')


def _apt(r, packages, log, update=True):
    """apt-get install, waiting while another apt run holds its lock. DPkg::Lock::Timeout covers dpkg's
    lock; apt-get update's lists lock has no such option, hence the retries."""
    cmd = (f'{APT} update -q && ' if update else '') + f'{APT} install -y {packages}'
    waited = 0
    while True:
        try:
            return r.run(cmd, sudo=True, label=f'apt-get install {packages.split()[0]}', timeout=APT_LOCK_WAIT + 600)
        except RemoteError as e:
            if 'Could not get lock' not in e.output or waited >= APT_LOCK_WAIT:
                raise
        if not waited:
            log("  another apt run holds its lock (Debian's daily update?): waiting for it")
        time.sleep(15)
        waited += 15


def _backup_bind(r, node, backups_dir, log):
    """Snapshot /etc/bind before changing anything (restore: tar zxf FILE -C /)."""
    _, data, _ = r.run_bytes('tar czf - -C / etc/bind', sudo=True, label='tar /etc/bind')
    folder = backups_dir / node['name']
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{node['name']}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-prebootstrap.tgz"
    path.touch(mode=0o600)
    path.write_bytes(data)
    node['prebootstrap_backup'] = path
    log(f'Saved /etc/bind snapshot to {path} ({len(data)} bytes)')


def _discover(r, log):
    _, printed = r.run('/usr/bin/named-checkconf -p', sudo=True, label='named-checkconf -p')
    zones = primary_zones(printed)
    log(f"Primary zones on the node: {', '.join(z['name'] for z in zones) or 'none'}")
    return zones


def _agent_user(r, log, bind=True):
    r.run(f'getent passwd {AGENT_USER} >/dev/null || useradd --system --user-group --no-create-home '
          f'--home-dir /var/lib/{AGENT_USER} --shell /usr/sbin/nologin {AGENT_USER}', sudo=True,
          label='useradd')
    if not bind:
        log(f'User {AGENT_USER} exists')
        return
    r.run(f'usermod -aG bind {AGENT_USER}', sudo=True, label='usermod')
    log(f'User {AGENT_USER} exists and is in group bind')


def ping_range(current, gid):
    """The ping_group_range that lets gid open ICMP sockets, or None when current already does. A real range is
    only widened to take gid in; an empty one ("1 0") becomes gid alone."""
    lo, hi = (int(x) for x in current.split())
    if lo <= gid <= hi:
        return None
    return f'{min(lo, gid)} {max(hi, gid)}' if lo <= hi else f'{gid} {gid}'


def _ping_group(r, log):
    """Let the agent ping without privileges (IPAM's probes and sweeps); without it they read ARP only."""
    try:
        _, current = r.run('cat /proc/sys/net/ipv4/ping_group_range', check=False)
        _, gid = r.run(f'id -g {AGENT_USER}', check=False)
        wanted = ping_range(current, int(gid))
    except ValueError:
        log("  couldn't read net.ipv4.ping_group_range: IPAM's probes may see ARP answers only")
        return
    if wanted is None:
        return
    r.run(f"printf '%s\\n' '# Installed by LiteBlox: lets liteblox-agent ping (IPAM)' "
          f"'net.ipv4.ping_group_range = {wanted}' > {PING_SYSCTL} && "
          f"sysctl -q -w net.ipv4.ping_group_range='{wanted}'", sudo=True, label='ping_group_range')
    log(f"  net.ipv4.ping_group_range was {' '.join(current.split())}: now {wanted} so the agent can ping "
        f'({PING_SYSCTL})')


def _permissions(r, zones, options, log):
    files = [z['file'] for z in zones]
    dirs = sorted({BIND_DIR} | {posixpath.dirname(f) for f in files})
    if not options.fix_permissions:
        log('Leaving permissions as they are (the agent may not be able to write zone files)')
        return
    for d in dirs:
        r.run(f'chgrp bind {q(d)} && chmod g+ws {q(d)}', sudo=True, label=f'chmod {d}')
        log(f'  {d}: group bind, group-writable (setgid kept)')
    for f in files:
        r.run(f'chgrp bind {q(f)} && chmod g+rw {q(f)}', sudo=True, label=f'chmod {f}')
        log(f'  {f}: group bind, group-writable')


def _kea_present(r):
    """Has LiteBlox set Kea up on this node (so a repair keeps the agent's access to it)?"""
    code, _ = r.run('test -f /etc/systemd/system/liteblox-kea4-ctrl.socket', check=False)
    return code == 0


def _kea(r, node, options, log):
    """Set up Kea when asked: installed masked (Debian's sample config never runs), LiteBlox's config with no
    interfaces, the socket proxies. Returns whether the node has LiteBlox's Kea (then or from before)."""
    present = _kea_present(r)
    if not options.dhcp:
        return present
    from ..dhcp import model as kea_model
    from ..dhcp.render import file_hashes, render
    log('Setting up Kea (DHCP)')
    code, _ = r.run('test -x /usr/sbin/kea-dhcp4 && test -x /usr/sbin/kea-dhcp-ddns', check=False)
    if code != 0:
        # masked first: the packages would start Kea with their sample config on install
        r.run(f'systemctl mask {KEA_UNITS} kea-ctrl-agent', sudo=True, label='systemctl mask kea')
        log(f'  installing {KEA_PACKAGES} (masked until LiteBlox has written its config)')
        _apt(r, KEA_PACKAGES, log)
    _, version = r.run('/usr/sbin/kea-dhcp4 -v', check=False)
    log(f'  Kea: {version}')
    _, hooks = r.run('ls -d /usr/lib/*/kea/hooks 2>/dev/null | head -1', check=False)
    hooks = hooks.strip() or '/usr/lib/kea/hooks'
    # setgid: every file written there (the agent's, a rollback's) stays readable for Kea's group
    r.run(f'usermod -aG {KEA_GROUP} {AGENT_USER} && chgrp {KEA_GROUP} {KEA_DIR} && chmod 2770 {KEA_DIR}', sudo=True,
          label='kea permissions')
    log(f'  {AGENT_USER} is in group {KEA_GROUP}; {KEA_DIR} is group-writable (setgid {KEA_GROUP})')
    units = {}
    for name, target in KEA_PROXIES.items():
        units[f'liteblox-{name}-ctrl.socket'] = PROXY_SOCKET.format(name=name, target=target).encode()
        units[f'liteblox-{name}-ctrl.service'] = PROXY_SERVICE.format(name=name, target=target).encode()
    files = None
    # sudo: /etc/kea is 0770 _kea, so the SSH account itself can't read it; a config LiteBlox wrote is kept
    code, _ = r.run(f"grep -qs '\"generated-by\": \"LiteBlox\"' {KEA_DIR}/kea-dhcp4.conf", sudo=True, check=False)
    if code != 0:
        layout = kea_model.KeaLayout(hooks_dir=hooks)
        files = render(kea_model.for_node(None, node), layout)
        units.update({role: text.encode() for role, text in files.items()})
    tmp = r.upload(units)
    try:
        steps = [f'install -m 0644 -o root -g root {tmp}/{u} /etc/systemd/system/{u}' for u in units if u.startswith('liteblox-')]
        if files:
            stamp = datetime.now().strftime('%Y%m%dT%H%M%S')
            steps += [f'install -d -m 0750 -o root -g {KEA_GROUP} {KEA_DIR}/pre-liteblox/{stamp}',
                      f'for f in {" ".join(files)}; do [ -e {KEA_DIR}/$f ] && mv {KEA_DIR}/$f {KEA_DIR}/pre-liteblox/{stamp}/; done; true']
            steps += [f'install -m 0640 -o {AGENT_USER} -g {KEA_GROUP} {tmp}/{role} {KEA_DIR}/{role}' for role in files]
        # a config LiteBlox wrote before stays, but readable for Kea whatever left it otherwise
        steps.append(f'chgrp {KEA_GROUP} {KEA_DIR}/kea-dhcp4.conf {KEA_DIR}/kea-dhcp-ddns.conf && '
                     f'chmod 0640 {KEA_DIR}/kea-dhcp4.conf {KEA_DIR}/kea-dhcp-ddns.conf')
        r.run(' && '.join(steps), sudo=True, label='install kea config')
    finally:
        r.run(f'rm -rf {q(tmp)}', check=False)
    if files:
        log(f"  wrote LiteBlox's Kea config (no interfaces: it serves nothing yet); the package's own files are "
            f'in {KEA_DIR}/pre-liteblox/')
    for conf, daemon in (('kea-dhcp4.conf', 'kea-dhcp4'), ('kea-dhcp-ddns.conf', 'kea-dhcp-ddns')):
        r.run(f'runuser -u {KEA_GROUP} -- /usr/sbin/{daemon} -t {KEA_DIR}/{conf}', sudo=True, label=f'{daemon} -t')
    sockets = ' '.join(f'liteblox-{n}-ctrl.socket' for n in KEA_PROXIES)
    r.run(f'systemctl daemon-reload && systemctl enable --now {sockets} >/dev/null 2>&1 && '
          f'systemctl unmask {KEA_UNITS} >/dev/null 2>&1 && systemctl enable {KEA_UNITS} >/dev/null 2>&1 && '
          f'systemctl {"restart" if files else "start"} {KEA_UNITS}', sudo=True, label='systemctl kea')
    code, out = r.run(f'systemctl is-active {KEA_UNITS}', check=False)
    if code != 0:
        _, journal = r.run('journalctl -u kea-dhcp4-server -u kea-dhcp-ddns-server -n 20 --no-pager', sudo=True,
                           check=False)
        raise BootstrapError(f'Kea did not start ({out}):\n{journal}')
    log('  kea-dhcp4 and kea-dhcp-ddns are running')
    node['dhcp_setup'] = {'dhcp': 1, 'kea_hooks_dir': hooks, **(
        {'dhcp_files': json.dumps(file_hashes(files)), 'dhcp_drift': None} if files else {})}
    return True


def _ntp_present(r):
    """Has LiteBlox set chrony up on this node (so a repair keeps the agent's access to /etc/chrony)?"""
    code, _ = r.run('test -f /etc/systemd/system/liteblox-chrony.path', check=False)
    return code == 0


def _ntp(r, node, options, log):
    """Set chrony up when asked: installed (apt removes systemd-timesyncd), LiteBlox's config (node['ntp_conf'],
    rendered by the caller) with the package's own kept aside, and the path unit that restarts chrony when the
    agent replaces its config. Returns whether the node has LiteBlox's chrony (then or from before)."""
    present = _ntp_present(r)
    if not options.ntp:
        return present
    from ..ntp.render import file_hashes
    log('Setting up time sync (chrony)')
    code, _ = r.run('test -x /usr/sbin/chronyd', check=False)
    if code != 0:
        log('  installing chrony (it replaces systemd-timesyncd)')
        _apt(r, 'chrony', log)
    _, version = r.run('/usr/sbin/chronyd -v', check=False)
    log(f'  {version.strip()}')
    files = {'liteblox-chrony.path': CHRONY_PATH_UNIT.encode(), 'liteblox-chrony.service': CHRONY_RESTART_UNIT.encode()}
    code, _ = r.run(f"grep -qs '^# Generated by LiteBlox' {CHRONY_CONF}", check=False)
    write = code != 0
    if write:
        files['chrony.conf'] = node['ntp_conf'].encode()
    tmp = r.upload(files)
    try:
        steps = [f'install -m 0644 -o root -g root {tmp}/{u} /etc/systemd/system/{u}'
                 for u in ('liteblox-chrony.path', 'liteblox-chrony.service')]
        if write:
            stamp = datetime.now().strftime('%Y%m%dT%H%M%S')
            steps += [f'install -d -m 0755 {CHRONY_DIR}/pre-liteblox/{stamp}',
                      f'[ -e {CHRONY_CONF} ] && cp -p {CHRONY_CONF} {CHRONY_DIR}/pre-liteblox/{stamp}/ || true',
                      f'install -m 0664 -o root -g {AGENT_USER} {tmp}/chrony.conf {CHRONY_CONF}']
        # setgid: every file the agent writes there (candidates, a rollback's copy) stays the agent group's
        steps.append(f'chgrp {AGENT_USER} {CHRONY_DIR} {CHRONY_CONF} && chmod 2775 {CHRONY_DIR} && chmod 0664 {CHRONY_CONF}')
        r.run(' && '.join(steps), sudo=True, label='install chrony config')
    finally:
        r.run(f'rm -rf {q(tmp)}', check=False)
    if write:
        log(f"  wrote LiteBlox's chrony config; the package's own is in {CHRONY_DIR}/pre-liteblox/")
    r.run('systemctl daemon-reload && systemctl enable --now liteblox-chrony.path >/dev/null 2>&1 && '
          'systemctl enable chrony >/dev/null 2>&1 && systemctl restart chrony', sudo=True, label='systemctl chrony')
    code, out = r.run('systemctl is-active chrony', check=False)
    if code != 0:
        _, journal = r.run('journalctl -u chrony -n 20 --no-pager', sudo=True, check=False)
        raise BootstrapError(f'chrony did not start ({out}):\n{journal}')
    log('  chrony is running; LiteBlox writes its config from now on')
    node['ntp_setup'] = {'ntp': 1, **({'ntp_files': json.dumps(file_hashes({'chrony.conf': node['ntp_conf']})),
                                       'ntp_drift': None} if write else {})}
    return True


def _install(r, node, zones, pki, version, log, kea=False, ntp=False, bind=True):
    key_pem, cert_pem = pki.issue_server_cert(node['name'], [node['host']])
    log(f"Issued agent certificate for {node['host']} (SHA-256 {pki_mod.fingerprint(cert_pem)[:23]}…)")
    zone_dirs = {posixpath.dirname(z['file']) for z in zones}
    tmp = r.upload({
        'liteblox_agent.py': (agent_dir() / 'liteblox_agent.py').read_bytes(),
        'liteblox_agent_install.py': (agent_dir() / 'liteblox_agent_install.py').read_bytes(),
        'VERSION': f'{version}\n'.encode(),
        'liteblox-agent.service': unit_text(zone_dirs, kea, ntp, bind).encode(),
        'config.json': agent_config(node, version, bind).encode(),
        'agent.crt': cert_pem,
        'agent.key': key_pem,
        'ca.crt': pki.ca_pem(),
    })
    g = AGENT_USER
    try:
        r.run(' && '.join([
            f'install -d -m 0755 -o root -g root {AGENT_LIB}',
            f'install -d -m 0750 -o root -g {g} {AGENT_ETC}',
            f'install -m 0644 -o root -g root {tmp}/liteblox_agent.py {AGENT_LIB}/liteblox_agent.py',
            f'install -m 0644 -o root -g root {tmp}/liteblox_agent_install.py {AGENT_LIB}/liteblox_agent_install.py',
            f'install -m 0644 -o root -g root {tmp}/VERSION {AGENT_LIB}/VERSION',
            # Repair puts this exact agent in place: nothing half-done from an upgrade over mTLS may undo it
            f'rm -f {AGENT_LIB}/trial.json {AGENT_LIB}/liteblox_agent.py.prev',
            f'rm -rf {AGENT_STATE}/pending',
            f'install -m 0640 -o root -g {g} {tmp}/config.json {AGENT_ETC}/config.json',
            f'install -m 0640 -o root -g {g} {tmp}/agent.key {AGENT_ETC}/agent.key',
            f'install -m 0644 -o root -g root {tmp}/agent.crt {AGENT_ETC}/agent.crt',
            f'install -m 0644 -o root -g root {tmp}/ca.crt {AGENT_ETC}/ca.crt',
            f'install -m 0644 -o root -g root {tmp}/liteblox-agent.service {UNIT_PATH}',
        ]), sudo=True, label='install agent files')
    finally:
        r.run(f'rm -rf {q(tmp)}', check=False)
    log(f'Installed agent {version} to {AGENT_LIB}, config and certificates to {AGENT_ETC}')
    r.run('systemctl daemon-reload && systemctl enable liteblox-agent >/dev/null 2>&1 && '
          'systemctl restart liteblox-agent', sudo=True, label='systemctl')
    time.sleep(1)
    code, out = r.run('systemctl is-active liteblox-agent', check=False)
    if code != 0:
        _, journal = r.run('journalctl -u liteblox-agent -n 20 --no-pager', sudo=True, check=False)
        raise BootstrapError(f'liteblox-agent did not start ({out}):\n{journal}')
    log('liteblox-agent service is running')
    node['cert_fingerprint'] = pki_mod.fingerprint(cert_pem)
    node['cert_not_after'] = pki_mod.not_after(cert_pem).isoformat()


VERIFY_WAIT = 90         # seconds: a Pi right after its apt run took 15 s to start the agent


def _verify(node, pki, log, wait=VERIFY_WAIT):
    log(f"Checking the agent over mutual TLS at {node['host']}:{node['agent_port']}")
    last, said = None, False
    deadline = time.monotonic() + wait
    while True:
        try:
            with AgentClient(node['host'], pki, port=node['agent_port'], timeout=5) as c:
                status = c.status()
            break
        except AgentError as e:
            last = e
        if time.monotonic() >= deadline:
            raise BootstrapError(f'agent did not answer over mTLS within {wait} s: {last} '
                                 f'(is TCP {node["agent_port"]} open from LiteBlox?)')
        if not said and time.monotonic() >= deadline - wait + 10:
            # a slow node (a Raspberry Pi just after installing packages) can take a while to start Python
            log(f'  not answering yet ({last}); waiting up to {wait} s for it to start')
            said = True
        time.sleep(1)
    if status.get('bind', True):
        log(f"  agent {status['agent_version']}, {status['named_version']}")
        log(f"  rndc: {'ok' if status['rndc_ok'] else 'FAILED'}; named-checkconf: "
            f"{'ok' if status['checkconf_ok'] else 'FAILED'}")
        for zone, ok in sorted(status['zones_writable'].items()):
            log(f"  {zone}: {'writable' if ok else 'NOT writable by the agent'}")
    else:
        log(f"  agent {status['agent_version']} (no BIND), Python {status.get('python')}")
        for i in status.get('interfaces') or []:
            log(f"  {i['name']} {'up' if i.get('up') else 'DOWN'}: {', '.join(i.get('addresses') or []) or 'no address'}")
    kea = status.get('kea') or {}
    if kea.get('installed'):
        states = {s: 'running' if v.get('running') else f"NOT reachable ({v.get('error', 'down')})"
                  for s, v in kea['services'].items()}
        log(f"  Kea {kea.get('version')}: dhcp4 {states.get('dhcp4')}, D2 {states.get('d2')}")
    return status
