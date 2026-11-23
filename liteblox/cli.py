"""Command line: `liteblox serve`, `liteblox user ...`, `liteblox check`."""

import argparse
import getpass
import json
import shutil
import sys

from . import auth, db
from .config import load_settings
from .timefmt import local
from .version import __version__


def _read_password(args):
    if args.password_stdin:
        password = sys.stdin.readline().rstrip('\n')
    else:
        password = getpass.getpass('Password: ')
        if getpass.getpass('Repeat password: ') != password:
            raise auth.AuthError('passwords do not match')
    return password


def _open_db():
    settings = load_settings()
    db.migrate(settings.db_path)
    return db.connect(settings.db_path)


def cmd_serve(args):
    import logging
    import uvicorn
    # uvicorn only configures its own loggers; app messages (scheduled backups, jobs) need this
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:     %(name)s: %(message)s')
    settings = load_settings()
    db.migrate(settings.db_path)     # a database from a newer LiteBlox stops here, with one line
    if args.reload:     # development: one server, plain HTTP only
        uvicorn.run('liteblox.main:create_app', factory=True, host=args.host, port=args.port,
                    reload=True, proxy_headers=True)
        return
    import asyncio
    from .listeners import serve
    from .main import create_app
    from .web_tls import https_port
    asyncio.run(serve(create_app(settings), settings, args.host, args.port, args.https_port or https_port()))


def cmd_user_add(args):
    conn = _open_db()
    auth.create_user(conn, args.username, _read_password(args), args.role)
    db.audit(conn, 'cli', 'user_add', f'{args.username} ({args.role}) via CLI')
    print(f'✓ Created {args.role} user {args.username}')


def cmd_user_passwd(args):
    conn = _open_db()
    auth.set_password(conn, args.username, _read_password(args))
    db.audit(conn, 'cli', 'user_password_reset', f'{args.username} via CLI')
    print(f'✓ Password updated for {args.username}')


def cmd_user_role(args):
    conn = _open_db()
    auth.set_role(conn, args.username, args.role)
    db.audit(conn, 'cli', 'user_role', f'{args.username} -> {args.role} via CLI')
    print(f'✓ {args.username} is now {args.role}')


def cmd_user_del(args):
    conn = _open_db()
    auth.delete_user(conn, args.username)
    db.audit(conn, 'cli', 'user_delete', f'{args.username} via CLI')
    print(f'✓ Deleted user {args.username}')


def cmd_user_list(args):
    rows = auth.list_users(_open_db())
    if not rows:
        print('No users. Create one with: liteblox user add <name> --role admin')
        return
    print(f"{'USER':<20} {'ROLE':<10} {'CREATED':<24} LAST LOGIN")
    for r in rows:
        print(f"{r['username']:<20} {r['role']:<10} {local(r['created_at']):<24} {local(r['last_login_at']) or '-'}")


def cmd_check(args):
    settings = load_settings()
    version = db.migrate(settings.db_path)
    ok = True
    print(f'LiteBlox {__version__}')
    print(f'  data dir:    {settings.data_dir}')
    print(f'  backups dir: {settings.backups_dir}')
    print(f'  database:    schema v{version}')
    for tool in ('named-checkzone', 'named-checkconf', 'git'):
        path = shutil.which(tool)
        ok &= path is not None
        print(f"  {tool + ':':<16} {path or 'NOT FOUND'}")
    return 0 if ok else 1


def cmd_healthcheck(args):
    import urllib.request
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{args.port}/healthz', timeout=3) as r:
            return 0 if r.status == 200 else 1
    except OSError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


# ── HTTPS (4.6) ────────────────────────────────────────────────────────────────

def _https():
    from . import web_tls
    settings = load_settings()
    db.migrate(settings.db_path)
    return web_tls, settings, db.connect(settings.db_path)


def _https_names(web_tls, conn, settings, given):
    if given:
        return web_tls.parse_names(','.join(given))
    row = web_tls.load(conn)
    if row['names']:
        return web_tls.parse_names(row['names'])
    info = web_tls.current(settings)
    return info['names'] if info and info['names'] else web_tls.default_names(None)


def cmd_https_status(args):
    web_tls, settings, conn = _https()
    row, info = web_tls.load(conn), web_tls.current(settings)
    port = row['port'] or web_tls.https_port()
    if not row['enabled']:
        state = 'off (plain HTTP only, on 53530)'
    else:
        state = f'on, port {port}' + ('' if row['listening'] else ' (not listening: is LiteBlox running?)')
    print(f'HTTPS:       {state}')
    print(f"HTTPS only:  {'yes (plain HTTP answers with a page saying HTTP is not supported)' if row['https_only'] else 'no'}")
    if info:
        print(f"Certificate: {info['subject']}, {'self-signed' if info['self_signed'] else 'issued by ' + info['issuer']}")
        print(f"  names:     {', '.join(info['names']) or '-'}")
        print(f"  valid:     {info['not_before']:%Y-%m-%d} to {info['not_after']:%Y-%m-%d}"
              + (' (EXPIRED)' if info['expired'] else f" ({info['days_left']} days left)"))
        print(f"  SHA-256:   {info['fingerprint']}")
        if row['fingerprint'] and info['fingerprint'] != row['fingerprint']:
            print('  replaced outside LiteBlox')
    else:
        print('Certificate: none yet (in ./data/tls)')
    if row['enabled'] and row['error']:
        print(f"ERROR: {row['error']}")
        return 1


def cmd_https_allow_http(args):
    web_tls, settings, conn = _https()
    if not web_tls.load(conn)['https_only']:
        print('✓ Plain HTTP is already allowed')
        return
    web_tls.save(conn, 'cli', https_only=0)
    db.audit(conn, 'cli', 'https_allow_http', 'via CLI')
    print('✓ Plain HTTP works again (within a few seconds, on 53530)')


def cmd_https_off(args):
    web_tls, settings, conn = _https()
    web_tls.disable(conn, 'cli')
    db.audit(conn, 'cli', 'https_disable', 'via CLI')
    print('✓ HTTPS is off (plain HTTP only, within a few seconds)')


def cmd_https_on(args):
    web_tls, settings, conn = _https()
    if args.name:
        web_tls.save(conn, 'cli', names=', '.join(web_tls.parse_names(','.join(args.name))))
    made = web_tls.enable(conn, settings, 'cli')
    port = web_tls.load(conn)['port'] or web_tls.https_port()
    db.audit(conn, 'cli', 'https_enable', f'port {port} via CLI'
             + (f", a self-signed certificate for {', '.join(made['names'])}" if made else ''))
    if made:
        print(f"✓ Made a self-signed certificate for {', '.join(made['names'])}")
        print(f"  SHA-256: {made['fingerprint']}")
    print(f'✓ HTTPS is on: port {port} opens within a few seconds')


def cmd_https_regenerate(args):
    web_tls, settings, conn = _https()
    names = _https_names(web_tls, conn, settings, args.name)
    info = web_tls.generate(conn, settings, names, 'cli')
    db.audit(conn, 'cli', 'https_generate', f"{', '.join(names)} ({info['fingerprint'][:23]}…) via CLI")
    print(f"✓ A new self-signed certificate for {', '.join(names)}")
    print(f"  SHA-256: {info['fingerprint']}")


def _node_settings_conn():
    settings = load_settings()
    db.migrate(settings.db_path)
    from .pki import PKI
    PKI(settings.pki_dir).ensure()
    return settings, db.connect(settings.db_path)


def cmd_node_add(args):
    from .nodes import service, ssh
    settings, conn = _node_settings_conn()
    host_key, fp = ssh.fetch_host_key(args.host, args.ssh_port)
    print(f'{args.host}:{args.ssh_port} host key: {host_key.split()[0]} {fp}')
    if not args.yes and input('Pin this key and add the node? [y/N] ').strip().lower() != 'y':
        print('Not added.')
        return 1
    from .modules import enabled
    bind = not args.no_bind and enabled(conn)['dns']
    service.add_node(conn, args.name, args.host, args.ssh_port, args.agent_port, host_key, fp, bind=bind)
    db.audit(conn, 'cli', 'node_add', f"{args.name} {args.host} via CLI{'' if bind else ' (no BIND)'}")
    print(f"✓ Added node {args.name} (host key pinned{'' if bind else '; no BIND'})")


def cmd_node_edit(args):
    from .nodes import service, ssh
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    if args.dns_address is not None:
        service.set_dns_address(conn, node['id'], args.dns_address)
        db.audit(conn, 'cli', 'node_dns_address', f"{node['name']}: {args.dns_address or '(the address)'} via CLI")
        print(f"✓ {node['name']}'s DNS address is {args.dns_address or 'its address'}")
        if node['role']:
            print('Next: run `liteblox node primary <the primary>` again so the other nodes use it')
        if not (args.host or args.ssh_port or args.agent_port):
            return
    host = args.host or node['host']
    ssh_port = args.ssh_port or node['ssh_port']
    agent_port = args.agent_port or node['agent_port']
    host_key, fp = ssh.fetch_host_key(host, ssh_port)
    same = 'same as the pinned key' if fp == node['host_key_fp'] else f"pinned key is {node['host_key_fp']}"
    print(f'{host}:{ssh_port} host key: {host_key.split()[0]} {fp} ({same})')
    if not args.yes and input(f"Pin this key for {node['name']}? [y/N] ").strip().lower() != 'y':
        print('Not changed.')
        return 1
    changes = service.update_node(conn, node['id'], host, ssh_port, agent_port, host_key, fp)
    if not changes:
        print('Nothing changed.')
        return
    db.audit(conn, 'cli', 'node_update', f"{node['name']}: {'; '.join(changes)} via CLI")
    print(f"✓ Updated {node['name']}: {'; '.join(changes)}")
    if service.needs_repair(service.get_node(conn, node['id'])):
        print(f"Next: give the agent a certificate for the new address: liteblox node bootstrap {node['name']} --ssh-user <user>")


def cmd_node_remove(args):
    from .nodes import service
    _, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    zones = service.removal_impact(conn, node['id'])
    for z in zones:
        print(f"  serves {z['name']} ({z['mode']})" + ('' if z['others'] else ': no other node serves it'))
    if not args.yes and input(f"Remove {node['name']} from LiteBlox? Nothing on the server changes. [y/N] ").strip().lower() != 'y':
        print('Not removed.')
        return 1
    service.remove_node(conn, node['id'])
    db.audit(conn, 'cli', 'node_remove', f"{node['name']} {node['host']} via CLI")
    print(f"✓ Removed {node['name']} (its backup files stay in the backups folder)")


def cmd_node_list(args):
    from .nodes import service
    _, conn = _node_settings_conn()
    rows = service.list_nodes(conn)
    if not rows:
        print('No nodes. Add one with: liteblox node add <name> <host>')
        return
    print(f"{'NODE':<16} {'HOST':<18} {'STATUS':<8} {'AGENT':<8} {'LAST SEEN':<24} {'RUNS':<16} BIND")
    for n in rows:
        print(f"{n['name']:<16} {n['host']:<18} {n['status']:<8} {n['agent_version'] or '-':<8} "
              f"{local(n['last_seen_at']) or '-':<24} {service.kind(n):<16} {n['named_version'] or '-'}")


def cmd_node_bootstrap(args):
    from .nodes import bootstrap, service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    if args.bind is not None and bool(node['bind']) != args.bind:
        from .modules import enabled
        why = service.bind_change_blocked(conn, node) or (
            'the DNS module is off (liteblox modules --on dns)' if args.bind and not enabled(conn)['dns'] else None)
        if why:
            print(f'ERROR: {why}')
            return 1
    password = None if args.use_ssh_keys else getpass.getpass(f'SSH password for {args.ssh_user}: ')
    creds = bootstrap.Credentials(args.ssh_user, password=password, use_local_keys=args.use_ssh_keys)
    options = bootstrap.Options(bind=args.bind, install_bind=args.install_bind,
                                fix_permissions=not args.no_fix_permissions,
                                takeover=not args.no_takeover, dhcp=args.dhcp, ntp=args.ntp)
    job_id = service.start_bootstrap(settings, node['id'], creds, options, 'cli',
                                     background=False, echo=print)
    status = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0]
    return 0 if status == 'ok' else 1


def cmd_node_takeover(args):
    from .bindconf import takeover
    from .nodes import service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    try:
        pv = takeover.preview(conn, settings, node)
    except takeover.TakeoverError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    print(f"Taking over {node['name']} would:")
    print('\n'.join(takeover.summary_lines(pv)))
    if not pv.ready:
        print(f"ERROR: {node['name']} can't be taken over as it is", file=sys.stderr)
        return 1
    if not args.yes and input('Take over the BIND config? [y/N] ').strip().lower() != 'y':
        return 1
    job_id = takeover.start(settings, node['id'], 'cli', background=False, echo=print, expect_sha=pv.current_sha)
    status = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0]
    return 0 if status == 'ok' else 1


def cmd_node_readopt(args):
    from .bindconf import readopt
    from .nodes import service
    settings, conn = _node_settings_conn()
    try:
        ids = [service.get_node(conn, name)['id'] for name in args.names]
    except service.NodeError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    for name in args.names:
        service.refresh(conn, settings, service.get_node(conn, name))
    pv = readopt.preview(conn, settings, ids)
    for b in pv.blockers:
        print(f'  BLOCKED: {b}')
    for name, diff in (pv.diffs or {}).items():
        print(f'  {name}: NOT THE SAME:\n{diff}' if diff else f'  ✓ {name}: every generated file rendered back byte for byte')
    if not pv.blockers:
        for heading, lines in readopt.summary(pv.plan):
            print(f'  {heading}:')
            print('\n'.join(f'    {line}' for line in lines))
    if not pv.ready:
        print("ERROR: these nodes can't be re-adopted as they are", file=sys.stderr)
        return 1
    if not args.yes and input('Re-adopt them? [y/N] ').strip().lower() != 'y':
        return 1
    job_id = readopt.start(settings, ids, 'cli', background=False, echo=print)
    status = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0]
    return 0 if status == 'ok' else 1


def cmd_node_settings(args):
    from .bindconf.model import NodeOptions
    from .bindconf.render import options_text
    from .nodes import service
    _, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    if not node['managed']:
        print(f"ERROR: {node['name']} isn't taken over yet", file=sys.stderr)
        return 1
    print(options_text(NodeOptions.from_json(node['options'])), end='')
    if (node['top_extra'] or '').strip():
        print(node['top_extra'].strip())
    print(f"(change these on {node['name']}'s Server settings page)")


def cmd_node_primary(args):
    from . import jobs
    from .nodes import roles, service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    if not args.yes and input(f"Make {node['name']} the primary of every zone, the other nodes its "
                              'secondaries? [y/N] ').strip().lower() != 'y':
        return 1
    job_id = jobs.start(settings.db_path, 'make primary',
                        lambda log: roles.make_primary(settings, node['id'], 'cli', log),
                        node_id=node['id'], username='cli', background=False, echo=print)
    status = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0]
    return 0 if status == 'ok' else 1


def _node_job(settings, conn, node, kind, fn):
    from . import jobs
    job_id = jobs.start(settings.db_path, kind, fn, node_id=node['id'], username='cli', background=False, echo=print)
    status = conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0]
    return 0 if status == 'ok' else 1


def cmd_node_promote(args):
    from .nodes import roles, service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    primary = roles.topology(conn)['primary']
    if primary is None:
        print('ERROR: there is no primary yet: use `liteblox node primary`', file=sys.stderr)
        return 1
    if primary['id'] == node['id']:
        print(f"ERROR: {node['name']} is already the primary", file=sys.stderr)
        return 1
    if not args.yes and input(f"Promote {node['name']} to primary in place of {primary['name']}? [y/N] ").strip().lower() != 'y':
        return 1
    return _node_job(settings, conn, node, 'promote', lambda log: roles.promote(settings, node['id'], 'cli', log))


def cmd_node_drift(args):
    import json
    from .nodes import drift, service
    from .nodes.client import AgentError
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    try:
        text = drift.diff(settings, conn, node)
    except (AgentError, drift.DriftError) as e:
        print(f'ERROR: {getattr(e, "message", e)}', file=sys.stderr)
        return 1
    second = json.loads(node['second_primary'] or '[]')
    if second:
        print(f"{node['name']} declares {', '.join(second)} as primary outside LiteBlox")
    print(text, end='') if text else print(f"✓ {node['name']}'s config is what LiteBlox wrote")
    return 0


def cmd_node_overwrite(args):
    from .nodes import drift, service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    if not args.yes and input(f"Write LiteBlox's config over the changes on {node['name']}? [y/N] ").strip().lower() != 'y':
        return 1
    return _node_job(settings, conn, node, 'overwrite config',
                     lambda log: drift.overwrite(settings, node['id'], 'cli', log))


def _key_job(settings, conn, fn):
    from . import jobs
    job_id = jobs.start(settings.db_path, 'TSIG key', fn, username='cli', background=False, echo=print)
    return 0 if conn.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone()[0] == 'ok' else 1


def cmd_token_add(args):
    from .api import tokens
    conn = _open_db()
    try:
        token_id, secret = tokens.create(conn, args.username, args.name, 'read' if args.read_only else 'full', 'cli',
                                         args.expires)
    except tokens.TokenError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    db.audit(conn, 'cli', 'token_add', f"{args.username}: {args.name} ({'read' if args.read_only else 'full'}) via CLI")
    print(f"✓ Token {args.name} for {args.username} (id {token_id}); it's shown only now:")
    print(secret)


def cmd_token_list(args):
    from .api import tokens
    rows = tokens.list_tokens(_open_db(), args.username)
    print(f"{'ID':<5} {'USER':<16} {'NAME':<24} {'SCOPE':<6} {'TOKEN':<14} {'LAST USED':<24} EXPIRES")
    for t in rows:
        print(f"{t['id']:<5} {t['username']:<16} {t['name']:<24} {t['scope']:<6} {t['prefix'] + '…':<14} "
              f"{local(t['last_used_at']) or 'never':<24} {local(t['expires_at']) or 'never'}")


def cmd_token_revoke(args):
    from .api import tokens
    conn = _open_db()
    try:
        row = tokens.revoke(conn, args.id)
    except tokens.TokenError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    db.audit(conn, 'cli', 'token_revoke', f"{row['username']}: {row['name']} via CLI")
    print(f"✓ Revoked {row['username']}'s token {row['name']}")


def cmd_key_list(args):
    settings, conn = _node_settings_conn()
    for k in conn.execute('SELECT * FROM tsig_keys ORDER BY name'):
        grants = conn.execute('SELECT g.*, z.name AS zone, z.dynamic FROM key_grants g JOIN zones z ON z.id = g.zone_id '
                              'WHERE g.key_id = ? ORDER BY z.name', (k['id'],)).fetchall()
        print(f"{k['name']:<20} {k['algorithm']:<12} {k['purpose']}")
        for g in grants:
            print(f"    {g['zone']}: {g['scope']} {g['name']} {g['types']}{'' if g['dynamic'] else ' (inactive: static zone)'}"
                  f"  [grant {g['id']}]")


def cmd_key_add(args):
    from . import keys
    settings, conn = _node_settings_conn()
    try:
        name = keys.check_name(args.name)
        secret = keys.new_secret(args.algorithm)
    except keys.KeyProblem as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    status = _key_job(settings, conn, lambda log: keys.add(settings, name, args.algorithm, secret, 'cli', log))
    if status == 0:
        print('\nThe key file (shown only now):\n')
        print(keys.key_file(name, args.algorithm, secret))
    return status


def cmd_key_grant(args):
    from . import keys
    settings, conn = _node_settings_conn()
    return _key_job(settings, conn, lambda log: keys.grant(settings, args.name, args.zone, args.scope,
                                                           args.owner or '', ' '.join(args.types), 'cli', log))


def cmd_key_revoke(args):
    from . import keys
    settings, conn = _node_settings_conn()
    return _key_job(settings, conn, lambda log: keys.revoke(settings, args.grant_id, 'cli', log))


def cmd_key_delete(args):
    from . import keys
    settings, conn = _node_settings_conn()
    return _key_job(settings, conn, lambda log: keys.delete(settings, args.name, 'cli', log))


def cmd_node_status(args):
    from .nodes import service
    settings, conn = _node_settings_conn()
    node = service.get_node(conn, args.name)
    status, error = service.refresh(conn, settings, node)
    if error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    print(json.dumps(status, indent=2))


def cmd_backup_run(args):
    from .backups import service as backups
    from .nodes import service
    settings, conn = _node_settings_conn()
    if args.all:
        results = backups.backup_all(settings, args.kind, 'cli')
        return 1 if any(r['action'] == 'failed' for r in results.values()) else 0
    failed = False
    for name in args.nodes:
        node = service.get_node(conn, name)
        result = backups.backup_node(conn, settings, node, args.kind, username='cli')
        pruned = backups.prune(conn, settings, node['id'])
        print(f"{name}: {result['action']}" + (f" ({result['error']})" if result['error'] else '')
              + (f', pruned {len(pruned)}' if pruned else ''))
        failed |= result['action'] == 'failed'
    return 1 if failed else 0


def cmd_backup_list(args):
    from .nodes import service
    _, conn = _node_settings_conn()
    node = service.get_node(conn, args.node)
    rows = conn.execute('SELECT * FROM backups WHERE node_id = ? ORDER BY created_at DESC, id DESC',
                        (node['id'],)).fetchall()
    print(f"{'CREATED':<24} {'KIND':<14} {'STATUS':<7} {'SIZE':>8} {'FILES':>5}  FILE")
    for r in rows:
        print(f"{local(r['created_at']):<24} {r['kind']:<14} {r['status']:<7} {r['size'] or 0:>8} "
              f"{r['file_count'] or '-':>5}  {r['file'] or r['error']}")


def cmd_modules(args):
    from . import modules
    conn = _open_db()
    try:
        wanted = modules.enabled(conn)
        for name in args.on or []:
            wanted[name] = True
        for name in args.off or []:
            wanted[name] = False
        if args.on or args.off or args.save:
            errors = modules.save(conn, wanted)
            if errors:
                raise ValueError('; '.join(f"{modules.LABELS.get(n, 'modules')}: {why}" for n, why in errors.items()))
            db.audit(conn, 'cli', 'modules', modules.describe(wanted))
            print(f'✓ modules: {modules.describe(wanted)}')
            return
        for name in modules.NAMES:
            why = modules.in_use(conn, name)
            print(f"{modules.LABELS[name]:<5} {'on ' if wanted[name] else 'off'}{f'  (in use: {why})' if why else ''}")
        if not modules.chosen(conn):
            print('(not chosen yet: the Dashboard asks on first login)')
    finally:
        conn.close()


def build_parser():
    parser = argparse.ArgumentParser(prog='liteblox', description='LiteBlox: DNS, DHCP, time and IPAM for a home or small network')
    parser.add_argument('--version', action='version', version=f'liteblox {__version__}')
    sub = parser.add_subparsers(dest='command', required=True)

    serve = sub.add_parser('serve', help='run the web server')
    serve.add_argument('--host', default='0.0.0.0')
    serve.add_argument('--port', type=int, default=53530)
    serve.add_argument('--https-port', type=int, default=None,
                       help='the HTTPS port, while HTTPS is on (default 53443, or LITEBLOX_HTTPS_PORT)')
    serve.add_argument('--reload', action='store_true', help='auto-reload on code changes (dev; plain HTTP only)')
    serve.set_defaults(func=cmd_serve)

    sub.add_parser('check', help='check data dir, database and required tools').set_defaults(func=cmd_check)

    health = sub.add_parser('healthcheck', help='exit 0 if the local web server answers /healthz')
    health.add_argument('--port', type=int, default=53530)
    health.set_defaults(func=cmd_healthcheck)

    user = sub.add_parser('user', help='manage local accounts').add_subparsers(dest='user_command', required=True)

    add = user.add_parser('add', help='create a user')
    add.add_argument('username')
    add.add_argument('--role', choices=auth.ROLES, default='admin')
    add.add_argument('--password-stdin', action='store_true', help='read the password from stdin')
    add.set_defaults(func=cmd_user_add)

    passwd = user.add_parser('passwd', help='change a password')
    passwd.add_argument('username')
    passwd.add_argument('--password-stdin', action='store_true', help='read the password from stdin')
    passwd.set_defaults(func=cmd_user_passwd)

    role = user.add_parser('role', help='change a role')
    role.add_argument('username')
    role.add_argument('role', choices=auth.ROLES)
    role.set_defaults(func=cmd_user_role)

    delete = user.add_parser('del', help='delete a user')
    delete.add_argument('username')
    delete.set_defaults(func=cmd_user_del)

    user.add_parser('list', help='list users').set_defaults(func=cmd_user_list)

    https = sub.add_parser('https', help="LiteBlox's own HTTPS (also Settings → HTTPS)").add_subparsers(
        dest='https_command', required=True)
    https.add_parser('status', help='on or off, HTTPS only, the certificate').set_defaults(func=cmd_https_status)
    https.add_parser('allow-http', help='turn HTTPS only off: plain HTTP works again').set_defaults(func=cmd_https_allow_http)
    https.add_parser('off', help='turn HTTPS off (and HTTPS only with it)').set_defaults(func=cmd_https_off)
    on = https.add_parser('on', help='turn HTTPS on (a self-signed certificate if there is none)')
    on.add_argument('--name', action='append', help='a hostname or IP for the self-signed certificate (repeatable)')
    on.set_defaults(func=cmd_https_on)
    regen = https.add_parser('regenerate', help='a new self-signed certificate')
    regen.add_argument('--name', action='append', help='a hostname or IP (repeatable; default: the names it has)')
    regen.set_defaults(func=cmd_https_regenerate)

    node = sub.add_parser('node', help='manage nodes (DNS, DHCP and time servers, scanners)').add_subparsers(dest='node_command', required=True)

    nadd = node.add_parser('add', help='add a node and pin its SSH host key')
    nadd.add_argument('name')
    nadd.add_argument('host')
    nadd.add_argument('--ssh-port', type=int, default=22)
    nadd.add_argument('--agent-port', type=int, default=8530)
    nadd.add_argument('--yes', action='store_true', help='pin the host key without asking')
    nadd.add_argument('--no-bind', action='store_true',
                      help='a node without BIND: DHCP or Time only, or a scanner for IPAM (always so with DNS off)')
    nadd.set_defaults(func=cmd_node_add)

    node.add_parser('list', help='list nodes').set_defaults(func=cmd_node_list)

    nedit = node.add_parser('edit', help="change a node's address or ports and re-pin its SSH host key")
    nedit.add_argument('name')
    nedit.add_argument('--host', help='new address')
    nedit.add_argument('--ssh-port', type=int)
    nedit.add_argument('--agent-port', type=int)
    nedit.add_argument('--dns-address', help="IP the other nodes use for transfers and NOTIFY ('' = the address)")
    nedit.add_argument('--yes', action='store_true', help='pin the host key without asking')
    nedit.set_defaults(func=cmd_node_edit)

    nrm = node.add_parser('remove', help='forget a node (nothing on the node changes)')
    nrm.add_argument('name')
    nrm.add_argument('--yes', action='store_true', help="don't ask")
    nrm.set_defaults(func=cmd_node_remove)

    nboot = node.add_parser('bootstrap', help='install or repair the agent on a node over SSH')
    nboot.add_argument('name')
    nboot.add_argument('--ssh-user', required=True)
    nboot.add_argument('--use-ssh-keys', action='store_true',
                       help='log in with your ssh-agent / ~/.ssh keys instead of a password')
    nbind = nboot.add_mutually_exclusive_group()
    nbind.add_argument('--no-bind', dest='bind', action='store_false', default=None,
                       help="no BIND on this node from now on (a scanner, or DHCP/Time only); BIND itself isn't touched")
    nbind.add_argument('--bind', dest='bind', action='store_true', default=None,
                       help='the node runs BIND for LiteBlox from now on (a node added with --no-bind)')
    nboot.add_argument('--install-bind', action='store_true', help='install BIND if missing')
    nboot.add_argument('--no-fix-permissions', action='store_true',
                       help="don't make /etc/bind and zone files group-writable for bind")
    nboot.add_argument('--no-takeover', action='store_true',
                       help="don't let LiteBlox generate the whole BIND config afterwards")
    nboot.add_argument('--dhcp', action='store_true',
                       help='set up Kea DHCP (a config that serves nothing until a subnet is added)')
    nboot.add_argument('--ntp', action='store_true',
                       help='set up time sync: chrony with the sources on Settings → Time (replaces systemd-timesyncd)')
    nboot.set_defaults(func=cmd_node_bootstrap)

    ntake = node.add_parser('takeover', help="let LiteBlox generate a node's whole BIND config (shows the preview first)")
    ntake.add_argument('name')
    ntake.add_argument('--yes', action='store_true', help="don't ask after the preview")
    ntake.set_defaults(func=cmd_node_takeover)
    nre = node.add_parser('readopt', help="rebuild LiteBlox's data from nodes another LiteBlox managed "
                                          '(its data lost; shows the preview first)')
    nre.add_argument('names', nargs='+', metavar='NAME')
    nre.add_argument('--yes', action='store_true', help="don't ask before going ahead")
    nre.set_defaults(func=cmd_node_readopt)

    nset = node.add_parser('settings', help="show a node's server settings (options as LiteBlox writes them)")
    nset.add_argument('name')
    nset.set_defaults(func=cmd_node_settings)

    nprim = node.add_parser('primary', help='make a node the primary of every zone, the others its secondaries')
    nprim.add_argument('name')
    nprim.add_argument('--yes', action='store_true', help="don't ask")
    nprim.set_defaults(func=cmd_node_primary)

    nprom = node.add_parser('promote', help='make a secondary the primary in place of the current one (failover)')
    nprom.add_argument('name')
    nprom.add_argument('--yes', action='store_true', help="don't ask")
    nprom.set_defaults(func=cmd_node_promote)

    ndrift = node.add_parser('drift', help="show changes made to a node's generated config outside LiteBlox")
    ndrift.add_argument('name')
    ndrift.set_defaults(func=cmd_node_drift)

    nover = node.add_parser('overwrite', help="write LiteBlox's config over changes made on the node")
    nover.add_argument('name')
    nover.add_argument('--yes', action='store_true', help="don't ask")
    nover.set_defaults(func=cmd_node_overwrite)

    nstat = node.add_parser('status', help="ask a node's agent for its status")
    nstat.add_argument('name')
    nstat.set_defaults(func=cmd_node_status)

    token = sub.add_parser('token', help='API tokens').add_subparsers(dest='token_command', required=True)
    tadd = token.add_parser('add', help='make an API token for a user (printed once)')
    tadd.add_argument('username')
    tadd.add_argument('name')
    tadd.add_argument('--read-only', action='store_true', help='GET calls only (default: whatever the role allows)')
    tadd.add_argument('--expires', type=int, metavar='DAYS', help='expire after this many days (default: never)')
    tadd.set_defaults(func=cmd_token_add)
    tlist = token.add_parser('list', help="list API tokens (every user's, or one user's)")
    tlist.add_argument('username', nargs='?')
    tlist.set_defaults(func=cmd_token_list)
    trev = token.add_parser('revoke', help='revoke an API token (its id from token list)')
    trev.add_argument('id', type=int)
    trev.set_defaults(func=cmd_token_revoke)

    key = sub.add_parser('key', help='TSIG keys for DHCP/ACME clients').add_subparsers(dest='key_command', required=True)
    key.add_parser('list', help='keys and their grants').set_defaults(func=cmd_key_list)
    kadd = key.add_parser('add', help='create a client key (its secret is printed once)')
    kadd.add_argument('name')
    kadd.add_argument('--algorithm', default='hmac-sha256')
    kadd.set_defaults(func=cmd_key_add)
    kgrant = key.add_parser('grant', help='let a key update a zone (while the zone is dynamic)')
    kgrant.add_argument('name')
    kgrant.add_argument('zone')
    kgrant.add_argument('scope', choices=('zonesub', 'subdomain', 'name'))
    kgrant.add_argument('types', nargs='*', default=['ANY'], help='record types (default ANY)')
    kgrant.add_argument('--owner', help='the name, for subdomain / name')
    kgrant.set_defaults(func=cmd_key_grant)
    krev = key.add_parser('revoke', help='remove a grant (its number from key list)')
    krev.add_argument('grant_id', type=int)
    krev.set_defaults(func=cmd_key_revoke)
    kdel = key.add_parser('delete', help='delete a client key and its grants')
    kdel.add_argument('name')
    kdel.set_defaults(func=cmd_key_delete)

    mods = sub.add_parser('modules', help='show or switch the modules this install runs (Settings → Modules)')
    mods.add_argument('--on', nargs='+', choices=('dns', 'dhcp', 'ntp', 'ipam'), metavar='MODULE',
                      help='switch on (dns, dhcp, ntp, ipam)')
    mods.add_argument('--off', nargs='+', choices=('dns', 'dhcp', 'ntp', 'ipam'), metavar='MODULE',
                      help='switch off (refused while in use)')
    mods.add_argument('--save', action='store_true', help='keep the current choice as chosen (skips the first-run card)')
    mods.set_defaults(func=cmd_modules)

    backup = sub.add_parser('backup', help='node config backups').add_subparsers(dest='backup_command', required=True)
    brun = backup.add_parser('run', help='back up nodes now (then prune old backups)')
    brun.add_argument('nodes', nargs='*')
    brun.add_argument('--all', action='store_true', help='every set-up node')
    brun.add_argument('--kind', choices=('manual', 'scheduled'), default='manual',
                      help='scheduled runs skip writing when nothing changed')
    brun.set_defaults(func=cmd_backup_run)
    blist = backup.add_parser('list', help="list a node's backups")
    blist.add_argument('node')
    blist.set_defaults(func=cmd_backup_list)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except (auth.AuthError, ValueError, RuntimeError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
