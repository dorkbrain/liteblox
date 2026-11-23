"""Node roles: one primary node holding every zone, the other nodes its secondaries.

make_primary() turns whatever LiteBlox has (one node, a dual-master pair, a new
node taken over later) into that shape, one node at a time with the primary
first, so a secondary's first transfer finds the primary ready. Static zones
on the primary get LiteBlox's published copy; secondaries transfer from it
(NOTIFY + IXFR, signed with LiteBlox's own key).

promote() moves the primary to another node, with the old one up (a planned
switch) or down (failover). A node that missed a change (down at the time) is
marked pending; reconcile() brings it in line when it answers again, keeping
whatever only its copies held in a demote report.
"""

import base64
import contextlib
import json
import secrets
import threading

from .. import db
from ..bindconf.model import DEBIAN, UPDATE_KEY, XFR_KEY, for_node, node_address
from ..bindconf.render import record_commit, render
from . import service as nodes
from .client import AgentError


class RoleError(RuntimeError):
    pass


# one role change at a time in this process: promote, make_primary, reconcile; publishes wait for it
ROLE_LOCK = threading.Lock()


@contextlib.contextmanager
def role_change():
    if not ROLE_LOCK.acquire(blocking=False):
        raise RoleError('another role change is running; try again when it has finished')
    try:
        yield
    finally:
        ROLE_LOCK.release()


def busy():
    return ROLE_LOCK.locked()


class Lagging(RoleError):
    """The node took its new config but doesn't serve the expected serials yet.

    Not a failure: a secondary transfers the zones on its own, so the job ends
    ok with a warning (lagging()) instead of marking the node pending again.
    """


def follow_dhcp(conn, settings, log):
    """Point DHCP's DNS updates at the primary as it is now (dhcp.apply.follow_primary, best effort)."""
    from ..dhcp import apply as dhcp_apply
    if any(n['dhcp'] for n in nodes.list_nodes(conn)):
        log('DHCP:')
        try:
            dhcp_apply.follow_primary(settings, conn, log)
        except Exception as e:      # the role change itself is done; DHCP catches up on the health check
            log(f'  ⚠ DHCP not updated yet: {e}')


def lagging(log, node, e):
    log(f"  ⚠ {node['name']} took its new config but is still catching up ({e}); it transfers the zones on its own")


def ensure_keys(conn):
    """LiteBlox's own keys (transfers between its nodes; its reads and updates), created when first needed."""
    for name in (XFR_KEY, UPDATE_KEY):
        if not conn.execute('SELECT 1 FROM tsig_keys WHERE name = ?', (name,)).fetchone():
            with conn:
                conn.execute("INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES (?, 'hmac-sha256', ?, ?)",
                             (name, base64.b64encode(secrets.token_bytes(32)).decode(), name))


ensure_xfr_key = ensure_keys


def topology(conn):
    """The primary (or None), and taken-over nodes that aren't its secondaries yet."""
    rows = nodes.list_nodes(conn)
    primary = next((n for n in rows if n['role'] == 'primary'), None)
    pending = [n for n in rows if primary and n['id'] != primary['id'] and n['managed'] and n['role'] != 'secondary']
    return {'primary': primary, 'pending': pending}


def _names(rows):
    return ', '.join(n['name'] for n in rows)


def zone_serial(text, name):
    from ..dns.zonefile import Zone
    return Zone.parse(text, name + '.').serial


def _apply(conn, settings, node, log, username, zone_files=None):
    """Back up, then write the node's whole config as the DB now describes it."""
    from ..backups import service as backups
    backups.snapshot_before_change(conn, settings, node, 'change node roles', username)
    files = render(for_node(conn, node))
    with nodes.agent_client(settings, node, timeout=60.0) as c:
        try:
            c.commit_config(c.stage_config(files, zone_files or {})['stage_id'])
        except AgentError as e:
            detail = e.details.get('output')
            raise RoleError(f"{node['name']} refused the change: {e.message}" + (f'\n{detail}' if detail else ''))
    record_commit(conn, node['id'], files)
    log(f"  ✓ {node['name']}: backed up, new config committed (rndc reconfig done)")


def _rollback(settings, node, log):
    try:
        with nodes.agent_client(settings, node, timeout=60.0) as c:
            c.rollback_config()
        log(f"  ✓ {node['name']}: rolled back to its previous config")
    except AgentError as e:
        log(f"  ✗ {node['name']}: rollback failed: {e.message}")


def _check(log, node, zones, verify, attempts):
    """[problems] after asking the node over DNS for each zone's serial."""
    problems = []
    for name, serial in zones:
        seen = verify(node_address(node), name, serial, attempts=attempts)
        if seen is None or seen < serial:
            problems.append(f"{node['name']} answers {name} with serial {seen}, expected {serial}")
        else:
            log(f"  ✓ {node['name']}: serving {name} at serial {seen}")
    return problems


def make_primary(settings, node_id, username, log, verify=None, attempts=20, **kw):
    """Make node_id the primary of every zone and every other taken-over node its secondary.
    With another node already the primary, that's a promote()."""
    conn = db.connect(settings.db_path)
    try:
        with role_change():
            current = topology(conn)['primary']
            if current is not None and current['id'] != int(node_id):
                return _promote(conn, settings, int(node_id), username, log, verify=verify, attempts=attempts, **kw)
            return _make_primary(conn, settings, node_id, username, log, verify, attempts)
    finally:
        conn.close()


def _make_primary(conn, settings, node_id, username, log, verify=None, attempts=20):
    from ..dns.drafts import Drafts
    from ..dns.publish import node_states, sha, wait_for_serial
    verify = verify or wait_for_serial
    target = nodes.get_node(conn, int(node_id))
    # forwarding-only zones aren't held by a primary: each of their nodes forwards on its own
    zones = [dict(z) for z in conn.execute("SELECT * FROM zones WHERE kind = 'primary' ORDER BY name")]
    serving = {}
    for z in zones:
        serving[z['id']] = [r[0] for r in conn.execute('SELECT node_id FROM zone_nodes WHERE zone_id = ?', (z['id'],))]
    involved = {target['id']} | {i for ids in serving.values() for i in ids}
    rows = {n['id']: n for n in nodes.list_nodes(conn)}
    problems = []
    for i in sorted(involved, key=lambda i: rows[i]['name']):
        n = rows[i]
        if not n['managed']:
            problems.append(f"{n['name']} isn't taken over yet (its page → Take over)")
        if node_address(n) is None:
            problems.append(f"{n['name']}'s DNS address isn't known (its page → Change address: DNS address)")
    if not problems:
        for z in zones:
            for st in node_states(conn, settings, z):
                n = st['node']
                if st['state'] == 'unreachable':
                    problems.append(f"{n['name']} ({z['name']}): unreachable: {st['error']}")
                elif st['state'] == 'drift':
                    problems.append(f"{z['name']}: {n['name']}'s copy was changed outside LiteBlox; resolve it "
                                    "on the zone's Review page first")
                elif st['state'] == 'behind' and n['id'] == target['id']:
                    problems.append(f"{z['name']}: {n['name']} serves an older copy; publish it again first")
    if problems:
        raise RoleError('nothing was changed:\n' + '\n'.join(f'  - {p}' for p in problems))

    published = {z['id']: Drafts(settings).published(z) for z in zones}
    serials = {z['id']: zone_serial(published[z['id']], z['name']) for z in zones}
    others = [rows[i] for i in sorted(involved - {target['id']}, key=lambda i: rows[i]['name'])]
    idle = [n for n in rows.values() if n['managed'] and n['id'] not in involved]
    log(f"Making {target['name']} the primary of {len(zones)} zone(s)"
        + (f"; {_names(others + idle)} will be its secondar{'y' if len(others + idle) == 1 else 'ies'}"
           if others or idle else ''))
    ensure_keys(conn)

    old_roles = {i: n['role'] for i, n in rows.items()}
    added = [z for z in zones if target['id'] not in serving[z['id']]]
    with conn:
        conn.execute('UPDATE nodes SET role = NULL')
        conn.execute("UPDATE nodes SET role = 'primary' WHERE id = ?", (target['id'],))
        for n in others + idle:
            conn.execute("UPDATE nodes SET role = 'secondary' WHERE id = ?", (n['id'],))
        for z in added:
            conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?)',
                         (z['id'], target['id'], f"{DEBIAN.config_dir}/db.{z['name']}", sha(published[z['id']])))
    target = nodes.get_node(conn, target['id'])

    # 1. the primary: every zone, transfers allowed to the secondaries with LiteBlox's key
    try:
        _apply(conn, settings, target, log, username, {z['name']: published[z['id']] for z in added})
        failed = _check(log, target, [(z['name'], serials[z['id']]) for z in zones], verify, 6)
    except Exception as e:
        failed = [str(e)]
    if failed:
        if not any('refused the change' in f for f in failed):
            _rollback(settings, target, log)
        with conn:
            for i, role in old_roles.items():
                conn.execute('UPDATE nodes SET role = ? WHERE id = ?', (role, i))
            for z in added:
                conn.execute('DELETE FROM zone_nodes WHERE zone_id = ? AND node_id = ?', (z['id'], target['id']))
        raise RoleError(f"{target['name']} could not become the primary; nothing else was changed:\n"
                        + '\n'.join(f'  - {f}' for f in failed))

    # 2. each other node: its zones become secondaries of the primary
    problems = []
    for n in others:
        n = nodes.get_node(conn, n['id'])
        mine = [z for z in zones if n['id'] in serving[z['id']]]
        try:
            _apply(conn, settings, n, log, username)
            failed = _check(log, n, [(z['name'], serials[z['id']]) for z in mine], verify, attempts)
        except Exception as e:
            failed = [str(e)]
        if failed:
            if not any('refused the change' in f for f in failed):
                _rollback(settings, n, log)
            with conn:
                conn.execute('UPDATE nodes SET role = NULL WHERE id = ?', (n['id'],))
            problems += failed
            continue
        with conn:
            for z in mine:
                conn.execute('UPDATE zone_nodes SET node_file = ?, deployed_sha256 = NULL '
                             'WHERE zone_id = ? AND node_id = ?',
                             (f"{DEBIAN.sec_dir}/db.{z['name']}", z['id'], n['id']))
    # the primary's also-notify named nodes that stayed primary copies: write it again without them
    if problems:
        try:
            _apply(conn, settings, nodes.get_node(conn, target['id']), log, username)
        except RoleError as e:
            problems.append(str(e))
    db.audit(conn, username, 'node_primary', target['name'])
    if problems:
        raise RoleError(f"{target['name']} is the primary, but not every node became its secondary:\n"
                        + '\n'.join(f'  - {p}' for p in problems))
    log(f"✓ {target['name']} is the primary"
        + (f"; {_names(others + idle)} {'is its secondary' if len(others + idle) == 1 else 'are its secondaries'}"
           if others or idle else ''))
    follow_dhcp(conn, settings, log)


# ── promote / reconcile ────────────────────────────────────────────────────────

def _zone_rows(conn):
    """Zones a primary holds (forwarding-only zones aside) and {zone id: [node ids serving it]}."""
    zones = [dict(z) for z in conn.execute("SELECT * FROM zones WHERE kind = 'primary' ORDER BY name")]
    serving = {z['id']: [r[0] for r in conn.execute('SELECT node_id FROM zone_nodes WHERE zone_id = ?', (z['id'],))]
               for z in zones}
    return zones, serving


def _unreachable(settings, node):
    """None when the node's agent answers, else why not."""
    try:
        with nodes.agent_client(settings, node, timeout=5.0) as c:
            c.status()
    except AgentError as e:
        return e.message
    return None


def _node_copy(conn, zone, node, transfer=None):
    """A dynamic zone as `node` serves it: a secondary allows LiteBlox's transfer key, a primary its update key."""
    from ..dns import dynamic
    return dynamic.axfr_from(conn, zone, node_address(node), keys=(XFR_KEY, UPDATE_KEY), transfer=transfer,
                             where=f"{node['name']} at ")


def promote(settings, node_id, username, log, **kw):
    """Make node_id the primary in place of the current one, which may be down (failover)."""
    conn = db.connect(settings.db_path)
    try:
        with role_change():
            return _promote(conn, settings, int(node_id), username, log, **kw)
    finally:
        conn.close()


def _promote(conn, settings, node_id, username, log, verify=None, attempts=20, transfer=None, served=None):
    from ..dns import dynamic
    from ..dns.drafts import Drafts
    from ..dns.publish import running, served_serial, sha, wait_for_serial
    from ..dns.repo import Repo
    from ..dns.zonefile import Zone
    verify = verify or wait_for_serial
    served = served or served_serial
    target = nodes.get_node(conn, node_id)
    old = topology(conn)['primary']
    if old is None:
        raise RoleError('there is no primary to replace yet: use Make primary')
    if old['id'] == target['id']:
        raise RoleError(f"{target['name']} is already the primary")
    zones, serving = _zone_rows(conn)
    rows = {n['id']: n for n in nodes.list_nodes(conn)}
    problems = []
    if not target['managed']:
        problems.append(f"{target['name']} isn't taken over yet (its page → Take over)")
    if node_address(target) is None:
        problems.append(f"{target['name']}'s DNS address isn't known (its page → Change address: DNS address)")
    if target['role'] != 'secondary' and any(target['id'] in ids for ids in serving.values()):
        problems.append(f"{target['name']} still holds primary copies of its own: run Make primary on "
                        f"{old['name']} first, so it becomes a secondary")
    publishing = [z['name'] for z in zones if running(conn, z['id'])]
    if publishing:
        problems.append(f"{', '.join(publishing)} {'is' if len(publishing) == 1 else 'are'} being published; "
                        'wait for that to finish')
    error = _unreachable(settings, target)
    if error:
        problems.append(f"{target['name']} is unreachable: {error}")
    if problems:
        raise RoleError('nothing was changed:\n' + '\n'.join(f'  - {p}' for p in problems))

    # every other taken-over node ends up a secondary of the new primary
    others = sorted((n for n in rows.values() if n['managed'] and n['id'] != target['id']),
                    key=lambda n: (n['id'] != old['id'], n['name']))
    down = {n['id']: e for n in others if (e := _unreachable(settings, n))}
    log(f"Promoting {target['name']} to primary in place of {old['name']}"
        + (f" (unreachable: {down[old['id']]})" if old['id'] in down else ''))

    # the copies the new primary starts from
    published = {z['id']: Drafts(settings).published(z) for z in zones}
    texts, serials = {}, {}
    for z in zones:
        holders = [n for n in [target] + others if n['id'] in serving[z['id']] and n['id'] not in down]
        if z['dynamic']:
            best = None
            for n in holders:
                try:
                    text = _node_copy(conn, z, n, transfer)
                except dynamic.DynamicError as e:
                    log(f"  {z['name']}: {e}")
                    continue
                s = zone_serial(text, z['name'])
                if best is None or s > best[0] or (s == best[0] and n['id'] == old['id']):
                    best = (s, text, n)
            if best is None:
                problems.append(f"{z['name']} is dynamic and no reachable node has a copy to start from")
                continue
            serials[z['id']], texts[z['id']] = best[0], best[1]
            log(f"  {z['name']}: {best[2]['name']}'s copy (serial {best[0]})")
        else:
            text = published[z['id']]
            serial = zone_serial(text, z['name'])
            seen = [s for s in (served(node_address(n), z['name']) for n in holders) if s is not None]
            if seen and max(seen) > serial:
                # a copy changed outside LiteBlox got a higher serial; go past it so every secondary transfers
                zone = Zone.parse(text, z['name'] + '.')
                zone.serial = serial = max(seen) + 1
                text = zone.render()
                Repo(settings.repo_dir).ensure().write(
                    z['repo_file'], text, f'Promote: serial raised past {max(seen)} (a copy changed outside LiteBlox)',
                    username)
                log(f"  {z['name']}: a node serves serial {max(seen)}, past LiteBlox's copy; "
                    f'its serial is raised to {serial} (a new version)')
            serials[z['id']], texts[z['id']] = serial, text
    if problems:
        raise RoleError('nothing was changed:\n' + '\n'.join(f'  - {p}' for p in problems))
    ensure_keys(conn)

    saved = {i: (n['role'], n['pending'], n['config_sha256'], n['config_files']) for i, n in rows.items()}
    saved_zn = [dict(r) for r in conn.execute('SELECT * FROM zone_nodes')]
    with conn:
        conn.execute("UPDATE nodes SET role = 'primary', pending = NULL WHERE id = ?", (target['id'],))
        for n in others:
            pending = ('demote' if n['id'] == old['id'] else 'apply') if n['id'] in down else None
            conn.execute("UPDATE nodes SET role = 'secondary', pending = ? WHERE id = ?", (pending, n['id']))
        for z in zones:
            folder = DEBIAN.dyn_dir if z['dynamic'] else DEBIAN.config_dir
            conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?) '
                         'ON CONFLICT (zone_id, node_id) DO UPDATE SET node_file = excluded.node_file, '
                         'deployed_sha256 = excluded.deployed_sha256',
                         (z['id'], target['id'], f"{folder}/db.{z['name']}",
                          None if z['dynamic'] else sha(texts[z['id']])))
            conn.execute('UPDATE zone_nodes SET node_file = ?, deployed_sha256 = NULL WHERE zone_id = ? AND node_id = ?',
                         (f"{DEBIAN.sec_dir}/db.{z['name']}", z['id'], old['id']))

    # 1. the new primary, from the copies above
    try:
        _apply(conn, settings, nodes.get_node(conn, target['id']), log, username,
               {z['name']: texts[z['id']] for z in zones})
        failed = _check(log, target, [(z['name'], serials[z['id']]) for z in zones], verify, 6)
    except Exception as e:
        failed = [str(e)]
    if failed:
        if not any('refused the change' in f for f in failed):
            _rollback(settings, target, log)
        with conn:
            for i, values in saved.items():
                conn.execute('UPDATE nodes SET role = ?, pending = ?, config_sha256 = ?, config_files = ? '
                             'WHERE id = ?', (*values, i))
            conn.execute('DELETE FROM zone_nodes')
            for r in saved_zn:
                conn.execute('INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) '
                             'VALUES (?, ?, ?, ?)', (r['zone_id'], r['node_id'], r['node_file'], r['deployed_sha256']))
        raise RoleError(f"{target['name']} could not become the primary; nothing else was changed:\n"
                        + '\n'.join(f'  - {f}' for f in failed))
    db.audit(conn, username, 'node_promote', f"{target['name']} (was {old['name']})")

    # 2. the old primary, if it's up (its copies are compared first), then every other node
    problems, behind = [], []
    for n in others:
        if n['id'] in down:
            log(f"  {n['name']} is unreachable ({down[n['id']]}): it is "
                + ('demoted' if n['id'] == old['id'] else 'brought in line') + ' when it answers again')
            continue
        try:
            _reconcile(conn, settings, nodes.get_node(conn, n['id']), username, log, verify=verify,
                       attempts=attempts, transfer=transfer, compare=n['id'] == old['id'])
        except Lagging as e:
            lagging(log, n, e)
            behind.append(n['name'])
        except Exception as e:
            with conn:
                conn.execute('UPDATE nodes SET pending = ? WHERE id = ?',
                             ('demote' if n['id'] == old['id'] else 'apply', n['id']))
            problems.append(f"{n['name']}: {e} (tried again when the health check next sees it)")
    if problems:
        follow_dhcp(conn, settings, log)        # the primary did move: DHCP's updates go there now
        raise RoleError(f"{target['name']} is the primary, but not every node followed:\n"
                        + '\n'.join(f'  - {p}' for p in problems))
    following = [n for n in others if n['id'] not in down]
    log(f"✓ {target['name']} is the primary"
        + (f"; {_names(following)} {'follows' if len(following) == 1 else 'follow'} it" if following else '')
        + (f" ({', '.join(behind)} still catching up)" if behind else ''))
    follow_dhcp(conn, settings, log)


def reconcile(settings, node_id, username, log, **kw):
    """The pending change for a node that was down during a role change (the health check runs it)."""
    conn = db.connect(settings.db_path)
    try:
        with role_change():
            node = nodes.get_node(conn, int(node_id))
            if not node['pending']:
                log(f"{node['name']} has nothing pending")
                return
            log(f"{node['name']} answers again: "
                + ('demoting it (it was the primary)' if node['pending'] == 'demote' else 'bringing it in line'))
            kw.pop('served', None)
            try:
                _reconcile(conn, settings, node, username, log, **kw)
            except Lagging as e:
                lagging(log, node, e)
            follow_dhcp(conn, settings, log)
    finally:
        conn.close()


def _reconcile(conn, settings, node, username, log, verify=None, attempts=20, transfer=None, compare=True):
    """Write the node's config as the DB says now. compare: first keep what only its copies hold
    (records it took while it was a primary, or a copy ahead of the primary's) in demote reports."""
    from ..dns import dynamic
    from ..dns.drafts import Drafts
    from ..dns.publish import wait_for_serial
    verify = verify or wait_for_serial
    zones, serving = _zone_rows(conn)
    mine = [z for z in zones if node['id'] in serving[z['id']]]
    if compare and mine:
        import dns.exception
        import dns.name
        with nodes.agent_client(settings, node, timeout=30.0) as c:
            declared = {z['name']: z for z in c.config()['zones']}
        for z in mine:
            d = declared.get(z['name'])
            if d is None or (d['type'] != 'primary' and not z['dynamic']):
                continue                # a static secondary copy is only ever the primary's
            try:
                if d['type'] == 'primary' and not z['dynamic']:
                    with nodes.agent_client(settings, node, timeout=30.0) as c:
                        old_text = c.get_zone(z['name'])['content']
                    new_text = Drafts(settings).published(z)
                else:
                    old_text = _node_copy(conn, z, node, transfer)
                    new_text = dynamic.axfr(conn, z, transfer)
                origin = dns.name.from_text(z['name'] + '.')
                rrsets = dynamic.only_on(old_text, new_text, origin)
                node_serial, primary_serial = dynamic.serial(old_text, origin), dynamic.serial(new_text, origin)
                differs = bool(dynamic.changes(old_text, new_text, origin))
            except (AgentError, dynamic.DynamicError, dns.exception.DNSException) as e:
                log(f"  {z['name']}: couldn't compare {node['name']}'s copy ({getattr(e, 'message', e)}); "
                    'nothing kept from it')
                continue
            seen = conn.execute('SELECT 1 FROM demote_reports WHERE node_id = ? AND zone_id = ? AND rrsets = ? '
                                'AND resolved_at IS NULL', (node['id'], z['id'], json.dumps(rrsets))).fetchone()
            if rrsets and not seen:       # a retry after a failure finds the same records again
                with conn:
                    conn.execute('INSERT INTO demote_reports (node_id, zone_id, node_serial, primary_serial, old_text, '
                                 'rrsets) VALUES (?, ?, ?, ?, ?, ?)',
                                 (node['id'], z['id'], node_serial, primary_serial, old_text, json.dumps(rrsets)))
                log(f"  {z['name']}: {len(rrsets)} record set(s) only on {node['name']}'s copy, kept in a "
                    "report on its page")
            if z['dynamic'] and (node_serial > primary_serial or (node_serial == primary_serial and differs)):
                # its copy would look current to it and never transfer again
                new = dynamic.raise_serial(conn, z, node_serial, transfer)
                log(f"  {z['name']}: the primary's serial raised to {new}, past {node['name']}'s {node_serial}")
    _apply(conn, settings, node, log, username)
    with conn:
        conn.execute('UPDATE nodes SET pending = NULL WHERE id = ?', (node['id'],))
    expected = []
    for z in mine:
        try:
            text = dynamic.axfr(conn, z, transfer) if z['dynamic'] else Drafts(settings).published(z)
        except dynamic.DynamicError as e:
            log(f"  {z['name']}: {e}")
            continue
        expected.append((z['name'], zone_serial(text, z['name'])))
    problems = _check(log, nodes.get_node(conn, node['id']), expected, verify, attempts)
    if problems:
        raise Lagging('; '.join(problems))
