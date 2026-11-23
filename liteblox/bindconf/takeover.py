"""Take over a node: from then on LiteBlox generates its whole BIND config.

preview() imports the node's config (importconf), renders the candidate, has
the agent print it with named-checkconf (/config/check) and compares that with
what the node prints now. takeover() goes ahead only when nothing blocks and
the two are equivalent. The node's own config files move to
/etc/bind/pre-liteblox/<stamp>/, zone files are copied into /etc/bind/liteblox/,
and the agent keeps a rollback copy.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from .. import db
from ..nodes import service as nodes
from ..nodes.client import AgentError
from .importconf import ImportPlan, check_allow_lists, equivalence, grant_line, import_config
from .model import DEBIAN
from .render import file_hashes, render, set_sha256


class TakeoverError(RuntimeError):
    pass


class NotFresh(TakeoverError):
    """The node has a config of its own: an admin takes it over from the preview, not setup."""


@dataclass
class Preview:
    plan: ImportPlan
    files: dict
    current_sha: str                    # of the node's printed config, so a takeover can't act on a stale preview
    blockers: list = field(default_factory=list)
    diff: Optional[str] = None          # None: not compared (blocked); '': equivalent
    notes: list = field(default_factory=list)
    contents: dict = field(default_factory=dict)     # zone: (text, sha256) read from the node

    @property
    def ready(self):
        return not self.blockers and self.diff == ''


def probe(host, attempts=5, delay=1.0, timeout=2.0):
    """named's answer to version.bind CH TXT (any answer shows it is up and listening), or None."""
    query = dns.message.make_query('version.bind.', dns.rdatatype.TXT, dns.rdataclass.CH)
    for i in range(attempts):
        try:
            response = dns.query.udp(query, host, timeout=timeout)
        except (dns.exception.DNSException, OSError):
            if i < attempts - 1:
                time.sleep(delay)
            continue
        for rrset in response.answer:
            return rrset[0].to_text().strip('"')
        return dns.rcode.to_text(response.rcode())
    return None


def _served_serial(host, zone):
    from ..dns.publish import served_serial
    return served_serial(host, zone)


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def known_from_db(conn, node):
    """What LiteBlox has already, in the shape import_config() takes."""
    zones = {}
    for z in conn.execute('SELECT * FROM zones'):
        others = conn.execute('SELECT 1 FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id '
                              'WHERE zn.zone_id = ? AND n.id != ? AND n.managed = 1', (z['id'], node['id'])).fetchone()
        zones[z['name']] = {'row': dict(z), 'fixed': z['mode'] == 'managed' or bool(others)}
    return {
        'acls': {r['name']: json.loads(r['items']) for r in conn.execute('SELECT * FROM acls')},
        'keys': {r['name']: (r['algorithm'], r['secret']) for r in conn.execute('SELECT * FROM tsig_keys')},
        'zones': zones,
        'primary': next((r['name'] for r in conn.execute("SELECT name FROM nodes WHERE role = 'primary'")), None),
    }


def _link_row(conn, zone_id, node_id):
    return conn.execute('SELECT * FROM zone_nodes WHERE zone_id = ? AND node_id = ?', (zone_id, node_id)).fetchone()


def preview(conn, settings, node, layout=None):
    """Everything a takeover would do, worked out with read-only agent calls."""
    from ..dns.drafts import Drafts
    layout = layout or DEBIAN
    if 'bind' in node.keys() and not node['bind']:
        raise TakeoverError(f"{node['name']} doesn't run BIND for LiteBlox (Repair / upgrade agent → Runs DNS first)")
    with nodes.agent_client(settings, node, timeout=60.0) as c:
        try:
            status = c.status()
            masked, secret = c.config(), c.config(secrets=True)
        except AgentError as e:
            raise TakeoverError(f"{node['name']} is unreachable: {e.message}")
        plan = import_config(masked, secret, layout, known_from_db(conn, node))
        pv = Preview(plan, render(plan.config, layout), hashlib.sha256(masked['checkconf'].encode()).hexdigest(),
                     blockers=list(plan.blockers))
        if 'taken_over' not in status:
            pv.blockers.insert(0, 'the agent on this node is too old: run "Repair / upgrade agent" first')
        elif status['taken_over'] or node['managed']:
            pv.blockers.insert(0, 'LiteBlox already manages the whole BIND config on this node')
        declared = {z.name for z in plan.zones}
        for r in conn.execute('SELECT z.name FROM zone_nodes zn JOIN zones z ON z.id = zn.zone_id '
                              'WHERE zn.node_id = ? ORDER BY z.name', (node['id'],)):
            if r['name'] not in declared:
                pv.blockers.append(f"zone {r['name']}: LiteBlox has this node serving it, but its config doesn't "
                                   'declare it (Stop serving it on this node first)')
        for z in plan.zones:
            if z.kind == 'forwarding':
                continue            # no file
            try:
                got = c.get_zone(z.name, sync=z.dynamic)     # with what's only in its journal yet
            except AgentError as e:
                pv.blockers.append(f'zone {z.name}: {e.message}')
                continue
            pv.contents[z.name] = (got['content'], got['sha256'])
            if z.row and not _link_row(conn, z.row['id'], node['id']) \
                    and Drafts(settings).published(z.row) != got['content']:
                pv.notes.append(f"{z.name}: this node's copy differs from LiteBlox's; after the takeover the zone's "
                                'Review page shows it as a change on the node, to keep or overwrite')
        if not pv.blockers:
            pv.blockers += check_allow_lists(pv.files, layout)
        if not pv.blockers:
            try:
                candidate = c.check_config(pv.files)['checkconf']
            except AgentError as e:
                out = e.details.get('output')
                pv.blockers.append(f'the node\'s named-checkconf rejects the generated config: {e.message}'
                                   + (f'\n{out}' if out else ''))
            else:
                pv.diff, notes = equivalence(masked['checkconf'], candidate,
                                             {z.name for z in plan.zones if z.relocated})
                pv.notes += notes
    return pv


def option_fields(options):
    """[(BIND option, value text)] for the NodeOptions fields an import set."""
    out = []
    for label, value in (('listen-on', options.listen_on), ('listen-on-v6', options.listen_on_v6),
                         ('allow-query', options.allow_query), ('recursion', options.recursion),
                         ('allow-recursion', options.allow_recursion), ('forwarders', options.forwarders),
                         ('forward', options.forward), ('dnssec-validation', options.dnssec_validation),
                         ('validate-except', options.validate_except)):
        if value is None:
            continue
        out.append((label, ('yes' if value else 'no') if isinstance(value, bool)
                    else ', '.join(value) if isinstance(value, list) else value))
    return out


def summary_lines(pv):
    """The preview as text for the CLI (no key secrets)."""
    plan, out = pv.plan, []
    for label, value in option_fields(plan.config.options):
        out.append(f'  option {label}: {value}')
    if plan.config.options.extra:
        out.append('  options kept as written:')
        out += [f'    {line}' for line in plan.config.options.extra.splitlines()]
    out += [f"  ACL {a.name}: {', '.join(a.items)}" for a in plan.acls]
    out += [f'  key {k.name} ({k.algorithm})' for k in plan.keys]
    if plan.config.top_extra:
        out.append('  top-level statements kept as written:')
        out += [f'    {line}' for line in plan.config.top_extra.splitlines()]
    for z in plan.zones:
        out.append(f"  zone {z.name}: {'already in LiteBlox' if z.row else 'new to LiteBlox'}"
                   + (f", forwarding to {z.settings['forwarders'].replace(chr(10), ', ')}" if z.kind == 'forwarding'
                      else f', file {z.old_file} → {z.new_file}' if z.relocated else '')
                   + (', dynamic: ' + '; '.join(grant_line(*g) for g in z.grants) if z.dynamic else ''))
    out += [f'  keep {p}' for p in plan.config.distro_includes]
    out += [f'  retire {p} (into /etc/bind/pre-liteblox/)' for p in plan.retire]
    out += [f'  no longer read: {p} (left in place)' for p in plan.left_in_place]
    out += [f'  note: {n}' for n in pv.notes]
    out += [f'  BLOCKED: {b}' for b in pv.blockers]
    if pv.diff:
        out.append('  NOT EQUIVALENT:')
        out += [f'    {line}' for line in pv.diff.splitlines()]
    elif pv.diff == '':
        out.append('  ✓ named-checkconf -px of the generated config matches the node\'s (normalized)')
    return out


def _serial_after(host, zone, expected, dns_serial, attempts=6, delay=1.0):
    seen = None
    for i in range(attempts):
        seen = dns_serial(host, zone)
        if seen == expected:
            return seen
        if i < attempts - 1:
            time.sleep(delay)
    return seen


def takeover(conn, settings, node, username, log, check_dns=None, layout=None, expect_sha=None,
             require_fresh=False, dns_serial=None):
    """Switch the node to the generated config. require_fresh (setup): raise NotFresh for a node
    with config of its own, which an admin takes over from the preview instead."""
    from ..backups import service as backups
    from ..nodes.roles import zone_serial
    layout, check_dns, dns_serial = layout or DEBIAN, check_dns or probe, dns_serial or _served_serial
    log(f"Taking over the BIND config on {node['name']}")
    pv = preview(conn, settings, node, layout)
    plan = pv.plan
    if require_fresh and not plan.fresh:
        raise NotFresh('this node has BIND config of its own; review it on the node page (Take over)')
    if pv.blockers:
        raise TakeoverError('cannot take over:\n' + '\n'.join(f'  - {b}' for b in pv.blockers))
    if expect_sha and expect_sha != pv.current_sha:
        raise TakeoverError("the node's config changed since the preview; look at the preview again")
    if pv.diff:
        raise TakeoverError(f'the generated config is not equivalent to the node\'s:\n{pv.diff}')
    log('  ✓ the generated config is equivalent to the node\'s (named-checkconf -px, normalized)')
    for note in pv.notes:
        log(f'  note: {note}')
    if plan.zones:
        log(f"  zones: {', '.join(z.name for z in plan.zones)}")
    if plan.config.distro_includes:
        log(f"  keeping {', '.join(plan.config.distro_includes)}")
    if plan.retire:
        log(f"  retiring {', '.join(plan.retire)}")
    before = {z.name: dns_serial(node['host'], z.name) for z in plan.zones if z.kind != 'forwarding'}
    backups.snapshot_before_change(conn, settings, node, 'take over BIND config', username)
    log('  ✓ backed up the node')
    dynamic = [z for z in plan.zones if z.dynamic]
    with nodes.agent_client(settings, node, timeout=60.0) as c:
        try:
            for z in dynamic:
                # held from here to the commit (which thaws it), so the copy moved into dyn/ misses no update
                got = c.get_zone(z.name, freeze=True)
                pv.contents[z.name] = (got['content'], got['sha256'])
                before[z.name] = zone_serial(got['content'], z.name)
                log(f'  ✓ {z.name}: updates held (rndc freeze) at serial {before[z.name]}')
        except AgentError as e:
            _thaw(c, dynamic, log)
            raise TakeoverError(f"{node['name']}: could not hold the dynamic zones' updates: {e.message}")
        relocated = {z.name: pv.contents[z.name][0] for z in plan.zones if z.relocated}
        try:
            staged = c.stage_config(pv.files, relocated, takeover=True, retire=plan.retire)
            log('  ✓ staged: named-checkconf accepts the generated config'
                + (f", zone files copied to their new place ({', '.join(sorted({z.new_file.rsplit('/', 1)[0] for z in plan.zones if z.relocated}))})"
                   if relocated else ''))
            result = c.commit_config(staged['stage_id'])
        except AgentError as e:
            _thaw(c, dynamic, log)          # a refused stage holds them still (a failed commit thaws itself)
            detail = e.details.get('output')
            raise TakeoverError(f"{node['name']} refused the generated config: {e.message}"
                                + (f'\n{detail}' if detail else ''))
        log(f"  ✓ committed: rndc reconfig done; the node's own files are in {result['preserved']}")
        problems = []
        for z in plan.zones:
            if z.kind == 'forwarding':
                continue
            try:
                if c.get_zone(z.name)['sha256'] != pv.contents[z.name][1]:
                    problems.append(f'{z.name}: the zone file LiteBlox wrote differs from the original')
            except AgentError as e:
                problems.append(f'{z.name}: {e.message}')
        for name, serial in before.items():
            if serial is None:
                log(f'  note: {name} did not answer LiteBlox before the takeover, so its serial was not compared')
                continue
            after = _serial_after(node['host'], name, serial, dns_serial)
            if after is not None and after > serial and name in {z.name for z in dynamic}:
                log(f'  ✓ {name}: serving serial {after} (updates came in since serial {serial})')
                continue
            if after != serial:
                problems.append(f'{name} answers with serial {after}, not {serial} as before')
            else:
                log(f'  ✓ {name}: still serving serial {serial}')
        answer = check_dns(node['host'])
        if answer is None:
            problems.append(f"{node['host']} does not answer DNS queries")
        if problems:
            log('  ✗ ' + '; '.join(problems) + ': rolling back')
            try:
                c.rollback_config()
                log('  ✓ rolled back to the previous config')
            except AgentError as e:
                log(f'  ✗ rollback failed: {e.message}')
            raise TakeoverError(f"{node['name']} did not serve as before after the takeover: " + '; '.join(problems))
        log(f'  ✓ named answers on {node["host"]} (version.bind: {answer})')
    _record(conn, settings, node, plan, pv, username)
    from ..dns import importer
    from ..dns.drafts import Drafts
    importer.sort_all(conn, Drafts(settings), username, log)      # imported static zones, in order as drafts
    db.audit(conn, username, 'node_takeover', node['name'])
    log(f"✓ LiteBlox now manages the whole BIND config on {node['name']}")


def _thaw(c, zones, log):
    for z in zones:
        try:
            c.thaw_zone(z.name)
            log(f'  {z.name}: takes updates again')
        except AgentError as e:
            if e.status != 404:         # 404: not held (any more)
                log(f'  ✗ {z.name}: rndc thaw failed ({e.message}); run it on the node')


def _record(conn, settings, node, plan, pv, username):
    """Store what the takeover imported: node settings, ACLs, keys, zones and where their files now are."""
    from ..dns import importer
    from ..dns.drafts import Drafts
    from ..dns.repo import Repo
    with conn:
        conn.execute('UPDATE nodes SET managed = 1, options = ?, top_extra = ?, distro_includes = ?, '
                     'config_sha256 = ?, config_files = ?, taken_over_at = ? WHERE id = ?',
                     (plan.config.options.to_json(), plan.config.top_extra,
                      json.dumps(plan.config.distro_includes), set_sha256(pv.files),
                      json.dumps(file_hashes(pv.files)), _now(), node['id']))
        for a in plan.acls:
            conn.execute('INSERT INTO acls (name, items) VALUES (?, ?)', (a.name, json.dumps(a.items)))
        for k in plan.keys:
            conn.execute("INSERT INTO tsig_keys (name, algorithm, secret, purpose) VALUES (?, ?, ?, 'imported')",
                         (k.name, k.algorithm, k.secret))
    repo = Repo(settings.repo_dir).ensure() if plan.zones else None
    for z in plan.zones:
        if z.kind == 'forwarding':
            _record_forwarding(conn, node, z)
            continue
        content, sha = pv.contents[z.name]
        if z.row is None:
            importer.import_zone(conn, repo, node, {'name': z.name, 'file': z.new_file, 'managed': True},
                                 content, sha, username)
            zone_id = conn.execute('SELECT id FROM zones WHERE name = ?', (z.name,)).fetchone()[0]
            fixed = False
        else:
            zone_id = z.row['id']
            link = _link_row(conn, zone_id, node['id'])
            if link:        # a file copied byte for byte keeps its drift state
                deployed = link['deployed_sha256']
            else:           # a copy LiteBlox didn't write: it shows as drift unless it's the published one
                deployed = hashlib.sha256(Drafts(settings).published(z.row).encode()).hexdigest()
            with conn:
                importer._link(conn, zone_id, node['id'], z.new_file, deployed)
            fixed = known_from_db(conn, node)['zones'][z.name]['fixed']
        if z.dynamic:
            with conn:
                conn.execute('UPDATE zones SET dynamic = 1 WHERE id = ?', (zone_id,))
                for key, scope, owner, types in z.grants:
                    key_id = conn.execute('SELECT id FROM tsig_keys WHERE name = ?', (key,)).fetchone()[0]
                    conn.execute('INSERT INTO key_grants (key_id, zone_id, scope, name, types) VALUES (?, ?, ?, ?, ?)',
                                 (key_id, zone_id, scope, owner.rstrip('.'), types))
        with conn:
            if not fixed:
                conn.execute('UPDATE zones SET notify = ?, also_notify = ?, allow_transfer = ?, allow_query = ? '
                             'WHERE id = ?', (z.settings['notify'], z.settings['also_notify'],
                                              z.settings['allow_transfer'], z.settings['allow_query'], zone_id))
            # declared by LiteBlox everywhere once every node serving it is taken over
            if not conn.execute('SELECT 1 FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id '
                                'WHERE zn.zone_id = ? AND n.managed = 0', (zone_id,)).fetchone():
                conn.execute("UPDATE zones SET mode = 'managed' WHERE id = ?", (zone_id,))


def _record_forwarding(conn, node, z):
    with conn:
        if z.row is None:
            zone_id = conn.execute(
                "INSERT INTO zones (name, mode, repo_file, kind, forwarders, forward_mode) "
                "VALUES (?, 'managed', '', 'forwarding', ?, ?)",
                (z.name, z.settings['forwarders'], z.settings['forward_mode'])).lastrowid
        else:
            zone_id = z.row['id']
            if not known_from_db(conn, node)['zones'][z.name]['fixed']:
                conn.execute('UPDATE zones SET forwarders = ?, forward_mode = ? WHERE id = ?',
                             (z.settings['forwarders'], z.settings['forward_mode'], zone_id))
        conn.execute("INSERT INTO zone_nodes (zone_id, node_id, node_file) VALUES (?, ?, '') "
                     "ON CONFLICT (zone_id, node_id) DO UPDATE SET node_file = ''", (zone_id, node['id']))
        if not conn.execute('SELECT 1 FROM zone_nodes zn JOIN nodes n ON n.id = zn.node_id '
                            'WHERE zn.zone_id = ? AND n.managed = 0', (zone_id,)).fetchone():
            conn.execute("UPDATE zones SET mode = 'managed' WHERE id = ?", (zone_id,))


def start(settings, node_id, username, background=True, echo=None, expect_sha=None):
    """The takeover as a job of its own (the node page's Take over, CLI `node takeover`)."""
    from .. import jobs

    def run(log):
        conn = db.connect(settings.db_path)
        try:
            node = nodes.get_node(conn, node_id)
            if node['managed']:
                raise TakeoverError(f"{node['name']} is already taken over")
            takeover(conn, settings, node, username, log, expect_sha=expect_sha)
        finally:
            conn.close()
    return jobs.start(settings.db_path, 'takeover', run, node_id=node_id, username=username,
                      background=background, echo=echo)
