"""Config drift: a node's generated BIND files changed outside LiteBlox.

The agent's /status hashes each generated file; LiteBlox keeps the hashes of what it last
committed (nodes.config_files). Overwrite writes LiteBlox's config back; Keep takes a changed
options.conf / top.conf into the node's server settings (the other files are global or follow
the node's role, so only Overwrite fits them).
"""

import difflib
import json
from types import SimpleNamespace

from .. import db
from ..bindconf import apply
from ..bindconf.importconf import _options
from ..bindconf.model import DEBIAN, ROLES, for_node
from ..bindconf.render import HEADER, file_hashes, own_top, render
from . import agent_module
from . import service as nodes

KEEPABLE = {'options.conf', 'top.conf'}


class DriftError(RuntimeError):
    pass


def expected_hashes(conn, node):
    """{role: sha256} LiteBlox last committed; nodes taken over before it kept them get today's rendering."""
    if node['config_files']:
        return json.loads(node['config_files'])
    return file_hashes(render(for_node(conn, node)))


def dhcp_changed(node, status):
    """Kea config files changed on the node since LiteBlox last committed them ([] when none, or no Kea)."""
    expected = json.loads(node['dhcp_files'] or '{}') if node['dhcp'] else {}
    actual = ((status or {}).get('kea') or {}).get('files') or {}
    return [role for role, sha in sorted(expected.items()) if actual.get(role) != sha]


def changed_roles(conn, node, status):
    """Generated files whose hash on the node differs from LiteBlox's (a missing file counts)."""
    expected = expected_hashes(conn, node)
    seen = status.get('config_files') or {}
    return sorted(role for role in ROLES if seen.get(role) != expected.get(role))


def second_primaries(conn, node, declared):
    """Zones the node declares as primary although LiteBlox has it as their secondary."""
    if node['role'] != 'secondary':
        return []
    mine = {r[0] for r in conn.execute('SELECT z.name FROM zones z JOIN zone_nodes zn ON zn.zone_id = z.id '
                                       "WHERE zn.node_id = ? AND z.kind = 'primary'", (node['id'],))}
    return sorted(z['name'] for z in declared if z['type'] == 'primary' and z['name'] in mine)


def node_files(settings, node):
    """The generated files as they are on the node (key secrets masked by the agent)."""
    with nodes.agent_client(settings, node, timeout=30.0) as c:
        files = c.config(files=True).get('files')
    if files is None:
        raise DriftError(f"the agent on {node['name']} is too old to show its files: run Repair / upgrade agent")
    return files


def diff(settings, conn, node):
    """A unified diff of LiteBlox's rendering (---) against the node's files (+++), changed files only."""
    ours = render(for_node(conn, node))
    theirs = node_files(settings, node)
    return ''.join(''.join(difflib.unified_diff(
        nodes.mask_secrets(ours[role]).splitlines(True), nodes.mask_secrets(theirs.get(role) or '').splitlines(True),
        f'LiteBlox: {role}', f"{node['name']}: {role}")) for role in ROLES)


def overwrite(settings, node_id, username, log):
    """Write LiteBlox's config over the node's changes (with apply's probes and rollback)."""
    conn = db.connect(settings.db_path)
    try:
        node = nodes.get_node(conn, int(node_id))
        log(f"Writing LiteBlox's config over the changes on {node['name']}")
        apply.apply_nodes(settings, conn, [node['id']], lambda c: None, lambda c: None,
                          'overwrite config changed outside LiteBlox', username, log)
        db.audit(conn, username, 'node_overwrite', node['name'])
    finally:
        conn.close()


def kept_settings(settings, conn, node):
    """Server settings form values read from the node's own options.conf and top.conf (for Keep)."""
    roles = json.loads(node['drift'] or '[]')
    if not roles or not set(roles) <= KEEPABLE:
        raise DriftError('only changes to options.conf and top.conf can be kept; overwrite the others')
    files = node_files(settings, node)
    agent = agent_module()
    try:
        stmts = agent.parse_conf(files.get('options.conf') or '')
    except agent.ConfError as e:
        raise DriftError(f"can't read {node['name']}'s options.conf: {e}")
    block = [st for st in stmts if st.keyword == 'options']
    if len(block) != 1 or len(stmts) != 1:
        raise DriftError(f"{node['name']}'s options.conf must hold exactly one options {{ }} block to keep it")
    plan = SimpleNamespace(own_options=[], blockers=[])
    options = _options(block[0], DEBIAN, plan)
    if plan.blockers:
        raise DriftError('; '.join(plan.blockers))
    top = files.get('top.conf') or ''
    header = HEADER.format(pre_dir=DEBIAN.pre_dir)
    if top.startswith(header):
        top = top[len(header):]
    return apply.form_values(options, own_top(top))
