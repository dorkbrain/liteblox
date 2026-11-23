"""Import zones from a node into LiteBlox (git repo + zones/zone_nodes rows)."""

import difflib

from .canonical import sorted_text
from .repo import zone_file
from .zonefile import Zone, ZoneParseError


def _link(conn, zone_id, node_id, node_file, sha):
    conn.execute(
        'INSERT INTO zone_nodes (zone_id, node_id, node_file, deployed_sha256) VALUES (?, ?, ?, ?) '
        'ON CONFLICT (zone_id, node_id) DO UPDATE SET node_file = excluded.node_file, '
        'deployed_sha256 = excluded.deployed_sha256',
        (zone_id, node_id, node_file, sha))


def diff(old, new, old_label, new_label):
    return ''.join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        old_label, new_label)).replace('\r', '')


def import_zone(conn, repo, node, info, content, sha, username):
    """Import one zone read from node. info is the agent's zone entry (name, file, managed).

    The node's file is imported as it is; sort_all afterwards (once dynamic zones are known) puts the
    static ones in order as drafts. Returns a dict with action 'imported', 'linked' or 'conflict' (+ diff),
    and any parse warning.
    """
    name = info['name']
    result = {'zone': name, 'warning': None}
    try:
        Zone.parse(content, name + '.')
    except ZoneParseError as e:
        result['warning'] = f'the row editor cannot parse this file ({e}); only the raw editor will work'

    row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
    if row is None:
        path = zone_file(name)
        repo.write(path, content, f"Import {name} from {node['name']}", username)
        with conn:
            zone_id = conn.execute('INSERT INTO zones (name, mode, repo_file) VALUES (?, ?, ?)',
                                   (name, 'managed' if info.get('managed') else 'local', path)).lastrowid
            _link(conn, zone_id, node['id'], info['file'], sha)
        return dict(result, action='imported')

    current = repo.read(row['repo_file']) or ''
    if current == content:
        with conn:
            _link(conn, row['id'], node['id'], info['file'], sha)
        return dict(result, action='linked')
    return dict(result, action='conflict',
                diff=diff(current, content, f'LiteBlox: {name}', f"{node['name']}: {info['file']}"))


def keep_zone_sorted(conn, drafts, name, username):
    """Put the zone in sorted order: its current text (draft or published), sorted, becomes the draft.

    Returns 'draft' (the sorted copy is a draft to review) or 'unchanged' (already in order). A file that
    can't be sorted ($INCLUDE, a line that doesn't parse) raises SortError and is left as it was.
    """
    row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
    text, _ = drafts.load(row)
    if sorted_text(text, name + '.') == text:   # SortError before anything changes
        return 'unchanged'                      # (a draft already in order keeps who made it)
    return 'draft' if drafts.save(row, text, username, note={'put_in_order': True}) else 'unchanged'


def sort_all(conn, drafts, username='liteblox', log=None):
    """Every static zone in sorted order (at startup and after a takeover): a draft for each one
    that isn't yet. Returns {zone: 'draft' | 'unchanged' | why it can't be sorted}."""
    out = {}
    for row in conn.execute("SELECT name FROM zones WHERE kind = 'primary' AND dynamic = 0 AND repo_file != '' "
                            'ORDER BY name').fetchall():
        try:
            out[row['name']] = keep_zone_sorted(conn, drafts, row['name'], username)
        except ZoneParseError as e:
            out[row['name']] = str(e)
        if log and out[row['name']] != 'unchanged':
            log(f"  {'✓' if out[row['name']] == 'draft' else '✗'} {row['name']}: "
                + ('put in sorted order as a draft to review' if out[row['name']] == 'draft'
                   else f"can't be kept sorted: {out[row['name']]}"))
    return out


def resolve_conflict(conn, repo, node, info, content, sha, choice, username):
    """choice 'node': the node's copy replaces LiteBlox's. 'liteblox': keep ours; the node gets it on the next publish."""
    row = conn.execute('SELECT * FROM zones WHERE name = ?', (info['name'],)).fetchone()
    if row is None:
        raise ValueError(f"zone {info['name']} is not in LiteBlox")
    if choice == 'node':
        repo.write(row['repo_file'], content,
                   f"Import {info['name']} from {node['name']} (replacing LiteBlox's copy)", username)
    elif choice != 'liteblox':
        raise ValueError('choice must be node or liteblox')
    with conn:
        _link(conn, row['id'], node['id'], info['file'], sha)
