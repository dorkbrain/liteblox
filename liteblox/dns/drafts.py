"""Per-zone drafts: the working copy edits go into before review and publish.

<data>/drafts/<zone>.zone holds the draft text; <zone>.json records who edited
it and the hash of the repo copy it started from, so a draft made stale by a
newer import or publish can be flagged.
"""

import hashlib
import json
from datetime import datetime, timezone

from .canonical import SortError, note_lines, sorted_text
from .repo import Repo


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def keeps_sorted(zone_row):
    """Every static zone; named owns a dynamic zone's file and its order."""
    try:
        return not zone_row['dynamic']
    except (KeyError, IndexError):
        return True


def rev(text):
    """Short revision tag; edit requests must carry the rev they were made against."""
    return sha(text)[:16]


class Drafts:
    def __init__(self, settings):
        self.dir = settings.data_dir / 'drafts'
        self.repo = Repo(settings.repo_dir).ensure()

    def _paths(self, zone_name):
        return self.dir / f'{zone_name}.zone', self.dir / f'{zone_name}.json'

    def published(self, zone_row):
        if not zone_row['repo_file']:       # a forwarding-only zone has no file
            return ''
        return self.repo.read(zone_row['repo_file']) or ''

    def load(self, zone_row):
        """(text, is_draft): the draft if there is one, else the published copy."""
        text_path, _ = self._paths(zone_row['name'])
        if text_path.exists():
            return text_path.read_bytes().decode(), True
        return self.published(zone_row), False

    def has_draft(self, zone_name):
        return self._paths(zone_name)[0].exists()

    def meta(self, zone_name):
        _, meta_path = self._paths(zone_name)
        return json.loads(meta_path.read_text()) if meta_path.exists() else None

    def save(self, zone_row, text, username, note=None):
        """Store the draft; a draft identical to the published copy is simply dropped.

        note: extra meta to record with the draft (e.g. {'restored_from': sha}).
        The text is put in canonical order first; comment lines that takes out wait in the meta
        ('moved_comments') and join the zone's notes when the draft is published. A file that can't be
        sorted ($INCLUDE, say) keeps its own order, and the Dashboard says why.
        """
        moved = []
        if keeps_sorted(zone_row):
            try:
                text = sorted_text(text, zone_row['name'] + '.', moved)
            except SortError:
                moved = []
        published = self.published(zone_row)
        if text == published:
            self.discard(zone_row['name'])
            return False
        self.dir.mkdir(parents=True, exist_ok=True)
        text_path, meta_path = self._paths(zone_row['name'])
        meta = self.meta(zone_row['name']) or {'base_sha256': sha(published), 'created_by': username}
        meta.update(updated_by=username, updated_at=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    **(note or {}))
        if moved:
            meta['moved_comments'] = meta.get('moved_comments', []) + note_lines(moved)
        text_path.write_bytes(text.encode())
        meta_path.write_text(json.dumps(meta, indent=2))
        return True

    def discard(self, zone_name):
        for path in self._paths(zone_name):
            path.unlink(missing_ok=True)

    def link(self, *zone_names):
        """Mark drafts as belonging together (an edit in one changed the others): they publish together."""
        for name in zone_names:
            meta = self.meta(name)
            if meta is None:
                continue
            meta['linked'] = sorted((set(meta.get('linked', [])) | set(zone_names)) - {name})
            self._paths(name)[1].write_text(json.dumps(meta, indent=2))

    def linked(self, zone_name):
        """Other zones with drafts linked to this one, followed transitively."""
        seen, todo = {zone_name}, [zone_name]
        while todo:
            meta = self.meta(todo.pop()) or {}
            for other in meta.get('linked', []):
                if other not in seen and self._paths(other)[0].exists():
                    seen.add(other)
                    todo.append(other)
        return seen - {zone_name}

    def is_stale(self, zone_row):
        """True when the published copy changed after this draft was started."""
        meta = self.meta(zone_row['name'])
        return bool(meta) and meta['base_sha256'] != sha(self.published(zone_row))
