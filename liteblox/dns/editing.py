"""Changing a zone's records: the record grid and the API share this.

A static zone's edits go into its draft; a dynamic zone's go out at once as
one guarded update (dynamic.send_edit). An A/AAAA change can also change the
matching PTR in a reverse zone LiteBlox holds (sync_ptr). Writes to one zone
take its lock and read the zone inside it, so two edits arriving together
(a page and a script) can't overwrite each other's draft.
"""

import contextlib
import threading

import dns.ttl

from ..db import audit
from . import dynamic, ptr, records
from .drafts import Drafts, rev
from .zonefile import Zone, ZoneParseError, _rdata_tokens

SOA_KEYS = ('mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum')
SOA_TIMERS = ('refresh', 'retry', 'expire', 'minimum')


class ZoneError(Exception):
    pass


class NoSuchZone(ZoneError):
    pass


class ForwardingZone(ZoneError):
    """A forwarding zone has no records, history or publish."""


_locks, _locks_lock = {}, threading.Lock()


@contextlib.contextmanager
def zone_lock(name):
    """One write at a time per zone in this process (reentrant: a PTR change locks its reverse zone too)."""
    with _locks_lock:
        lock = _locks.setdefault(name, threading.RLock())
    with lock:
        yield


class ZoneEdit:
    """A zone's DB row, drafts and parsed working copy (the draft, the published copy, or what named serves)."""

    def __init__(self, settings, conn, name, forwarding_ok=False):
        self.settings = settings
        self.row = conn.execute('SELECT * FROM zones WHERE name = ?', (name,)).fetchone()
        if self.row is None:
            raise NoSuchZone(name)
        self.forwarding = self.row['kind'] == 'forwarding'
        if self.forwarding and not forwarding_ok:
            raise ForwardingZone(name)
        self.dynamic = bool(self.row['dynamic'])
        self.conn = conn
        self.name = name
        self.drafts = Drafts(settings)
        if self.dynamic:
            # named owns it: what it serves now is the working copy, and an edit goes out as an update
            self.text, self.is_draft = dynamic.axfr(conn, self.row), False
        else:
            self.text, self.is_draft = self.drafts.load(self.row)
        self.rev = rev(self.text)
        try:
            self.zone = Zone.parse(self.text, name + '.')
            self.error = None
        except ZoneParseError as e:
            self.zone, self.error = None, str(e)

    def published_zone(self):
        if self.dynamic:
            return self.zone
        try:
            return Zone.parse(self.drafts.published(self.row), self.name + '.')
        except ZoneParseError:
            return None

    def summary(self):
        if not self.is_draft or self.zone is None:
            return None
        published = self.published_zone()
        return records.summarize(published, self.zone) if published else None

    def save(self, username):
        if self.dynamic:
            self.text = dynamic.send_edit(self.settings, self.conn, self.row, self.text, self.zone.render(),
                                          username, 'Edit')
            self.rev = rev(self.text)
            self.zone = Zone.parse(self.text, self.name + '.')
            return
        self.is_draft = self.drafts.save(self.row, self.zone.render(), username)
        self.text, _ = self.drafts.load(self.row)      # sorted, in a zone LiteBlox keeps sorted
        self.rev = rev(self.text)
        # re-parse: record ids are positions in a parse, and the next request will
        # parse the saved text; rendering the in-memory zone after an insert would
        # show ids that point at different records on the next request
        self.zone = Zone.parse(self.text, self.name + '.')


def find(edit, record_id=None, key=None, rr=None):
    """The record a grid row (record_id: its position), the API (key: dynamic.record_key) or a dynamic zone's
    row (rr: dynamic.rr_token) names; None when it's gone, or its RRset changed since the token was read.
    Raises KeyError for a grid position that doesn't exist."""
    if rr:
        return dynamic.find_token(edit.zone, rr)
    if key:
        return next((r for r in edit.zone.records() if dynamic.record_key(r) == key), None)
    return edit.zone.get(record_id)


class Op:
    """One change for batch(): add (rec None), change (rec and the new fields) or delete (rec, delete=True)."""

    def __init__(self, rec=None, name='', ttl=None, rtype='', rdata='', comment=None, after=None, delete=False):
        self.rec, self.name, self.ttl, self.rtype, self.rdata = rec, name, ttl, rtype, rdata
        self.comment, self.after, self.delete = comment, after, delete

    @classmethod
    def removing(cls, rec):
        return cls(rec=rec, delete=True)


def _stage(edit, op):
    """Apply one op to the working copy in memory. Returns (old, new, warnings); raises RecordError."""
    rec = op.rec
    if op.delete:
        old = (rec.name, rec.rtype, rec.rdata)
        edit.zone.delete(rec)
        return old, None, []
    owner, ttl, rtype, warnings = records.check(edit.zone, rec, op.name, op.ttl, op.rtype, op.rdata)
    rdata = op.rdata
    if rec is None or (rtype, rdata, owner) != (rec.rtype, rec.rdata, rec.name):
        from ..ipam.checks import record_warnings      # a changed A record, not a comment or TTL change
        warnings += record_warnings(edit.conn, owner.to_text(), rtype, rdata)
    name_text = owner.relativize(edit.zone.origin).to_text()
    old = (rec.name, rec.rtype, rec.rdata) if rec is not None else None
    if rec is None:
        edit.zone.add(name_text, rtype, rdata, ttl=ttl, comment=op.comment or None, after=op.after)
    else:
        if rtype == rec.rtype and records.same_data(rtype, rec.rdata, rdata, rec.origin):
            rdata = rec.rdata       # semantically unchanged: keep the original text and layout
        edit.zone.update(rec, name=name_text, rtype=rtype, rdata=rdata, ttl=ttl, comment=op.comment or None)
    return old, (owner, rtype, rdata), warnings


def _saved(edit, new):
    """The record a staged change became, found again in the saved zone (in a sorted zone it may have moved)."""
    owner, rtype, rdata = new
    tokens = _rdata_tokens(rdata)
    return next((r for r in reversed(edit.zone.records()) if r.name == owner and r.rtype == rtype
                 and _rdata_tokens(r.rdata) == tokens), None)


def stage_all(edit, ops):
    """Stage every op in the working copy, in order. Returns ([(old, new)], warnings); on a bad op raises
    RecordError with .index (the failing op) after dropping everything staged."""
    staged, warnings = [], []
    for i, op in enumerate(ops):
        try:
            old, new, op_warnings = _stage(edit, op)
        except records.RecordError as e:
            e.index = i
            unstage(edit)
            raise
        staged.append((old, new))
        warnings += op_warnings
    return staged, warnings


def unstage(edit):
    """Drop what was staged: the working copy as it was read."""
    edit.zone = Zone.parse(edit.text, edit.name + '.')


def commit(edit, staged, ptr_on, username, via=''):
    """Save what stage_all staged, once (a draft, or one update for a dynamic zone), then let the PTRs follow.
    Returns (notes, warnings, [the record each change became, or None])."""
    edit.save(username)
    saved = [_saved(edit, new) if new else None for _, new in staged]
    notes, warnings = sync_ptrs(edit, staged, username, via) if ptr_on else ([], [])
    return notes, warnings, saved


def batch(edit, ops, ptr_on, username, via=''):
    """Apply many changes as one: all are checked against the working copy as it changes, and only when every
    one is good is the zone saved, once; then the PTRs follow. Returns (notes, warnings, [the record each op
    became, or None]); raises RecordError with .index (the failing op) and leaves nothing saved."""
    staged, warnings = stage_all(edit, ops)
    notes, more, saved = commit(edit, staged, ptr_on, username, via)
    return notes, warnings + more, saved


def apply_row(edit, rec, name, ttl, rtype, rdata, comment, ptr_on, after, username, via=''):
    """Add a record (rec None) or change one; then mirror an A/AAAA change into PTRs when ptr_on.
    Returns (notes, warnings, the record as saved, or None if it can't be found again); raises RecordError."""
    notes, warnings, saved = batch(edit, [Op(rec, name, ttl, rtype, rdata, comment, after)], ptr_on, username, via)
    return notes, warnings, saved[0]


def delete_row(edit, rec, ptr_on, username, via=''):
    """Delete a record, and its PTR when ptr_on. Returns (notes, warnings)."""
    notes, warnings, _ = batch(edit, [Op.removing(rec)], ptr_on, username, via)
    return notes, warnings


def sync_ptr(edit, old, new, username, via=''):
    """Mirror one A/AAAA change into reverse zones LiteBlox holds. Returns (notes, warnings)."""
    return sync_ptrs(edit, [(old, new)], username, via)


def sync_ptrs(edit, pairs, username, via=''):
    """Mirror A/AAAA changes [(old, new)] into reverse zones LiteBlox holds, each reverse zone read and saved
    once. Returns (notes, warnings)."""
    conn = edit.conn
    notes, warnings = [], []
    todo = [c for old, new in pairs for c in ptr.changes(old, new)]
    if not todo:
        return notes, warnings
    names = [r['name'] for r in conn.execute("SELECT name FROM zones WHERE kind = 'primary'")]
    touched = {}
    with contextlib.ExitStack() as stack:     # each reverse zone's lock, from reading it to saving it
        for kind, address, target in todo:
            if kind == 'add' and not ptr.is_host_name(target):
                notes.append(f'no PTR for {target}: a PTR has to point at a host name, so wildcards and names '
                             'with underscores never get one')
                continue
            rname = ptr.reverse_zone_for(address, names)
            if rname is None or rname == edit.name:
                if kind == 'add':
                    notes.append(f'no reverse zone for {address} in LiteBlox, so no PTR was added')
                continue
            rrow = conn.execute('SELECT * FROM zones WHERE name = ?', (rname,)).fetchone()
            if rrow['dynamic'] and not edit.dynamic:
                # a static forward zone's change isn't live until it's published: send the PTR then
                dynamic.queue_ptr(conn, edit.row, rrow, [(kind, address, target)])
                notes.append(f'{f"PTR {address} → {target}" if kind == "add" else f"removing the PTR for {address}"} '
                             f'in {rname} is sent when you publish {edit.name}')
                continue
            redit = touched.get(rname)
            if redit is None:
                stack.enter_context(zone_lock(rname))
                redit = ZoneEdit(edit.settings, conn, rname)
            if redit.zone is None:
                warnings.append(f'{rname} does not parse, so its PTR was not updated; fix it on its Raw tab')
                continue
            changed, message = ptr.apply(redit.zone, kind, address, target)
            if message:
                (notes if changed else warnings).append(message)
            if changed:
                touched[rname] = redit
        for rname, redit in touched.items():
            redit.save(username)
            if not edit.dynamic and not redit.dynamic:
                edit.drafts.link(edit.name, rname)        # reviewed and published together
            elif not redit.dynamic:
                notes.append(f'the PTR change is a draft in {rname}: publish it there')
            audit(conn, username, 'ptr_sync', f'{rname} from {edit.name}{via}')
        return notes, warnings


def seconds(text):
    """'1h' → '3600', so the file keeps plain seconds; anything unparsable is left for check_rdata to report."""
    try:
        return str(dns.ttl.from_text(text))
    except (dns.ttl.BadTTL, ValueError):
        return text


def soa_fields(zone):
    return dict(zip(SOA_KEYS, _rdata_tokens(zone.soa.rdata)))


def save_soa(edit, fields, username, via=''):
    """Change the SOA's names and timers (the serial stays LiteBlox's). Returns an error text, or None."""
    from .validate import check_rdata
    current = soa_fields(edit.zone)
    values = [current['serial'] if k == 'serial' else seconds((fields.get(k) or '').strip()) if k in SOA_TIMERS
              else (fields.get(k) or '').strip() for k in SOA_KEYS]
    rdata = ' '.join(values)
    problem = check_rdata('SOA', rdata, edit.zone.origin)
    if problem:
        return problem
    if not records.same_data('SOA', edit.zone.soa.rdata, rdata, edit.zone.origin):
        edit.zone.update(edit.zone.soa, rdata=rdata)
        edit.save(username)
        audit(edit.conn, username, 'soa_edit', edit.name + via)
    return None


def discard(edit, username, via=''):
    """Drop a static zone's draft and the drafts linked to it, and the PTR updates waiting for its publish."""
    zones = [edit.name, *sorted(edit.drafts.linked(edit.name))]
    for zone in zones:
        edit.drafts.discard(zone)
        audit(edit.conn, username, 'draft_discard', zone + via)
    dynamic.drop_ptr_queue(edit.conn, edit.row['id'])
    return zones
