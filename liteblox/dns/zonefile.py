"""Lossless zone-file model.

A zone file is parsed into a list of entries: blank lines, comments,
$directives and resource records. Every entry keeps its original text, so
rendering an unedited zone reproduces the file byte-for-byte (line endings,
tabs and comments included). Edited and new records are re-rendered into the
column layout of their own line or their neighbour's, so a diff only shows the
lines that actually changed.
"""

import re

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.ttl

TABSTOP = 8
FIELDS = ('owner', 'ttl', 'class', 'type', 'rdata')
_LINE_END = re.compile(r'\r\n|\n|\r')


class ZoneParseError(ValueError):
    def __init__(self, message, line):
        super().__init__(f'line {line}: {message}')
        self.line = line


# ── Lexing ─────────────────────────────────────────────────────────────────────

def _physical_lines(text):
    """[(content, line_ending)], keeping '\\r\\n' / '\\n' / '\\r' / '' (last line, no newline)."""
    lines, pos = [], 0
    for m in _LINE_END.finditer(text):
        lines.append((text[pos:m.start()], m.group()))
        pos = m.end()
    if pos < len(text):
        lines.append((text[pos:], ''))
    return lines


def _lex_line(s, depth=0, lineno=0):
    """Split one physical line into tokens.

    Returns ([(text, start, end)], comment_start or None, paren depth after the line).
    Parentheses and comments are not tokens; quoted strings are one token, quotes included.
    """
    tokens, comment = [], None
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in ' \t':
            i += 1
        elif c == ';':
            comment = i
            break
        elif c == '(':
            depth += 1
            i += 1
        elif c == ')':
            if depth == 0:
                raise ZoneParseError("unbalanced ')'", lineno)
            depth -= 1
            i += 1
        elif c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == '\\' else 1
            if j >= n:
                raise ZoneParseError('unterminated quoted string', lineno)
            tokens.append((s[i:j + 1], i, j + 1))
            i = j + 1
        else:
            j = i
            while j < n and s[j] not in ' \t;()"':
                j += 2 if s[j] == '\\' else 1
            j = min(j, n)
            tokens.append((s[i:j], i, j))
            i = j
    return tokens, comment, depth


def _rdata_tokens(rdata):
    tokens, _, depth = _lex_line(rdata)
    if depth:
        raise ValueError("unbalanced '(' in record data")
    return [t[0] for t in tokens]


def _advance(col, text):
    for ch in text:
        col = (col // TABSTOP + 1) * TABSTOP if ch == '\t' else col + 1
    return col


def _pad(col, target, padchar):
    """Whitespace from visual column col to target (at least one character)."""
    if target is None or target <= col:
        return padchar
    if padchar == ' ':
        return ' ' * (target - col)
    out = ''
    while col < target:
        out += '\t'
        col = (col // TABSTOP + 1) * TABSTOP
    return out


def _is_ttl(tok):
    try:
        dns.ttl.from_text(tok)
        return True
    except (dns.ttl.BadTTL, ValueError):
        return False


def _is_class(tok):
    try:
        dns.rdataclass.from_text(tok)
        return not tok.isdigit()
    except (dns.rdataclass.UnknownRdataclass, ValueError):
        return False


def _is_type(tok):
    try:
        dns.rdatatype.from_text(tok)
        return not tok.isdigit()
    except (dns.rdatatype.UnknownRdatatype, ValueError):
        return False


# ── Entries ────────────────────────────────────────────────────────────────────

class Entry:
    """Anything in the file. raw is the original text including line endings."""

    def __init__(self, raw, line):
        self.raw = raw
        self.line = line

    def __repr__(self):
        return f'<{type(self).__name__} line {self.line}: {self.raw.strip()!r}>'


class Blank(Entry):
    pass


class Comment(Entry):
    pass


class Directive(Entry):
    """$TTL, $ORIGIN, $INCLUDE, $GENERATE (and any other $ line)."""

    def __init__(self, raw, line, name, args):
        super().__init__(raw, line)
        self.name = name
        self.args = args

    @property
    def editable(self):
        return self.name in ('$TTL', '$ORIGIN')


class Unparsed(Entry):
    """A line we could not make sense of. Kept verbatim, shown read-only."""

    def __init__(self, raw, line, error):
        super().__init__(raw, line)
        self.error = error


class Record(Entry):
    """One resource record.

    name is the absolute owner; ttl/rclass are None when the file leaves them
    implicit; rdata is the record data as text (tokens joined by single spaces
    for parsed records). The parse-time values are kept so rendering can tell
    which fields changed and reuse the original text for the rest.
    """

    def __init__(self, id, name, rtype, rdata, ttl=None, rclass=None, comment=None,
                 owner_explicit=True, raw='', line=0):
        super().__init__(raw, line)
        self.id = id
        self.name = name
        self.rtype = rtype
        self.rdata = rdata
        self.ttl = ttl
        self.rclass = rclass
        self.comment = comment
        self.owner_explicit = owner_explicit
        self.origin = None          # $ORIGIN in effect, set by Zone._recontext
        self.default_ttl = None     # $TTL in effect
        # parse-time details
        self._orig = None           # (name, ttl, rclass, rtype, rdata, comment)
        self._tokens = {}           # field -> (text, start, end) in raw; 'rdata' -> list
        self._multiline = False
        self._ending = ''
        self._cols = {}             # field -> visual start column (single-line layout)
        self._gaps = {}             # field -> (column where the gap starts, original gap text)
        self._tail = ''             # text after rdata on a single line: whitespace + comment
        self._padchar = '\t'

    def __repr__(self):
        return f'<Record #{self.id} {self.name} {self.rtype} {self.rdata!r}>'

    def _values(self):
        return (self.name, self.ttl, self.rclass, self.rtype, self.rdata, self.comment)

    @property
    def is_new(self):
        return self._orig is None

    @property
    def dirty(self):
        return self._orig is None or self._values() != self._orig

    def relative_name(self, origin=None):
        """Owner relative to origin (default: the $ORIGIN in effect), '@' for the origin itself."""
        return self.name.relativize(origin or self.origin).to_text()

    # ── rendering ──

    def render(self, prev_name, newline):
        force_owner = not self.owner_explicit and self.name != prev_name
        if not self.dirty and not force_owner:
            return self.raw
        if self._multiline and not force_owner:
            text = self._render_inplace()
            if text is not None:
                return text
        return self._render_line(force_owner) + (self._ending or newline)

    def _field_text(self, field):
        """Current text for a non-rdata field, reusing the original token when unchanged."""
        name, ttl, rclass, rtype, _, _ = self._orig or (None,) * 6
        orig = self._tokens.get(field)
        if field == 'owner':
            if orig and self.name == name:
                return orig[0]
            return self.relative_name()
        if field == 'ttl':
            return orig[0] if orig and self.ttl == ttl else str(self.ttl)
        if field == 'class':
            return orig[0] if orig and self.rclass == rclass else self.rclass
        if field == 'type':
            return orig[0] if orig and self.rtype == rtype else self.rtype
        raise KeyError(field)

    def _rdata_text(self):
        """Current rdata; when the token count is unchanged, substitute tokens into the original text."""
        orig = self._tokens.get('rdata')
        if not orig:
            return self.rdata
        new = _rdata_tokens(self.rdata)
        if len(new) != len(orig):
            return self.rdata
        base = orig[0][1]
        text = self.raw[base:orig[-1][2]]
        for (old, start, end), tok in sorted(zip(orig, new), key=lambda p: -p[0][1]):
            if tok != old:
                text = text[:start - base] + tok + text[end - base:]
        return text

    def _render_line(self, force_owner):
        fields = []
        if self.owner_explicit or force_owner:
            fields.append(('owner', self._field_text('owner')))
        if self.ttl is not None:
            fields.append(('ttl', self._field_text('ttl')))
        if self.rclass is not None:
            fields.append(('class', self._field_text('class')))
        fields.append(('type', self._field_text('type')))
        fields.append(('rdata', self._rdata_text() if not self._multiline else self.rdata))

        out, col = '', 0
        for i, (field, text) in enumerate(fields):
            if i == 0 and field != 'owner':
                # implicit owner: line starts with whitespace
                gap = self._gaps.get(field)
                ws = gap[1] if gap and gap[0] == 0 else _pad(0, self._cols.get(field), self._padchar)
                out, col = ws, _advance(0, ws)
            elif i > 0:
                gap = self._gaps.get(field)
                ws = gap[1] if gap and gap[0] == col else _pad(col, self._cols.get(field), self._padchar)
                out += ws
                col = _advance(col, ws)
            out += text
            col = _advance(col, text)
        return out + self._render_tail()

    def _render_tail(self):
        orig_comment = self._orig[5] if self._orig else None
        if self.comment == orig_comment and not self._multiline:
            return self._tail
        if not self.comment:
            return ''
        sep = self._tail[:len(self._tail) - len(self._tail.lstrip(' \t'))] or self._padchar
        return f'{sep}; {self.comment}'

    def _render_inplace(self):
        """Substitute changed tokens in a multi-line record, keeping its layout and inner comments."""
        name, ttl, rclass, rtype, rdata, comment = self._orig
        if (self.comment != comment or (self.ttl is None) != (ttl is None)
                or (self.rclass is None) != (rclass is None)):
            return None
        new_rdata = _rdata_tokens(self.rdata)
        if len(new_rdata) != len(self._tokens['rdata']):
            return None

        subs = []
        for field in ('owner', 'ttl', 'class', 'type'):
            if field in self._tokens:
                subs.append((self._tokens[field], self._field_text(field)))
        subs += list(zip(self._tokens['rdata'], new_rdata))
        text = self.raw
        for (old, start, end), new in sorted(subs, key=lambda p: -p[0][1]):
            if new != old:
                text = text[:start] + new + text[end:]
        return text


# ── Zone ───────────────────────────────────────────────────────────────────────

class Zone:
    def __init__(self, origin, entries, newline='\n'):
        self.origin = origin
        self.entries = entries
        self.newline = newline
        self._next_id = 1 + max((e.id for e in entries if isinstance(e, Record)), default=0)
        self._recontext()

    # ── parsing ──

    @classmethod
    def parse(cls, text, origin):
        if isinstance(origin, str):
            origin = dns.name.from_text(origin)
        lines = _physical_lines(text)
        crlf = sum(1 for _, end in lines if end == '\r\n')
        newline = '\r\n' if crlf > len(lines) // 2 else '\n'

        entries, ids = [], iter(range(1, len(lines) + 2))
        current_origin, prev_name = origin, origin
        i = 0
        while i < len(lines):
            first = i
            depth, parts, toks, first_comment = 0, [], [], None
            offset = 0
            while True:
                content, ending = lines[i]
                tokens, comment, depth = _lex_line(content, depth, i + 1)
                toks += [(t, s + offset, e + offset, len(parts)) for t, s, e in tokens]
                if comment is not None and first_comment is None and len(parts) == 0:
                    first_comment = comment
                parts.append((content, ending))
                offset += len(content) + len(ending)
                i += 1
                if depth == 0:
                    break
                if i >= len(lines):
                    raise ZoneParseError("unclosed '('", first + 1)

            raw = ''.join(c + e for c, e in parts)
            entry = cls._classify(raw, parts, toks, first_comment, first + 1, ids,
                                  current_origin, prev_name)
            if isinstance(entry, Directive) and entry.name == '$ORIGIN' and entry.args:
                current_origin = dns.name.from_text(entry.args[0], current_origin)
            if isinstance(entry, Record):
                prev_name = entry.name
            entries.append(entry)

        return cls(origin, entries, newline)

    @staticmethod
    def _classify(raw, parts, toks, first_comment, lineno, ids, origin, prev_name):
        if not toks:
            return Comment(raw, lineno) if ';' in raw else Blank(raw, lineno)

        texts = [t[0] for t in toks]
        if texts[0].startswith('$'):
            return Directive(raw, lineno, texts[0].upper(), texts[1:])

        owner_explicit = not parts[0][0][:1] in (' ', '\t')
        idx = 0
        if owner_explicit:
            try:
                name = dns.name.from_text(texts[0], origin)
            except dns.exception.DNSException as e:
                return Unparsed(raw, lineno, f'bad owner name: {e}')
            idx = 1
        else:
            name = prev_name

        ttl = rclass = None
        field_tok = {}
        for _ in range(2):
            if idx >= len(texts):
                break
            if ttl is None and _is_ttl(texts[idx]):
                ttl, field_tok['ttl'] = dns.ttl.from_text(texts[idx]), toks[idx]
            elif rclass is None and _is_class(texts[idx]):
                rclass, field_tok['class'] = texts[idx].upper(), toks[idx]
            else:
                break
            idx += 1

        if idx >= len(texts) or not _is_type(texts[idx]):
            return Unparsed(raw, lineno, 'missing or unknown record type')
        rtype = dns.rdatatype.to_text(dns.rdatatype.from_text(texts[idx]))
        field_tok['type'] = toks[idx]
        rdata_toks = toks[idx + 1:]

        comment = None
        if first_comment is not None:
            comment = parts[0][0][first_comment + 1:].strip() or None

        rec = Record(next(ids), name, rtype, ' '.join(t[0] for t in rdata_toks), ttl, rclass,
                     comment, owner_explicit, raw, lineno)
        rec._orig = rec._values()
        rec._multiline = len(parts) > 1
        rec._ending = parts[-1][1]
        if owner_explicit:
            field_tok['owner'] = toks[0]
        rec._tokens = {f: t[:3] for f, t in field_tok.items()}
        rec._tokens['rdata'] = [t[:3] for t in rdata_toks]

        if not rec._multiline:
            content = parts[0][0]
            ordered = sorted(((t[1], f) for f, t in rec._tokens.items() if f != 'rdata'))
            if rdata_toks:
                ordered.append((rdata_toks[0][1], 'rdata'))
            prev_end = 0
            for start, field in ordered:
                gap = content[prev_end:start]
                gap_col = _advance(0, content[:prev_end])
                rec._cols[field] = _advance(0, content[:start])
                if gap:
                    rec._gaps[field] = (gap_col, gap)
                end = rdata_toks[-1][2] if field == 'rdata' else rec._tokens[field][2]
                prev_end = end
            rec._tail = content[prev_end:]
            gaps = ''.join(g for _, g in rec._gaps.values())
            rec._padchar = '\t' if '\t' in gaps or not gaps else ' '
        return rec

    def _recontext(self):
        """Set the $ORIGIN and $TTL in effect on every record."""
        origin, default_ttl = self.origin, None
        for e in self.entries:
            if isinstance(e, Directive):
                if e.name == '$ORIGIN' and e.args:
                    origin = dns.name.from_text(e.args[0], origin)
                elif e.name == '$TTL' and e.args:
                    default_ttl = dns.ttl.from_text(e.args[0])
                e.origin, e.default_ttl = origin, default_ttl
            elif isinstance(e, Record):
                e.origin, e.default_ttl = origin, default_ttl

    # ── rendering ──

    def render(self):
        out, prev_name = [], self.origin
        for e in self.entries:
            if isinstance(e, Record):
                text = e.render(prev_name, self.newline)
                prev_name = e.name
            else:
                text = e.raw
            if out and out[-1] and not out[-1].endswith(('\n', '\r')):
                out[-1] += self.newline     # an entry now follows the old last line
            out.append(text)
        return ''.join(out)

    # ── queries ──

    def records(self):
        return [e for e in self.entries if isinstance(e, Record)]

    def get(self, record_id):
        for e in self.entries:
            if isinstance(e, Record) and e.id == record_id:
                return e
        raise KeyError(record_id)

    @property
    def soa(self):
        for rec in self.records():
            if rec.rtype == 'SOA':
                return rec
        raise LookupError('zone has no SOA record')

    @property
    def unsupported(self):
        """Entries the row editor can't handle ($INCLUDE, $GENERATE, unparsable lines)."""
        return [e for e in self.entries
                if isinstance(e, Unparsed) or (isinstance(e, Directive) and not e.editable)]

    # ── serial ──

    @property
    def serial(self):
        return int(_rdata_tokens(self.soa.rdata)[2])

    @serial.setter
    def serial(self, value):
        soa = self.soa
        tokens = _rdata_tokens(soa.rdata)
        tokens[2] = str(value)
        soa.rdata = ' '.join(tokens)

    # ── editing ──

    def name_from_text(self, text):
        return dns.name.from_text(text.strip(), self.origin)

    def add(self, name, rtype, rdata, ttl=None, comment=None, after=None):
        """Insert a record after `after` (a Record), or after the last record of the same type."""
        if after is None:
            same_type = [r for r in self.records() if r.rtype == rtype.upper()]
            after = same_type[-1] if same_type else (self.records() or [None])[-1]
        pos = self.entries.index(after) + 1 if after is not None else len(self.entries)

        rec = Record(self._next_id, self.name_from_text(name), rtype.upper(), rdata.strip(),
                     ttl, 'IN' if after is not None and after.rclass else None,
                     comment or None)
        self._next_id += 1
        if after is not None:
            rec._cols, rec._padchar = dict(after._cols), after._padchar
        self.entries.insert(pos, rec)
        self._recontext()
        return rec

    def update(self, rec, *, name=None, rtype=None, rdata=None, ttl=..., comment=...):
        if name is not None:
            new_name = self.name_from_text(name)
            if new_name != rec.name:
                rec.name, rec.owner_explicit = new_name, True
        if rtype is not None:
            rec.rtype = rtype.upper()
        if rdata is not None:
            rec.rdata = rdata.strip()
        if ttl is not ...:
            rec.ttl = ttl
        if comment is not ...:
            rec.comment = comment or None
        return rec

    def delete(self, rec):
        self.entries.remove(rec)
