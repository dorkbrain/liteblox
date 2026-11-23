"""Import a node's existing BIND config into the model, and prove the generated one equivalent.

import_config() maps the printed config (named-checkconf -px, plus -p for key
secrets only) to a NodeConfig: options that a field renders back identically
become fields, everything else is kept verbatim as extra statements. What the
model can't hold yet becomes a blocker. equivalence() compares the node's
printed config with the candidate's, after normalizing what legitimately
differs (statement order, master/primary, relocated zone files).
"""

import difflib
import posixpath
from dataclasses import dataclass, field
from typing import Optional

from ..nodes import agent_module
from .model import DEBIAN, Acl, NodeConfig, NodeOptions, TsigKey, ZoneDecl

DISTRO_FILES = ('named.conf.default-zones', 'named.conf.root-hints', 'rndc.key')
# options a stock bind9 package writes; anything else makes the node "not fresh"
STOCK_OPTIONS = ('directory', 'dnssec-validation', 'listen-on', 'listen-on-v6')
LIST_FIELDS = {'allow-query': 'allow_query', 'allow-recursion': 'allow_recursion', 'listen-on': 'listen_on',
               'listen-on-v6': 'listen_on_v6', 'forwarders': 'forwarders', 'validate-except': 'validate_except'}
WORD_FIELDS = {'dnssec-validation': ('dnssec_validation', ('auto', 'yes', 'no')),
               'forward': ('forward', ('first', 'only'))}
ZONE_SETTINGS = {'notify': 'notify', 'also-notify': 'also_notify', 'allow-transfer': 'allow_transfer',
                 'allow-query': 'allow_query'}
LATER = {'secondary': "a secondary of a server outside LiteBlox isn't supported yet"}
RENAMES = {'master': 'primary', 'slave': 'secondary', 'masters': 'primaries'}
RELOCATED = '<zone file>'


@dataclass
class ImportedZone:
    name: str
    old_file: Optional[str]
    new_file: Optional[str]
    settings: dict                  # the zones columns it sets (notify ... or forwarders / forward_mode)
    row: Optional[dict] = None      # the zone in LiteBlox, if it is there already
    kind: str = 'primary'           # or 'forwarding': no file
    dynamic: bool = False
    grants: list = field(default_factory=list)      # (key, scope, name, types) from its update-policy

    @property
    def relocated(self):
        return self.old_file != self.new_file


@dataclass
class ImportPlan:
    config: NodeConfig
    zones: list = field(default_factory=list)
    acls: list = field(default_factory=list)        # imported (new to LiteBlox)
    keys: list = field(default_factory=list)
    retire: list = field(default_factory=list)
    left_in_place: list = field(default_factory=list)
    own_options: list = field(default_factory=list)  # option keywords beyond the stock ones
    blockers: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def fresh(self):
        """What the bind9 package installs: nothing of the node's own to import."""
        c = self.config
        return not (self.zones or self.acls or self.keys or self.own_options or c.top_extra.strip()
                    or c.options.extra.strip())


# ── printing parsed statements ─────────────────────────────────────────────────

def _word(kind, value):
    return f'"{value}"' if kind == 's' else value


def inline(st, quote=True):
    """A statement on one line without its final ';'. quote=False for list items: -p quotes
    names (\"trusted\", key \"x\") that LiteBlox's lists hold bare."""
    head = ' '.join(_word(k, v) if quote else v for k, v in st.words)
    if st.block is None:
        return head
    body = ' '.join(inline(c, quote) + ';' for c in st.block)
    return (head + ' ' if head else '') + '{ ' + body + (' }' if body else '}')


def print_statement(st, depth=0):
    pad = '\t' * depth
    head = ' '.join(_word(k, v) for k, v in st.words)
    if st.block is None:
        return f'{pad}{head};'
    inner = ''.join(print_statement(c, depth + 1) + '\n' for c in st.block)
    return f'{pad}{head} {{\n{inner}{pad}}};'


def _items(st):
    """Items of a simple list statement, or None when it has words or nesting a field can't hold."""
    if len(st.words) != 1 or st.block is None or any(c.block is not None for c in st.block):
        return None
    return [inline(c, quote=False) for c in st.block]


# ── import ─────────────────────────────────────────────────────────────────────

def _options(st, layout, plan):
    options, extra = NodeOptions(), []
    for opt in st.block or ():
        kw, words = opt.keyword, [w for _, w in opt.words]
        if kw not in STOCK_OPTIONS:
            plan.own_options.append(kw)
        if kw == 'directory':
            if words[1:] != [layout.directory]:
                plan.blockers.append(f'options: directory is {" ".join(words[1:])}; LiteBlox needs '
                                     f'"{layout.directory}"')
            continue
        if kw in LIST_FIELDS and getattr(options, LIST_FIELDS[kw]) is None:
            items = _items(opt)
            if kw == 'validate-except' and items and any(i.endswith('.') for i in items):
                items = None        # the field writes names without the final dot
            if items is not None:
                setattr(options, LIST_FIELDS[kw], items)
                continue
        elif kw == 'recursion' and words[1:] in (['yes'], ['no']) and options.recursion is None:
            options.recursion = words[1] == 'yes'
            continue
        elif kw in WORD_FIELDS and len(words) == 2 and opt.block is None and words[1] in WORD_FIELDS[kw][1]:
            attr = WORD_FIELDS[kw][0]
            if getattr(options, attr) is None:
                setattr(options, attr, words[1])
                continue
        extra.append(print_statement(opt))
    options.extra = '\n'.join(extra)
    return options


def _zone(st, info, distro, layout, known, plan):
    """An ImportedZone for a zone statement, or None (kept via a distro file, or a blocker)."""
    name = info['name'] if info else st.words[1][1]
    if info is None or info.get('view'):
        plan.blockers.append(f'zone {name}: not found in the node\'s zone list')
        return None
    if info['builtin'] or info['type'] == 'hint':
        if info.get('declared_in') in distro:
            return None
        plan.blockers.append(f'zone {name}: a {info["type"]} zone declared outside the distro\'s own files')
        return None
    if info['type'] == 'forward':
        return _forward_zone(st, name, known, plan)
    if info['type'] != 'primary':
        plan.blockers.append(f'zone {name}: type {info["type"]}: '
                             + LATER.get(info['type'], 'LiteBlox does not handle this zone type'))
        return None
    grants = None
    if st.child('allow-update') or st.child('update-policy'):
        grants = _grants(st, name, known, plan)
        if grants is None:
            return None
    from ..dns.declare import parse_list
    settings = {'notify': '', 'also_notify': '', 'allow_transfer': '', 'allow_query': ''}
    ok = True
    for opt in st.block or ():
        if opt.keyword in ('type', 'file', 'allow-update', 'update-policy'):
            continue
        column = ZONE_SETTINGS.get(opt.keyword)
        if column is None:
            plan.blockers.append(f'zone {name}: option {opt.keyword} is not supported yet')
            ok = False
        elif column == 'notify':
            words = [w for _, w in opt.words]
            if len(words) != 2 or words[1] not in ('yes', 'no', 'explicit'):
                plan.blockers.append(f'zone {name}: notify {" ".join(words[1:])} is not supported yet')
                ok = False
            else:
                settings['notify'] = words[1]
        else:
            items = _items(opt)
            try:
                if items is None:
                    raise ValueError(f'{inline(opt)} is not a simple list')
                parse_list('\n'.join(items))
            except ValueError as e:
                plan.blockers.append(f'zone {name}: {opt.keyword}: {e}')
                ok = False
                continue
            settings[column] = '\n'.join(items)
    if not ok:
        return None
    if grants is not None:
        # named owns a dynamic zone's file: it moves to the dynamic zones' directory
        return ImportedZone(name, info['file'], f'{layout.dyn_dir}/db.{name}', settings, dynamic=True, grants=grants)
    zone = ImportedZone(name, info['file'], f'{layout.config_dir}/db.{name}', settings)
    return _match_known(zone, known, plan)


def _grants(st, name, known, plan):
    """[(key, scope, name, types)] for a dynamic zone's update rules, or None (a blocker).

    LiteBlox writes updates as key grants (keys.py), so it takes `grant KEY
    zonesub|subdomain|name ...` rules and `allow-update { key K; }` (the same as
    `grant K zonesub ANY`); anything else stays the node's own business.
    """
    def block(why):
        plan.blockers.append(f'zone {name}: {why}')
        return None
    if known.get('zones', {}).get(name):
        return block('it is dynamic here and LiteBlox has it already; take this node over without it '
                     '(remove the zone here first)')
    if known.get('primary'):
        return block(f"it is dynamic, and {known['primary']} is already LiteBlox's primary: LiteBlox can only import "
                     'a dynamic zone onto a node before any primary is picked (move the zone to '
                     f"{known['primary']} by hand, or take this node over without it)")
    allow, policy = st.child('allow-update'), st.child('update-policy')
    if allow and policy:
        return block('both allow-update and update-policy are set')
    grants = []
    if allow:
        items = _items(allow) or []
        keys = [i.split()[1] for i in items if len(i.split()) == 2 and i.split()[0] == 'key']
        if not items or len(keys) != len(items):
            return block(f'{inline(allow)}: an update rule by address or ACL can\'t be expressed as a key grant; '
                         'switch its clients to a TSIG key first')
        grants = [(k, 'zonesub', '', 'ANY') for k in keys]
    else:
        if policy.block is None:
            return block(f'{inline(policy)}: only grant rules for TSIG keys can be imported')
        for rule in policy.block:
            words = [w for _, w in rule.words]
            if len(words) < 4 or words[0] != 'grant' or words[2] not in ('zonesub', 'subdomain', 'name'):
                return block(f'{inline(rule)}: only "grant KEY zonesub|subdomain|name ..." rules can be imported')
            key, scope = words[1], words[2]
            owner, types = ('', words[3:]) if scope == 'zonesub' else (words[3], words[4:])
            if not types:
                return block(f'{inline(rule)}: name the record types it may update (or ANY)')
            grants.append((key, scope, owner, ' '.join(types)))
    return grants


def _match_known(zone, known, plan):
    """Attach the zone LiteBlox already has by this name; its kind and the settings it writes must agree."""
    name, settings = zone.name, zone.settings
    k = known.get('zones', {}).get(name)
    if k:
        if (k['row'].get('kind') or 'primary') != zone.kind:
            plan.blockers.append(f"zone {name}: LiteBlox has it as a {k['row'].get('kind') or 'primary'} zone, "
                                 f'this node as a {zone.kind} zone')
            return None
        zone.row = k['row']
        if k['fixed']:
            differs = [c for c in settings if (k['row'][c] or '') != settings[c]]
            if differs:
                plan.blockers.append(f'zone {name}: its {", ".join(differs)} differ from LiteBlox\'s settings '
                                     'for this zone')
    return zone


def _forward_zone(st, name, known, plan):
    """An ImportedZone for `type forward`, or None (a blocker)."""
    from ..dns.declare import parse_forwarders
    settings = {'forwarders': '', 'forward_mode': ''}
    for opt in st.block or ():
        words = [w for _, w in opt.words]
        if opt.keyword == 'type':
            continue
        if opt.keyword == 'forward' and words[1:] in (['only'], ['first']):
            settings['forward_mode'] = words[1]
        elif opt.keyword == 'forwarders':
            items = _items(opt)
            try:
                if items is None:
                    raise ValueError(f'{inline(opt)} is not a simple list')
                settings['forwarders'] = '\n'.join(parse_forwarders('\n'.join(items)))
            except ValueError as e:
                plan.blockers.append(f'zone {name}: forwarders: {e}')
                return None
        else:
            plan.blockers.append(f'zone {name}: option {" ".join(words)} is not supported in a forwarding zone yet')
            return None
    return _match_known(ImportedZone(name, None, None, settings, kind='forwarding'), known, plan)


def import_config(masked, secret, layout=DEBIAN, known=None):
    """ImportPlan from the agent's /config (masked) and /config?secrets=1 (read for key secrets only).

    known: what LiteBlox has already, {'acls': {name: items}, 'keys': {name: (algorithm, secret)},
    'zones': {name: {'row': zone row, 'fixed': bool}}}; 'fixed' = settings LiteBlox already writes.
    """
    agent = agent_module()
    known = known or {}
    plan = ImportPlan(NodeConfig())
    if 'declared' not in masked:
        plan.blockers.append('the agent on this node is too old: run "Repair / upgrade agent" first')
        return plan
    bind_dir = posixpath.dirname(layout.named_conf)
    distro = []
    for path in masked['conf_files']:
        if path == layout.named_conf:
            continue
        if posixpath.dirname(path) == bind_dir and posixpath.basename(path) in DISTRO_FILES:
            distro.append(path)
        elif posixpath.dirname(path) == bind_dir:
            plan.retire.append(path)
        else:
            plan.left_in_place.append(path)
    plan.config.distro_includes = distro

    secrets = {}
    for st in agent.parse_conf(secret['checkconf']):
        if st.keyword == 'key' and len(st.words) > 1:
            secrets[st.words[1][1]] = st.value('secret')
    zone_info = {z['name']: z for z in masked['zones'] if not z.get('view')}
    top = []
    for st in agent.parse_conf(masked['checkconf']):
        kw = st.keyword
        name = st.words[1][1] if len(st.words) > 1 else None
        if kw == 'options':
            plan.config.options = _options(st, layout, plan)
        elif kw == 'acl' and name and st.block is not None:
            items = [inline(c, quote=False) for c in st.block]
            have = known.get('acls', {}).get(name)
            if have is None:
                plan.acls.append(Acl(name, items))
            elif have != items:
                plan.blockers.append(f'acl {name}: LiteBlox already has an ACL with this name and other contents')
        elif kw == 'key' and name and st.block is not None:
            if masked['declared'].get(f'key {name}') in distro:
                continue            # e.g. rndc-key from rndc.key, which stays the node's own
            algorithm = st.value('algorithm')
            have = known.get('keys', {}).get(name)
            if have is None:
                plan.keys.append(TsigKey(name, algorithm, secrets.get(name) or ''))
            elif have != (algorithm, secrets.get(name)):
                plan.blockers.append(f'key {name}: LiteBlox already has a key with this name and another secret')
        elif kw == 'zone' and name:
            zone = _zone(st, zone_info.get(agent.normalize_zone(name)), distro, layout, known, plan)
            if zone:
                plan.zones.append(zone)
        elif kw == 'view':
            plan.blockers.append(f'view {name}: views are not supported')
        else:
            top.append(print_statement(st))
    plan.config.top_extra = '\n'.join(top)
    have = set(known.get('keys', {})) | {k.name for k in plan.keys}
    for z in plan.zones:
        missing = sorted({g[0] for g in z.grants} - have)
        if missing:
            plan.blockers.append(f"zone {z.name}: its update rules name key(s) {', '.join(missing)}, which this "
                                 "node's config doesn't define")
    if any(not k.secret for k in plan.keys):
        plan.blockers.append('could not read the secret of key(s) '
                             + ', '.join(k.name for k in plan.keys if not k.secret))
    for z in plan.zones:
        if z.relocated:
            plan.left_in_place.append(z.old_file)
    # LiteBlox writes every ACL and key it has on every node, the imported ones included
    plan.config.acls = sorted([Acl(n, items) for n, items in known.get('acls', {}).items()] + plan.acls,
                              key=lambda a: a.name)
    plan.config.keys = sorted([TsigKey(n, alg, sec) for n, (alg, sec) in known.get('keys', {}).items()]
                              + plan.keys, key=lambda k: k.name)
    plan.config.zones = [
        ZoneDecl(z.name, kind='forward', forwarders=_split(z.settings['forwarders']),
                 forward_mode=z.settings['forward_mode'] or None) if z.kind == 'forwarding'
        else ZoneDecl(z.name, file=z.new_file, notify=z.settings['notify'] or None,
                      also_notify=_split(z.settings['also_notify']),
                      allow_transfer=_split(z.settings['allow_transfer']),
                      allow_query=_split(z.settings['allow_query']), dynamic=z.dynamic,
                      # the node's own rules, as written: LiteBlox's key joins them at its next change
                      update_policy=[grant_line(*g) for g in z.grants])
        for z in plan.zones]
    return plan


def grant_line(key, scope, name, types):
    return f'grant {key} {scope}' + (f' {name}' if name else '') + f' {types}'


def _split(text):
    return [i for i in text.split('\n') if i]


def check_allow_lists(files, layout=DEBIAN):
    """Run the agent's own allow-lists on a rendered set here, so refusals show up as blockers."""
    agent = agent_module()
    bind_dir = posixpath.dirname(layout.named_conf)
    cfg = dict(agent.DEFAULT_CONFIG, named_conf=layout.named_conf, managed_dir=layout.config_dir,
               dyn_dir=layout.dyn_dir, sec_dir=layout.sec_dir, directory=layout.directory,
               distro_includes=[f'{bind_dir}/{f}' for f in DISTRO_FILES])
    problems = []
    for role, text in files.items():
        try:
            agent.CONFIG_VALIDATORS[role](text, cfg)
        except agent.ConfError as e:
            problems.append(f'{role}: {e}')
    return problems


# ── equivalence ────────────────────────────────────────────────────────────────

def _normalize(st, relocated, in_zone=None):
    """A copy with the differences that don't matter removed (in_zone: the zone this is inside)."""
    agent = agent_module()
    if in_zone is not None and st.keyword == 'allow-update' and st.block is not None:
        items = [[w for _, w in c.words] for c in st.block]
        if items and all(len(i) == 2 and i[0] == 'key' and c.block is None for i, c in zip(items, st.block)):
            # what LiteBlox writes for it (importconf._grants)
            st = agent.Statement([('w', 'update-policy')],
                                 [agent.Statement([('w', 'grant'), ('w', i[1]), ('w', 'zonesub'), ('w', 'ANY')], None)
                                  for i in items])
    # quoted and bare words mean the same to BIND (-p quotes names; hand-written files often don't)
    words = [('w', v) for _, v in st.words]
    if in_zone is not None:
        if words and words[0][1] in RENAMES:                      # masters → primaries
            words[0] = (words[0][0], RENAMES[words[0][1]])
        if st.keyword == 'type' and len(words) > 1:               # master → primary
            words[1] = (words[1][0], RENAMES.get(words[1][1], words[1][1]))
        if st.keyword == 'file' and in_zone in relocated:
            words = [words[0], ('w', RELOCATED)]
    block = None
    if st.block is not None:
        zone = (agent.normalize_zone(st.words[1][1]) if st.keyword == 'zone' and len(st.words) > 1
                else in_zone)
        block = [_normalize(c, relocated, zone) for c in st.block]
        if st.keyword in ('options', 'zone'):
            block.sort(key=lambda c: c.keyword)
    return agent.Statement(words, block)


def _key(st):
    return (st.keyword, st.words[1][1].lower().rstrip('.') if len(st.words) > 1 else '')


def equivalence(current, candidate, relocated=()):
    """(diff text, notes) between the node's printed config and the candidate's; empty diff = equivalent.

    ACLs and keys only the candidate has (LiteBlox's other nodes' lists, unused
    here) are left out of the comparison and named in the notes.
    """
    agent = agent_module()
    relocated = set(relocated)
    now = [_normalize(st, relocated) for st in agent.parse_conf(current)]
    new = [_normalize(st, relocated) for st in agent.parse_conf(candidate)]
    have = {_key(st) for st in now}
    notes = [f'{st.keyword} {st.words[1][1]} is defined too (LiteBlox defines it on every node)'
             for st in new if st.keyword in ('acl', 'key') and _key(st) not in have]
    new = [st for st in new if st.keyword not in ('acl', 'key') or _key(st) in have]
    if not any(st.keyword == 'statistics-channels' for st in now):
        if any(st.keyword == 'statistics-channels' for st in new):
            notes.append("BIND's statistics channel is added on 127.0.0.1:8053 (the Dashboard reads the query "
                         'counters there)')
        new = [st for st in new if st.keyword != 'statistics-channels']

    def lines(stmts):
        return [print_statement(st) + '\n' for st in sorted(stmts, key=_key)]
    a = ''.join(lines(now)).splitlines(keepends=True)
    b = ''.join(lines(new)).splitlines(keepends=True)
    return ''.join(difflib.unified_diff(a, b, 'node now', 'generated by LiteBlox')), notes
