import re
import shutil
import subprocess
from pathlib import Path

import pytest

from liteblox.bindconf.importconf import (RELOCATED, check_allow_lists, equivalence, import_config,
                                          print_statement)
from liteblox.bindconf.model import Layout
from liteblox.bindconf.render import render
from liteblox.nodes import agent_module

agent = agent_module()
LAB_CONF = Path(__file__).parents[1] / 'WIP' / 'lab' / 'lab-ns1.checkconf-px.txt'
HINTS = '/etc/bind/named.conf.root-hints'
FILES = ['/etc/bind/named.conf', '/etc/bind/named.conf.options', '/etc/bind/named.conf.local', HINTS]

# shaped like a real home server's config (lab-ns1 restored from production), with example names
OWN = '''acl "trusted" {
	"localhost";
	192.0.2.0/24;
	198.51.100.0/24;
};
options {
	directory "/var/cache/bind";
	listen-on port 53 {
		"any";
	};
	allow-recursion {
		"trusted";
	};
	dnssec-validation auto;
	recursion yes;
	allow-query {
		"trusted";
	};
	allow-transfer  {
		"none";
	};
	forward only;
	forwarders {
		1.1.1.1;
		9.9.9.9;
	};
};
statistics-channels {
	inet 0.0.0.0 port 8053 allow {
		127.0.0.1/32;
		192.0.2.0/24;
	};
};
zone "example.net" {
	type master;
	file "/etc/bind/db.example.net";
};
zone "2.0.192.in-addr.arpa" {
	type master;
	file "/etc/bind/db.192.0.2";
	allow-transfer {
		key "xfer";
	};
	also-notify {
		192.0.2.54;
	};
	notify explicit;
};
key "xfer" {
	algorithm "hmac-sha256";
	secret "????????";
};
zone "." {
	type hint;
	file "/usr/share/dns/root.hints";
};
'''


def answer(printed, files=FILES, declared=None):
    zones = agent.zones_from_conf(agent.parse_conf(printed))
    for z in zones:
        z['declared_in'] = HINTS if z['name'] == '.' or z['builtin'] else '/etc/bind/named.conf.local'
    return {'checkconf': printed, 'zones': zones, 'conf_files': files,
            'declared': {'key xfer': '/etc/bind/named.conf.local', **(declared or {})}}


def unmasked(printed):
    return answer(printed.replace('"????????"', '"c2VjcmV0c2VjcmV0"'))


def test_import_maps_fields_extras_acls_keys_and_zones():
    plan = import_config(answer(OWN), unmasked(OWN))
    assert plan.blockers == [] and not plan.fresh
    o = plan.config.options
    assert (o.allow_query, o.allow_recursion, o.recursion, o.dnssec_validation, o.forward, o.forwarders) == (
        ['trusted'], ['trusted'], True, 'auto', 'only', ['1.1.1.1', '9.9.9.9'])
    assert o.listen_on is None                  # "port 53" has no field: kept as written
    assert o.extra == 'listen-on port 53 {\n\t"any";\n};\nallow-transfer {\n\t"none";\n};'
    assert [(a.name, a.items) for a in plan.acls] == [('trusted', ['localhost', '192.0.2.0/24', '198.51.100.0/24'])]
    assert [(k.name, k.algorithm, k.secret) for k in plan.keys] == [('xfer', 'hmac-sha256', 'c2VjcmV0c2VjcmV0')]
    assert plan.config.top_extra.startswith('statistics-channels {\n\tinet 0.0.0.0 port 8053 allow {')
    zones = {z.name: z for z in plan.zones}
    assert zones['example.net'].settings == {'notify': '', 'also_notify': '', 'allow_transfer': '', 'allow_query': ''}
    assert zones['2.0.192.in-addr.arpa'].settings == {
        'notify': 'explicit', 'also_notify': '192.0.2.54', 'allow_transfer': 'key xfer', 'allow_query': ''}
    assert zones['example.net'].new_file == '/etc/bind/liteblox/db.example.net'
    assert plan.config.distro_includes == [HINTS]
    assert plan.retire == ['/etc/bind/named.conf.options', '/etc/bind/named.conf.local']
    assert plan.left_in_place == ['/etc/bind/db.example.net', '/etc/bind/db.192.0.2']
    assert check_allow_lists(render(plan.config)) == []


def test_keys_from_rndc_key_stay_the_nodes_own():
    text = OWN + 'key "rndc-key" {\n\talgorithm hmac-sha256;\n\tsecret "????????";\n};\n'
    files = FILES + ['/etc/bind/rndc.key']
    masked = answer(text, files, {'key rndc-key': '/etc/bind/rndc.key'})
    plan = import_config(masked, dict(masked, checkconf=text.replace('????????', 'c2VjcmV0')))
    assert [k.name for k in plan.keys] == ['xfer']
    assert plan.config.distro_includes == [HINTS, '/etc/bind/rndc.key']
    assert '"/etc/bind/rndc.key"' in render(plan.config)['named.conf']


def test_known_acls_keys_and_zones():
    known = {'acls': {'trusted': ['localhost', '192.0.2.0/24', '198.51.100.0/24'], 'lan': ['10.0.0.0/8']},
             'keys': {'xfer': ('hmac-sha256', 'c2VjcmV0c2VjcmV0')},
             'zones': {'example.net': {'row': {'id': 1, 'mode': 'managed', 'notify': 'no', 'also_notify': '',
                                               'allow_transfer': '', 'allow_query': ''}, 'fixed': True}}}
    plan = import_config(answer(OWN), unmasked(OWN), known=known)
    assert plan.acls == [] and plan.keys == []          # the same as LiteBlox's: nothing new
    assert [a.name for a in plan.config.acls] == ['lan', 'trusted']
    assert plan.blockers == ["zone example.net: its notify differ from LiteBlox's settings for this zone"]
    known['acls']['trusted'] = ['any']
    known['keys']['xfer'] = ('hmac-sha256', 'b3RoZXI=')
    blockers = import_config(answer(OWN), unmasked(OWN), known=known).blockers
    assert any(b.startswith('acl trusted: LiteBlox already has') for b in blockers)
    assert any(b.startswith('key xfer: LiteBlox already has') for b in blockers)


FORWARDS = '''zone "corp.example" {
	type forward;
	forward only;
	forwarders {
		10.0.0.53;
		10.0.1.53 port 5353;
	};
};
zone "10.in-addr.arpa" {
	type forward;
	forwarders {
		10.0.0.53;
	};
};
'''


def test_forward_zones_import():
    text = OWN + FORWARDS
    plan = import_config(answer(text), unmasked(text))
    assert plan.blockers == []
    zones = {z.name: z for z in plan.zones}
    corp, arpa = zones['corp.example'], zones['10.in-addr.arpa']
    assert (corp.kind, corp.settings) == ('forwarding', {'forwarders': '10.0.0.53\n10.0.1.53 port 5353',
                                                         'forward_mode': 'only'})
    assert arpa.settings['forward_mode'] == ''          # no forward statement: BIND's default (first), kept unwritten
    assert not corp.relocated and corp.old_file not in plan.left_in_place
    zones_conf = render(plan.config)['zones.conf']
    assert 'forwarders { 10.0.0.53; 10.0.1.53 port 5353; };' in zones_conf
    stanza = zones_conf[zones_conf.index('zone "10.in-addr.arpa"'):]
    assert 'forward ' not in stanza.split('};')[0]
    assert check_allow_lists(render(plan.config)) == []


def test_a_known_zone_of_the_other_kind_blocks():
    text = OWN + FORWARDS
    known = {'zones': {'corp.example': {'row': {'id': 1, 'kind': 'primary', 'notify': 'no', 'also_notify': '',
                                                'allow_transfer': '', 'allow_query': ''}, 'fixed': True}}}
    blockers = import_config(answer(text), unmasked(text), known=known).blockers
    assert blockers == ['zone corp.example: LiteBlox has it as a primary zone, this node as a forwarding zone']
    known = {'zones': {'corp.example': {'row': {'id': 1, 'kind': 'forwarding', 'forwarders': '10.9.9.9',
                                                'forward_mode': 'only'}, 'fixed': True}}}
    blockers = import_config(answer(text), unmasked(text), known=known).blockers
    assert blockers == ["zone corp.example: its forwarders differ from LiteBlox's settings for this zone"]


@pytest.mark.parametrize('extra, blocker', [
    ('view "lan" { match-clients { any; }; };', 'view lan: views are not supported'),
    ('zone "s.example" { type slave; masters { 192.0.2.1; }; file "s"; };', 'zone s.example: type secondary'),
    ('zone "f.example" { type forward; forwarders { 192.0.2.1 port 853 tls dot; }; };', 'zone f.example: forwarders'),
    ('zone "f2.example" { type forward; forwarders { 192.0.2.1; }; max-cache-ttl 60; };',
     'zone f2.example: option max-cache-ttl'),
    ('zone "st.example" { type stub; masters { 192.0.2.1; }; file "st"; };', 'zone st.example: type stub'),
    ('zone "d.example" { type master; file "/etc/bind/db.d"; allow-update { 192.0.2.0/24; }; };',
     'zone d.example: allow-update { 192.0.2.0/24; }: an update rule by address'),
    ('zone "d2.example" { type master; file "/etc/bind/db.d2"; update-policy local; };',
     'zone d2.example: update-policy local: only grant rules'),
    ('zone "d3.example" { type master; file "/etc/bind/db.d3"; update-policy { grant xfer self * A; }; };',
     'zone d3.example: grant xfer self * A: only "grant KEY'),
    ('zone "d4.example" { type master; file "/etc/bind/db.d4"; update-policy { grant nokey zonesub ANY; }; };',
     "zone d4.example: its update rules name key(s) nokey"),
    ('zone "o.example" { type master; file "/etc/bind/db.o"; max-zone-ttl 3600; };',
     'zone o.example: option max-zone-ttl is not supported yet'),
    ('zone "n.example" { type master; file "/etc/bind/db.n"; notify master-only; };',
     'zone n.example: notify master-only is not supported yet'),
    ('zone "l.example" { type master; file "/etc/bind/db.l"; also-notify { 192.0.2.1 port 5300; }; };',
     'zone l.example: also-notify'),
    ('zone "hint2" { type hint; file "/x"; };', 'zone hint2: a hint zone declared outside'),
])
def test_blockers(extra, blocker):
    plan = import_config(answer(OWN + extra), unmasked(OWN + extra))
    assert any(b.startswith(blocker) for b in plan.blockers), plan.blockers


def test_directory_and_path_option_blockers():
    text = OWN.replace('"/var/cache/bind"', '"/srv/bind"')
    assert 'options: directory is /srv/bind' in import_config(answer(text), unmasked(text)).blockers[0]
    text = OWN.replace('recursion yes;', 'recursion yes;\n\tkey-directory "/etc/bind/keys";')
    plan = import_config(answer(text), unmasked(text))
    assert plan.blockers == []
    assert check_allow_lists(render(plan.config)) == [
        'options.conf: options: key-directory is not allowed (it names a file or directory)']


def test_an_old_agent_blocks():
    masked = answer(OWN)
    del masked['declared']
    assert 'too old' in import_config(masked, masked).blockers[0]


def test_print_statement_round_trips():
    for st in agent.parse_conf(OWN):
        again = agent.parse_conf(print_statement(st))
        assert print_statement(again[0]) == print_statement(st)


def test_equivalence_normalizes_order_names_quotes_and_moved_files():
    now = ('options { directory "/var/cache/bind"; recursion yes; allow-query { trusted; }; };\n'
           'zone "a.example" { type master; file "/etc/bind/db.a"; };\nacl trusted { localhost; };\n')
    new = ('acl "trusted" { "localhost"; };\nacl "other" { any; };\n'
           'options { allow-query { "trusted"; }; recursion yes; directory "/var/cache/bind"; };\n'
           'zone "a.example" { type primary; file "/etc/bind/liteblox/db.a.example"; };\n')
    diff, notes = equivalence(now, new, {'a.example'})
    assert diff == ''
    assert notes == ['acl other is defined too (LiteBlox defines it on every node)']
    diff, _ = equivalence(now, new, set())         # not relocated: the path difference counts
    assert '/etc/bind/liteblox/db.a.example' in diff
    diff, _ = equivalence(now, new.replace('recursion yes', 'recursion no'), {'a.example'})
    assert '-\trecursion yes;' in diff and '+\trecursion no;' in diff
    assert RELOCATED not in equivalence(now, now)[0]


def _real_checkconf_equivalence(tmp_path, text):
    """named-checkconf -px of `text` and of its imported, rendered set: (diff, notes)."""
    plan = import_config(answer(text), unmasked(text))
    assert plan.blockers == []
    (tmp_path / 'orig.conf').write_text(text.replace('/var/cache/bind', str(tmp_path)))
    cand = tmp_path / 'cand'
    cand.mkdir()
    for role, body in render(plan.config, Layout(directory=str(tmp_path))).items():
        (cand / role).write_text(body.replace('/etc/bind/liteblox/', f'{cand}/').replace(HINTS, f'{tmp_path}/hints'))
    (tmp_path / 'hints').write_text('zone "." { type hint; file "/usr/share/dns/root.hints"; };\n')
    printed = []
    for conf in (tmp_path / 'orig.conf', cand / 'named.conf'):
        r = subprocess.run(['named-checkconf', '-px', str(conf)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        printed.append(r.stdout.replace(str(tmp_path), '/var/cache/bind'))
    return equivalence(printed[0], printed[1], {z.name for z in plan.zones if z.relocated})


@pytest.mark.skipif(not shutil.which('named-checkconf'), reason='named-checkconf not installed')
def test_real_named_checkconf_finds_the_import_equivalent(tmp_path):
    text = re.sub(r'secret "\?+"', 'secret "c2VjcmV0c2VjcmV0"', OWN + FORWARDS)
    assert _real_checkconf_equivalence(tmp_path, text) == ('', [])


@pytest.mark.skipif(not shutil.which('named-checkconf') or not LAB_CONF.exists(),
                    reason='needs named-checkconf and the lab config copy (WIP/ is not in git)')
def test_real_named_checkconf_on_the_production_derived_config(tmp_path):
    assert _real_checkconf_equivalence(tmp_path, LAB_CONF.read_text()) == ('', [])


DYNAMIC = OWN + '''zone "dhcp.example" {
	type master;
	file "/var/lib/bind/db.dhcp.example";
	update-policy {
		grant "xfer" zonesub A AAAA DHCID;
		grant "xfer" name "printer.dhcp.example." TXT;
	};
};
zone "acme.example" {
	type master;
	file "/var/lib/bind/db.acme.example";
	allow-update {
		key "xfer";
	};
};
'''


def test_dynamic_zones_import_with_their_grants():
    plan = import_config(answer(DYNAMIC), unmasked(DYNAMIC))
    assert plan.blockers == []
    zones = {z.name: z for z in plan.zones}
    dhcp, acme = zones['dhcp.example'], zones['acme.example']
    assert dhcp.dynamic and dhcp.new_file == '/var/lib/bind/liteblox/dyn/db.dhcp.example' and dhcp.relocated
    assert dhcp.grants == [('xfer', 'zonesub', '', 'A AAAA DHCID'), ('xfer', 'name', 'printer.dhcp.example.', 'TXT')]
    assert acme.grants == [('xfer', 'zonesub', '', 'ANY')]
    zones_conf = render(plan.config)['zones.conf']
    assert 'update-policy { grant xfer zonesub A AAAA DHCID; grant xfer name printer.dhcp.example. TXT; };' in zones_conf
    assert 'file "/var/lib/bind/liteblox/dyn/db.acme.example";' in zones_conf
    assert check_allow_lists(render(plan.config)) == []


def test_a_dynamic_zone_waits_for_no_primary_and_a_new_name():
    known = {'primary': 'ns2', 'keys': {'xfer': ('hmac-sha256', 'c2VjcmV0c2VjcmV0')}}
    assert any(b.startswith("zone dhcp.example: it is dynamic, and ns2 is already LiteBlox's primary")
               for b in import_config(answer(DYNAMIC), unmasked(DYNAMIC), known=known).blockers)
    known = {'zones': {'acme.example': {'row': {'id': 1}, 'fixed': False}}}
    assert any(b.startswith('zone acme.example: it is dynamic here and LiteBlox has it already')
               for b in import_config(answer(DYNAMIC), unmasked(DYNAMIC), known=known).blockers)


def test_equivalence_takes_allow_update_by_key_as_its_grant():
    now = 'zone "a.example" { type master; file "/x"; allow-update { key "k"; key "j"; }; };\n'
    new = 'zone "a.example" { type primary; file "/x"; update-policy { grant "k" zonesub ANY; grant j zonesub ANY; }; };\n'
    assert equivalence(now, new)[0] == ''
    assert equivalence(now, new.replace('grant j zonesub ANY', 'grant j zonesub A'))[0] != ''


@pytest.mark.skipif(not shutil.which('named-checkconf'), reason='named-checkconf not installed')
def test_real_named_checkconf_finds_dynamic_zones_equivalent(tmp_path):
    text = re.sub(r'secret "\?+"', 'secret "c2VjcmV0c2VjcmV0"', DYNAMIC)
    assert _real_checkconf_equivalence(tmp_path, text) == ('', [])
