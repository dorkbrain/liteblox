"""Server settings and ACLs: sequential apply with probes, previews, the lockout guard, the pages."""

import json

import pytest

from liteblox import acls, jobs
from liteblox.bindconf import apply
from liteblox.bindconf.model import NodeOptions
from liteblox.dns import declare
from liteblox.nodes import service as nodes

from conftest import csrf_from
from test_managed import NS, Client, lab, make_roles, ok_verify  # noqa: F401 (fixtures)


class Dns:
    """Probe stand-in: which (node address, zone) answer, and whether recursion works, before/after."""

    def __init__(self):
        self.down = set()           # addresses that stop answering once a change lands
        self.calls = []

    def serving(self, host, zone):
        self.calls.append((host, zone))
        return host not in self.down

    def recursive(self, host):
        return host not in self.down


@pytest.fixture
def env(conn, settings, lab, monkeypatch):  # noqa: F811
    """ns1 primary + ns2 secondary of new.lab; probes go to a Dns stand-in."""
    fakes, snapshots = lab
    make_roles(conn)
    declare.create_zone(settings, 'new.lab', ['1', '2'], declare.starter_zone('new.lab', NS), 'admin', print,
                        verify=ok_verify)
    monkeypatch.setattr('liteblox.backups.service.snapshot_before_change',
                        lambda conn, settings, node, reason, username: snapshots.append((node['name'], reason)))
    dns = Dns()
    monkeypatch.setattr(apply, '_served', dns.serving)
    monkeypatch.setattr(apply, 'recursive_ok', dns.recursive)
    monkeypatch.setattr(apply.time, 'sleep', lambda s: None)
    for f in fakes.values():
        f.calls.clear()
    fakes[1].all_calls.clear()          # shared by both fakes
    return fakes, dns


def options(conn, node_id):
    return NodeOptions.from_json(nodes.get_node(conn, node_id)['options'])


def test_settings_apply_to_each_node_the_primary_last(conn, settings, env):
    fakes, dns = env
    new = NodeOptions(recursion=True, allow_recursion=['192.168.1.0/24'], forwarders=['1.1.1.1'], forward='only')
    lines = []
    apply.set_node_settings(settings, [1, 2], new, 'statistics-channels { inet 127.0.0.1 port 8053; };',
                            'admin', lines.append)
    calls = fakes[1].all_calls
    assert calls.index(('ns2', 'commit')) < calls.index(('ns1', 'commit'))      # the secondary first
    for f in fakes.values():
        conf = f.config_files['options.conf']
        assert 'forwarders { 1.1.1.1; };' in conf and 'forward only;' in conf
        assert 'statistics-channels' in f.config_files['top.conf']
    assert options(conn, 1) == new and options(conn, 2) == new
    assert any('still fine: new.lab answers, recursion works' in line for line in lines)


def test_a_node_that_stops_answering_rolls_everything_back(conn, settings, env):
    fakes, dns = env
    old1, old2 = fakes[1].config_files, fakes[2].config_files

    class Breaks(Dns):
        """ns1 (the second node changed) stops answering after its commit."""
        def serving(self, host, zone):
            return not (host == '192.0.2.53' and fakes[1].calls.count('commit') >= 1)
    breaks = Breaks()
    lines = []
    with pytest.raises(apply.ApplyError, match='ns1 stopped working after the change'):
        apply.set_node_settings(settings, [1, 2], NodeOptions(recursion=False), '', 'admin', lines.append,
                                dns_serving=breaks.serving, dns_recursive=lambda h: True)
    assert fakes[1].calls[-1] == 'rollback' and fakes[2].calls[-1] == 'rollback'
    assert fakes[1].config_files == old1 and fakes[2].config_files == old2
    assert options(conn, 1) == NodeOptions() and options(conn, 2) == NodeOptions()
    assert any('new.lab answers: no' in line for line in lines)


def test_a_probe_that_failed_before_is_not_held_against_the_change(conn, settings, env):
    fakes, _ = env
    apply.set_node_settings(settings, [2], NodeOptions(dnssec_validation='no'), '', 'admin', print,
                            dns_serving=lambda h, z: True, dns_recursive=lambda h: False)
    assert 'dnssec-validation no;' in fakes[2].config_files['options.conf']


def test_turning_recursion_off_does_not_trip_the_recursion_probe(conn, settings, env):
    fakes, _ = env
    apply.set_node_settings(settings, [2], NodeOptions(recursion=False), '', 'admin', print,
                            dns_serving=lambda h, z: True,
                            dns_recursive=lambda h: 'recursion no;' not in fakes[2].config_files.get('options.conf', ''))
    assert 'recursion no;' in fakes[2].config_files['options.conf']


def test_a_refusing_node_changes_nothing(conn, settings, env):
    fakes, _ = env
    fakes[1].fail_stage = True
    with pytest.raises(apply.ApplyError, match='ns1 refused'):
        apply.set_node_settings(settings, [1, 2], NodeOptions(recursion=True), '', 'admin', print)
    assert fakes[2].calls[-1] == 'rollback' and options(conn, 2) == NodeOptions()


def test_preview(conn, settings, env):
    fakes, _ = env
    node = nodes.get_node(conn, 2)
    pv = apply.preview(conn, settings, node, NodeOptions(allow_query=['192.168.1.0/24']), '')
    assert '+\tallow-query { 192.168.1.0/24; };' in pv['diff'] and pv['problems'] == []
    assert pv['findings'] == [('block', "allow-query would refuse LiteBlox itself (192.0.2.10), so it could no "
                                        "longer check this node's zones")]
    fakes[2].calls.clear()
    pv = apply.preview(conn, settings, node, NodeOptions(extra='pid-file "/tmp/x";'), '')
    assert pv['problems'] and 'pid-file is not allowed' in pv['problems'][0]
    assert 'check' not in fakes[2].calls                          # refused here, never sent
    fakes[2].fail_check = True
    pv = apply.preview(conn, settings, node, NodeOptions(extra='minimal-responses yes;'), '')
    assert "ns2's named-checkconf" in pv['problems'][0] and 'unknown option' in pv['problems'][0]


def test_primary_zones_let_secondaries_through_a_restricted_allow_query(conn, settings, env):
    fakes, _ = env
    apply.set_node_settings(settings, [1], NodeOptions(allow_query=['192.168.1.0/24']), '', 'admin', print)
    zones_conf = fakes[1].zones_conf
    assert 'allow-query { key liteblox-xfr; 192.168.1.0/24; };' in zones_conf
    assert 'allow-query' not in fakes[2].zones_conf                       # a secondary's zones unchanged


def test_parse_settings_and_form_values():
    o, top = apply.parse_settings({'recursion': 'yes', 'allow_recursion': 'lan\n10.0.0.0/8', 'forwarders': '1.1.1.1',
                                   'forward': 'only', 'dnssec_validation': '', 'validate_except': 'Corp.\nhome.lab',
                                   'extra': ' minimal-responses yes; ', 'top_extra': ''})
    assert o == NodeOptions(recursion=True, allow_recursion=['lan', '10.0.0.0/8'], forwarders=['1.1.1.1'],
                            forward='only', validate_except=['corp', 'home.lab'], extra='minimal-responses yes;')
    assert apply.parse_settings({})[0] == NodeOptions()
    values = apply.form_values(o, '')
    assert values['allow_recursion'] == 'lan\n10.0.0.0/8' and values['recursion'] == 'yes'
    assert apply.parse_settings(values)[0] == o
    for bad, field in (({'allow_query': '1.2.3.4 }; x'}, 'allow-query'), ({'forwarders': 'dns.x'}, 'forwarders'),
                       ({'recursion': 'maybe'}, 'recursion'), ({'validate_except': 'a..b'}, 'validate-except')):
        with pytest.raises(ValueError, match=field):
            apply.parse_settings(bad)


# ── ACLs ───────────────────────────────────────────────────────────────────────

def test_acl_lifecycle(conn, settings, env):
    fakes, _ = env
    acls.save(settings, 'lan', ['192.168.1.0/24', 'localhost'], 'admin', print, create=True)
    for f in fakes.values():
        assert 'acl "lan" { 192.168.1.0/24; localhost; };' in f.config_files['acls.conf']
    with pytest.raises(acls.AclError, match='already'):
        acls.save(settings, 'lan', ['any'], 'admin', print, create=True)
    acls.save(settings, 'lan', ['192.168.0.0/16'], 'admin', print, create=False)
    assert 'acl "lan" { 192.168.0.0/16; };' in fakes[1].config_files['acls.conf']

    apply.set_node_settings(settings, [2], NodeOptions(allow_recursion=['lan']), '', 'admin', print)
    acls.save(settings, 'outer', ['lan', '10.0.0.0/8'], 'admin', print, create=True)
    with conn:
        conn.execute("UPDATE zones SET allow_transfer = '!lan' WHERE name = 'new.lab'")
    assert acls.references(conn, 'lan') == ['node ns2: allow-recursion', 'zone new.lab: allow-transfer', 'ACL outer']
    with pytest.raises(acls.AclError, match='still used by'):
        acls.delete(settings, 'lan', 'admin', print)
    with pytest.raises(acls.AclError, match='include itself'):
        acls.save(settings, 'lan', ['outer'], 'admin', print, create=False)
    acls.delete(settings, 'outer', 'admin', print)
    assert 'outer' not in fakes[1].config_files['acls.conf']
    assert [r['name'] for r in conn.execute('SELECT name FROM acls')] == ['lan']


def test_acl_change_that_breaks_a_node_is_rolled_back(conn, settings, env):
    fakes, _ = env
    acls.save(settings, 'lan', ['192.168.1.0/24'], 'admin', print, create=True)
    before = {i: f.config_files for i, f in fakes.items()}
    fakes[1].fail_commit = True
    with pytest.raises(apply.ApplyError, match='ns1 refused'):
        acls.save(settings, 'lan', ['any'], 'admin', print, create=False)
    assert json.loads(conn.execute("SELECT items FROM acls WHERE name = 'lan'").fetchone()[0]) == ['192.168.1.0/24']
    assert fakes[2].config_files == before[2]                    # ns2 had changed first: rolled back


@pytest.mark.parametrize('name', ['any', 'localnets', 'has space', '-lead', ''])
def test_acl_names(name):
    with pytest.raises(acls.AclError):
        acls.check_name(name)


def test_extras_referencing_an_acl_count(conn, settings, env):
    acls.save(settings, 'mgmt', ['10.0.0.0/8'], 'admin', print, create=True)
    apply.set_node_settings(settings, [1], NodeOptions(extra='allow-notify { mgmt; };'), '', 'admin', print)
    assert acls.references(conn, 'mgmt') == ['node ns1: extra statements']


# ── pages ──────────────────────────────────────────────────────────────────────

def test_settings_pages(client, make_user, login, conn, settings, env, monkeypatch):
    fakes, _ = env
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    make_user('reader', 'pw-reader-1', 'readonly')
    login('reader', 'pw-reader-1')
    page = client.get('/nodes/2/settings').text
    assert 'Server settings' in page and 'readonly' in page and 'Apply</button>' not in page
    assert client.post('/nodes/2/settings', data={'csrf_token': csrf_from(page)}).status_code == 403
    assert client.get('/settings/acls', follow_redirects=False).status_code == 403
    client.cookies.clear()
    login(*make_user('admin', 'admin-password', 'admin'))
    page = client.get('/nodes/2/settings').text
    t = csrf_from(page)
    assert 'name="also" value="1"' in page and 'name="copy"' in page and 'Review changes' in page
    assert 'name="apply_anyway"' not in page                  # only a review that finds a lockout offers it

    preview = client.post('/nodes/2/settings/preview', data={'recursion': 'no', 'csrf_token': t},
                          headers={'X-CSRF-Token': t}).text
    assert '<span class="add">+\trecursion no;</span>' in preview and 'accepts it' in preview
    assert 'Apply to ns2</button>' in preview and 'apply_anyway' not in preview
    preview = client.post('/nodes/2/settings/preview', data={'allow_query': 'none', 'also': '1', 'csrf_token': t},
                          headers={'X-CSRF-Token': t}).text
    assert 'would refuse LiteBlox itself' in preview and 'name="apply_anyway"' in preview
    assert 'Apply to ns2 and ns1</button>' in preview
    preview = client.post('/nodes/2/settings/preview', data={'csrf_token': t}, headers={'X-CSRF-Token': t}).text
    assert 'Nothing to apply' in preview and '</button>' not in preview
    preview = client.post('/nodes/2/settings/preview', data={'extra': 'pid-file "/x";', 'csrf_token': t},
                          headers={'X-CSRF-Token': t}).text
    assert 'Fix the problems above' in preview and '</button>' not in preview
    # a definite lockout needs the extra tick
    r = client.post('/nodes/2/settings', data={'allow_query': 'none', 'csrf_token': t})
    assert r.status_code == 422 and 'lock LiteBlox out' in r.text and 'none' in r.text
    r = client.post('/nodes/2/settings', data={'recursion': 'no', 'also': '1', 'csrf_token': t},
                    follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert options(conn, 1).recursion is False and options(conn, 2).recursion is False

    assert 'settings differ' not in client.get('/nodes').text
    client.post('/nodes/2/settings', data={'recursion': 'yes', 'csrf_token': t})
    assert 'settings differ' in client.get('/nodes').text
    copied = client.get('/nodes/1/settings?copy=2').text
    assert "Filled in from <strong>ns2</strong>" in copied and '<option value="yes" selected>' in copied

    acl_page = client.get('/settings/acls').text
    r = client.post('/settings/acls', data={'name': 'lan', 'items': '192.168.1.0/24', 'create': 'true',
                                            'csrf_token': csrf_from(acl_page)}, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    assert 'acl "lan"' in fakes[1].config_files['acls.conf']
    r = client.post('/settings/acls', data={'name': 'none', 'items': 'any', 'create': 'true', 'csrf_token': t})
    assert r.status_code == 422 and 'built into BIND' in r.text
