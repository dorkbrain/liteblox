"""The DHCP failover pair: the agent's TLS files and HA checks, rendering, pairing, failover states."""

import json
import os
from pathlib import Path

import pytest

from liteblox import jobs
from liteblox.dhcp import apply as dhcp_apply, leases as lease_mod, store, validate
from liteblox.dhcp.model import HaPair, KeaConfig, Subnet, ha_pair
from liteblox.dhcp.render import render
from liteblox.nodes import health, service as nodes
from liteblox.nodes.client import AgentError
from liteblox.pki import PKI

from conftest import csrf_from
from test_agent import agent_mod, fake_root, pki  # noqa: F401 (fixtures)
from test_agent import agent_config as bind_agent_config  # noqa: F401 (fixture)
from test_agent_kea import kea_client, kea_root, layout  # noqa: F401 (fixtures)
from test_managed import Client, FakeNode, lab  # noqa: F401 (fixtures)

ENS19 = [{'name': 'ens19', 'up': True, 'addresses': ['198.51.100.53/24']}]
ENS19_2 = [{'name': 'ens19', 'up': True, 'addresses': ['198.51.100.54/24']}]


def tls_for(pki_, ip):  # noqa: F811
    key, cert = pki_.issue_peer_cert('n', [ip])
    return {'address': ip, 'cert': cert.decode(), 'key': key.decode(), 'ca': pki_.ca_pem().decode()}


def pair_config(pki_, layout_=None, this='ns1'):  # noqa: F811
    pair = HaPair(1, 2, 'ns1', 'ns2', '198.51.100.53', '198.51.100.54')
    cfg = KeaConfig(['ens19'], subnets=[Subnet(1, '198.51.100.0/24', 'ens19', ['198.51.100.100 - 198.51.100.199'])],
                    ha={'this': this, 'pair': pair, 'tls': tls_for(pki_, '198.51.100.53' if this == 'ns1' else '198.51.100.54')})
    return render(cfg, layout_) if layout_ else render(cfg)


# ── certificates ───────────────────────────────────────────────────────────────

def test_peer_certificates_serve_and_connect(pki):  # noqa: F811
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    _, cert = pki.issue_peer_cert('ns1-dhcp', ['198.51.100.53'])
    usages = set(x509.load_pem_x509_certificate(cert).extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    assert usages == {ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH}


# ── the agent ──────────────────────────────────────────────────────────────────

def test_tls_files_are_single_pem_blocks():
    agent_mod.validate_tls('tls/ha.crt', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n')
    with pytest.raises(agent_mod.ConfError, match='one PEM private key'):
        agent_mod.validate_tls('tls/ha.key', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')
    two = '-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n' * 2
    with pytest.raises(agent_mod.ConfError):
        agent_mod.validate_tls('tls/ca.crt', two)


@pytest.mark.parametrize('change, message', [
    (lambda ha: ha.update(mode='load-balancing'), 'hot-standby'),
    (lambda ha: ha['peers'].pop(), 'exactly two peers'),
    (lambda ha: ha['peers'][1].update(role='primary'), 'one primary and one standby'),
    (lambda ha: ha.update({'this-server-name': 'ns9'}), 'one of the peers'),
    (lambda ha: ha['peers'][0].update(url='http://example.com:8001/'), 'IP:PORT'),
    (lambda ha: ha.update({'cert-file': '/etc/ssl/private/x.crt'}), 'cert-file must be'),
    (lambda ha: ha.update({'basic-auth-password-file': '/x'}), 'not allowed'),
])
def test_ha_shapes_refused(kea_client, layout, pki, change, message):  # noqa: F811
    _, cfg = kea_client
    data = json.loads(pair_config(pki, layout)['kea-dhcp4.conf'])
    change(data['Dhcp4']['hooks-libraries'][1]['parameters']['high-availability'][0])
    with pytest.raises(agent_mod.ConfError, match=message):
        agent_mod.validate_kea('kea-dhcp4.conf', json.dumps(data), cfg)


def test_stage_checks_the_config_against_the_staged_tls_files(kea_client, kea_root, layout, pki):  # noqa: F811
    client, cfg = kea_client
    _, sockets = kea_root
    files = pair_config(pki, layout)
    agent_mod.validate_kea('kea-dhcp4.conf', files['kea-dhcp4.conf'], cfg)
    # without the TLS files the config alone fails Kea's check: they aren't there yet
    with pytest.raises(AgentError, match='Kea rejected'):
        client.check_dhcp({'kea-dhcp4.conf': files['kea-dhcp4.conf']})
    assert client.check_dhcp(files)['ok']
    client.commit_dhcp(client.stage_dhcp(files)['stage_id'])
    tls = Path(cfg['kea_dir']) / 'tls'
    assert (tls / 'ha.key').read_text() == files['tls/ha.key'] and (tls / 'ha.key').stat().st_mode & 0o777 == 0o640
    assert not [p for p in os.listdir(tls) if 'liteblox' in p]
    assert client.dhcp_files()['tls/ha.key'] == '(private key, not shown)'
    sockets['dhcp4'].ha_state = 'partner-down'
    ha = client.status()['kea']['services']['dhcp4']['ha']
    assert ha['local'] == {'name': 'ns1', 'role': 'primary', 'state': 'partner-down'}
    assert ha['remote']['in_touch'] is True


# ── rendering and checks ───────────────────────────────────────────────────────

def test_render_the_pair(pki):  # noqa: F811
    files = pair_config(pki, this='ns2')
    body = json.loads(files['kea-dhcp4.conf'])['Dhcp4']
    (lease_cmds, ha) = body['hooks-libraries']
    params = ha['parameters']['high-availability'][0]
    assert ha['library'].endswith('libdhcp_ha.so') and params['this-server-name'] == 'ns2'
    assert params['peers'] == [
        {'name': 'ns1', 'url': 'https://198.51.100.53:8001/', 'role': 'primary', 'auto-failover': True},
        {'name': 'ns2', 'url': 'https://198.51.100.54:8001/', 'role': 'standby', 'auto-failover': True}]
    assert params['require-client-certs'] is True and params['key-file'] == '/etc/kea/tls/ha.key'
    assert params['multi-threading']['http-dedicated-listener'] is True
    assert {'tls/ha.crt', 'tls/ha.key', 'tls/ca.crt'} <= set(files)


def test_check_pair(monkeypatch):
    p, s = {'id': 1, 'name': 'ns1', 'dhcp': 1}, {'id': 2, 'name': 'ns2', 'dhcp': 1}
    live = {1: ENS19, 2: ENS19_2}
    assert validate.check_pair(p, s, '198.51.100.53', '198.51.100.54', 8001, live, ['ens19']) == {}
    assert 'two different' in validate.check_pair(p, p, '', '', 8001, live, [])['nodes']
    assert "isn't an address of ns2" in validate.check_pair(p, s, '198.51.100.53', '198.51.100.53', 8001, live,
                                                            ['ens19'])['standby_address']
    errors = validate.check_pair(p, s, '198.51.100.53', '198.51.100.54', 80, {1: ENS19, 2: [
        {'name': 'eth0', 'addresses': ['198.51.100.54/24']}]}, ['ens19'])
    assert 'no interface named ens19' in errors['nodes'] and 'port' in errors
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '198.51.100.0/24')
    assert 'never serves' in validate.check_pair(p, s, '198.51.100.53', '198.51.100.54', 8001, live,
                                                 ['ens19'])['primary_address']


def test_the_dev_guard_refuses_a_listener_on_its_networks(pki, monkeypatch):  # noqa: F811
    monkeypatch.setenv(validate.DEV_NEVER_SERVE, '198.51.100.53/32')
    files = pair_config(pki)
    data = json.loads(files['kea-dhcp4.conf'])
    data['Dhcp4']['subnet4'] = []
    with pytest.raises(validate.Invalid, match='failover listener on 198.51.100.53'):
        validate.guard_rendered({**files, 'kea-dhcp4.conf': json.dumps(data)})


# ── pairing, failover ──────────────────────────────────────────────────────────

def both_dhcp(conn):
    with conn:
        conn.execute("UPDATE nodes SET dhcp = 1, kea_hooks_dir = '/usr/lib/x86_64-linux-gnu/kea/hooks'")
        conn.execute("UPDATE nodes SET dhcp_interfaces = '[\"ens19\"]' WHERE id = 1")
    store.save_subnet(conn, Subnet(1, '198.51.100.0/24', 'ens19', ['198.51.100.100 - 198.51.100.199']))


def fakes_live(fakes):
    fakes[1].status_interfaces = ENS19
    fakes[2].status_interfaces = ENS19_2


@pytest.fixture
def paired_lab(conn, settings, lab, monkeypatch):  # noqa: F811
    fakes, _ = lab
    both_dhcp(conn)
    monkeypatch.setattr(dhcp_apply.time, 'sleep', lambda s: None)
    real_status = FakeNode.status

    def status(self):
        out = real_status(self)
        out['interfaces'] = ENS19 if self.name == 'ns1' else ENS19_2
        return out
    monkeypatch.setattr(FakeNode, 'status', status)
    return fakes


def test_pairing_goes_standby_first_and_waits_for_hot_standby(conn, settings, paired_lab):
    fakes = paired_lab
    for f in fakes.values():
        f.kea_ha_state = 'hot-standby'
    pki_ = PKI(settings.pki_dir)
    snap = store.snapshot(conn)
    lines = []
    dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'pair', 'admin', lines.append,
                          change=lambda c: store.set_pair(c, pki_, 1, 2, '198.51.100.53', '198.51.100.54', 8001),
                          undo=lambda c: store.restore(c, snap))
    order = [n for n, what in fakes[1].all_calls if what == 'commit dhcp']
    assert order == ['ns2', 'ns1']
    assert any('ns1 serves, ns2 stands by' in line for line in lines)
    d2 = json.loads(fakes[2].kea_files['kea-dhcp4.conf'])['Dhcp4']
    assert d2['interfaces-config']['interfaces'] == ['ens19'] and d2['subnet4'][0]['subnet'] == '198.51.100.0/24'
    assert 'tls/ha.key' in fakes[2].kea_files and ha_pair(conn).active


def test_a_pair_that_never_meets_is_rolled_back(conn, settings, paired_lab):
    fakes = paired_lab
    fakes[1].kea_ha_state = 'hot-standby'
    fakes[2].kea_ha_state = 'waiting'
    pki_ = PKI(settings.pki_dir)
    snap = store.snapshot(conn)
    with pytest.raises(dhcp_apply.DhcpError, match='failover pair did not start'):
        dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'pair', 'admin', print, ha_wait=6,
                              change=lambda c: store.set_pair(c, pki_, 1, 2, '198.51.100.53', '198.51.100.54', 8001),
                              undo=lambda c: store.restore(c, snap))
    assert 'rollback dhcp' in fakes[1].calls and 'rollback dhcp' in fakes[2].calls
    assert not ha_pair(conn).active and nodes.get_node(conn, 2)['dhcp_interfaces'] == '[]'


def test_health_flags_partner_down(conn, settings, paired_lab, client, make_user, login):
    fakes = paired_lab
    for f in fakes.values():
        f.kea_ha_state = 'hot-standby'
    pki_ = PKI(settings.pki_dir)
    dhcp_apply.apply_dhcp(settings, conn, [1, 2], 'pair', 'admin', print,
                          change=lambda c: store.set_pair(c, pki_, 1, 2, '198.51.100.53', '198.51.100.54', 8001))
    fakes[2].kea_ha_state = 'partner-down'
    fakes[2].kea_files_status = True
    line = health.check_node(settings, conn, nodes.get_node(conn, 2), background=False)
    assert 'DHCP failover: partner-down' in line
    login(*make_user('admin', 'admin-password', 'admin'))
    assert 'DHCP partner-down' in client.get('/nodes').text


def test_pair_routes_and_leases(conn, settings, paired_lab, client, make_user, login, monkeypatch):
    fakes = paired_lab
    for f in fakes.values():
        f.kea_ha_state = 'hot-standby'
    real_start = jobs.start
    monkeypatch.setattr(jobs, 'start', lambda *a, **k: real_start(*a, **{**k, 'background': False}))
    login(*make_user('admin', 'admin-password', 'admin'))
    page = client.get('/dhcp').text
    assert 'Failover pair' in page and 'ns2: 198.51.100.54' in page
    t = csrf_from(page)
    form = {'csrf_token': t, 'primary': '1', 'standby': '2', 'primary_address': '198.51.100.53',
            'standby_address': '198.51.100.54', 'port': '8001'}
    review = client.post('/dhcp/ha/preview', data=form, headers={'X-CSRF-Token': t}).text
    assert 'libdhcp_ha.so' in review and '(a private key' in review and 'BEGIN PRIVATE KEY' not in review
    r = client.post('/dhcp/ha', data=form, follow_redirects=False)
    job = jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))
    assert job['status'] == 'ok', job['log']
    page = client.get('/dhcp').text
    assert '<span class="pill ready">primary</span>' in page and '<span class="pill ">standby</span>' in page and 'End the pair' in page
    # the standby's interfaces follow the primary's
    r = client.post('/dhcp/nodes/2/interfaces', data={'csrf_token': t, 'interfaces': 'ens19'}, follow_redirects=False)
    assert 'is+the+standby' in r.headers['location'] or 'is%20the%20standby' in r.headers['location']

    # leases come from the primary, or the standby when the primary is gone; a delete goes to both
    lease = {'ip-address': '198.51.100.120', 'hw-address': 'aa:bb:cc:dd:ee:ff', 'subnet-id': 1, 'cltt': 0,
             'valid-lft': 3600, 'state': 0}
    fakes[1].kea_leases, fakes[2].kea_leases = [dict(lease)], [dict(lease)]
    assert client.get('/dhcp/leases').text.count('198.51.100.120') >= 1
    fakes[1].down = True
    assert '198.51.100.120' in client.get('/dhcp/leases').text
    fakes[1].down = False
    client.post('/dhcp/leases/delete', data={'csrf_token': t, 'ip': '198.51.100.120', 'node_id': '1'})
    assert fakes[1].kea_leases == [] and fakes[2].kea_leases == []
    assert ('lease4-del', {'ip-address': '198.51.100.120', 'update-ddns': False}) in fakes[2].kea_commands

    r = client.post('/dhcp/ha/unpair', data={'csrf_token': t, 'keep': '2'}, follow_redirects=False)
    assert jobs.get(conn, int(r.headers['location'].rsplit('/', 1)[1]))['status'] == 'ok'
    assert not ha_pair(conn).active
    assert nodes.get_node(conn, 2)['dhcp_interfaces'] == '["ens19"]' and nodes.get_node(conn, 1)['dhcp_interfaces'] == '[]'
    assert 'libdhcp_ha.so' not in fakes[1].kea_files['kea-dhcp4.conf']
