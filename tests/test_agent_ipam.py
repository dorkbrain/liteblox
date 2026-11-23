"""The agent's IPAM side: /neigh (the neighbour table) and /probe (ping + the neighbour entry it leaves)."""

import struct

import pytest

from liteblox.nodes.client import AgentError

from test_agent import agent_mod, fake_root, pki  # noqa: F401 (fixtures)
from test_agent import agent_config as bind_agent_config  # noqa: F401 (fixture)
from test_agent_kea import kea_client, kea_root  # noqa: F401 (fixtures: they bring the fake `ip`)


class FakeIcmp:
    """An ICMP datagram socket whose echo requests to `answer` get replies (the kernel's view: no IP header)."""

    def __init__(self, answer):
        self.answer, self.queue = set(answer), []

    def setblocking(self, flag):
        pass

    def sendto(self, packet, addr):
        assert packet[0] == 8 and agent_mod._icmp_checksum(packet) == 0      # a valid echo request
        if addr[0] in self.answer:
            self.queue.append((b'\0\0' + packet[2:], (addr[0], 0)))

    def recvfrom(self, n):
        if not self.queue:
            raise BlockingIOError
        return self.queue.pop(0)

    def fileno(self):
        return self._r.fileno()

    def __enter__(self):
        import socket
        self._r, self._w = socket.socketpair()
        self._w.send(b'x')          # select() always finds it readable; recvfrom decides
        return self

    def __exit__(self, *exc):
        self._r.close()
        self._w.close()


def test_parse_neigh_keeps_entries_with_a_mac():
    rows = [{'dst': '10.0.0.1', 'dev': 'eth0', 'lladdr': 'AA:BB:CC:DD:EE:FF', 'used': 9, 'confirmed': 5, 'updated': 7,
             'probes': 1, 'state': ['REACHABLE']},
            {'dst': '10.0.0.2', 'dev': 'eth0', 'state': ['FAILED']},
            {'dst': '10.0.0.3', 'dev': 'eth0', 'lladdr': '00:11:22:33:44:55', 'state': ['PERMANENT']}]
    assert agent_mod.parse_neigh(rows) == [
        {'ip': '10.0.0.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'dev': 'eth0', 'state': 'REACHABLE', 'used': 9,
         'confirmed': 5, 'updated': 7, 'probes': 1},
        {'ip': '10.0.0.3', 'mac': '00:11:22:33:44:55', 'dev': 'eth0', 'state': 'PERMANENT', 'used': None,
         'confirmed': None, 'updated': None, 'probes': None}]


def test_icmp_checksum():
    packet = struct.pack('!BBHHH', 8, 0, 0, 0, 1) + b'liteblox'
    packet = packet[:2] + struct.pack('!H', agent_mod._icmp_checksum(packet)) + packet[4:]
    assert agent_mod._icmp_checksum(packet) == 0


def test_neigh_endpoint(kea_client):  # noqa: F811
    client, _ = kea_client
    found = client.neigh()
    assert [n['ip'] for n in found] == ['198.51.100.10', '198.51.100.20']
    assert found[0]['mac'] == 'bc:24:11:6c:51:d8' and found[0]['state'] == 'REACHABLE'


def test_probe_reports_replies_and_neighbour_entries(kea_client, monkeypatch):  # noqa: F811
    client, _ = kea_client
    monkeypatch.setattr(agent_mod, '_icmp_socket', lambda: FakeIcmp({'198.51.100.20'}))
    out = client.probe(['198.51.100.10', '198.51.100.20', '198.51.100.99'], interval_ms=10, wait=0.5)
    assert out['method'] == 'icmp'
    r = out['results']
    # .10 drops pings but answered ARP; .20 answered the ping; .99 is nobody (INCOMPLETE has no MAC)
    assert r['198.51.100.10'] == {'replied': False, 'rtt_ms': None, 'state': 'REACHABLE',
                                  'mac': 'bc:24:11:6c:51:d8', 'confirmed': 1}
    assert r['198.51.100.20']['replied'] is True and r['198.51.100.20']['rtt_ms'] is not None
    assert r['198.51.100.99'] == {'replied': False, 'rtt_ms': None, 'state': None, 'mac': None, 'confirmed': None}


def test_probe_falls_back_to_udp_without_icmp_sockets(kea_client, monkeypatch):  # noqa: F811
    client, _ = kea_client

    def refused():
        raise PermissionError(13, 'Permission denied')
    monkeypatch.setattr(agent_mod, '_icmp_socket', refused)
    out = client.probe(['198.51.100.77'], interval_ms=10, wait=0.5)
    assert out['method'] == 'udp' and out['results']['198.51.100.77']['replied'] is False


@pytest.mark.parametrize('addresses, why', [
    (['203.0.113.5'], 'not on a network this node is directly on'),
    (['127.0.0.1'], 'not on a network'),
    (['198.51.100.0'], 'not on a network'),          # the network address itself
    (['198.51.100.255'], 'not on a network'),        # broadcast
    (['nope'], 'not an IPv4 address'),
    ([], 'a list of 1 to 64'),
    ([f'198.51.100.{i}' for i in range(1, 66)], 'a list of 1 to 64'),
])
def test_probe_refuses(kea_client, addresses, why):  # noqa: F811
    client, _ = kea_client
    with pytest.raises(AgentError) as e:
        client.probe(addresses)
    assert e.value.status == 400 and why in e.value.message
