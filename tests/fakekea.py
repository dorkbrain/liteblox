"""Stand-ins for Kea in the agent tests: kea-dhcp4 / kea-dhcp-ddns (-t, -v), `ip -j addr` and `ip -4 -s -j neigh`, and a
control socket that answers like Kea (one JSON answer, then it closes the connection).

  - a config file containing BROKEN fails -t
  - FakeKeaSocket.fail_reload makes config-reload answer result 1
"""

import json
import os
import socket
import sys
import threading

IP_ADDR = [
    {'ifname': 'lo', 'flags': ['LOOPBACK', 'UP'], 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8}]},
    {'ifname': 'ens18', 'flags': ['BROADCAST', 'UP'],
     'addr_info': [{'family': 'inet', 'local': '192.0.2.53', 'prefixlen': 24}]},
    {'ifname': 'ens19', 'flags': ['BROADCAST', 'UP'],
     'addr_info': [{'family': 'inet', 'local': '198.51.100.53', 'prefixlen': 24}]},
]


def kea(args):
    if args[:1] == ['-v']:
        print('2.6.3')
        return 0
    if args[:1] == ['-t'] and len(args) == 2:
        try:
            text = open(args[1]).read()
        except OSError:
            print(f'Syntax check failed with: Unable to open file {args[1]}')
            return 1
        if 'BROKEN' in text:
            print('Syntax check failed with: fake failure')
            return 1
        import re
        for path in re.findall(r'"(/[^"]+\.(?:crt|key))"', text):        # TLS files must exist, as for Kea
            if not os.path.exists(path):
                print(f'Syntax check failed with: unable to open {path}')
                return 1
        print('Configuration check successful')
        return 0
    print(f'unknown arguments {args}', file=sys.stderr)
    return 1


IP_NEIGH = [
    {'dst': '198.51.100.10', 'dev': 'ens19', 'lladdr': 'BC:24:11:6C:51:D8', 'used': 3, 'confirmed': 1, 'updated': 1,
     'state': ['REACHABLE']},
    {'dst': '198.51.100.20', 'dev': 'ens19', 'lladdr': 'aa:bb:cc:00:00:20', 'used': 900, 'confirmed': 600,
     'updated': 600, 'state': ['STALE']},
    {'dst': '198.51.100.99', 'dev': 'ens19', 'used': 1, 'confirmed': 60, 'updated': 1, 'state': ['INCOMPLETE']},
]


def ip(args):
    if args == ['-j', 'addr']:
        print(json.dumps(IP_ADDR))
        return 0
    if args == ['-4', '-s', '-j', 'neigh']:
        print(json.dumps(IP_NEIGH))
        return 0
    return 1


class FakeKeaSocket:
    """A Kea control socket at `path`, answering in a thread."""

    def __init__(self, path, service='dhcp4'):
        self.path, self.service = path, service
        self.commands, self.fail_reload = [], False
        self.unknown_interface = None     # an interface made after Kea started: config-reload fails until config-set
        self.ha_state = None
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                request = json.loads(conn.recv(65536))
                self.commands.append(request)
                conn.sendall(json.dumps(self.answer(request)).encode())

    def answer(self, request):
        command = request['command']
        if command == 'status-get':
            args = {'pid': 4242, 'uptime': 60, 'reload': 30}
            if self.ha_state:
                args['high-availability'] = [{'ha-mode': 'hot-standby', 'ha-servers': {
                    'local': {'role': 'primary', 'server-name': 'ns1', 'state': self.ha_state},
                    'remote': {'role': 'standby', 'server-name': 'ns2', 'last-state': 'hot-standby', 'in-touch': True}}}]
            return {'result': 0, 'arguments': args}
        if command == 'config-set':
            subnets = request['arguments']['Dhcp4'].get('subnet4') or []
            if self.unknown_interface and any(x.get('interface') == self.unknown_interface for x in subnets):
                return {'result': 1, 'text': 'still not present'}
            self.unknown_interface = None                 # opening the sockets re-detected the interfaces
            return {'result': 0, 'text': 'Configuration successful.'}
        if command == 'config-reload':
            if self.unknown_interface:
                return {'result': 1, 'text': 'configuration error using file: subnet configuration failed: Specified '
                        f'network interface name {self.unknown_interface} for subnet 192.0.2.0/24 is not present in the '
                        'system (kea-dhcp4.conf:90:22)'}
            if self.fail_reload:
                return {'result': 1, 'text': 'fake reload failure'}
            return {'result': 0, 'text': 'Configuration successful.', 'arguments': {'hash': 'ABC'}}
        if command == 'version-get':
            return {'result': 0, 'text': '2.6.3'}
        return {'result': 2, 'text': f"'{command}' command not supported."}

    def close(self):
        self.sock.close()
        if os.path.exists(self.path):
            os.unlink(self.path)


def timedatectl(args):
    if args == ['show', '-p', 'NTPSynchronized', '--value']:
        print('yes')
        return 0
    return 1


TOOLS = {'kea-dhcp4': kea, 'kea-dhcp-ddns': kea, 'ip': ip, 'timedatectl': timedatectl}

if __name__ == '__main__':
    sys.exit(TOOLS[sys.argv[1]](sys.argv[2:]))
