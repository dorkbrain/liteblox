"""Stand-ins for named, named-checkconf, named-checkzone and rndc, used by the agent tests.

Each tool is a tiny shell wrapper that runs `python fakebind.py <tool> <args>`
with FAKEBIND_ROOT pointing at a fake filesystem root. Behaviour switches:
  - a zone file containing BADZONE fails named-checkzone
  - a conf file containing BROKEN fails named-checkconf
  - the file <root>/rndc-fail makes `rndc reload` / `rndc reconfig` fail
rndc appends every call to <root>/rndc.log and remembers loaded serials.
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ['FAKEBIND_ROOT'])
NAMED_CONF = ROOT / 'etc/bind/named.conf'


def conf_files(path, seen=None):
    seen = seen if seen is not None else []
    if path in seen or not path.exists():
        return seen
    seen.append(path)
    for inc in re.findall(r'^\s*include\s+"([^"]+)"\s*;', path.read_text(), re.M):
        conf_files(Path(inc), seen)
    return seen


def zone_files():
    """{zone: file} from the conf (no views/relative-path subtleties needed for rndc)."""
    text = '\n'.join(p.read_text() for p in conf_files(NAMED_CONF))
    out = {}
    for m in re.finditer(r'zone\s+"([^"]+)"[^{]*\{(.*?)\};', text, re.S):
        f = re.search(r'file\s+"([^"]+)"', m.group(2))
        if f:
            path = Path(f.group(1))
            if not path.is_absolute():
                path = ROOT / 'var/cache/bind' / path
            out[m.group(1).rstrip('.')] = path
    return out


def soa_serial(path):
    m = re.search(r'SOA\s.*?(\d{6,10})', path.read_text(), re.S)
    return int(m.group(1)) if m else 0


def loaded():
    f = ROOT / 'loaded.json'
    return json.loads(f.read_text()) if f.exists() else {}


def named(args):
    print('BIND 9.20.99-fake (Extended Support Version) <id:fake>')
    return 0


def named_checkconf(args):
    conf = Path(args[-1]) if args and not args[-1].startswith('-') else NAMED_CONF
    files = conf_files(conf)
    bad = [p for p in files if 'BROKEN' in p.read_text()]
    if bad:
        print(f'{bad[0]}:1: unknown option BROKEN', file=sys.stderr)
        return 1
    flags = next((a for a in args if a.startswith('-p')), None)
    if flags:
        for p in files:
            text = re.sub(r'^\s*include\s+"[^"]+"\s*;\s*$', '', p.read_text(), flags=re.M)
            if 'x' in flags:
                text = re.sub(r'(secret\s+)"[^"]*"', r'\1"????????"', text)
            print(text)
    return 0


def named_checkzone(args):
    name, path = args[-2], Path(args[-1])
    if 'BADZONE' in path.read_text():
        print(f'zone {name}/IN: bad record\nzone {name}/IN: not loaded due to errors.')
        return 1
    print(f'zone {name}/IN: loaded serial {soa_serial(path)}\nOK')
    return 0


def rndc(args):
    with open(ROOT / 'rndc.log', 'a') as f:
        f.write(' '.join(args) + '\n')
    cmd = args[0]
    if cmd == 'status':
        print('server is up and running')
        return 0
    if cmd in ('reload', 'reconfig'):
        if (ROOT / 'rndc-fail').exists():
            print('rndc: reload failed: fake failure', file=sys.stderr)
            return 1
        state = loaded()
        zones = zone_files()
        for name in ([args[1]] if len(args) > 1 else zones):
            if name in zones and zones[name].exists():
                state[name] = soa_serial(zones[name])
        (ROOT / 'loaded.json').write_text(json.dumps(state))
        print('zone reload queued' if len(args) > 1 else 'server reload successful')
        return 0
    if cmd in ('freeze', 'thaw', 'sync', 'refresh'):
        print(f'{cmd} done' if cmd != 'thaw' else 'a zone reload and thaw was started.')
        return 0
    if cmd == 'zonestatus':
        serial = loaded().get(args[1])
        if serial is None:
            print(f"rndc: 'zonestatus' failed: not found", file=sys.stderr)
            return 1
        print(f'name: {args[1]}\ntype: primary\nserial: {serial}')
        return 0
    print(f'rndc: unknown command {cmd}', file=sys.stderr)
    return 1


TOOLS = {'named': named, 'named-checkconf': named_checkconf,
         'named-checkzone': named_checkzone, 'rndc': rndc}

if __name__ == '__main__':
    sys.exit(TOOLS[sys.argv[1]](sys.argv[2:]))
