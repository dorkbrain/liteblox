"""Stand-ins for chronyd, chronyc and systemctl in the agent's chrony tests.

`chronyd -p -f FILE` prints the file, or fails on a line '# reject-me'. `systemctl show chrony.service`
reports the config's mtime as chrony's start time, so replacing chrony.conf looks like the path unit
restarting chrony; a config with '# breaks-chrony' leaves it failed. chronyc answers from fixed text.
"""

import os
import sys

TRACKING = 'C0A80001,192.168.1.1,3,1793498212.266548440,-0.000099466,0.000082395,0.000082395,-3.875,-17.484,1000000.000,0.072990634,2.702188015,2.0,Normal\n'
SOURCES = ('^,*,192.168.1.1,2,6,377,12,-0.001789135,-0.001706740,0.036824208\n'
           '^,?,203.0.113.9,0,6,0,-,0.0,0.0,0.0\n')


def conf():
    return os.environ.get('FAKE_CHRONY_CONF', '/etc/chrony/chrony.conf')


def main(tool, args):
    if tool == 'chronyd':
        if args[:1] == ['-v']:
            print('chronyd (chrony) version 4.6.1 (+CMDMON +NTP)')
            return 0
        path = args[args.index('-f') + 1]
        text = open(path).read()
        if '# reject-me' in text:
            print(f'Fatal error : Invalid directive at line 2 in file {path}', file=sys.stderr)
            return 1
        sys.stdout.write(text)
        return 0
    if tool == 'chronyc':
        sys.stdout.write(TRACKING if 'tracking' in args else SOURCES if 'sources' in args else '')
        return 0
    if tool == 'systemctl':
        try:
            st = os.stat(conf())
            broken = '# breaks-chrony' in open(conf()).read()
        except OSError:
            st, broken = None, True
        if args[:1] == ['show']:
            print(f"ActiveState={'failed' if broken else 'active'}")
            print(f'ExecMainStartTimestampMonotonic={st.st_mtime_ns if st else 0}')
            return 0
        if args[:1] == ['is-active']:
            return 3 if args[1] == 'systemd-timesyncd' else 0
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2:]))
