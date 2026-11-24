#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dorkbrain (https://dorkbrain.com)
"""lbcli.py: LiteBlox's IPAM from the command line (Python 3.9+, nothing to install).

  lbcli.py next --subnet 192.168.1.0/24 --blocksize 3
  lbcli.py reserve 'k8s-{n}' --network 192.168.10.0/24 --blocksize 3 --group k8s-lab
  lbcli.py reserve printer --subnet 192.168.1.0/24 --mac aa:bb:cc:dd:ee:ff
  lbcli.py reserve nas --network 192.168.1.0/24 --ipam        (a name kept in IPAM only)
  lbcli.py unassign --group k8s-lab
  lbcli.py release --hold 3f9c0a1b2c4d
  lbcli.py show 192.168.1.20

The server and token come from --url / LITEBLOX_URL and LITEBLOX_TOKEN / --token-file. next, reserve, unassign
and release need a full token; show works with a read-only one. --json prints the API's answer for scripts.
"""

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

opener = urllib.request.build_opener()       # tests swap this for one that talks to their app


class Failed(Exception):
    pass


def call(args, method, path, body=None, query=None):
    url = args.url.rstrip('/') + '/api/v1' + path + ('?' + urllib.parse.urlencode(query) if query else '')
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Authorization': f'Bearer {args.token}', 'Accept': 'application/json',
        **({'Content-Type': 'application/json'} if data is not None else {})})
    kw = ({'context': ssl._create_unverified_context()} if args.insecure else
          {'context': ssl.create_default_context(cafile=args.ca)} if args.ca else {})
    try:
        with opener.open(req, timeout=args.timeout, **kw) as r:
            text = r.read().decode()
    except urllib.error.HTTPError as e:
        text = e.read().decode(errors='replace')
        try:
            answer = json.loads(text)
            detail = answer.get('detail')
            if isinstance(detail, list):         # FastAPI's validation errors
                detail = '; '.join(f"{'.'.join(str(x) for x in d.get('loc', [])[1:])}: {d.get('msg')}" for d in detail)
            errors = answer.get('errors')
            if errors:
                detail = f"{detail}: {'; '.join(f'{k}: {v}' for k, v in errors.items())}"
        except ValueError:
            detail = text.strip()[:200] or e.reason
        raise Failed(f'{e.code} {detail}')
    except urllib.error.URLError as e:
        raise Failed(f"can't reach {args.url}: {e.reason}")
    return json.loads(text) if text else None


def _target(args):
    body = {}
    if args.subnet:
        body['subnet'] = args.subnet
    elif args.network:
        body['network'] = args.network
    elif args.range:
        body['range'] = args.range
    else:
        raise Failed('give --subnet, --network or --range')
    return body


def _free(args, hold=True):
    return call(args, 'POST', '/ipam/next-free', {**_target(args), 'count': args.blocksize, 'align': args.align,
                                                 'hold': hold, 'minutes': args.minutes, 'note': args.note or ''})


def _warn(answer):
    for w in answer.get('warnings') or []:
        print(f'  note: {w}')


def cmd_next(args):
    answer = _free(args, hold=not args.no_hold)
    if args.json:
        return answer
    print(', '.join(answer['ips']))
    if answer.get('hold_id'):
        print(f"  held until {answer['hold_until']} (hold {answer['hold_id']})", file=sys.stderr)
    for w in answer.get('warnings') or []:
        print(f'  note: {w}', file=sys.stderr)


def cmd_reserve(args):
    macs = args.mac or []
    if args.ip:
        ips, hold = args.ip, None
    else:
        found = _free(args)
        ips, hold = found['ips'], found.get('hold_id')
    if macs and len(macs) != len(ips):
        raise Failed(f'give one --mac per address ({len(ips)})')
    try:
        answer = call(args, 'POST', '/ipam/assign', {
            'ips': ips, 'name': args.name, 'zone': args.zone, 'macs': macs or None, 'comment': args.comment or '',
            'group': args.group or '', 'publish': not args.no_publish, 'target': 'ipam' if args.ipam else None})
    except Failed:
        if hold:
            call(args, 'DELETE', '/ipam/holds', query={'hold_id': hold})
        raise
    if args.json:
        return answer
    what = {'reservation': 'reservation', 'static': 'A record', 'ipam': 'IPAM name'}
    kinds = answer.get('kinds') or [answer['kind']] * len(answer['ips'])
    for ip, name, kind in zip(answer['ips'], answer['names'], kinds):
        print(f'✓ {ip} {name} ({what.get(kind, kind)})')
    if answer.get('jobs'):
        print(f"  jobs: {', '.join(str(j) for j in answer['jobs'])} (GET /api/v1/jobs/<id>)")
    for n in answer.get('notes') or []:
        print(f'  note: {n}')
    _warn(answer)


def cmd_unassign(args):
    if args.group:
        body = {'group': args.group}
    elif args.what and '-' in args.what[0]:
        body = {'range': args.what[0]}
    elif args.what:
        body = {'ips': args.what}
    else:
        raise Failed('give addresses, a range a-b, or --group')
    answer = call(args, 'POST', '/ipam/unassign', {**body, 'publish': not args.no_publish})
    if args.json:
        return answer
    for ip in answer['removed']:
        print(f'✓ unassigned {ip}')
    for ip in answer['skipped']:
        print(f'  skipped {ip}: not made by assign')
    for n in answer.get('notes') or []:
        print(f'  note: {n}')
    _warn(answer)


def cmd_release(args):
    if args.hold:
        answer = call(args, 'DELETE', '/ipam/holds', query={'hold_id': args.hold})
    elif args.ip:
        answer = call(args, 'DELETE', f'/ipam/holds/{args.ip}')
    else:
        raise Failed('give an address or --hold')
    if args.json:
        return answer
    print(f"✓ released {', '.join(answer['released']) or 'nothing (no such hold)'}")


def _client(x):
    """A DHCP client as Search names it: its MAC, or a DHCPv6 client's DUID."""
    return x.get('mac') or (f"duid {x['duid']}" if x.get('duid') else '?')


def cmd_show(args):
    answer = call(args, 'GET', '/search', query={'q': args.ip})
    a = answer.get('address')
    if args.json:
        return a or answer
    if not a:
        raise Failed(f'{args.ip} is not an IP address')
    r, lease = a.get('reservation'), a.get('lease')
    # a module that's off gets no '-' lines (an IPAM-only install has no names or leases to show)
    on = set(call(args, 'GET', '/status').get('modules') or ('dns', 'dhcp'))
    print(a['ip'])
    if 'dns' in on or a['names'] or a['ptr']:
        print(f"  names        {', '.join(a['names']) or '-'}")
        print(f"  ptr          {', '.join(a['ptr']) or '-'}")
    if a.get('ipam'):
        print(f"  ipam name    {a['ipam']['name']}{' ' + a['ipam']['mac'] if a['ipam']['mac'] else ''}")
    if a.get('rdns'):
        print(f"  rdns         {a['rdns']['name'] or a['rdns']['error'] or 'no PTR'}")
    if 'dhcp' in on or r or lease or a.get('subnet'):
        print(f"  reservation  {_client(r) + ' ' + (r['hostname'] or '') if r else '-'}")
        print(f"  lease        {_client(lease) + ' ' + lease['state'] if lease else '-'}")
        print(f"  subnet       {a.get('subnet') or '-'}")
    for c in a.get('checks') or []:
        print(f"  {c['level']:<12} {c['text']}")


def parser():
    p = argparse.ArgumentParser(prog='lbcli.py', description="LiteBlox's IPAM from the command line.")
    p.add_argument('--url', default=os.environ.get('LITEBLOX_URL'), help='LiteBlox, e.g. https://liteblox.example.com '
                   '(or LITEBLOX_URL)')
    p.add_argument('--token-file', help='a file holding the API token (else LITEBLOX_TOKEN)')
    p.add_argument('--json', action='store_true', help="print the API's answer as JSON")
    p.add_argument('--ca', default=os.environ.get('LITEBLOX_CA'), help='trust this certificate '
                   "(e.g. the one from Settings → HTTPS: Download the certificate; or LITEBLOX_CA)")
    p.add_argument('--insecure', action='store_true', help="don't check the server's TLS certificate")
    p.add_argument('--timeout', type=float, default=120.0)
    sub = p.add_subparsers(dest='command', required=True)

    def target(sp):
        g = sp.add_mutually_exclusive_group()
        g.add_argument('--subnet', help='a DHCP subnet (id or prefix): outside its pools')
        g.add_argument('--network', help='an IPAM network (id or prefix)')
        g.add_argument('--range', type=int, help="an IPAM range's id")
        sp.add_argument('--blocksize', type=int, default=1, help='addresses in a row (1-64)')
        sp.add_argument('--align', action='store_true', help='start the block on a multiple of its size')
        sp.add_argument('--minutes', type=int, default=10, help='how long the hold lasts')
        sp.add_argument('--note', help='kept with the hold')

    sp = sub.add_parser('next', help='the next free addresses (held for --minutes)')
    target(sp)
    sp.add_argument('--no-hold', action='store_true')
    sp.set_defaults(func=cmd_next)

    sp = sub.add_parser('reserve', help='next free + assign a name (with --mac: a DHCP reservation)')
    sp.add_argument('name', help="host, host.zone, or k8s-{n} for a block")
    target(sp)
    sp.add_argument('--ip', nargs='+', help='these addresses instead of the next free')
    sp.add_argument('--mac', nargs='+', help='one per address: DHCP reservations')
    sp.add_argument('--zone')
    sp.add_argument('--group', help='a tag to unassign the lot by')
    sp.add_argument('--comment')
    sp.add_argument('--no-publish', action='store_true', help='leave the A records in the draft')
    sp.add_argument('--ipam', action='store_true',
                    help='keep the names in IPAM only, no A records (the default when LiteBlox runs no DNS)')
    sp.set_defaults(func=cmd_reserve)

    sp = sub.add_parser('unassign', help='remove what reserve made: addresses, a range a-b, or --group')
    sp.add_argument('what', nargs='*')
    sp.add_argument('--group')
    sp.add_argument('--no-publish', action='store_true')
    sp.set_defaults(func=cmd_unassign)

    sp = sub.add_parser('release', help='drop a hold: an address, or --hold ID for a block')
    sp.add_argument('ip', nargs='?')
    sp.add_argument('--hold')
    sp.set_defaults(func=cmd_release)

    sp = sub.add_parser('show', help='everything about one address')
    sp.add_argument('ip')
    sp.set_defaults(func=cmd_show)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not args.url:
            raise Failed('give --url or set LITEBLOX_URL')
        if args.token_file:
            with open(args.token_file) as f:
                args.token = f.read().strip()
        else:
            args.token = os.environ.get('LITEBLOX_TOKEN', '').strip()
        if not args.token:
            raise Failed('give --token-file or set LITEBLOX_TOKEN')
        out = args.func(args)
        if args.json and out is not None:
            print(json.dumps(out, indent=2))
        return 0
    except Failed as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
