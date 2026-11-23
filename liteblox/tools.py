"""Tools: the subnet reference (/0 to /32) and the subnet calculator, for any logged-in user."""

import ipaddress

from fastapi import APIRouter, Depends, Request

from .auth import User, current_user
from .templating import templates

router = APIRouter()
COMMON = {8, 16, 24}       # lightly highlighted in the reference


def usable_hosts(prefix):
    """Addresses a host can use: all but the network and broadcast, except /31 (point-to-point, RFC 3021) and /32."""
    if prefix == 32:
        return 1
    if prefix == 31:
        return 2
    return 2 ** (32 - prefix) - 2


def next_net(prefix):
    """Where the next network of this size starts, written over a.b.c.d: /24 is a.b.c+1.d, /26 is a.b.c.d+64."""
    if prefix == 0:
        return 'n/a'
    octet = (prefix - 1) // 8           # the octet holding the last network bit
    step = 2 ** (8 * (octet + 1) - prefix)
    return '.'.join(f'{letter}+{step}' if i == octet else letter for i, letter in enumerate('abcd'))


def reference():
    return [{'prefix': n,
             'mask': str(ipaddress.IPv4Network(f'0.0.0.0/{n}').netmask),
             'hosts': usable_hosts(n),
             'next': next_net(n),
             'common': n in COMMON} for n in range(33)]


@router.get('/tools/subnets')
def subnets(request: Request, user: User = Depends(current_user)):
    return templates.TemplateResponse(request, 'tools_subnets.html', {'user': user, 'rows': reference()})


@router.get('/tools/subnet-calculator')
def calculator(request: Request, user: User = Depends(current_user)):
    return templates.TemplateResponse(request, 'tools_calculator.html', {'user': user})
