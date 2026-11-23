"""Would a settings change lock LiteBlox (or the node's own DNS address) out?

matches() evaluates a BIND address-match list for one address the way named
does (first match wins, `!` negates, ACLs nest). Where the answer depends on
something LiteBlox can't see (localhost, localnets, an unknown name) it
returns None: "can't tell", which the caller shows as a warning.
"""

import ipaddress

UNKNOWABLE = ('localhost', 'localnets')


ALLOW, DENY, UNKNOWN = 'allow', 'deny', 'unknown'


def _element(item, address, acls, depth):
    """Does this one element (without its `!`) match? True/False, or UNKNOWN; a nested ACL gives its verdict."""
    if item == 'any':
        return True
    if item == 'none':
        return False
    if item.startswith('key '):
        return False            # LiteBlox's own queries aren't signed
    if item in UNKNOWABLE:
        return UNKNOWN
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(item, strict=False)
    except ValueError:
        pass
    if item in acls and depth < 10:
        return _evaluate(acls[item], address, acls, depth + 1)
    return UNKNOWN


def _evaluate(items, address, acls, depth):
    """ALLOW / DENY at the first element that matches, UNKNOWN, or None when nothing matched."""
    for item in items:
        negated = item.startswith('!')
        hit = _element(item.lstrip('!').strip(), address, acls, depth)
        if hit == UNKNOWN:
            return UNKNOWN
        if hit in (ALLOW, DENY):        # a nested list decided; `!` in front of it flips that
            return (DENY if hit == ALLOW else ALLOW) if negated else hit
        if hit:
            return DENY if negated else ALLOW
    return None


def matches(items, address, acls=None, depth=0):
    """Is `address` allowed by the list? True, False, or None when LiteBlox can't tell."""
    verdict = _evaluate(items, address, acls or {}, depth)
    if verdict == UNKNOWN:
        return None
    return verdict == ALLOW     # nothing matched: refused


def check(options, node_address, client_address, acls):
    """[(level, message)] for a node's new options; level 'block' (needs "apply anyway") or 'warn'.

    Also returns whether LiteBlox can probe recursion afterwards (it can't when
    the new allow-recursion leaves its own address out).
    """
    found, probe_recursion = [], options.recursion is not False
    if client_address is None:
        found.append(('warn', "the agent didn't say which address LiteBlox reaches it from, so allow-query "
                              "can't be checked"))
    elif options.allow_query is not None:
        verdict = matches(options.allow_query, client_address, acls)
        if verdict is False:
            found.append(('block', f'allow-query would refuse LiteBlox itself ({client_address}), so it could '
                                   "no longer check this node's zones"))
        elif verdict is None:
            found.append(('warn', f"can't tell whether allow-query admits LiteBlox ({client_address}): it uses "
                                  'localhost, localnets or a name LiteBlox doesn\'t know'))
    if client_address and probe_recursion and options.allow_recursion is not None:
        verdict = matches(options.allow_recursion, client_address, acls)
        if verdict is not True:
            probe_recursion = False
            found.append(('warn', f'allow-recursion {"leaves out" if verdict is False else "may leave out"} '
                                  f'LiteBlox ({client_address}), so recursion is not checked after the change'))
    if node_address:
        version = ipaddress.ip_address(node_address).version
        listen = options.listen_on if version == 4 else options.listen_on_v6
        if listen is not None:
            verdict = matches(listen, node_address, acls)
            name = 'listen-on' if version == 4 else 'listen-on-v6'
            if verdict is False:
                found.append(('block', f"{name} doesn't include the node's DNS address {node_address}: named "
                                       'would stop answering there'))
            elif verdict is None:
                found.append(('warn', f"can't tell whether {name} includes the node's DNS address {node_address}"))
    return found, probe_recursion
