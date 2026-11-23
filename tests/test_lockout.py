import pytest

from liteblox.bindconf.lockout import check, matches
from liteblox.bindconf.model import NodeOptions

ACLS = {'lan': ['!192.168.1.66', '192.168.1.0/24'], 'outer': ['lan', '10.0.0.0/8'], 'fuzzy': ['localnets']}


@pytest.mark.parametrize('items, address, verdict', [
    (['any'], '192.0.2.1', True),
    (['none'], '192.0.2.1', False),
    ([], '192.0.2.1', False),
    (['192.0.2.0/24'], '192.0.2.1', True),
    (['192.0.2.1'], '192.0.2.2', False),
    (['!192.0.2.1', 'any'], '192.0.2.1', False),          # first match wins
    (['any', '!192.0.2.1'], '192.0.2.1', True),
    (['key liteblox-xfr'], '192.0.2.1', False),           # LiteBlox's own queries aren't signed
    (['key liteblox-xfr', 'any'], '192.0.2.1', True),
    (['lan'], '192.168.1.5', True),
    (['lan'], '192.168.1.66', False),
    (['outer'], '10.1.2.3', True),
    (['outer'], '172.16.0.1', False),
    (['lan', 'any'], '192.168.1.66', False),             # the nested list's "no" stands
    (['!lan', 'any'], '192.168.1.5', False),
    (['!lan', 'any'], '172.16.0.1', True),
    (['192.0.2.0/24', '!192.0.2.1'], '192.0.2.1', True),  # first match wins
    (['localhost'], '192.0.2.1', None),
    (['fuzzy'], '192.0.2.1', None),
    (['unknown-acl'], '192.0.2.1', None),
    (['192.0.2.1', 'localnets'], '192.0.2.1', True),     # decided before the unknowable item
    (['2001:db8::/32'], '2001:db8::53', True),
])
def test_matches(items, address, verdict):
    assert matches(items, address, ACLS) is verdict


def test_matches_survives_a_loop():
    assert matches(['a'], '192.0.2.1', {'a': ['b'], 'b': ['a']}) is None


def test_check_flags_a_lockout_and_skips_the_recursion_probe():
    o = NodeOptions(allow_query=['192.168.1.0/24'], allow_recursion=['localhost'], listen_on=['192.168.1.213'])
    found, recursion = check(o, '192.168.1.213', '10.9.9.9', ACLS)
    assert ('block', "allow-query would refuse LiteBlox itself (10.9.9.9), so it could no longer check this node's zones") in found
    assert any(level == 'warn' and 'allow-recursion may leave out' in msg for level, msg in found)
    assert recursion is False
    assert not any('listen-on' in msg for _, msg in found)

    found, _ = check(NodeOptions(listen_on=['127.0.0.1']), '192.168.1.213', '192.168.1.5', ACLS)
    assert found == [('block', "listen-on doesn't include the node's DNS address 192.168.1.213: named would "
                               'stop answering there')]
    found, recursion = check(NodeOptions(allow_query=['lan'], recursion=False), '192.168.1.213', '192.168.1.5', ACLS)
    assert found == [] and recursion is False                   # recursion off: nothing to probe
    found, _ = check(NodeOptions(allow_query=['fuzzy']), '192.168.1.213', '192.168.1.5', ACLS)
    assert [level for level, _ in found] == ['warn']
    found, _ = check(NodeOptions(), None, None, ACLS)
    assert [level for level, _ in found] == ['warn']            # an agent that doesn't say
