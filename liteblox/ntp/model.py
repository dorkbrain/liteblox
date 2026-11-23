"""What LiteBlox knows about one node's time config: the sources (the same for every node) and whether it serves."""

import json
from dataclasses import asdict, dataclass, field
from typing import Optional

ROLES = ('chrony.conf',)
DEFAULT_LOCAL_STRATUM = 10


@dataclass
class Source:
    kind: str                       # server (one address) or pool (a name with several)
    address: str
    iburst: bool = True
    prefer: bool = False
    nts: bool = False
    minpoll: Optional[int] = None
    maxpoll: Optional[int] = None

    def line(self):
        words = [self.kind, self.address] + [w for w, on in (('iburst', self.iburst), ('prefer', self.prefer),
                                                              ('nts', self.nts)) if on]
        words += [f'{k} {v}' for k, v in (('minpoll', self.minpoll), ('maxpoll', self.maxpoll)) if v is not None]
        return ' '.join(words)


# what Debian ships, until an admin picks sources
DEFAULT_SOURCES = [Source('pool', '2.debian.pool.ntp.org')]


@dataclass
class NtpConfig:
    sources: list = field(default_factory=lambda: list(DEFAULT_SOURCES))
    serve: bool = False
    allow: list = field(default_factory=list)       # networks it serves time to
    local: Optional[int] = None                     # local stratum (orphan) when the upstreams are unreachable
    chrony_version: Optional[str] = None            # the node's chrony; None: a current one (4.6 and later)


def sources(conn):
    """The sources every node syncs from (Debian's pool until some are set)."""
    row = conn.execute('SELECT sources FROM ntp_settings WHERE id = 1').fetchone()
    stored = json.loads(row[0]) if row else []
    return [Source(**s) for s in stored] or list(DEFAULT_SOURCES)


def custom(conn):
    row = conn.execute('SELECT sources FROM ntp_settings WHERE id = 1').fetchone()
    return bool(row and json.loads(row[0]))


def to_json(source_list):
    return json.dumps([asdict(s) for s in source_list])


def ntp_nodes(conn):
    return conn.execute('SELECT * FROM nodes WHERE ntp = 1 ORDER BY name').fetchall()


def for_node(conn, node, source_list=None, serve=None, allow=None, local=None):
    """The node's chrony config from the DB; the keyword arguments stand in for unsaved changes (previews)."""
    if conn is None:
        return NtpConfig()
    keys = node.keys() if hasattr(node, 'keys') else node
    stored_allow = json.loads(node['ntp_allow'] or '[]') if 'ntp_allow' in keys else []
    return NtpConfig(sources=sources(conn) if source_list is None else list(source_list),
                     serve=bool(node['ntp_serve']) if serve is None and 'ntp_serve' in keys else bool(serve),
                     allow=stored_allow if allow is None else list(allow),
                     local=(node['ntp_local'] if 'ntp_local' in keys else None) if local is None else local or None,
                     chrony_version=node['chrony_version'] if 'chrony_version' in keys else None)
