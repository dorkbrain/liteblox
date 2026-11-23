"""BIND nodes: the liteblox-agent client, and (later) bootstrap over SSH."""

import hashlib
from pathlib import Path

_PACKAGE_AGENT = Path(__file__).resolve().parent.parent / '_agent'
_REPO_AGENT = Path(__file__).resolve().parents[2] / 'agent'


def agent_dir():
    """Directory holding liteblox_agent.py and its unit file (repo checkout or installed package)."""
    return _REPO_AGENT if (_REPO_AGENT / 'liteblox_agent.py').exists() else _PACKAGE_AGENT


def agent_sha256():
    """Hash of the agent source we ship; a node reporting a different one needs upgrading."""
    return hashlib.sha256((agent_dir() / 'liteblox_agent.py').read_bytes()).hexdigest()


_agent_module = None


def agent_module():
    """The agent's own code, imported so LiteBlox parses named.conf exactly as the agent does."""
    global _agent_module
    if _agent_module is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location('liteblox_agent', agent_dir() / 'liteblox_agent.py')
        _agent_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_agent_module)
    return _agent_module
