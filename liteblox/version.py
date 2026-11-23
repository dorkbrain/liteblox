"""Version lookup: VERSION at the repo root in a dev checkout, package metadata when installed."""

from importlib import metadata
from pathlib import Path

_REPO_VERSION = Path(__file__).resolve().parent.parent / 'VERSION'


def get_version():
    if _REPO_VERSION.exists():
        return _REPO_VERSION.read_text().strip()
    try:
        return metadata.version('liteblox')
    except metadata.PackageNotFoundError:
        return '0.0.0'


__version__ = get_version()
