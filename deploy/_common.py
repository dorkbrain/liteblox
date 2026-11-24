"""Shared helpers for the deploy pipeline: project root, name, version, registries, changelog."""

import hashlib
import os
import re
import shutil
import sys
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent     # deploy/ lives at the project root
DEFAULT_VERSION = "0.1.0"

VERSION_FILE = ROOT / 'VERSION'
PROJECT_FILE = ROOT / 'PROJECT'
CHANGELOG_FILE = ROOT / 'CHANGELOG.md'
PUBLISH_FILE = ROOT / '.publish'

# the architectures every release image is built for; the first is the workstation's own
ARCHES = ['amd64', 'arm64']


# ── .publish ───────────────────────────────────────────────────────────────────

SINGLE_KEYS = ('to', 'site', 'forgejo', 'github', 'author', 'signingkey')


def read_publish():
    """.publish as a dict: 'to' (downloads), 'site', 'forgejo' (URL and owner/repo), 'github'
    (owner/repo), 'author' (of the GitHub copy), 'signingkey', 'registry' (a list) and 'extra' (paths)."""
    out = {key: None for key in SINGLE_KEYS} | {'registry': [], 'extra': []}
    if PUBLISH_FILE.exists():
        for line in PUBLISH_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            key, _, rest = line.partition(' ')
            if key in SINGLE_KEYS:
                out[key] = rest.strip()
            elif key == 'registry':
                out['registry'].append(rest.strip().rstrip('/'))
            else:
                out['extra'].append(line)
    return out


def registries():
    """Where the image is pushed, in order: REGISTRY (space-separated) or .publish's registry lines."""
    env = os.environ.get('REGISTRY', '').split()
    return [r.rstrip('/') for r in env] if env else read_publish()['registry']


def push_name(project):
    """The image's name at the registries: PUSH_AS (a scratch package, to try a push) or the project's."""
    return os.environ.get('PUSH_AS') or project


def image_tags(version):
    """X.Y.Z, X.Y, X and latest: the full version first, so a failed push never moves the others."""
    major, minor, _ = version.split('.')
    return [version, f'{major}.{minor}', major, 'latest']


# ── Seeding ────────────────────────────────────────────────────────────────────

def seed_files():
    """Create VERSION and PROJECT on first run so a fresh project just works."""
    if not VERSION_FILE.exists():
        VERSION_FILE.write_text(DEFAULT_VERSION + '\n')
        print(f"✓ Seeded VERSION with {DEFAULT_VERSION}")
    if not PROJECT_FILE.exists():
        PROJECT_FILE.write_text(ROOT.name + '\n')
        print(f"✓ Seeded PROJECT with {ROOT.name}")


# ── Project / version ──────────────────────────────────────────────────────────

def read_project():
    name = PROJECT_FILE.read_text().strip() if PROJECT_FILE.exists() else ''
    return name or ROOT.name


def read_version():
    try:
        return VERSION_FILE.read_text().strip()
    except FileNotFoundError:
        print("ERROR: VERSION file not found", file=sys.stderr)
        return None


def parse_version(version_str):
    return [int(x) for x in version_str.split('.')]


def bump_version(version_str, bump_type='patch'):
    parts = parse_version(version_str)
    if bump_type == 'patch':
        parts[2] += 1
    elif bump_type == 'minor':
        parts[1] += 1
        parts[2] = 0
    elif bump_type == 'major':
        parts[0] += 1
        parts[1] = 0
        parts[2] = 0
    return '.'.join(str(x) for x in parts)


def bump_to(version_str, target):
    """target (X.Y.Z) when it's later than version_str: a jump such as 4.8.0 → 6.0.0. Raises ValueError otherwise."""
    if not re.fullmatch(r'\d+\.\d+\.\d+', target or ''):
        raise ValueError(f'{target!r} is not a version (X.Y.Z)')
    if parse_version(target) <= parse_version(version_str):
        raise ValueError(f'{target} is not later than {version_str}: --bump-to only moves forward')
    return target


def write_version(new_version):
    VERSION_FILE.write_text(new_version + '\n')
    print(f"✓ Updated VERSION to {new_version}")


def changelog_section(version):
    """The changelog lines of one version (without its heading), or '' when it has none."""
    text = CHANGELOG_FILE.read_text() if CHANGELOG_FILE.exists() else ''
    found = re.search(rf'^## {re.escape(version)} — .*?\n(.*?)(?=^## |\Z)', text, re.M | re.S)
    return found[1].strip() if found else ''


# ── Changelog ──────────────────────────────────────────────────────────────────

def prompt_changelog():
    print("\nEnter changelog message (empty line to finish):")
    print("Each line will be prefixed with '- ' automatically")
    print("-" * 50)

    lines = []
    try:
        while True:
            line = input()
            if not line:
                break
            lines.append(f"- {line}")
    except EOFError:
        pass

    if not lines:
        lines.append("- Version bump")

    return '\n'.join(lines)


def update_changelog(new_version, message):
    entry = f"## {new_version} — {date.today()}\n\n{message}\n"

    old_content = CHANGELOG_FILE.read_text() if CHANGELOG_FILE.exists() else ""

    with CHANGELOG_FILE.open('w') as f:
        f.write("# Changelog\n\n" + entry + "\n")
        for line in old_content.splitlines(keepends=True):
            if line.strip() == "# Changelog":
                continue
            f.write(line)

    print(f"✓ Added changelog entry for {new_version}")


# ── Checksums ──────────────────────────────────────────────────────────────────

def checksum_path(path):
    # .txt so a browser shows it instead of downloading it
    return path.with_name(path.name + '.sha256.txt')


def write_checksum(path):
    """<file>.sha256.txt in sha256sum's format, with the bare file name, so `sha256sum -c` works beside it."""
    digest = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            digest.update(chunk)
    out = checksum_path(path)
    out.write_text(f"{digest.hexdigest()}  {path.name}\n")
    return out


# ── Tooling ────────────────────────────────────────────────────────────────────

def check_podman():
    if shutil.which('podman') is None:
        print("ERROR: podman not found in PATH", file=sys.stderr)
        return False
    return True
