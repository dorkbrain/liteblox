"""Release step (./deploy/deploy.py --release): after the release commit and tag are pushed to Forgejo,
put the release out everywhere else:

  1. the public GitHub copy (deploy/_mirror.py): checked, committed, tagged v<ver> and pushed;
  2. a release on Forgejo for the tag, with the downloads attached (Forgejo's API; the token is read
     from ~/.config/liteblox/forgejo-token, never printed or put on a command line);
  3. a release on GitHub for the copy's tag, with the same downloads (the gh command, signed in);
  4. both read back: every file there, at its size.

The downloads are the source tarball and each image tarball, with their .sha256.txt checksums.
.publish names the places: `forgejo https://HOST owner/repo`, `github owner/repo`, plus the copy's
`author` and `signingkey`. --dry-run checks and commits the copy locally and does nothing else.
"""

import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import _archive
import _mirror
import _publish
from _common import ROOT, changelog_section, read_publish

TOKEN_FILE = Path('~/.config/liteblox/forgejo-token').expanduser()
INSTALL_URL = 'https://liteblox.dorkbrain.com/install/'


class ReleaseError(Exception):
    pass


def notes(version):
    return f"{changelog_section(version)}\n\nInstall and docs: {INSTALL_URL}\n"


# ── Before anything ────────────────────────────────────────────────────────────

def preflight(project, version, files):
    """The tag is here and on Forgejo, HEAD is at it, and every download is built."""
    tag = f'v{version}'
    here = _mirror.git('rev-parse', '-q', '--verify', f'refs/tags/{tag}^{{commit}}', cwd=ROOT, check=False)
    if not here:
        raise ReleaseError(f'no tag {tag} here: commit, tag and push the release first')
    if _mirror.git('rev-parse', 'HEAD', cwd=ROOT) != here:
        raise ReleaseError(f'HEAD is not at {tag}')
    if not _mirror.git('ls-remote', '--tags', 'origin', f'refs/tags/{tag}', cwd=ROOT):
        raise ReleaseError(f'{tag} is not on origin: git push origin {tag}')
    missing = [p.name for p in files if not p.exists()]
    if missing:
        raise ReleaseError(f"not built: {', '.join(missing)}")
    return tag


# ── Forgejo ────────────────────────────────────────────────────────────────────

class Forgejo:
    """The few release calls, with the token in a header only."""

    def __init__(self, base, repo, token):
        self.api = f"{base.rstrip('/')}/api/v1/repos/{repo}"
        self._token = token

    @classmethod
    def from_publish(cls, conf, token_file=TOKEN_FILE):
        parts = (conf.get('forgejo') or '').split()
        if len(parts) != 2:
            raise ReleaseError("no 'forgejo https://HOST owner/repo' line in .publish")
        if not token_file.exists():
            raise ReleaseError(f'no Forgejo token in {token_file} (write:repository; mode 600)')
        if token_file.stat().st_mode & 0o077:
            raise ReleaseError(f'{token_file} is readable by others: chmod 600 it')
        return cls(*parts, token_file.read_text().strip())

    def call(self, method, path, body=None, content_type='application/json'):
        data = json.dumps(body).encode() if isinstance(body, dict) else body
        req = urllib.request.Request(f'{self.api}{path}', data=data, method=method, headers={
            'Authorization': f'token {self._token}', 'Accept': 'application/json',
            **({'Content-Type': content_type} if data is not None else {})})
        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 and method == 'GET':
                return None
            raise ReleaseError(f'Forgejo {method} {path}: HTTP {e.code} {e.read()[:300].decode("utf-8", "replace")}') from None
        return json.loads(raw) if raw else {}

    def release(self, tag, title, body):
        """The tag's release, made when it isn't there yet."""
        found = self.call('GET', f'/releases/tags/{urllib.parse.quote(tag)}')
        if found:
            return found, False
        made = self.call('POST', '/releases', {'tag_name': tag, 'name': title, 'body': body,
                                               'draft': False, 'prerelease': False})
        return made, True

    def upload(self, release_id, path):
        boundary = uuid.uuid4().hex
        head = (f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; filename="{path.name}"\r\n'
                'Content-Type: application/octet-stream\r\n\r\n').encode()
        body = head + path.read_bytes() + f'\r\n--{boundary}--\r\n'.encode()
        return self.call('POST', f'/releases/{release_id}/assets?name={urllib.parse.quote(path.name)}', body,
                         f'multipart/form-data; boundary={boundary}')

    def assets(self, tag):
        found = self.call('GET', f'/releases/tags/{urllib.parse.quote(tag)}') or {}
        return {a['name']: a['size'] for a in found.get('assets', [])}


def forgejo_release(forgejo, tag, version, files):
    release, made = forgejo.release(tag, f'LiteBlox {version}', notes(version))
    print(f"{'✓ Made' if made else '  Found'} the Forgejo release for {tag}")
    have = {a['name'] for a in release.get('assets', [])}
    for path in files:
        if path.name in have:
            print(f"  {path.name}: already attached")
            continue
        print(f"  uploading {path.name} ({path.stat().st_size / 1048576:.1f} MB)...")
        forgejo.upload(release['id'], path)
    return forgejo.assets(tag)


# ── GitHub ─────────────────────────────────────────────────────────────────────

def gh(*args, input=None, check=True):
    result = subprocess.run(['gh', *args], capture_output=True, text=True, input=input)
    if check and result.returncode != 0:
        raise ReleaseError(f"gh {' '.join(args[:3])}: {(result.stderr or result.stdout).strip()}")
    return result


def github_assets(repo, tag):
    """{name: size} of the GitHub release, or None when there's no release."""
    result = gh('release', 'view', tag, '--repo', repo, '--json', 'assets', check=False)
    if result.returncode != 0:
        if 'not found' in (result.stderr or '').lower():
            return None
        raise ReleaseError(f'gh release view {tag}: {result.stderr.strip()}')
    return {a['name']: a['size'] for a in json.loads(result.stdout)['assets']}


def github_release(repo, tag, version, files):
    have = github_assets(repo, tag)
    if have is None:
        print(f"  making the GitHub release for {tag}, uploading {len(files)} files...")
        gh('release', 'create', tag, '--repo', repo, '--verify-tag', '--title', f'LiteBlox {version}',
           '--notes-file', '-', *map(str, files), input=notes(version))
        print(f"✓ Made the GitHub release for {tag}")
    else:
        missing = [p for p in files if p.name not in have]
        print(f"  Found the GitHub release for {tag}" + (f"; uploading {len(missing)} files" if missing else ''))
        if missing:
            gh('release', 'upload', tag, '--repo', repo, *map(str, missing))
    return github_assets(repo, tag) or {}


# ── Reading back ───────────────────────────────────────────────────────────────

def compare(where, files, assets):
    """Every file there at its size, or a ReleaseError naming the differences."""
    wrong = [f'{p.name} (missing)' if p.name not in assets else f'{p.name} ({assets[p.name]} bytes, not {p.stat().st_size})'
             for p in files if assets.get(p.name) != p.stat().st_size]
    if wrong:
        raise ReleaseError(f"{where} doesn't match dist/: " + ', '.join(wrong))
    print(f"✓ {where}: all {len(files)} files, sizes match")


def release(project, version, dry_run=False):
    conf = read_publish()
    files = _publish.release_files(project, version)
    try:
        tag = preflight(project, version, files)
        with tempfile.TemporaryDirectory(prefix='liteblox-release-') as work:
            _mirror.publish(conf, version, _archive.archive_path(project, version), tag, dry_run=dry_run, workdir=work)
        if dry_run:
            print("\n  dry run: no releases made")
            return True
        forgejo = Forgejo.from_publish(conf)
        compare('Forgejo release', files, forgejo_release(forgejo, tag, version, files))
        repo = conf.get('github')
        compare('GitHub release', files, github_release(repo, tag, version, files))
    except (ReleaseError, _mirror.MirrorError) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return False
    return True
