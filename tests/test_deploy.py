"""The release pipeline's image steps (deploy/_common.py, _build.py, _push.py, _publish.py), podman faked."""

import gzip
import io
import json
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'deploy'))
import _build  # noqa: E402
import _common  # noqa: E402
import _publish  # noqa: E402
import _push  # noqa: E402


@pytest.fixture
def publish_file(tmp_path, monkeypatch):
    path = tmp_path / '.publish'
    monkeypatch.setattr(_common, 'PUBLISH_FILE', path)
    monkeypatch.delenv('REGISTRY', raising=False)
    monkeypatch.delenv('PUBLISH_TO', raising=False)
    return path


class Podman:
    """Records every podman call; fail_on(cmd) picks the calls that fail."""

    def __init__(self, fail_on=None, manifest=None):
        self.calls, self.fail_on, self.manifest = [], fail_on, manifest

    def __call__(self, cmd, **kwargs):
        self.calls.append(cmd)
        if self.fail_on and self.fail_on(cmd):
            return SimpleNamespace(returncode=1, stdout='', stderr='denied')
        out = json.dumps(self.manifest) if self.manifest and cmd[1:3] == ['manifest', 'inspect'] else ''
        return SimpleNamespace(returncode=0, stdout=out, stderr='')


def index(*arches):
    return {'manifests': [{'digest': f'sha256:{a}', 'platform': {'os': 'linux', 'architecture': a}} for a in arches]}


def test_image_tags():
    assert _common.image_tags('4.6.1') == ['4.6.1', '4.6', '4', 'latest']
    assert _common.image_tags('10.0.0') == ['10.0.0', '10.0', '10', 'latest']


def test_registries_come_from_publish_in_order(publish_file):
    publish_file.write_text('to host:/dl\nregistry git.example.com/org/\nregistry reg.example.com\nwiki/x.txt\n')
    assert _common.registries() == ['git.example.com/org', 'reg.example.com']
    assert _publish.settings() == ('host:/dl', ['wiki/x.txt'])    # a registry line isn't an extra file


def test_registry_env_overrides_as_a_list(publish_file, monkeypatch):
    publish_file.write_text('registry reg.example.com\n')
    monkeypatch.setenv('REGISTRY', 'one.example.com/a  two.example.com')
    assert _common.registries() == ['one.example.com/a', 'two.example.com']


def test_push_as_renames_only_the_destination(monkeypatch):
    monkeypatch.setenv('PUSH_AS', 'liteblox-test')
    podman = Podman(manifest=index('amd64', 'arm64'))
    monkeypatch.setattr(_push.subprocess, 'run', podman)
    assert _push.push_image('liteblox', ['reg.example.com'], '4.6.1')
    assert podman.calls[0][-2:] == ['liteblox-manifest:4.6.1', 'docker://reg.example.com/liteblox-test:4.6.1']
    assert _common.read_project() == 'liteblox'


def test_names_per_architecture():
    assert _common.ARCHES[0] == 'amd64' and 'arm64' in _common.ARCHES
    assert _build.local_image('liteblox', '4.6.1', 'amd64') == 'liteblox:4.6.1'
    assert _build.local_image('liteblox', '4.6.1', 'arm64') == 'liteblox:4.6.1-arm64'
    assert _build.manifest_name('liteblox', '4.6.1') == 'liteblox-manifest:4.6.1'
    assert _build.tarball_path('liteblox', '4.6.1', 'arm64').name == 'liteblox-image-v4.6.1-arm64.tar.gz'


def test_release_files_hold_every_architecture():
    names = [p.name for p in _publish.release_files('liteblox', '4.6.1')]
    assert names == ['liteblox-src-v4.6.1.tgz', 'liteblox-src-v4.6.1.tgz.sha256.txt',
                     'liteblox-image-v4.6.1-amd64.tar.gz', 'liteblox-image-v4.6.1-amd64.tar.gz.sha256.txt',
                     'liteblox-image-v4.6.1-arm64.tar.gz', 'liteblox-image-v4.6.1-arm64.tar.gz.sha256.txt']


def test_push_every_tag_to_every_registry_in_order(monkeypatch):
    podman = Podman(manifest=index('amd64', 'arm64'))
    monkeypatch.setattr(_push.subprocess, 'run', podman)
    assert _push.push_image('liteblox', ['git.example.com/org', 'reg.example.com'], '4.6.1')
    pushes = [c[-1] for c in podman.calls if c[1:3] == ['manifest', 'push']]
    assert pushes == [f'docker://{r}/liteblox:{t}' for r in ('git.example.com/org', 'reg.example.com')
                      for t in ('4.6.1', '4.6', '4', 'latest')]
    assert all(c[3:5] == ['--all', 'liteblox-manifest:4.6.1'] for c in podman.calls if c[1:3] == ['manifest', 'push'])
    checks = [c[-1] for c in podman.calls if c[1:3] == ['manifest', 'inspect']]
    assert checks == ['git.example.com/org/liteblox:4.6.1', 'reg.example.com/liteblox:4.6.1']


def test_push_stops_at_the_first_failure(monkeypatch, capsys):
    podman = Podman(fail_on=lambda cmd: cmd[-1] == 'docker://git.example.com/org/liteblox:4.6',
                    manifest=index('amd64', 'arm64'))
    monkeypatch.setattr(_push.subprocess, 'run', podman)
    assert not _push.push_image('liteblox', ['git.example.com/org', 'reg.example.com'], '4.6.1')
    pushed = [c[-1] for c in podman.calls if c[1:3] == ['manifest', 'push']]
    assert pushed == ['docker://git.example.com/org/liteblox:4.6.1', 'docker://git.example.com/org/liteblox:4.6']
    assert 'git.example.com/org/liteblox:4.6 (later tags and registries not pushed)' in capsys.readouterr().err


def test_push_needs_a_registry(monkeypatch, capsys):
    podman = Podman()
    monkeypatch.setattr(_push.subprocess, 'run', podman)
    assert not _push.push_image('liteblox', [], '4.6.1')
    assert podman.calls == []
    assert 'no registry' in capsys.readouterr().err


def test_push_fails_when_the_registry_lacks_an_architecture(monkeypatch, capsys):
    monkeypatch.setattr(_push.subprocess, 'run', Podman(manifest=index('amd64')))
    assert not _push.push_image('liteblox', ['reg.example.com'], '4.6.1')
    assert "lists ['amd64'], not ['amd64', 'arm64']" in capsys.readouterr().err


def test_build_checks_architecture_and_smoke_tests_each(monkeypatch, tmp_path):
    podman = Podman()

    def run(cmd, **kwargs):
        result = podman(cmd, **kwargs)
        if cmd[1:3] == ['image', 'inspect']:
            result.stdout = 'arm64\n' if cmd[-1].endswith('-arm64') else 'amd64\n'
        return result

    monkeypatch.setattr(_build.subprocess, 'run', run)
    monkeypatch.setattr(_build, 'save_tarball', lambda *a: True)
    assert _build.build_image('liteblox', '4.6.1')
    builds = [c for c in podman.calls if c[1] == 'build']
    assert [(c[3], c[5]) for c in builds] == [('linux/amd64', 'liteblox:4.6.1'), ('linux/arm64', 'liteblox:4.6.1-arm64')]
    smokes = [c for c in podman.calls if c[1] == 'run']
    assert [c[5] for c in smokes] == ['liteblox:4.6.1', 'liteblox:4.6.1-arm64']
    adds = [c[-1] for c in podman.calls if c[1:3] == ['manifest', 'add']]
    assert adds == ['containers-storage:localhost/liteblox:4.6.1', 'containers-storage:localhost/liteblox:4.6.1-arm64']
    assert ['podman', 'manifest', 'rm', 'liteblox-manifest:4.6.1'] in podman.calls


def test_build_refuses_an_image_of_the_wrong_architecture(monkeypatch, capsys):
    def run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout='amd64\n' if cmd[1:3] == ['image', 'inspect'] else '', stderr='')

    monkeypatch.setattr(_build.subprocess, 'run', run)
    assert not _build.build_image('liteblox', '4.6.1')
    assert 'came out as amd64, not arm64' in capsys.readouterr().err


def test_archive_info_reads_name_and_architecture(tmp_path):
    path = tmp_path / 'image.tar.gz'
    with gzip.open(path, 'wb') as gz, tarfile.open(fileobj=gz, mode='w') as tar:
        for name, data in (('manifest.json', [{'Config': 'abc.json', 'RepoTags': ['localhost/liteblox:4.6.1']}]),
                           ('abc.json', {'architecture': 'arm64', 'os': 'linux'})):
            raw = json.dumps(data).encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    assert _build.archive_info(path) == (['localhost/liteblox:4.6.1'], 'arm64')


# ── The public copy and the release pages ─────────────────────────────────────

import re  # noqa: E402
import subprocess  # noqa: E402
import urllib.error  # noqa: E402

import _archive  # noqa: E402
import _mirror  # noqa: E402
import _release  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.com', 'GIT_COMMITTER_NAME': 't',
           'GIT_COMMITTER_EMAIL': 't@example.com', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1'}
AUTHOR = 'Example <1+example@users.noreply.github.com>'


def sh(*args, cwd=None):
    import os
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, **GIT_ENV}).stdout.strip()


def tarball(tmp_path, files, name="src.tgz"):
    src = tmp_path / f'build-{name}' / 'liteblox'
    for rel, text in files.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)
    out = tmp_path / name
    with tarfile.open(out, 'w:gz') as tar:
        tar.add(src, arcname='liteblox')
    return out


@pytest.fixture
def github(tmp_path, monkeypatch):
    """A bare repo standing in for GitHub, holding a placeholder README commit, like the real one."""
    bare = tmp_path / 'github.git'
    sh('git', 'init', '--bare', '-q', '-b', 'main', str(bare))
    seed = tmp_path / 'seed'
    sh('git', 'clone', '-q', str(bare), str(seed))
    (seed / 'README.md').write_text('placeholder\n')
    sh('git', 'add', '.', cwd=seed)
    sh('git', 'commit', '-q', '-m', 'Initial commit', cwd=seed)
    sh('git', 'push', '-q', 'origin', 'HEAD:main', cwd=seed)
    monkeypatch.setattr(_mirror, 'untracked', lambda tree, tag: [])
    monkeypatch.setattr(_mirror, 'changelog_section', lambda v: f'- what changed in {v}')
    for key, value in GIT_ENV.items():
        monkeypatch.setenv(key, value)
    return bare


def publish(tmp_path, github, version, files, **kw):
    conf = {'github': 'example/liteblox', 'author': AUTHOR, 'signingkey': None}
    import tempfile
    work = Path(tempfile.mkdtemp(dir=tmp_path))
    (work / 'x').mkdir()
    return _mirror.publish(conf, version, tarball(work, files), 'HEAD', url=str(github),
                           mirror=tmp_path / 'mirror.git', pattern=re.compile('secret'), workdir=work / 'x', **kw)


def test_the_first_copy_replaces_the_placeholder_with_a_root_commit(tmp_path, github):
    commit = publish(tmp_path, github, '4.7.0', {'README.md': 'LiteBlox\n', 'liteblox/app.py': 'x = 1\n',
                                                 '.gitignore': 'liteblox/\n'})
    assert sh('git', 'rev-parse', 'main', cwd=github) == commit
    assert sh('git', 'rev-list', '--count', 'main', cwd=github) == '1'
    assert sh('git', 'ls-tree', '-r', '--name-only', 'main', cwd=github).split() == ['.gitignore', 'README.md', 'liteblox/app.py']
    assert sh('git', 'log', '-1', '--format=%an <%ae>|%s|%b', 'main', cwd=github) == f'{AUTHOR}|LiteBlox 4.7.0|- what changed in 4.7.0'
    assert sh('git', 'rev-parse', 'v4.7.0^{commit}', cwd=github) == commit
    assert sh('git', 'cat-file', '-t', 'v4.7.0', cwd=github) == 'tag'      # annotated


def test_later_copies_build_on_it_and_drop_removed_files(tmp_path, github):
    first = publish(tmp_path, github, '4.7.0', {'README.md': 'a\n', 'old.txt': 'gone soon\n'})
    second = publish(tmp_path, github, '4.7.1', {'README.md': 'b\n'})
    assert sh('git', 'rev-parse', f'{second}^', cwd=github) == first
    assert sh('git', 'ls-tree', '-r', '--name-only', 'main', cwd=github) == 'README.md'
    assert publish(tmp_path, github, '4.7.1', {'README.md': 'b\n'}) is None       # a rerun: already there


def test_a_dry_run_pushes_nothing(tmp_path, github):
    commit = publish(tmp_path, github, '4.7.0', {'README.md': 'a\n'}, dry_run=True)
    assert commit and sh('git', 'log', '-1', '--format=%s', 'main', cwd=github) == 'Initial commit'
    assert sh('git', 'tag', cwd=github) == ''


def test_a_private_name_stops_it_before_anything_leaves(tmp_path, github):
    with pytest.raises(_mirror.MirrorError, match=r'private: notes/a\.md:2: secret'):
        publish(tmp_path, github, '4.7.0', {'notes/a.md': 'fine\nthe secret host\n'})
    assert not (tmp_path / 'mirror.git').exists()


def test_the_check_skips_binary_files_and_counts_the_email(tmp_path):
    tree = tmp_path / 't'
    tree.mkdir()
    (tree / 'logo.png').write_bytes(b'\x89PNG\0 secret')
    (tree / 'a.txt').write_text('mail me@example.org\n')
    pattern = _mirror.private_pattern(tmp_path / 'absent', email='me@example.org')
    assert _mirror.private_hits(tree, pattern) == ['a.txt:1: me@example.org']


def test_the_repo_names_and_the_email_are_checked():
    # every line of .private-names, and the email (any case); no private name is spelled out here
    pattern = _mirror.private_pattern(email='someone@example.org')
    lines = [s.strip() for s in _mirror.PRIVATE_FILE.read_text().splitlines() if s.strip() and not s.startswith('#')]
    assert lines and all(f'(?:{line})' in pattern.pattern for line in lines)
    assert pattern.search('SOMEONE@example.org')


def test_files_git_doesnt_track_are_found():
    assert _mirror.untracked_of(['README.md', 'deploy/deploy.py'], 'HEAD') == []
    assert _mirror.untracked_of(['README.md', 'no-such-file.txt'], 'HEAD') == ['no-such-file.txt']


def test_the_author_line_must_be_name_and_email():
    assert _mirror.author_env(AUTHOR)['GIT_AUTHOR_EMAIL'] == '1+example@users.noreply.github.com'
    with pytest.raises(_mirror.MirrorError, match='Name <email>'):
        _mirror.author_env('just a name')


def test_the_archive_leaves_out_publish_and_private_names():
    keep = _archive._make_filter(_archive.exclude_patterns())
    for name in ('.publish', '.private-names', 'WIP/x.md'):
        assert keep(tarfile.TarInfo(f'liteblox/{name}')) is None
    assert keep(tarfile.TarInfo('liteblox/README.md')) is not None


def test_changelog_section(tmp_path, monkeypatch):
    log = tmp_path / 'CHANGELOG.md'
    log.write_text('# Changelog\n\n## 4.7.0 — 2026-11-23\n\n- one\n- two\n\n\n## 4.6.1 — 2026-11-22\n\n- older\n')
    monkeypatch.setattr(_common, 'CHANGELOG_FILE', log)
    assert _common.changelog_section('4.7.0') == '- one\n- two'
    assert _common.changelog_section('4.6.1') == '- older'
    assert _common.changelog_section('9.9.9') == ''


def test_release_refuses_without_the_tag(tmp_path):
    with pytest.raises(_release.ReleaseError, match='no tag v0.0.0'):
        _release.preflight('liteblox', '0.0.0', [])


def test_the_forgejo_token_file_must_be_private(tmp_path):
    token = tmp_path / 'forgejo-token'
    token.write_text('abc\n')
    token.chmod(0o644)
    conf = {'forgejo': 'https://forge.example liteblox/liteblox'}
    with pytest.raises(_release.ReleaseError, match='chmod 600'):
        _release.Forgejo.from_publish(conf, token)
    token.chmod(0o600)
    assert _release.Forgejo.from_publish(conf, token).api == 'https://forge.example/api/v1/repos/liteblox/liteblox'


class FakeForgejo:
    """urlopen for the release calls: no release at first, then one that collects uploads."""

    def __init__(self, existing=()):
        self.requests, self.assets = [], [{'name': n, 'size': s} for n, s in existing]
        self.made = bool(existing)

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        url, method = req.full_url, req.get_method()
        if method == 'GET' and '/releases/tags/' in url:
            if not self.made:
                raise urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO(b'{}'))
            body = {'id': 5, 'assets': self.assets}
        elif method == 'POST' and url.endswith('/releases'):
            self.made = True
            body = {'id': 5, 'assets': []}
        else:
            name = url.split('name=', 1)[1]
            size = len(req.data.split(b'\r\n\r\n', 1)[1].rsplit(b'\r\n--', 1)[0])
            self.assets.append({'name': name, 'size': size})
            body = {}
        return io.BytesIO(json.dumps(body).encode())


def files(tmp_path):
    out = []
    for name, data in (('a.tgz', b'source'), ('a.tgz.sha256.txt', b'sum\n')):
        (tmp_path / name).write_bytes(data)
        out.append(tmp_path / name)
    return out


def test_the_forgejo_release_is_made_and_filled(tmp_path, monkeypatch, capsys):
    fake = FakeForgejo()
    monkeypatch.setattr(_release.urllib.request, 'urlopen', fake)
    monkeypatch.setattr(_release, 'changelog_section', lambda v: '- a change')
    forgejo = _release.Forgejo('https://forge.example', 'o/r', 'sekrit-token')
    assets = _release.forgejo_release(forgejo, 'v4.7.0', '4.7.0', files(tmp_path))
    _release.compare('Forgejo release', files(tmp_path), assets)
    made = json.loads(fake.requests[1].data)
    assert made['tag_name'] == 'v4.7.0' and made['name'] == 'LiteBlox 4.7.0' and '- a change' in made['body']
    assert all(r.get_header('Authorization') == 'token sekrit-token' for r in fake.requests)
    assert 'sekrit' not in capsys.readouterr().out


def test_only_missing_files_are_uploaded(tmp_path, monkeypatch):
    fake = FakeForgejo(existing=[('a.tgz', 6)])
    monkeypatch.setattr(_release.urllib.request, 'urlopen', fake)
    forgejo = _release.Forgejo('https://forge.example', 'o/r', 't')
    _release.forgejo_release(forgejo, 'v4.7.0', '4.7.0', files(tmp_path))
    uploads = [r.full_url for r in fake.requests if '/assets' in r.full_url]
    assert uploads == ['https://forge.example/api/v1/repos/o/r/releases/5/assets?name=a.tgz.sha256.txt']


def test_compare_names_what_differs(tmp_path):
    with pytest.raises(_release.ReleaseError, match=r'a\.tgz \(5 bytes, not 6\), a\.tgz\.sha256\.txt \(missing\)'):
        _release.compare('GitHub release', files(tmp_path), {'a.tgz': 5})


def test_the_github_release_is_made_with_gh(tmp_path, monkeypatch):
    calls, made = [], []

    def run(cmd, **kw):
        calls.append((cmd, kw.get('input')))
        if cmd[1:3] == ['release', 'view']:
            if not made:
                return SimpleNamespace(returncode=1, stdout='', stderr='release not found')
            return SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(
                {'assets': [{'name': 'a.tgz', 'size': 6}, {'name': 'a.tgz.sha256.txt', 'size': 4}]}))
        made.append(cmd)
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(_release.subprocess, 'run', run)
    monkeypatch.setattr(_release, 'changelog_section', lambda v: '- a change')
    assets = _release.github_release('o/r', 'v4.7.0', '4.7.0', files(tmp_path))
    create, notes = calls[1]
    assert create[:9] == ['gh', 'release', 'create', 'v4.7.0', '--repo', 'o/r', '--verify-tag', '--title', 'LiteBlox 4.7.0']
    assert create[-2:] == [str(tmp_path / 'a.tgz'), str(tmp_path / 'a.tgz.sha256.txt')]
    assert notes.startswith('- a change') and _release.INSTALL_URL in notes
    _release.compare('GitHub release', files(tmp_path), assets)


# ── --bump-to ──────────────────────────────────────────────────────────────────

def test_bump_to_only_moves_forward():
    assert _common.bump_to('4.8.0', '6.0.0') == '6.0.0'
    assert _common.bump_to('4.8.0', '4.8.1') == '4.8.1'
    assert _common.bump_to('4.8.0', '4.10.0') == '4.10.0'                 # compared as numbers, not text
    for bad, message in (('4.8.0', 'not later'), ('4.7.9', 'not later'), ('6.0', 'not a version'),
                         ('v6.0.0', 'not a version'), ('', 'not a version')):
        with pytest.raises(ValueError, match=message):
            _common.bump_to('4.8.0', bad)


def test_bump_to_on_the_command_line(tmp_path, monkeypatch, capsys):
    import _site
    import deploy
    monkeypatch.chdir(tmp_path)                 # main() changes directory: put it back afterwards
    monkeypatch.setattr(_common, 'ROOT', tmp_path)
    monkeypatch.setattr(_common, 'seed_files', lambda: None)
    monkeypatch.setattr(_common, 'read_project', lambda: 'liteblox')
    monkeypatch.setattr(_common, 'registries', lambda: [])
    monkeypatch.setattr(_common, 'read_version', lambda: '4.8.0')
    written = []
    monkeypatch.setattr(_common, 'prompt_changelog', lambda: 'IPv6')
    monkeypatch.setattr(_common, 'write_version', written.append)
    monkeypatch.setattr(_common, 'update_changelog', lambda v, msg: written.append((v, msg)))
    monkeypatch.setattr(_site, 'publish', lambda: True)
    monkeypatch.setattr(_publish, 'site_destination', lambda: None)
    monkeypatch.setattr(sys, 'argv', ['deploy.py', '--bump-to', '4.7.0', '--site'])
    assert deploy.main() == 1 and 'only moves forward' in capsys.readouterr().out and written == []
    monkeypatch.setattr(sys, 'argv', ['deploy.py', '--bump-to', '6.0.0', '--release'])
    with pytest.raises(SystemExit):
        deploy.main()
    monkeypatch.setattr(sys, 'argv', ['deploy.py', '--bump-to', '6.0.0', '--bump-major', '--site'])
    with pytest.raises(SystemExit):
        deploy.main()
    monkeypatch.setattr(sys, 'argv', ['deploy.py', '--bump-to', '6.0.0', '--site'])
    assert deploy.main() == 0
    assert 'Bumping to 6.0.0: 4.8.0 → 6.0.0' in capsys.readouterr().out
    assert written == ['6.0.0', ('6.0.0', 'IPv6')]
