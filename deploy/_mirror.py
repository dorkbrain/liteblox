"""The public GitHub copy: one commit per release, made from the release's source tarball.

Forgejo keeps the real history; GitHub gets exactly what the downloads hold, as one commit by the
`author` line of .publish (GitHub's no-reply address), signed with its `signingkey` (an SSH public
key; git finds the private half beside it or in the agent), and a signed tag v<ver>. The copy lives
in a bare clone, dist/github.git. The first release there replaces whatever the repository held
(a placeholder README) with a root commit; later ones build on it.

Before anything leaves, every text file in the tree is checked against .private-names and the git
user's email, and every file must be tracked by git at the release tag (nothing stray from the
working tree).
"""

import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

from _common import ROOT, changelog_section

MIRROR = ROOT / 'dist' / 'github.git'
PRIVATE_FILE = ROOT / '.private-names'
GITHUB_SSH = 'git@github.com:{repo}.git'


def git(*args, cwd=None, env=None, check=True, input=None):
    result = subprocess.run(['git', *args], cwd=cwd, env=env, capture_output=True, text=True, input=input)
    if check and result.returncode != 0:
        raise MirrorError(f"git {' '.join(args)}: {(result.stderr or result.stdout).strip()}")
    return result.stdout.strip()


class MirrorError(Exception):
    pass


# ── The tree ───────────────────────────────────────────────────────────────────

def extract(tarball, dest):
    """Unpack the source tarball into dest; returns the folder it holds (<project>/)."""
    with tarfile.open(tarball, 'r:gz') as tar:
        tar.extractall(dest, filter='data')
    tops = [p for p in Path(dest).iterdir() if p.is_dir()]
    if len(tops) != 1:
        raise MirrorError(f'{tarball.name} should hold one folder, not {len(tops)}')
    return tops[0]


def tree_files(tree):
    return sorted(p.relative_to(tree).as_posix() for p in tree.rglob('*') if p.is_file())


def private_pattern(path=PRIVATE_FILE, email=None):
    """.private-names' lines and the git user's email, as one regex."""
    parts = []
    if path.exists():
        parts = [s for s in (line.strip() for line in path.read_text().splitlines()) if s and not s.startswith('#')]
    if email is None:
        email = git('config', 'user.email', cwd=ROOT, check=False)
    if email:
        parts.append(re.escape(email))
    if not parts:
        raise MirrorError('nothing to check against: no .private-names and no git user.email')
    return re.compile('|'.join(f'(?:{p})' for p in parts), re.I)


def private_hits(tree, pattern):
    """'path:line: match' for every hit in a text file (a file with a NUL byte counts as binary)."""
    hits = []
    for rel in tree_files(tree):
        data = (tree / rel).read_bytes()
        if b'\0' in data:
            continue
        for number, line in enumerate(data.decode('utf-8', 'replace').splitlines(), 1):
            found = pattern.search(line)
            if found:
                hits.append(f'{rel}:{number}: {found[0]}')
    return hits


def untracked_of(names, tag):
    tracked = set(git('ls-tree', '-r', '--name-only', tag, cwd=ROOT).splitlines())
    return [rel for rel in names if rel not in tracked]


def untracked(tree, tag):
    """Files in the tree that git doesn't track at the tag (the tarball is made from the working tree)."""
    return untracked_of(tree_files(tree), tag)


def check(tree, tag, pattern=None):
    """Raise MirrorError listing every private name or untracked file in the tree."""
    problems = [f'private: {h}' for h in private_hits(tree, pattern or private_pattern())]
    problems += [f'not tracked by git at {tag}: {rel}' for rel in untracked(tree, tag)]
    if problems:
        raise MirrorError('the source tarball can\'t go public:\n  ' + '\n  '.join(problems))


# ── The copy ───────────────────────────────────────────────────────────────────

def author_env(author):
    found = re.fullmatch(r'\s*(.+?)\s*<([^>]+)>\s*', author or '')
    if not found:
        raise MirrorError(f"the author line in .publish should be 'Name <email>', not {author!r}")
    name, email = found.groups()
    return {**os.environ, 'GIT_AUTHOR_NAME': name, 'GIT_AUTHOR_EMAIL': email,
            'GIT_COMMITTER_NAME': name, 'GIT_COMMITTER_EMAIL': email}


def signing(key):
    """git -c options that sign with an SSH key, or none (unsigned) without one."""
    if not key:
        return []
    path = Path(key).expanduser()
    if not path.exists():
        raise MirrorError(f'signing key {key} not found')
    return ['-c', 'gpg.format=ssh', '-c', f'user.signingkey={path}']


def remote_tags(mirror):
    out = git('ls-remote', '--tags', 'origin', 'refs/tags/v*', cwd=mirror)
    return {line.split('refs/tags/', 1)[1] for line in out.splitlines() if '^{}' not in line}


def open_mirror(url, mirror=MIRROR):
    """The bare clone, made the first time and brought up to date with GitHub every time."""
    if not (mirror / 'HEAD').exists():
        mirror.parent.mkdir(parents=True, exist_ok=True)
        git('clone', '--bare', '--quiet', url, str(mirror))
    git('fetch', '--quiet', '--prune', '--tags', 'origin', '+refs/heads/*:refs/heads/*', cwd=mirror)
    return mirror


def make_commit(mirror, tree, version, author, key, first):
    """Commit the tree on main (a root commit when first). Returns the commit's hash; moves no refs."""
    index = mirror / 'release.index'
    index.unlink(missing_ok=True)
    env = author_env(author) | {'GIT_INDEX_FILE': str(index)}
    try:
        # -f: the tarball's files are wanted even when a .gitignore in the tree names them
        git('--work-tree', str(tree), 'add', '-A', '-f', '.', cwd=mirror, env=env)
        tree_id = git('write-tree', cwd=mirror, env=env)
    finally:
        index.unlink(missing_ok=True)
    message = f'LiteBlox {version}\n\n{changelog_section(version)}\n'
    parent = [] if first else ['-p', git('rev-parse', 'refs/heads/main', cwd=mirror)]
    sign = ['-S'] if key else []
    return git(*signing(key), 'commit-tree', tree_id, *parent, *sign, '-F', '-', cwd=mirror, env=env, input=message)


def publish(conf, version, tarball, tag, dry_run=False, url=None, mirror=MIRROR, pattern=None, workdir=None):
    """Check the tarball, commit it to the copy, tag it and push both. Returns the commit's hash, or
    None when GitHub already has v<ver> (a rerun)."""
    repo, author, key = conf.get('github'), conf.get('author'), conf.get('signingkey')
    if not repo:
        raise MirrorError("no 'github owner/repo' line in .publish")
    tree = extract(tarball, workdir)
    check(tree, tag, pattern)
    print(f"✓ Checked {len(tree_files(tree))} files: no private names, all tracked at {tag}")

    mirror = open_mirror(url or GITHUB_SSH.format(repo=repo), mirror)
    tags = remote_tags(mirror)
    name = f'v{version}'
    if name in tags:
        print(f"  {repo} already has {name}: nothing to push")
        return None
    first = not tags
    commit = make_commit(mirror, tree, version, author, key, first)
    print(f"✓ Commit {commit[:12]} for {repo}{' (a new root: replaces what the repository held)' if first else ''}")
    if dry_run:
        print(f"  dry run: not tagged or pushed. Look at it with: git -C {mirror} show --stat {commit[:12]}")
        return commit

    env = author_env(author)
    git(*signing(key), 'tag', '-f', *(['-s'] if key else ['-a']), name, commit, '-m', f'LiteBlox {version}',
        cwd=mirror, env=env)
    git('update-ref', 'refs/heads/main', commit, cwd=mirror)
    force = ['--force'] if first else []
    git('push', '--quiet', *force, 'origin', 'refs/heads/main:refs/heads/main', f'refs/tags/{name}', cwd=mirror)
    if name not in remote_tags(mirror):
        raise MirrorError(f'{name} is not on {repo} after the push')
    print(f"✓ Pushed {name} to {repo}")
    return commit
