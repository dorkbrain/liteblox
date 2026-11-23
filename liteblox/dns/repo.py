"""Zone history: a git repository in <data>/repo with one file per zone under zones/."""

import os
import subprocess
from pathlib import Path


class RepoError(RuntimeError):
    pass


def zone_file(zone_name):
    return f'zones/{zone_name}.zone'


class Repo:
    def __init__(self, path):
        self.path = Path(path)

    def _git(self, *args, check=True, raw=False):
        """Run git; raw=True returns stdout bytes untouched (text mode would turn CRLF into LF)."""
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
        r = subprocess.run(['git', '-C', str(self.path), *args], capture_output=True, text=not raw, env=env)
        if check and r.returncode != 0:
            err = r.stderr.decode(errors='replace') if raw else r.stderr
            raise RepoError(f"git {' '.join(args)}: {err.strip()}")
        return r.stdout

    def ensure(self):
        if (self.path / '.git').exists():
            return self
        self.path.mkdir(parents=True, exist_ok=True)
        self._git('init', '-q', '-b', 'main')
        for key, value in (('user.name', 'LiteBlox'), ('user.email', 'liteblox@localhost'),
                           ('core.autocrlf', 'false'), ('commit.gpgsign', 'false')):
            self._git('config', key, value)
        # zone files must keep their exact bytes, CRLF included
        (self.path / '.gitattributes').write_text('* -text\n')
        self._git('add', '.gitattributes')
        self._git('commit', '-q', '-m', 'Initialize zone repository')
        return self

    def read(self, file):
        path = self.path / file
        return path.read_bytes().decode() if path.exists() else None

    def write(self, file, content, message, author):
        """Write and commit one file; returns the commit sha, or None when nothing changed."""
        path = self.path / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())
        self._git('add', file)
        if not self._git('status', '--porcelain', '--', file).strip():
            return None
        self._git('commit', '-q', '-m', message, f'--author={author} <{author}@liteblox>')
        return self._git('rev-parse', 'HEAD').strip()

    def delete(self, file, message, author):
        """Remove and commit one file; its history stays. Returns the commit sha, or None if it wasn't there."""
        if not (self.path / file).exists():
            return None
        self._git('rm', '-q', '--', file)
        self._git('commit', '-q', '-m', message, f'--author={author} <{author}@liteblox>')
        return self._git('rev-parse', 'HEAD').strip()

    def log(self, file, limit=50):
        # deletions have no content to show or restore; a zone created again keeps its older versions
        out = self._git('log', f'-n{limit}', '--diff-filter=ACMRT', '--format=%H%x1f%an%x1f%aI%x1f%s', '--', file)
        return [dict(zip(('sha', 'author', 'date', 'subject'), line.split('\x1f')))
                for line in out.splitlines()]

    def show(self, sha, file):
        """The file's exact content at a commit."""
        return self._git('show', f'{sha}:{file}', raw=True).decode()
