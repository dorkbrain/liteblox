#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dorkbrain (https://dorkbrain.com)
"""liteblox-agent installer: puts a new agent in place before the agent starts.

systemd runs it as root (ExecStartPre=+) on every start of liteblox-agent; the agent itself stays unprivileged
and sandboxed. LiteBlox sends a new agent over mutual TLS, the agent stages it in its own state folder
(pending/agent.py and pending/manifest.json) and exits, and on the restart this installs it, if it passes:
  - read without following links, from a regular file the agent user owns, at most 2 MB
  - its SHA-256 is the manifest's, it parses as Python (it's never imported or run here), and it's a LiteBlox agent
  - its version isn't older than the installed one (no downgrades: Repair over SSH can still go back)
The old agent is kept as liteblox_agent.py.prev. If the new one doesn't start twice in a row (it writes
started-ok with its own SHA-256 once it listens), the old one comes back. Only the agent's code changes this
way: the unit, this installer, the config and the certificates change by Repair over SSH only.

Standard library only (Python 3.9+), no arguments, no network. It always exits 0, so a bad staging never stops
the installed agent from starting; what happened goes to last-upgrade.json (read by the agent's /status) and
the journal.
"""

import ast
import hashlib
import json
import os
import pwd
import re
import stat
import sys
import time

AGENT_LIB = '/usr/local/lib/liteblox-agent'
STATE_DIR = '/var/lib/liteblox-agent'
AGENT_USER = 'liteblox-agent'
AGENT = 'liteblox_agent.py'
MAX_SIZE = 2 * 1024 * 1024
MAX_STARTS = 2              # failed starts of a new agent before the old one comes back
MARKER = 'liteblox-agent'   # in the first lines of every agent


class Paths:
    def __init__(self, lib=AGENT_LIB, state=STATE_DIR, uid=None):
        self.lib, self.state = lib, state
        self.uid = pwd.getpwnam(AGENT_USER).pw_uid if uid is None else uid

    def lib_file(self, name):
        return os.path.join(self.lib, name)


class Refused(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def log(text):
    print(f'liteblox-agent-install: {text}', flush=True)


def version_key(text):
    """'4.5.0' → (4, 5, 0); None when it isn't one (a dev build)."""
    if isinstance(text, str) and re.fullmatch(r'\d+(\.\d+){1,3}', text.strip()):
        return tuple(int(x) for x in text.strip().split('.'))
    return None


# ── reading what the agent wrote ───────────────────────────────────────────────

def _open_dir(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def read_owned(dir_fd, name, uid, limit=MAX_SIZE):
    """name in the agent's folder: a regular file the agent user owns, one link, at most limit bytes. Opened
    without following links and checked on the open file, so nothing can be swapped in between."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        raise Refused(f'{name} is missing')
    except OSError as e:
        raise Refused(f'{name} could not be opened ({e.strerror}): a link?')
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(f'{name} is not a regular file')
        if st.st_uid != uid:
            raise Refused(f'{name} is not owned by {AGENT_USER}')
        if st.st_nlink != 1:
            raise Refused(f'{name} has other links')
        if st.st_size > limit:
            raise Refused(f'{name} is bigger than {limit} bytes')
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise Refused(f'{name} is bigger than {limit} bytes')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)


def _unlink(dir_fd, name):
    try:
        os.unlink(name, dir_fd=dir_fd)      # unlink never follows a link
    except FileNotFoundError:
        pass
    except OSError as e:
        log(f'could not remove pending/{name}: {e}')


# ── writing our own files (root-owned folder: the agent can't touch it) ────────

def write_lib(paths, name, data, mode=0o644):
    path = paths.lib_file(name)
    tmp = paths.lib_file(f'.{name}.new')
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def read_lib(paths, name):
    try:
        with open(paths.lib_file(name), 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def remove_lib(paths, name):
    try:
        os.unlink(paths.lib_file(name))
    except FileNotFoundError:
        pass


def record(paths, result, detail='', version=None, digest=None):
    out = {'at': int(time.time()), 'result': result, 'detail': detail, 'version': version, 'sha256': digest}
    write_lib(paths, 'last-upgrade.json', (json.dumps(out) + '\n').encode())
    log(f'{result}{": " + detail if detail else ""}')


# ── the checks ─────────────────────────────────────────────────────────────────

def verify(source, manifest):
    """A signature check would go here (a release key pinned at bootstrap); none for now."""
    return None


def check(source, manifest, installed_version):
    if not isinstance(manifest, dict):
        raise Refused('manifest.json is not an object')
    digest = manifest.get('sha256')
    if not isinstance(digest, str) or sha256(source) != digest.lower():
        raise Refused("the agent's SHA-256 isn't the one LiteBlox sent")
    version = manifest.get('version')
    if not isinstance(version, str) or not version.strip() or len(version) > 40:
        raise Refused('the manifest has no version')
    new, old = version_key(version), version_key(installed_version)
    if old is not None and (new is None or new < old):
        raise Refused(f'{version} is older than the installed {installed_version} (Repair over SSH can go back)')
    if MARKER.encode() not in source[:600]:
        raise Refused('it is not a LiteBlox agent')
    try:
        ast.parse(source.decode('utf-8'), filename=AGENT)
    except (SyntaxError, ValueError, UnicodeDecodeError) as e:
        raise Refused(f'it does not parse as Python: {e}')
    verify(source, manifest)
    return version.strip(), digest.lower()


# ── the steps ──────────────────────────────────────────────────────────────────

def _started_ok(paths):
    """The SHA-256 the running agent wrote once it was listening, or None."""
    try:
        dir_fd = _open_dir(paths.state)
    except OSError:
        return None
    try:
        return read_owned(dir_fd, 'started-ok', paths.uid, limit=200).decode().strip()
    except (Refused, UnicodeDecodeError):
        return None
    finally:
        os.close(dir_fd)


def settle_trial(paths):
    """A new agent on trial: kept once it has started, the old one back after MAX_STARTS failed starts."""
    raw = read_lib(paths, 'trial.json')
    if raw is None:
        return
    try:
        trial = json.loads(raw)
        digest = trial['sha256']
    except (ValueError, KeyError, TypeError):
        remove_lib(paths, 'trial.json')
        return
    if _started_ok(paths) == digest:
        remove_lib(paths, 'trial.json')
        record(paths, 'running', 'the new agent started', trial.get('version'), digest)
        return
    trial['attempts'] = int(trial.get('attempts') or 0) + 1
    if trial['attempts'] < MAX_STARTS:
        write_lib(paths, 'trial.json', json.dumps(trial).encode())
        log(f"the new agent hasn't started yet: trying again ({trial['attempts']} of {MAX_STARTS})")
        return
    prev = read_lib(paths, AGENT + '.prev')
    if prev is None:
        remove_lib(paths, 'trial.json')
        record(paths, 'failed', 'the new agent did not start, and there is no previous one to go back to',
               trial.get('version'), digest)
        return
    write_lib(paths, AGENT, prev)
    if trial.get('prev_version'):
        write_lib(paths, 'VERSION', (trial['prev_version'] + '\n').encode())
    remove_lib(paths, 'trial.json')
    record(paths, 'rolled back', f"the new agent did not start {MAX_STARTS} times: the previous one is back",
           trial.get('version'), digest)


def install_pending(paths):
    """Install pending/agent.py if it passes; the pending files go either way."""
    try:
        dir_fd = _open_dir(os.path.join(paths.state, 'pending'))
    except FileNotFoundError:
        return
    except OSError as e:
        record(paths, 'refused', f'pending/ could not be opened ({e.strerror}): a link?')
        return
    try:
        os.stat('agent.py', dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:      # the folder stays between upgrades: nothing staged
        _unlink(dir_fd, 'manifest.json')
        os.close(dir_fd)
        return
    try:
        source = read_owned(dir_fd, 'agent.py', paths.uid)
        manifest = json.loads(read_owned(dir_fd, 'manifest.json', paths.uid, limit=4096))
        installed = (read_lib(paths, 'VERSION') or b'').decode('utf-8', 'replace').strip()
        version, digest = check(source, manifest, installed)
        current = read_lib(paths, AGENT)
        if current is not None and sha256(current) == digest:
            record(paths, 'unchanged', 'this agent is already installed', version, digest)
            return
        if current is not None:
            write_lib(paths, AGENT + '.prev', current)
        write_lib(paths, AGENT, source)
        write_lib(paths, 'VERSION', (version + '\n').encode())
        write_lib(paths, 'trial.json', json.dumps({'sha256': digest, 'version': version, 'attempts': 0,
                                                   'prev_version': installed or None}).encode())
        record(paths, 'installed', f'agent {version} installed; on trial until it starts', version, digest)
    except Refused as e:
        record(paths, 'refused', str(e))
    except ValueError:
        record(paths, 'refused', 'manifest.json is not JSON')
    finally:
        for name in ('agent.py', 'manifest.json'):
            _unlink(dir_fd, name)
        os.close(dir_fd)


def main(paths=None):
    try:
        paths = paths or Paths()
        settle_trial(paths)
        install_pending(paths)
    except Exception as e:      # never keep the installed agent from starting
        log(f'ERROR: {e.__class__.__name__}: {e}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
