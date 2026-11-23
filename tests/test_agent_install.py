"""The agent's root installer (4.5): it puts a staged agent in place, refuses what it shouldn't trust, and rolls back
one that doesn't start."""

import ast
import hashlib
import importlib.util
import json
import os

import pytest

from liteblox.nodes import agent_dir

_spec = importlib.util.spec_from_file_location('liteblox_agent_install', agent_dir() / 'liteblox_agent_install.py')
inst = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inst)

OLD = b'#!/usr/bin/env python3\n# liteblox-agent: the old one\nprint("old")\n'
NEW = b'#!/usr/bin/env python3\n# liteblox-agent: the new one\nprint("new")\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def paths(tmp_path):
    lib, state = tmp_path / 'lib', tmp_path / 'state'
    lib.mkdir()
    state.mkdir()
    (lib / 'liteblox_agent.py').write_bytes(OLD)
    (lib / 'VERSION').write_text('4.4.0\n')
    return inst.Paths(str(lib), str(state), uid=os.getuid())


def stage(paths, source=NEW, version='4.5.0', digest=None):
    pending = os.path.join(paths.state, 'pending')
    os.makedirs(pending, exist_ok=True)
    with open(os.path.join(pending, 'agent.py'), 'wb') as f:
        f.write(source)
    with open(os.path.join(pending, 'manifest.json'), 'w') as f:
        json.dump({'version': version, 'sha256': digest or sha(source), 'size': len(source)}, f)
    return pending


def lib(paths, name):
    try:
        with open(paths.lib_file(name), 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def outcome(paths):
    return json.loads(lib(paths, 'last-upgrade.json'))


def started(paths, source):
    with open(os.path.join(paths.state, 'started-ok'), 'w') as f:
        f.write(sha(source) + '\n')


def pending_left(paths):
    return sorted(os.listdir(os.path.join(paths.state, 'pending')))


# ── installing ─────────────────────────────────────────────────────────────────

def test_a_good_staging_installs(paths):
    stage(paths)
    assert inst.main(paths) == 0
    assert lib(paths, 'liteblox_agent.py') == NEW and lib(paths, 'liteblox_agent.py.prev') == OLD
    assert lib(paths, 'VERSION') == b'4.5.0\n'
    assert json.loads(lib(paths, 'trial.json')) == {'sha256': sha(NEW), 'version': '4.5.0', 'attempts': 0,
                                                    'prev_version': '4.4.0'}
    got = outcome(paths)
    assert got['result'] == 'installed' and got['version'] == '4.5.0' and got['sha256'] == sha(NEW)
    assert pending_left(paths) == []
    assert oct(os.stat(paths.lib_file('liteblox_agent.py')).st_mode & 0o777) == '0o644'
    assert not [n for n in os.listdir(paths.lib) if n.endswith('.new')]


def test_the_same_agent_again_changes_nothing(paths):
    stage(paths, OLD, '4.4.0')
    inst.main(paths)
    assert outcome(paths)['result'] == 'unchanged' and lib(paths, 'trial.json') is None
    assert lib(paths, 'liteblox_agent.py.prev') is None and pending_left(paths) == []


def test_nothing_staged_does_nothing(paths):
    assert inst.main(paths) == 0
    assert lib(paths, 'last-upgrade.json') is None and lib(paths, 'liteblox_agent.py') == OLD


# ── refusals: the installed agent stays, the reason is kept ────────────────────

def refused(paths, words):
    assert inst.main(paths) == 0
    got = outcome(paths)
    assert got['result'] == 'refused' and words in got['detail'], got
    assert lib(paths, 'liteblox_agent.py') == OLD and lib(paths, 'VERSION') == b'4.4.0\n'
    assert lib(paths, 'trial.json') is None and lib(paths, 'liteblox_agent.py.prev') is None
    if os.path.isdir(os.path.join(paths.state, 'pending')) and not os.path.islink(os.path.join(paths.state, 'pending')):
        assert pending_left(paths) == []


def test_a_symlinked_agent_is_refused(paths, tmp_path):
    pending = stage(paths)
    target = tmp_path / 'elsewhere.py'
    target.write_bytes(NEW)
    os.unlink(os.path.join(pending, 'agent.py'))
    os.symlink(target, os.path.join(pending, 'agent.py'))
    refused(paths, 'a link?')
    assert target.read_bytes() == NEW           # what the link pointed at is left alone


def test_a_hard_linked_agent_is_refused(paths, tmp_path):
    pending = stage(paths)
    os.link(os.path.join(pending, 'agent.py'), tmp_path / 'other')
    refused(paths, 'other links')


def test_a_symlinked_pending_folder_is_refused(paths, tmp_path):
    real = tmp_path / 'real-pending'
    real.mkdir()
    (real / 'agent.py').write_bytes(NEW)
    (real / 'manifest.json').write_text(json.dumps({'version': '4.5.0', 'sha256': sha(NEW)}))
    os.symlink(real, os.path.join(paths.state, 'pending'))
    refused(paths, 'pending/ could not be opened')
    assert sorted(os.listdir(real)) == ['agent.py', 'manifest.json']    # nothing unlinked through the link


def test_a_file_the_agent_user_doesnt_own_is_refused(paths):
    stage(paths)
    paths.uid = os.getuid() + 1
    refused(paths, 'not owned by liteblox-agent')


def test_a_directory_in_place_of_the_agent_is_refused(paths):
    pending = stage(paths)
    os.unlink(os.path.join(pending, 'agent.py'))
    os.mkdir(os.path.join(pending, 'agent.py'))
    assert inst.main(paths) == 0
    assert outcome(paths)['result'] == 'refused' and lib(paths, 'liteblox_agent.py') == OLD


def test_a_hash_mismatch_is_refused(paths):
    stage(paths, digest=sha(OLD))
    refused(paths, "SHA-256 isn't the one")


def test_a_syntax_error_is_refused(paths):
    bad = b'# liteblox-agent\ndef broken(:\n'
    stage(paths, bad)
    refused(paths, 'does not parse')


def test_an_older_version_is_refused(paths):
    stage(paths, version='4.3.0')
    refused(paths, 'older than the installed 4.4.0')


def test_a_dev_version_over_a_release_is_refused(paths):
    stage(paths, version='4.5.0.dev1+abc')
    refused(paths, 'older than')


def test_too_big_is_refused(paths):
    stage(paths, b'# liteblox-agent\n' + b'#' * inst.MAX_SIZE)
    refused(paths, 'bigger than')


def test_not_an_agent_is_refused(paths):
    stage(paths, b'print("hello")\n')
    refused(paths, 'not a LiteBlox agent')


def test_a_bad_manifest_is_refused(paths):
    pending = stage(paths)
    with open(os.path.join(pending, 'manifest.json'), 'w') as f:
        f.write('{not json')
    refused(paths, 'not JSON')


def test_versions():
    assert inst.version_key('4.5.0') == (4, 5, 0) and inst.version_key('4.10') == (4, 10)
    assert inst.version_key('4.5.0.dev1') is None and inst.version_key('test') is None
    assert inst.version_key(None) is None


def test_any_version_goes_over_a_dev_build(paths):
    with open(paths.lib_file('VERSION'), 'w') as f:
        f.write('dev\n')
    stage(paths, version='4.0.0')
    inst.main(paths)
    assert outcome(paths)['result'] == 'installed'


# ── the trial ──────────────────────────────────────────────────────────────────

def test_a_trial_passes_once_the_new_agent_has_started(paths):
    stage(paths)
    inst.main(paths)
    started(paths, NEW)
    inst.main(paths)                            # the next start
    assert lib(paths, 'trial.json') is None and lib(paths, 'liteblox_agent.py') == NEW
    assert outcome(paths)['result'] == 'running'


def test_a_new_agent_that_doesnt_start_twice_is_rolled_back(paths):
    started(paths, OLD)                         # the old agent's mark, from before the upgrade
    stage(paths)
    inst.main(paths)                            # installed; it fails to start
    inst.main(paths)                            # 1 of 2: try again
    assert lib(paths, 'liteblox_agent.py') == NEW and json.loads(lib(paths, 'trial.json'))['attempts'] == 1
    assert outcome(paths)['result'] == 'installed'
    inst.main(paths)                            # 2 of 2: the old one comes back
    assert lib(paths, 'liteblox_agent.py') == OLD and lib(paths, 'VERSION') == b'4.4.0\n'
    assert lib(paths, 'trial.json') is None
    got = outcome(paths)
    assert got['result'] == 'rolled back' and got['sha256'] == sha(NEW)


def test_a_failed_trial_without_a_previous_agent(paths):
    with open(paths.lib_file('trial.json'), 'w') as f:
        json.dump({'sha256': sha(NEW), 'version': '4.5.0', 'attempts': 1}, f)
    inst.main(paths)
    assert outcome(paths)['result'] == 'failed' and lib(paths, 'trial.json') is None
    assert lib(paths, 'liteblox_agent.py') == OLD


def test_a_symlinked_started_mark_doesnt_pass_a_trial(paths, tmp_path):
    stage(paths)
    inst.main(paths)
    fake = tmp_path / 'fake-mark'
    fake.write_text(sha(NEW))
    os.symlink(fake, os.path.join(paths.state, 'started-ok'))
    inst.main(paths)
    assert json.loads(lib(paths, 'trial.json'))['attempts'] == 1


def test_a_broken_trial_file_is_dropped(paths):
    with open(paths.lib_file('trial.json'), 'w') as f:
        f.write('nonsense')
    assert inst.main(paths) == 0 and lib(paths, 'trial.json') is None


def test_it_always_exits_0(paths, monkeypatch):
    def boom(_):
        raise RuntimeError('disk on fire')
    monkeypatch.setattr(inst, 'settle_trial', boom)
    assert inst.main(paths) == 0


def test_the_installer_stays_python_3_9_compatible():
    src = (agent_dir() / 'liteblox_agent_install.py').read_text()
    ast.parse(src, feature_version=(3, 9))
    imported = {n.names[0].name.split('.')[0] for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Import)}
    assert imported <= {'ast', 'hashlib', 'json', 'os', 'pwd', 're', 'stat', 'sys', 'time'}
