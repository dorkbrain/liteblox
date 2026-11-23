"""Image build step: one podman build per architecture, a smoke test of each, a local manifest list
of them for the push step, and a gzipped tarball (+ checksum) per architecture in dist/.

Build context is build/ when build/Dockerfile exists, otherwise the project root. Architectures other
than the workstation's own build under qemu-user-static (binfmt with the F flag).
"""

import gzip
import io
import json
import subprocess
import sys
import tarfile

from _common import ARCHES, ROOT, write_checksum

# every compiled dependency, so a wheel broken on one architecture fails here and not on a user's box
SMOKE = ('python3 -c "import liteblox.main, pydantic_core, cryptography.hazmat.bindings._rust, argon2, '
         'nacl.bindings, bcrypt, uvloop, httptools, watchfiles" && liteblox --help >/dev/null && '
         'named-checkzone -v >/dev/null')


def build_context():
    return ROOT / 'build' if (ROOT / 'build' / 'Dockerfile').exists() else ROOT


def local_image(project, version, arch):
    """The workstation's own architecture keeps the plain name (testenv and the in-image tests use it)."""
    return f'{project}:{version}' if arch == ARCHES[0] else f'{project}:{version}-{arch}'


def manifest_name(project, version):
    # podman can't give a manifest list and an image the same name
    return f'{project}-manifest:{version}'


def tarball_path(project, version, arch):
    # `docker load -i` (or podman load) reads either one as localhost/<project>:<version>
    return ROOT / 'dist' / f'{project}-image-v{version}-{arch}.tar.gz'


def run(cmd, what):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\nERROR: {what} failed: {(result.stderr or result.stdout).strip()}", file=sys.stderr)
        return None
    return result.stdout


def build_image(project, version):
    context = build_context()
    for arch in ARCHES:
        image = local_image(project, version, arch)
        print(f"\nBuilding {image} (linux/{arch}) from {context.relative_to(ROOT.parent)}/ ...")
        result = subprocess.run(
            ['podman', 'build', '--platform', f'linux/{arch}', '-t', image,
             '--label', f'org.opencontainers.image.version={version}', str(context)],
        )
        if result.returncode != 0:
            print(f"\nERROR: Container build failed (linux/{arch})", file=sys.stderr)
            return False
        # podman can reuse a cached base image of the wrong architecture with only a warning
        built = run(['podman', 'image', 'inspect', '--format', '{{.Architecture}}', image], 'inspect')
        if built is None or built.strip() != arch:
            print(f"\nERROR: {image} came out as {built and built.strip()}, not {arch}", file=sys.stderr)
            return False
        print(f"\nSmoke test of {image}...")
        if run(['podman', 'run', '--rm', '--platform', f'linux/{arch}', image, 'sh', '-c', SMOKE],
               f'Smoke test ({arch})') is None:
            return False
        print(f"✓ {image} built and smoke-tested ({arch})")

    # keep a local :latest alias of the workstation's own image
    run(['podman', 'tag', local_image(project, version, ARCHES[0]), f'{project}:latest'], 'Tag latest')

    if not make_manifest(project, version):
        return False
    for arch in ARCHES:
        save_tarball(project, version, arch)
    return True


def make_manifest(project, version):
    """A fresh local manifest list holding every architecture's image, for `podman manifest push`."""
    name = manifest_name(project, version)
    subprocess.run(['podman', 'manifest', 'rm', name], capture_output=True)    # a rebuild starts clean
    if run(['podman', 'manifest', 'create', name], 'Manifest create') is None:
        return False
    for arch in ARCHES:
        image = f'containers-storage:localhost/{local_image(project, version, arch)}'
        if run(['podman', 'manifest', 'add', name, image], f'Manifest add {arch}') is None:
            return False
    print(f"✓ Manifest list {name} ({', '.join(ARCHES)})")
    return True


def archive_info(path):
    """(RepoTags, architecture) of a gzipped docker-archive, read from its manifest.json and config."""
    with tarfile.open(path, 'r:gz') as tar:
        manifest = json.load(tar.extractfile('manifest.json'))[0]
        config = json.load(tar.extractfile(manifest['Config']))
    return manifest.get('RepoTags') or [], config.get('architecture')


def gzip_with_one_name(raw, out, name):
    """Gzip a docker-archive, naming the image only `name`: podman also records the name it was saved
    from (liteblox:<ver>-arm64), which `docker load` would add as a second, stray tag."""
    repo, tag = name.rsplit(':', 1)
    with tarfile.open(raw) as src, gzip.open(out, 'wb', compresslevel=6) as gz, \
            tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as dst:
        for member in src:
            data = src.extractfile(member) if member.isfile() else None
            if member.name == 'manifest.json':
                manifest = json.load(data)
                for image in manifest:
                    image['RepoTags'] = [name]
                data = json.dumps(manifest).encode()
            elif member.name == 'repositories':
                image_id = next(iter(next(iter(json.load(data).values())).values()))
                data = json.dumps({repo: {tag: image_id}}).encode()
            if isinstance(data, bytes):
                member.size = len(data)
                data = io.BytesIO(data)
            dst.addfile(member, data)


def save_tarball(project, version, arch):
    """dist/<project>-image-v<ver>-<arch>.tar.gz + its checksum, loading as localhost/<project>:<ver>.
    A failed save only warns: the images themselves are fine."""
    tar_out = tarball_path(project, version, arch)
    tar_out.parent.mkdir(exist_ok=True)
    raw = tar_out.with_suffix('')          # the plain .tar podman writes, gzipped below
    print(f"\nSaving image to {tar_out.relative_to(ROOT)}...")
    # podman won't overwrite an existing docker-archive, so a rebuild at the same version would
    # otherwise silently leave the stale tarball in place
    raw.unlink(missing_ok=True)
    tar_out.unlink(missing_ok=True)
    name = f'localhost/{project}:{version}'
    if run(['podman', 'push', '--quiet', f'localhost/{local_image(project, version, arch)}',
            f'docker-archive:{raw}:{name}'], f'Save ({arch})') is None:
        print("WARNING: no tarball saved", file=sys.stderr)
        return False
    gzip_with_one_name(raw, tar_out, name)
    raw.unlink()
    tags, got = archive_info(tar_out)
    if tags != [name] or got != arch:
        print(f"WARNING: {tar_out.name} holds {tags} for {got}, not [{name}] for {arch}", file=sys.stderr)
        return False
    write_checksum(tar_out)
    print(f"✓ Saved {tar_out.relative_to(ROOT)} ({tar_out.stat().st_size / 1048576:.0f} MB) + checksum")
    return True
