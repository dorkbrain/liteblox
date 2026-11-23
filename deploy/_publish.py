"""Publish step: upload a release's downloads with rsync over ssh.

The destination and any extra files come from .publish at the project root:

    to HOST:/path/to/downloads/<project>
    site HOST:/path/to/website          (the website, see deploy/_site.py)
    registry REGISTRY/OWNER             (one line per registry the image goes to, see deploy/_push.py)
    wiki/INSTALL-WITHOUT-REGISTRY.txt

PUBLISH_TO in the environment overrides the destination. Each release sends its
source tarball and one image tarball per architecture, with their .sha256.txt checksums, then the extra files
(a folder lands under its own name). Without a destination the step is skipped.
"""

import os
import shutil
import subprocess
import sys

import _archive
import _build
from _common import ARCHES, ROOT, checksum_path, read_publish


def settings():
    """(destination or None, [extra paths])."""
    conf = read_publish()
    return os.environ.get('PUBLISH_TO') or conf['to'], conf['extra']


def site_destination():
    """Where the website goes, or None."""
    return read_publish()['site']


def release_files(project, version):
    out = []
    paths = [_archive.archive_path(project, version)] + [_build.tarball_path(project, version, a) for a in ARCHES]
    for path in paths:
        out += [path, checksum_path(path)]
    return out


def publish(project, version):
    dest, extra = settings()
    if not dest:
        print("\nNo destination (.publish or PUBLISH_TO): skipped")
        return True
    if shutil.which('rsync') is None:
        print("ERROR: rsync not found in PATH", file=sys.stderr)
        return False

    files = release_files(project, version)
    missing = [p for p in files if not p.exists()]
    if missing:
        print(f"ERROR: not built yet: {', '.join(str(p.relative_to(ROOT)) for p in missing)}", file=sys.stderr)
        return False
    for rel in extra:
        path = ROOT / rel
        if path.exists():
            files.append(path)
        else:
            print(f"  (skipping {rel}: not there)")

    print(f"\nUploading to {dest}:")
    for p in files:
        print(f"  {p.relative_to(ROOT)}{'/' if p.is_dir() else ''}")
    # no trailing slash on a folder: it lands under its own name; readable by the web server
    result = subprocess.run(['rsync', '-rt', '--chmod=D755,F644', '--partial', *map(str, files), dest.rstrip('/') + '/'])
    if result.returncode != 0:
        print("\nERROR: Upload failed", file=sys.stderr)
        return False
    print("✓ Uploaded")
    return True
