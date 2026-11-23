"""Website step: build dist/site (website/build.py) and upload it to the 'site' line of .publish.

The upload keeps the destination in line with the repo: anything not in the build goes, except the
release files directly under downloads/, which the publish step puts there. downloads/.autoindex is the
listing's theme, from the repo, so it isn't protected.
"""

import shutil
import subprocess
import sys

import _publish
from _common import ROOT

SITE_DIR = ROOT / 'dist' / 'site'
RSYNC_FILTERS = ['--filter=R /downloads/.autoindex/***', '--filter=P /downloads/*']


def rsync_command(dest):
    return ['rsync', '-rt', '--chmod=D755,F644', '--delete', *RSYNC_FILTERS, f'{SITE_DIR}/', dest.rstrip('/') + '/']


def publish():
    dest = _publish.site_destination()
    if not dest:
        print("\nNo website destination (a 'site' line in .publish): skipped")
        return True
    for tool in ('uv', 'rsync'):
        if shutil.which(tool) is None:
            print(f"ERROR: {tool} not found in PATH", file=sys.stderr)
            return False

    if subprocess.run(['uv', 'run', '--quiet', 'python', 'website/build.py'], cwd=ROOT).returncode != 0:
        print("\nERROR: Website build failed", file=sys.stderr)
        return False

    print(f"\nUploading to {dest}:")
    if subprocess.run(rsync_command(dest)).returncode != 0:
        print("\nERROR: Upload failed", file=sys.stderr)
        return False
    print("✓ Website uploaded")
    return True
