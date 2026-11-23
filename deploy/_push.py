"""Registry push step: the local manifest list (every architecture) to each registry, as
<registry>/<project>:X.Y.Z, :X.Y, :X and :latest.

Registries come from the registry lines of .publish, in order, or REGISTRY (space-separated). The
logins are podman's own (`podman login`), never read here. PUSH_AS pushes under another name (a
scratch package, to try a push without touching the real one). The first failure stops the push.
"""

import json
import subprocess
import sys

from _build import manifest_name
from _common import ARCHES, image_tags, push_name


def push_image(project, registries, version):
    if not registries:
        print("ERROR: no registry (registry lines in .publish, or REGISTRY)", file=sys.stderr)
        return False
    source, name = manifest_name(project, version), push_name(project)
    for registry in registries:
        for tag in image_tags(version):
            dest = f'{registry}/{name}:{tag}'
            print(f"\nPushing {dest}...")
            result = subprocess.run(['podman', 'manifest', 'push', '--all', source, f'docker://{dest}'])
            if result.returncode != 0:
                print(f"\nERROR: Push failed: {dest} (later tags and registries not pushed)", file=sys.stderr)
                return False
        if not check_platforms(f'{registry}/{name}:{version}'):
            return False
    return True


def platforms(manifest):
    return sorted(m['platform']['architecture'] for m in manifest.get('manifests', []) if 'platform' in m)


def check_platforms(ref):
    """What the registry now serves for ref lists every architecture. podman 4.9 takes no docker://
    here and looks at local storage first, which holds no registry names since the build stopped
    tagging them."""
    result = subprocess.run(['podman', 'manifest', 'inspect', ref], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\nERROR: can't read back {ref}: {result.stderr.strip()}", file=sys.stderr)
        return False
    got = platforms(json.loads(result.stdout))
    if got != sorted(ARCHES):
        print(f"\nERROR: {ref} lists {got}, not {sorted(ARCHES)}", file=sys.stderr)
        return False
    print(f"✓ {ref}: {', '.join(got)}")
    return True
