"""Source archive step: dist/<project>-src-v<version>.tgz of the project root.

Extra exclude patterns can be listed one per line in .archiveignore at the
project root (blank lines and # comments ignored). Patterns ending in '/' match
directories at any depth; patterns with '*' are fnmatch globs; anything else
matches an exact relative path or basename.
"""

import fnmatch
import os
import sys
import tarfile

from _common import ROOT, write_checksum


DEFAULT_EXCLUDES = [
    'dist/',
    '.git/',
    '.claude/',
    '.venv/',
    '__pycache__/',
    '*.pyc',
    '*.pyo',
]

IGNORE_FILE = ROOT / '.archiveignore'


def exclude_patterns():
    patterns = list(DEFAULT_EXCLUDES)
    if IGNORE_FILE.exists():
        for line in IGNORE_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    return patterns


def _make_filter(patterns):
    def should_exclude(tarinfo):
        path = tarinfo.name
        inner = path.split('/', 1)[1] if '/' in path else ''
        if not inner:
            return tarinfo      # the top-level arcname directory itself

        for pattern in patterns:
            if pattern.endswith('/'):
                name = pattern.rstrip('/')
                if (inner == name or inner.startswith(pattern)
                        or inner.endswith(f'/{name}') or f'/{pattern}' in inner):
                    return None
            elif '*' in pattern:
                if fnmatch.fnmatch(inner, pattern) or fnmatch.fnmatch(os.path.basename(inner), pattern):
                    return None
            else:
                if inner == pattern or inner.endswith('/' + pattern):
                    return None

        return tarinfo
    return should_exclude


def archive_path(project, version):
    return ROOT / 'dist' / f'{project}-src-v{version}.tgz'


def create_archive(project, version):
    out = archive_path(project, version)
    out.parent.mkdir(exist_ok=True)

    if out.exists():
        print(f"ERROR: {out.relative_to(ROOT)} already exists. Bump the version or remove it first.",
              file=sys.stderr)
        return False

    patterns = exclude_patterns()
    print(f"\nCreating source archive: {out.relative_to(ROOT)}")
    print(f"Excluding: {'  '.join(patterns)}")

    try:
        with tarfile.open(out, 'w:gz') as tar:
            tar.add(str(ROOT), arcname=f'{project}/', filter=_make_filter(patterns))

        with tarfile.open(out, 'r:gz') as tar:
            members = tar.getnames()

        top = sorted({m.split('/')[1] for m in members if m.count('/') >= 1 and m.split('/')[1]})
        size_bytes = out.stat().st_size
        size_str = (f"{size_bytes/1048576:.2f} MB" if size_bytes >= 1048576
                    else f"{size_bytes/1024:.2f} KB")

        write_checksum(out)

        print(f"\n✓ Archive created successfully")
        print(f"  Archive:  {out.relative_to(ROOT)}")
        print(f"  Size:     {size_str}")
        print(f"  Files:    {len(members)}")
        print(f"  Contents: {'  '.join(top)}")
        return True

    except Exception as e:
        print(f"\nERROR: Failed to create archive: {e}", file=sys.stderr)
        out.unlink(missing_ok=True)
        return False
