#!/usr/bin/env python3
"""
Release pipeline: archive → build → push → publish → site, then (after the release commit and tag
are pushed) release: the public GitHub copy and the Forgejo and GitHub release pages.

Drop this deploy/ directory into any project root. The project name comes from
PROJECT (default: the project directory's name) and the version from VERSION;
both are seeded on first run. PUSH_AS pushes under another name, to try a push.
Images are built for every architecture in _common.ARCHES. The registries they
go to are the registry lines of .publish (REGISTRY, space-separated, overrides
them). Extra archive excludes go in .archiveignore. Where publish uploads the
release's downloads goes in .publish (see deploy/_publish.py), and so does where
the website goes (see deploy/_site.py).

Usage:
    ./deploy/deploy.py                    # archive → build → push → publish → site at current version
    ./deploy/deploy.py --build            # build the images (every architecture) only
    ./deploy/deploy.py --push             # push the built images to the registries only
    ./deploy/deploy.py --publish          # upload the tarballs + checksums only
    ./deploy/deploy.py --site             # build and upload the website only
    ./deploy/deploy.py --release          # after commit + tag + push: GitHub copy, both release pages
    ./deploy/deploy.py --release --dry-run  # check and commit the GitHub copy locally; nothing leaves
    ./deploy/deploy.py --archive --build  # multiple steps, always in pipeline order
    ./deploy/deploy.py --bump-patch       # bump patch version + changelog, then all steps
    ./deploy/deploy.py --bump-minor --build
    ./deploy/deploy.py --bump-to 6.0.0    # a jump (4.8.0 → 6.0.0), forward only
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _common
import _archive
import _build
import _publish
import _push
import _release
import _site


def main():
    parser = argparse.ArgumentParser(
        description='Release pipeline: archive → build → push → publish → site',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage:', 1)[1].rstrip(),
    )
    parser.add_argument('--archive', action='store_true',
                        help='create source archive (dist/<project>-src-v<ver>.tgz)')
    parser.add_argument('--build', action='store_true',
                        help='build the image for each architecture, save a gzipped tarball + checksum of each to dist/')
    parser.add_argument('--push', action='store_true',
                        help='push the images (:X.Y.Z, :X.Y, :X, :latest) to each registry')
    parser.add_argument('--publish', action='store_true',
                        help='upload the tarballs, checksums and .publish extras (rsync)')
    parser.add_argument('--site', action='store_true',
                        help="build the website and upload it to .publish's site destination")
    parser.add_argument('--release', action='store_true',
                        help='after the release tag is pushed: the GitHub copy and the Forgejo and GitHub '
                             'release pages with the downloads (never part of a default run)')
    parser.add_argument('--dry-run', action='store_true',
                        help='with --release: check and commit the GitHub copy locally, push and upload nothing')

    bump = parser.add_mutually_exclusive_group()
    bump.add_argument('--bump-patch', dest='bump', action='store_const', const='patch',
                      help='increment patch version (1.0.0 → 1.0.1) before running steps')
    bump.add_argument('--bump-minor', dest='bump', action='store_const', const='minor',
                      help='increment minor version (1.0.0 → 1.1.0) before running steps')
    bump.add_argument('--bump-major', dest='bump', action='store_const', const='major',
                      help='increment major version (1.0.0 → 2.0.0) before running steps')
    bump.add_argument('--bump-to', metavar='X.Y.Z',
                      help='jump to this later version (4.8.0 → 6.0.0) before running steps')

    args = parser.parse_args()
    run_all = not any([args.archive, args.build, args.push, args.publish, args.site, args.release])
    if args.dry_run and not args.release:
        parser.error('--dry-run goes with --release')
    if args.release and (args.bump or args.bump_to):
        parser.error('--release runs after the release is committed and tagged, not with a bump')

    os.chdir(_common.ROOT)
    _common.seed_files()

    project = _common.read_project()
    registries = _common.registries()

    print("=" * 60)
    print(f"{project} Deploy")
    print("=" * 60)

    current_version = _common.read_version()
    if not current_version:
        return 1

    print(f"\nProject:  {project}")
    print(f"Registry: {', '.join(registries) or '(none)'}")
    print(f"Current version: {current_version}")

    if args.bump or args.bump_to:
        if args.bump_to:
            try:
                version = _common.bump_to(current_version, args.bump_to)
            except ValueError as e:
                print(f"ERROR: {e}")
                return 1
            print(f"Bumping to {version}: {current_version} → {version}")
        else:
            version = _common.bump_version(current_version, args.bump)
            print(f"Bumping {args.bump} version: {current_version} → {version}")

        changelog_msg = _common.prompt_changelog()
        _common.write_version(version)
        _common.update_changelog(version, changelog_msg)
    else:
        version = current_version

    steps = [s for s, flag in (('archive', args.archive), ('build', args.build), ('push', args.push),
                               ('publish', args.publish), ('site', args.site))
             if run_all or flag] + (['release'] if args.release else [])
    print(f"\nSteps: {' → '.join(steps)}")

    if ('build' in steps or 'push' in steps) and not _common.check_podman():
        return 1

    ok = True

    if 'archive' in steps:
        print("\n" + "-" * 60)
        print("STEP: Archive")
        print("-" * 60)
        if not _archive.create_archive(project, version):
            ok = False

    if 'build' in steps:
        print("\n" + "-" * 60)
        print("STEP: Build")
        print("-" * 60)
        if not _build.build_image(project, version):
            ok = False

    # never push after a failed build — it would publish a stale image
    if 'push' in steps and ok:
        print("\n" + "-" * 60)
        print("STEP: Push")
        print("-" * 60)
        if not _push.push_image(project, registries, version):
            ok = False

    if 'publish' in steps and ok:
        print("\n" + "-" * 60)
        print("STEP: Publish")
        print("-" * 60)
        if not _publish.publish(project, version):
            ok = False

    if 'site' in steps and ok:
        print("\n" + "-" * 60)
        print("STEP: Website")
        print("-" * 60)
        if not _site.publish():
            ok = False

    if 'release' in steps and ok:
        print("\n" + "-" * 60)
        print("STEP: Release" + (" (dry run)" if args.dry_run else ""))
        print("-" * 60)
        if not _release.release(project, version, dry_run=args.dry_run):
            ok = False

    if not ok:
        print("\n✗ DEPLOY FAILED", file=sys.stderr)
        return 1

    print("\n" + "=" * 60)
    print("✓ DEPLOY SUCCESSFUL")
    print("=" * 60)
    print(f"\n  Version: {version}")

    if 'archive' in steps:
        print(f"\n  Archive:  {_archive.archive_path(project, version).relative_to(_common.ROOT)}")

    if 'build' in steps:
        for arch in _common.ARCHES:
            print(f"\n  Image:    {_build.local_image(project, version, arch)} ({arch})")
            print(f"  Tarball:  {_build.tarball_path(project, version, arch).relative_to(_common.ROOT)}")
        print(f"  Manifest: {_build.manifest_name(project, version)}")

    if 'push' in steps:
        tags = ', '.join(_common.image_tags(version))
        for registry in registries:
            print(f"\n  Pushed:   {registry}/{_common.push_name(project)} ({tags})")
    elif 'build' in steps:
        print(f"\n  Test locally, then push with: ./deploy/deploy.py --push")

    if 'publish' in steps:
        dest = _publish.settings()[0]
        print(f"\n  Published: {dest}" if dest else "\n  Published: (no destination)")

    if 'site' in steps:
        dest = _publish.site_destination()
        print(f"\n  Website:  {dest}" if dest else "\n  Website:  (no destination)")

    if 'release' in steps:
        conf = _common.read_publish()
        print(f"\n  Release:  v{version}" + (" (dry run: nothing left this machine)" if args.dry_run else
              f" on Forgejo ({conf['forgejo']}) and GitHub ({conf['github']})"))

    print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
