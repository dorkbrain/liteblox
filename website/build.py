#!/usr/bin/env python3
"""Build the LiteBlox website into dist/site: plain HTML from website/content, the Help pages and CHANGELOG.md.

Run it with `uv run python website/build.py`, or ./deploy/deploy.py --site to build and upload.
Version, sizes and checksums come from VERSION and the release files in dist/, so nothing is typed in by hand.
"""

import argparse
import hashlib
import html
import json
import re
import shutil
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import jinja2  # noqa: E402
import markdown  # noqa: E402

from liteblox.help import PAGES, render  # noqa: E402

HERE = Path(__file__).resolve().parent
CONTENT = HERE / 'content'
AUTOINDEX = HERE / 'autoindex'
SCREENSHOTS = ROOT / 'wiki' / 'screenshots'
FAVICON = ROOT / 'liteblox' / 'static' / 'favicon.svg'
INSTALL_TEXT = ROOT / 'wiki' / 'INSTALL-WITHOUT-REGISTRY.txt'
CHANGELOG = ROOT / 'CHANGELOG.md'

# canonical links and the sitemap always name the public site, whichever hostname serves the pages
SITE_URL = 'https://liteblox.dorkbrain.com'
SITE_BG = ('#f6f7f9', '#12161d')     # style.css --bg, light and dark

# nothing matching a line of .private-names goes public (that file isn't in the public source)
PRIVATE_FILE = ROOT / '.private-names'
TEXT_SUFFIXES = {'.html', '.xml', '.txt', '.css', '.md', '.svg'}

# pages that exist only inside a running LiteBlox: a link to one becomes plain text
IN_APP = ('/static/', '/audit')
LINK = re.compile(r'<a href="(/[^"#]*)(#[^"]*)?"[^>]*>(.*?)</a>', re.S)
IMG = re.compile(r'<img ([^>]*?)\s*/?>')
FIGURE = re.compile(r'<p>(<img [^>]*>)\s*<em>(.*?)</em></p>', re.S)


class BuildError(Exception):
    pass


def human_size(n):
    if n < 1024 ** 2:
        return f'{max(n / 1024, 1):.0f} KB'
    mb = n / 1024 ** 2
    return f'{mb:.0f} MB' if mb >= 10 else f'{mb:.1f} MB'


def describe(body, fallback):
    """The page's first paragraph as plain text, short enough for a search result."""
    found = re.search(r'<p>(.*?)</p>', body, re.S)
    text = ' '.join(html.unescape(re.sub(r'<[^>]+>', '', found[1])).split()) if found else ''
    if len(text) < 40:
        return fallback
    return text if len(text) <= 155 else text[:154].rsplit(' ', 1)[0].rstrip(' ,;:(') + '…'


def docs_links(body, slug):
    """Point a Help page's links at /docs/ on this site."""
    known = {s for s, _ in PAGES}

    def replace(m):
        path, anchor, text = m[1], m[2] or '', m[3]
        if path.rstrip('/') == '/help':
            return f'<a href="/docs/{anchor}">{text}</a>'
        if path.startswith('/help/'):
            target = path[len('/help/'):].rstrip('/')
            if target not in known:
                raise BuildError(f'{slug}: link to an unknown Help page: {path}')
            return f'<a href="/docs/{target}/{anchor}">{text}</a>'
        if path.startswith(IN_APP):
            return text
        raise BuildError(f'{slug}: link to {path} has no page on the website')

    return LINK.sub(replace, body)


def release_date(version):
    found = re.search(rf'^## {re.escape(version)} — (\S+)', CHANGELOG.read_text(), re.M)
    if not found:
        raise BuildError(f'{version} has no entry in CHANGELOG.md')
    return found[1]


def downloads(version, dist):
    """(Markdown table, checksum lines) for the release's files in dist/."""
    amd64, arm64 = (f'liteblox-image-v{version}-{arch}.tar.gz' for arch in ('amd64', 'arm64'))
    src = f'liteblox-src-v{version}.tgz'
    sums = []
    for name in (amd64, arm64, src):
        for path in (dist / name, dist / f'{name}.sha256.txt'):
            if not path.exists():
                raise BuildError(f'not built yet: {path}')
        line = (dist / f'{name}.sha256.txt').read_text().strip()
        if not re.fullmatch(r'[0-9a-f]{64}\s+\S+', line):
            raise BuildError(f'{name}.sha256.txt is not a checksum line')
        sums.append(line)
    rows = [
        (amd64, human_size((dist / amd64).stat().st_size),
         'The ready-built container image for **x86-64**: most PCs, servers and VMs. Load it with `docker load`. '
         '**Start here.**'),
        (arm64, human_size((dist / arm64).stat().st_size),
         'The same image for **ARM64**: a Raspberry Pi 4 or 5 with a 64-bit OS, and other 64-bit ARM boards.'),
        (src, human_size((dist / src).stat().st_size), 'The source, with its Dockerfile, to build the image yourself.'),
        (INSTALL_TEXT.name, human_size(INSTALL_TEXT.stat().st_size), 'The install and upgrade steps below, as a text file.'),
    ]
    table = ['| File | Size | What it is |', '|---|---|---|']
    table += [f'| [{name}](/downloads/{name}) | {size} | {what} |' for name, size, what in rows]
    return '\n'.join(table), '\n'.join(sums)


def hashed_name(path):
    return f'{path.stem}-{hashlib.sha256(path.read_bytes()).hexdigest()[:8]}{path.suffix}'


def _light_dark_swapped(text):
    """Every light-dark(a, b) as light-dark(b, a); a and b may hold rgb(...)."""
    out, i = [], 0
    while (start := text.find('light-dark(', i)) != -1:
        open_at = start + len('light-dark(')
        depth, comma, j = 0, None, open_at
        while j < len(text):
            c = text[j]
            if c == '(':
                depth += 1
            elif c == ')':
                if depth == 0:
                    break
                depth -= 1
            elif c == ',' and depth == 0 and comma is None:
                comma = j
            j += 1
        if comma is None or j == len(text):
            raise BuildError('a light-dark() the build cannot read')
        first, second = text[open_at:comma].strip(), text[comma + 1:j].strip()
        out.append(f'{text[i:start]}light-dark({second}, {first})')
        i = j + 1
    out.append(text[i:])
    return ''.join(out)


def site_svg(text):
    """A draw.io export as the site shows it. Its colours are drawn for a dark page, and draw.io saves them as
    light-dark(as drawn, its light version): swapped, a dark page gets them as drawn and a light page draw.io's
    light version, both on the site's own background. The embedded diagram (for editing) is left out."""
    text = re.sub(r'\scontent="[^"]*"', '', text, count=1)
    text = _light_dark_swapped(text)
    text, n = re.subn(r'(<svg\b[^>]*?\sstyle=")[^"]*(")',
                      rf'\1background-color: light-dark({SITE_BG[0]}, {SITE_BG[1]}); color-scheme: light dark;\2',
                      text, count=1)
    if not n:
        raise BuildError('an SVG without a style on its <svg>')
    # draw.io's page background, a rect over the whole picture
    text = re.sub(r'(<rect\b[^>]*\swidth="100%"[^>]*\sheight="100%"[^>]*?)(?:\sstyle="[^"]*")?(\s*/?>)',
                  rf'\1 style="fill: light-dark({SITE_BG[0]}, {SITE_BG[1]});"\2', text, count=1)
    return text


def svg_size(text):
    root = re.search(r'<svg\b[^>]*>', text)[0]
    size = [re.search(rf'\s{k}="([0-9.]+)(?:px)?"', root) for k in ('width', 'height')]
    if not all(size):
        raise BuildError('an SVG without a width and height in px')
    return round(float(size[0][1])), round(float(size[1][1]))


def place_images(out):
    """Copy the screenshots (and draw.io diagrams) under names that change with their content (Cloudflare caches
    images for a long time)."""
    (out / 'img').mkdir()
    images = {}
    for path in sorted([*SCREENSHOTS.glob('*.png'), *SCREENSHOTS.glob('*.svg')]):
        if path.suffix == '.svg':
            data = site_svg(path.read_text()).encode()
            width, height = svg_size(data.decode())
        else:
            data = path.read_bytes()
            width, height = struct.unpack('>II', data[16:24])
        name = f'{path.stem}-{hashlib.sha256(data).hexdigest()[:8]}{path.suffix}'
        (out / 'img' / name).write_bytes(data)
        images[path.name] = {'url': f'/img/{name}', 'width': width, 'height': height}
    return images


def with_images(body, images):
    """Real image names and sizes in <img>; an image and its caption line become a figure linking to the full size."""
    def replace(m):
        attrs = m[1]
        src = re.search(r'src="([^"]+)"', attrs)[1]
        if not src.startswith('/img/'):
            return m[0]
        if src[len('/img/'):] not in images:
            raise BuildError(f'no such screenshot: {src}')
        image = images[src[len('/img/'):]]
        attrs = attrs.replace(f'src="{src}"', f'src="{image["url"]}"')
        return f'<img {attrs} width="{image["width"]}" height="{image["height"]}" loading="lazy">'

    def figure(m):
        src = re.search(r'src="([^"]+)"', m[1])[1]
        return f'<figure><a href="{src}">{m[1]}</a><figcaption>{m[2]}</figcaption></figure>'

    return FIGURE.sub(figure, IMG.sub(replace, body))


def convert(text):
    """(HTML, meta headers) of one of the site's own Markdown pages."""
    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'sane_lists', 'toc', 'meta', 'md_in_html'],
                           extension_configs={'toc': {'permalink': False}})
    body = md.convert(text)
    return body, {k: ' '.join(v) for k, v in md.Meta.items()}


def json_ld(version, description, screenshot):
    data = {
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        'name': 'LiteBlox',
        'url': f'{SITE_URL}/',
        'description': description,
        'applicationCategory': 'UtilitiesApplication',
        'operatingSystem': 'Linux (Docker or Podman)',
        'softwareVersion': version,
        'license': 'https://opensource.org/license/mit',
        'screenshot': f'{SITE_URL}{screenshot}',
        'offers': {'@type': 'Offer', 'price': '0', 'priceCurrency': 'USD'},
        'author': {'@type': 'Organization', 'name': 'Dorkbrain', 'url': 'https://dorkbrain.com'},
    }
    return json.dumps(data).replace('<', '\\u003c')


def private_pattern(path=None):
    """One regex of every line of .private-names, or None without the file (a public copy of the source)."""
    path = path or PRIVATE_FILE
    if not path.exists():
        return None
    lines = [s for s in (line.strip() for line in path.read_text().splitlines()) if s and not s.startswith('#')]
    return re.compile('|'.join(f'(?:{s})' for s in lines)) if lines else None


def check_private(out):
    """Every generated text file, last of all: a private name stops the build."""
    pattern = private_pattern()
    if pattern is None:
        return
    hits = []
    for path in sorted(out.rglob('*')):
        if path.is_file() and path.suffix in TEXT_SUFFIXES:
            for number, line in enumerate(path.read_text().splitlines(), 1):
                found = pattern.search(line)
                if found:
                    hits.append(f'{path.relative_to(out)}:{number}: {found[0]}')
    if hits:
        raise BuildError('private names in the site:\n  ' + '\n  '.join(hits))


def page_file(out, path):
    return out / path.strip('/') / 'index.html'


def build(out=ROOT / 'dist' / 'site', dist=ROOT / 'dist'):
    """Write the site to out and return the number of pages. On any error nothing is left to publish."""
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    try:
        count = _build(out, dist)
        check_private(out)
    except Exception:
        shutil.rmtree(out, ignore_errors=True)
        raise
    return count


def _build(out, dist):
    version = (ROOT / 'VERSION').read_text().strip()
    released = release_date(version)
    table, checksums = downloads(version, dist)
    images = place_images(out)

    css = hashed_name(HERE / 'style.css')
    shutil.copy(HERE / 'style.css', out / css)
    shutil.copy(FAVICON, out / 'favicon.svg')

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(HERE), autoescape=True, keep_trailing_newline=True)
    template = env.get_template('base.html')
    hero = images['dashboard.png']
    shared = {'version': version, 'released': released, 'css': f'/{css}', 'hero': hero, 'pages': PAGES}
    written = []

    def write(path, **page):
        page.setdefault('url', f'{SITE_URL}{path}')
        target = out / '404.html' if page.get('noindex') else page_file(out, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        page['image'] = f'{SITE_URL}{hero["url"]}'
        target.write_text(template.render(page=page, **shared))
        if not page.get('noindex'):
            written.append(path)

    def own_page(name):
        text = (CONTENT / name).read_text()
        for token, value in (('{{version}}', version), ('{{downloads}}', table), ('{{checksums}}', checksums)):
            text = text.replace(token, value)
        body, meta = convert(text)
        return with_images(body, images), meta

    body, meta = own_page('index.md')
    write('/', kind='home', section='home', title=meta['title'], description=meta['description'],
          tagline=meta['tagline'], body=body, jsonld=json_ld(version, meta['description'], hero['url']))

    body, meta = own_page('install.md')
    write('/install/', kind='page', section='install', title=meta['title'], description=meta['description'], body=body)

    index = []
    for number, (slug, title) in enumerate(PAGES):
        raw, toc = render(slug)
        body = docs_links(raw, slug)
        description = describe(body.split('</h1>', 1)[-1], f'{title}: LiteBlox documentation.')
        index.append({'slug': slug, 'title': title, 'description': description})
        write(f'/docs/{slug}/', kind='docs', section='docs', title=f'{title} · LiteBlox docs', description=description,
              body=body, slug=slug, toc=toc[0]['children'] if toc and len(toc) == 1 else toc,
              prev=PAGES[number - 1] if number else None, next=PAGES[number + 1] if number + 1 < len(PAGES) else None)
    write('/docs/', kind='docs-index', section='docs', title='LiteBlox documentation',
          description='The LiteBlox manual: installing, DNS zones, DHCP, time, IPAM, failover, backups, the API and the '
                      'command line.', index=index, slug=None)

    body = markdown.markdown(CHANGELOG.read_text(), extensions=['tables', 'fenced_code', 'sane_lists', 'toc'])
    write('/changelog/', kind='page', section='changelog', title='LiteBlox changelog',
          description=f'Every LiteBlox release, newest first. Current version: {version}, released {released}.', body=body)

    write('/404.html', kind='page', section='', title='Page not found · LiteBlox', description='That page does not exist.',
          noindex=True, body='<h1>Page not found</h1><p>That page isn\'t here. Try the <a href="/">home page</a> or the '
                             '<a href="/docs/">documentation</a>.</p>')

    urls = ''.join(f'  <url><loc>{SITE_URL}{path}</loc><lastmod>{released}</lastmod></url>\n' for path in written)
    (out / 'sitemap.xml').write_text('<?xml version="1.0" encoding="UTF-8"?>\n'
                                     '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                                     f'{urls}</urlset>\n')
    (out / 'robots.txt').write_text(f'User-agent: *\nAllow: /\nDisallow: /downloads/\n\nSitemap: {SITE_URL}/sitemap.xml\n')

    # the listing's theme lives in the repo; its icon is the app's own
    listing = out / 'downloads' / '.autoindex'
    shutil.copytree(AUTOINDEX, listing)
    shutil.copy(FAVICON, listing / 'favicon.svg')
    return len(written) + 1


def main():
    parser = argparse.ArgumentParser(description='Build the LiteBlox website')
    parser.add_argument('--out', type=Path, default=ROOT / 'dist' / 'site', help='where to write it (replaced)')
    args = parser.parse_args()
    try:
        count = build(args.out)
    except BuildError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    print(f'✓ Site built: {count} pages in {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
