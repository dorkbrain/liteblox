"""The website build (website/build.py) and its upload settings (deploy/_publish.py, deploy/_site.py)."""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / 'VERSION').read_text().strip()
FAVICON = ROOT / 'liteblox' / 'static' / 'favicon.svg'


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = _load('liteblox_website_build', ROOT / 'website' / 'build.py')
sys.path.insert(0, str(ROOT / 'deploy'))
import _common  # noqa: E402
import _publish  # noqa: E402
import _site  # noqa: E402


def fake_dist(path):
    path.mkdir()
    for name, size in ((f'liteblox-image-v{VERSION}-amd64.tar.gz', 3 * 1024 * 1024),
                       (f'liteblox-image-v{VERSION}-arm64.tar.gz', 5 * 1024 * 1024), (f'liteblox-src-v{VERSION}.tgz', 2048)):
        (path / name).write_bytes(b'x' * size)
        (path / f'{name}.sha256.txt').write_text(f'{"a" * 64}  {name}\n')
    return path


@pytest.fixture(scope='module')
def site(tmp_path_factory):
    base = tmp_path_factory.mktemp('site')
    out = base / 'out'
    builder.build(out, fake_dist(base / 'dist'))
    return out


def pages(site):
    return sorted(site.rglob('index.html'))


def test_every_help_page_is_built(site):
    for slug, title in builder.PAGES:
        text = (site / 'docs' / slug / 'index.html').read_text()
        assert f'{title} · LiteBlox docs' in text
    assert len(pages(site)) == len(builder.PAGES) + 4     # home, install, docs index, changelog


def test_every_page_links_to_github_in_its_header(site):
    for page in pages(site):
        header = page.read_text().split('</header>', 1)[0]
        assert 'href="https://github.com/dorkbrain/liteblox" aria-label="LiteBlox on GitHub"' in header, page


def test_no_link_back_into_the_app(site):
    for page in pages(site):
        assert 'href="/help' not in page.read_text(), page


def test_internal_links_and_anchors_resolve(site):
    anchors = {page: set(re.findall(r'\bid="([^"]+)"', page.read_text())) for page in pages(site)}
    for page in pages(site):
        for href in re.findall(r'href="([^"]*)"', page.read_text()):
            if href.startswith(('http:', 'https:')):
                continue
            path, _, anchor = href.partition('#')
            if path.startswith('/downloads/'):
                continue
            target = page if not path else site / path.strip('/')
            if target.is_dir():
                target = target / 'index.html'
            assert target.is_file(), f'{page}: {href}'
            if anchor:
                assert anchor in anchors[target], f'{page}: {href}'


def test_every_page_is_ready_for_search_engines(site):
    sitemap = (site / 'sitemap.xml').read_text()
    for page in pages(site):
        text = page.read_text()
        path = '/' + str(page.relative_to(site).parent).replace('.', '', 1) + '/' if page.parent != site else '/'
        url = f'{builder.SITE_URL}{path.replace("//", "/")}'
        assert re.search(r'<title>[^<]+</title>', text), page
        description = re.search(r'name="description" content="([^"]+)"', text)
        assert description and len(description[1]) <= 200, page
        assert f'<link rel="canonical" href="{url}">' in text, page
        assert f'<loc>{url}</loc>' in sitemap, page
        assert 'og:image' in text, page
    assert f'Sitemap: {builder.SITE_URL}/sitemap.xml' in (site / 'robots.txt').read_text()
    assert 'noindex' in (site / '404.html').read_text()
    assert 'SoftwareApplication' in (site / 'index.html').read_text()


def test_favicon_comes_from_the_image(site):
    for copy in (site / 'favicon.svg', site / 'downloads' / '.autoindex' / 'favicon.svg'):
        assert copy.read_bytes() == FAVICON.read_bytes()
    for page in [*pages(site), site / '404.html']:
        assert '<link rel="icon" type="image/svg+xml" href="/favicon.svg">' in page.read_text(), page


def test_the_listing_theme_comes_from_the_repo(site):
    for name in ('head.html', 'foot.html', 'style.css'):
        repo = ROOT / 'website' / 'autoindex' / name
        assert (site / 'downloads' / '.autoindex' / name).read_bytes() == repo.read_bytes()


def test_version_sizes_and_checksums_come_from_dist(site):
    text = (site / 'install' / 'index.html').read_text()
    for arch in ('amd64', 'arm64'):
        assert f'/downloads/liteblox-image-v{VERSION}-{arch}.tar.gz' in text
        assert f'{"a" * 64}  liteblox-image-v{VERSION}-{arch}.tar.gz' in text
    assert '3.0 MB' in text and '5.0 MB' in text and '2 KB' in text
    assert 'a' * 64 in text
    assert f'localhost/liteblox:{VERSION}' in text
    assert '{{' not in text


def test_screenshots_get_names_from_their_content(site):
    home = (site / 'index.html').read_text()
    names = re.findall(r'src="/img/([^"]+)"', home)
    assert names
    for name in names:
        assert re.fullmatch(r'[a-z-]+-[0-9a-f]{8}\.(png|svg)', name) and (site / 'img' / name).is_file()
    assert 'loading="lazy"' in home and 'width="' in home


DRAWIO = ('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" style="background: #FFFFFF; '
          'background-color: light-dark(#FFFFFF, #001933); color-scheme: light dark;" width="300px" height="120px" '
          'viewBox="0 0 300 120" content="&lt;mxfile&gt;secret model&lt;/mxfile&gt;"><rect fill="#FFFFFF" width="100%" '
          'height="100%" x="0" y="0" style="fill: light-dark(rgb(255, 255, 255), rgb(0, 25, 51));"/>'
          '<rect style="fill: light-dark(rgb(30, 41, 59), rgb(195, 204, 220)); stroke: light-dark(#CBD5E1,#808080);"/></svg>')


def test_a_drawio_diagram_on_the_site_background():
    out = builder.site_svg(DRAWIO)
    assert 'content=' not in out and 'secret model' not in out      # the editable model stays in the repo
    assert 'style="background-color: light-dark(#f6f7f9, #12161d); color-scheme: light dark;"' in out
    assert 'width="100%" height="100%" x="0" y="0" style="fill: light-dark(#f6f7f9, #12161d);"' in out
    # drawn for a dark page: as drawn there, draw.io's light version on a light page
    assert 'fill: light-dark(rgb(195, 204, 220), rgb(30, 41, 59)); stroke: light-dark(#808080, #CBD5E1);' in out
    assert builder.svg_size(out) == (300, 120)


def test_the_architecture_diagram_is_on_the_home_page(site):
    home = (site / 'index.html').read_text()
    m = re.search(r'<figure><a href="/img/(liteblox-architecture-[0-9a-f]{8}\.svg)">', home)
    assert m
    assert 'content="' not in (site / 'img' / m[1]).read_text()


def test_a_missing_release_file_fails_the_build(tmp_path):
    dist = fake_dist(tmp_path / 'dist')
    (dist / f'liteblox-src-v{VERSION}.tgz').unlink()
    with pytest.raises(builder.BuildError, match='not built yet'):
        builder.build(tmp_path / 'out', dist)
    assert not (tmp_path / 'out').exists()


def test_a_private_name_fails_the_build(tmp_path, monkeypatch):
    content = tmp_path / 'content'
    content.mkdir()
    for path in builder.CONTENT.iterdir():
        (content / path.name).write_text(path.read_text())
    with (content / 'install.md').open('a') as f:
        f.write('\nimage: registry.secret.example/liteblox\n')
    names = tmp_path / '.private-names'
    names.write_text('# a comment\n\nsecret\\.example\nnot-in-the-site\n')
    monkeypatch.setattr(builder, 'CONTENT', content)
    monkeypatch.setattr(builder, 'PRIVATE_FILE', names)
    with pytest.raises(builder.BuildError, match=r'install/index\.html:\d+: secret\.example'):
        builder.build(tmp_path / 'out', fake_dist(tmp_path / 'dist'))
    assert not (tmp_path / 'out').exists()


def test_without_private_names_there_is_no_check(tmp_path, monkeypatch):
    monkeypatch.setattr(builder, 'PRIVATE_FILE', tmp_path / 'absent')
    assert builder.private_pattern() is None
    builder.check_private(tmp_path)      # nothing to check against: no error


def test_the_repo_has_private_names():
    pattern = builder.private_pattern()       # its lines are private: none is spelled out in a test
    assert pattern is not None and not pattern.search('192.168.1.30') and not pattern.search('example.com')


def test_help_links_are_rewritten():
    body = builder.docs_links('<a href="/help/dhcp#ddns">a</a> <a href="/help">b</a> <a href="/audit">the log</a>', 'x')
    assert body == '<a href="/docs/dhcp/#ddns">a</a> <a href="/docs/">b</a> the log'


@pytest.mark.parametrize('href', ['/settings', '/help/not-a-page'])
def test_a_link_with_no_page_fails_the_build(href):
    with pytest.raises(builder.BuildError, match=href):
        builder.docs_links(f'<a href="{href}">x</a>', 'somepage')


@pytest.mark.parametrize('n,expected', [(2048, '2 KB'), (1895238, '1.8 MB'), (117507192, '112 MB')])
def test_human_size(n, expected):
    assert builder.human_size(n) == expected


def test_publish_file_with_a_site_line(tmp_path, monkeypatch):
    path = tmp_path / '.publish'
    path.write_text('# comment\nto host:/dl\nsite host:/web\nwiki/x.txt\n')
    monkeypatch.setattr(_common, 'PUBLISH_FILE', path)
    monkeypatch.delenv('PUBLISH_TO', raising=False)
    assert _publish.settings() == ('host:/dl', ['wiki/x.txt'])
    assert _publish.site_destination() == 'host:/web'


def test_publish_file_without_a_site_line_skips_the_website(tmp_path, monkeypatch, capsys):
    path = tmp_path / '.publish'
    path.write_text('to host:/dl\n')
    monkeypatch.setattr(_common, 'PUBLISH_FILE', path)
    assert _publish.site_destination() is None
    assert _site.publish() is True
    assert 'skipped' in capsys.readouterr().out


def test_the_upload_protects_release_files_but_not_the_theme():
    command = _site.rsync_command('host:/web/')
    assert '--delete' in command and command[-1] == 'host:/web/'
    # rsync takes the first matching rule, so the theme's rule has to come first
    assert command.index('--filter=R /downloads/.autoindex/***') < command.index('--filter=P /downloads/*')
