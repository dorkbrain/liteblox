import re
from pathlib import Path

from liteblox import help as help_mod

TEMPLATES = Path(help_mod.__file__).parent / 'templates'


def test_help_is_readable_without_login(client):
    index = client.get('/help')
    assert index.status_code == 200 and 'Preparing a node' in index.text and 'Log in' in index.text
    assert 'Quick start' in index.text
    qs = client.get('/help/quick-start').text
    assert 'ns1.example.com 192.168.1.213' in qs and 'href="/help/node-prep"' in qs
    page = client.get('/help/node-prep')
    assert page.status_code == 200
    html = page.text
    assert '<h1 id="preparing-a-node">Preparing a node</h1>' in html
    assert 'apt install -y bind9 bind9-utils bind9-dnsutils python3 sudo' in html
    assert '<table>' in html and 'href="#8-pre-flight-checklist"' in html      # table + on-this-page list


def test_unknown_or_odd_pages_404(client):
    for slug in ('nope', '..%2Fauth', 'Node-Prep'):
        assert client.get(f'/help/{slug}').status_code == 404


def test_logged_in_users_get_the_nav(client, make_user, login):
    login(*make_user())
    html = client.get('/help/node-prep').text
    assert 'aria-current="page">Help</a>' in html and 'Log out' in html


def _ids(tokens):
    for t in tokens:
        yield t['id']
        yield from _ids(t['children'])


def _anchors():
    # every heading id in the page, including levels the "On this page" list leaves out
    return {slug: set(re.findall(r'<h\d id="([^"]+)"', help_mod.render(slug)[0])) | set(_ids(help_mod.render(slug)[1]))
            for slug, _ in help_mod.PAGES}


def test_every_help_link_in_the_app_points_at_a_real_page_and_anchor():
    anchors = _anchors()
    found = 0
    for tpl in TEMPLATES.rglob('*.html'):
        for slug, anchor in re.findall(r'href="/help/([a-z0-9-]+)(?:#([a-z0-9-]+))?"', tpl.read_text()):
            found += 1
            assert slug in anchors, f'{tpl.name}: /help/{slug} does not exist'
            assert not anchor or anchor in anchors[slug], f'{tpl.name}: /help/{slug}#{anchor} does not exist'
    assert found >= 5


def test_every_link_inside_the_docs_resolves():
    anchors = _anchors()
    found = 0
    for slug, _ in help_mod.PAGES:
        text = (help_mod.DOCS_DIR / f'{slug}.md').read_text()
        for target, anchor in re.findall(r'\]\(/help/([a-z0-9-]+)(?:#([a-z0-9-]+))?\)', text):
            found += 1
            assert target in anchors, f'{slug}.md: /help/{target} does not exist'
            assert not anchor or anchor in anchors[target], f'{slug}.md: /help/{target}#{anchor} does not exist'
        for anchor in re.findall(r'\]\(#([a-z0-9-]+)\)', text):
            found += 1
            assert anchor in anchors[slug], f'{slug}.md: #{anchor} does not exist'
    assert found >= 10


def test_every_doc_file_is_listed():
    files = {p.stem for p in help_mod.DOCS_DIR.glob('*.md')}
    assert files == {slug for slug, _ in help_mod.PAGES}


def test_wizards_link_to_the_runbook(client, make_user, login, conn):
    from liteblox.nodes import service
    from test_nodes import FP, HOST_KEY
    login(*make_user())
    service.add_node(conn, 'ns1', '192.0.2.53', 22, 8530, HOST_KEY, FP)
    assert '/help/node-prep' in client.get('/nodes/new').text
    assert '/help/node-prep#9-what-litebloxs-setup-changes' in client.get('/nodes/1/bootstrap').text
    client.cookies.clear()
    assert '/help/node-prep' in client.get('/login').text


def test_static_assets_are_cache_busted(client):
    import re as _re
    html = client.get('/login').text
    css = _re.search(r'href="(/static/app\.css\?v=[0-9a-f]{10})"', html).group(1)
    assert client.get(css).status_code == 200
    assert _re.search(r'src="/static/vendor/htmx\.min\.js\?v=[0-9a-f]{10}"', html)


def test_code_blocks_render_as_blocks():
    # Python-Markdown doesn't take a ``` fence inside a list item: it collapses into one inline line
    for slug, _ in help_mod.PAGES:
        body, _ = help_mod.render(slug)
        assert '```' not in body and not re.search(r'<p>[^<]*<code>(bash|text)\b', body), slug


def test_nested_lists_are_indented_four_spaces():
    # Python-Markdown nests a list only at 4 spaces; at 2 or 3 the items render flat, or as plain text
    for slug, _ in help_mod.PAGES:
        text = (help_mod.DOCS_DIR / f'{slug}.md').read_text()
        assert not re.search(r'(?m)^ {1,3}(?:[-*]|\d+\.) ', text), slug
