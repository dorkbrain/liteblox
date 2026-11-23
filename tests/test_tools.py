"""Tools: the subnet reference's figures, both pages, the Tools menu and the light/dark toggle."""

import re
from pathlib import Path

import pytest

from liteblox import tools

ROOT = Path(__file__).parent.parent / 'liteblox'


def row(prefix):
    return tools.reference()[prefix]


def test_reference_has_every_prefix_in_order():
    rows = tools.reference()
    assert [r['prefix'] for r in rows] == list(range(33))
    assert [r['prefix'] for r in rows if r['common']] == [8, 16, 24]


@pytest.mark.parametrize('prefix, mask', [(0, '0.0.0.0'), (1, '128.0.0.0'), (23, '255.255.254.0'),
                                          (24, '255.255.255.0'), (26, '255.255.255.192'), (32, '255.255.255.255')])
def test_masks(prefix, mask):
    assert row(prefix)['mask'] == mask


@pytest.mark.parametrize('prefix, hosts', [(0, 4_294_967_294), (8, 16_777_214), (24, 254), (29, 6), (30, 2),
                                           (31, 2), (32, 1)])
def test_usable_hosts(prefix, hosts):
    assert row(prefix)['hosts'] == hosts


@pytest.mark.parametrize('prefix, nxt', [(0, 'n/a'), (1, 'a+128.b.c.d'), (7, 'a+2.b.c.d'), (8, 'a+1.b.c.d'),
                                         (9, 'a.b+128.c.d'), (16, 'a.b+1.c.d'), (23, 'a.b.c+2.d'),
                                         (24, 'a.b.c+1.d'), (25, 'a.b.c.d+128'), (26, 'a.b.c.d+64'),
                                         (32, 'a.b.c.d+1')])
def test_next_net(prefix, nxt):
    assert row(prefix)['next'] == nxt


def logged_in(client, make_user, login, role):
    login(*make_user('alice', role=role))
    return client


@pytest.mark.parametrize('role', ['admin', 'readonly'])
def test_pages_render_for_any_account(client, make_user, login, role):
    logged_in(client, make_user, login, role)
    ref = client.get('/tools/subnets')
    assert ref.status_code == 200
    assert '255.255.254.0' in ref.text and '4,294,967,294' in ref.text and 'a.b.c.d+64' in ref.text
    calc = client.get('/tools/subnet-calculator')
    assert calc.status_code == 200
    assert '/static/subnetcalc.css?v=' in calc.text and '/static/subnetcalc.js?v=' in calc.text
    assert 'fonts.googleapis' not in calc.text and 'confirm(' not in calc.text
    # Reset asks through app.js's dialog: its own form with data-confirm, submitted by the button
    assert 'id="calc-reset" data-confirm=' in calc.text and 'form="calc-reset"' in calc.text


def test_the_calculator_credits_its_origin(client, make_user, login):
    """Its license: the origin isn't misrepresented, altered versions are marked, the notice stays in any distribution."""
    logged_in(client, make_user, login, 'readonly')
    page = client.get('/tools/subnet-calculator').text
    assert "David C A Croft" in page and 'An altered version' in page and '/static/subnetcalc-LICENSE.txt' in page
    notice = client.get('/static/subnetcalc-LICENSE.txt').text
    assert 'Copyright (c) 2002, 2011, 2018, 2019 David C A Croft' in notice and 'This notice may not be removed' in notice
    for name in ('subnetcalc.js', 'subnetcalc.css'):
        assert 'David C A Croft' in (ROOT / 'static' / name).read_text()


def test_the_project_license():
    text = (ROOT.parent / 'LICENSE').read_text()
    assert text.startswith('MIT License') and 'Copyright (c) 2026 Dorkbrain (https://dorkbrain.com)' in text


@pytest.mark.parametrize('path', ['/tools/subnets', '/tools/subnet-calculator'])
def test_pages_need_a_login(client, path):
    r = client.get(path, follow_redirects=False)
    assert r.status_code in (302, 303) and r.headers['location'] == '/login'


def test_calculator_script_never_uses_the_browser_dialogs():
    src = re.sub(r'/\*.*?\*/|//[^\n]*', '', (ROOT / 'static' / 'subnetcalc.js').read_text(), flags=re.S)
    assert not re.search(r'(?<![.\w])(confirm|alert)\(', src)
    assert 'liteblox.confirm' in src and "execCommand('copy')" in src


def test_topbar_has_tools_menu_and_theme_toggle(client, make_user, login):
    logged_in(client, make_user, login, 'readonly')
    page = client.get('/').text
    menu = re.search(r'<details class="nav-menu">.*?</details>', page, re.S).group(0)
    assert '<summary' in menu and '>Tools</summary>' in menu
    for href in ('/tools/subnets', '/tools/subnet-calculator'):
        assert re.search(rf'<a href="{href}" target="_blank" rel="noopener">', menu)
    assert 'id="theme-toggle"' in page
    # the menu sits after IPAM and before Help (Settings is admin-only)
    assert page.index('href="/ipam"') < page.index('nav-menu') < page.index('href="/help"')
    assert 'aria-current' in client.get('/tools/subnets').text.split('</summary>')[0].rsplit('<summary', 1)[1]


@pytest.mark.parametrize('path', ['/', '/api/docs', '/login'])
def test_topbar_js_in_head_without_defer(client, make_user, login, path):
    if path != '/login':
        logged_in(client, make_user, login, 'admin')
    else:
        client.cookies.clear()
    head = client.get(path).text.split('</head>')[0]
    tag = re.search(r'<script src="/static/topbar\.js\?v=\w+"[^>]*>', head)
    assert tag and 'defer' not in tag.group(0) and 'async' not in tag.group(0)


def dark_pairs(css):
    """Selectors of the rules inside 'prefers-color-scheme: dark' and of the [data-theme="dark"] rules."""
    auto, forced = set(), set()
    for block in re.finditer(r'@media \(prefers-color-scheme: dark\) \{((?:[^{}]*\{[^{}]*\})+)\s*\}', css):
        for sel in re.findall(r'([^{}]+)\{', block.group(1)):
            auto.update(s.strip().replace(':root:not([data-theme="light"])', '').strip() for s in sel.split(','))
    for sel in re.findall(r'([^{}@]*\[data-theme="dark"\][^{}]*)\{', css):
        forced.update(s.strip().replace(':root[data-theme="dark"]', '').strip() for s in sel.split(','))
    return auto, forced


@pytest.mark.parametrize('name', ['static/app.css', 'static/subnetcalc.css', 'templates/api_docs.html'])
def test_every_dark_rule_has_a_toggle_twin(name):
    """Auto follows the system unless the toggle says light, and Dark applies everywhere: no dark rule forgets one."""
    css = re.sub(r'/\*.*?\*/', '', (ROOT / name).read_text(), flags=re.S)
    blocks = re.findall(r'@media \(prefers-color-scheme: dark\) \{((?:[^{}]*\{[^{}]*\})+)\s*\}', css)
    assert blocks
    for block in blocks:
        for sel in re.findall(r'([^{}]+)\{', block):
            for s in sel.split(','):
                assert s.strip().startswith(':root:not([data-theme="light"])'), s
    auto, forced = dark_pairs(css)
    assert auto and auto == forced
