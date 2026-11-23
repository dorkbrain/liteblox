"""Help pages: Markdown files in liteblox/docs/, rendered at /help. Readable without logging in."""

import re
from functools import lru_cache
from pathlib import Path

import markdown
from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import optional_user
from .templating import templates

DOCS_DIR = Path(__file__).parent / 'docs'
# (slug, title) in sidebar order; each slug is DOCS_DIR/<slug>.md
PAGES = [
    ('quick-start', 'Quick start'),
    ('concepts', 'How LiteBlox works'),
    ('modules', 'Modules: what to run'),
    ('dashboard', 'The Dashboard'),
    ('search', 'Search'),
    ('install', 'Installing and upgrading'),
    ('https', 'HTTPS'),
    ('node-prep', 'Preparing a node'),
    ('existing-servers', 'Bringing in existing servers'),
    ('editing', 'Editing and publishing'),
    ('zones', 'Zones and their settings'),
    ('dynamic', 'Dynamic zones and TSIG keys'),
    ('server-settings', 'Server settings and ACLs'),
    ('dhcp', 'DHCP (Kea)'),
    ('ntp', 'Time (NTP)'),
    ('ipam', 'IPAM (addresses)'),
    ('tools', 'Tools (subnet calculators)'),
    ('failover', 'Primary, failover and drift'),
    ('backups', 'Backups and restore'),
    ('security', 'Security model'),
    ('troubleshooting', 'Troubleshooting'),
    ('api', 'The API'),
    ('reference', 'Command line and settings'),
]
# pages about one module: listed under "Not in use" while it's off (Settings → Modules)
MODULE_PAGES = {'quick-start': 'dns', 'existing-servers': 'dns', 'editing': 'dns', 'zones': 'dns', 'dynamic': 'dns',
                'server-settings': 'dns', 'failover': 'dns', 'dhcp': 'dhcp', 'ntp': 'ntp', 'ipam': 'ipam'}
_SLUG = re.compile(r'[a-z0-9-]+')


def _split(request):
    """(pages, pages of modules that are off)."""
    from .modules import for_request
    on = for_request(request)
    used = [p for p in PAGES if on.get(MODULE_PAGES.get(p[0]), True)]
    return used, [p for p in PAGES if p not in used]

router = APIRouter()


@lru_cache(maxsize=None)
def render(slug):
    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'sane_lists', 'toc'],
                           extension_configs={'toc': {'permalink': False, 'toc_depth': '2'}})
    html = md.convert((DOCS_DIR / f'{slug}.md').read_text())
    return html, md.toc_tokens


@router.get('/help')
def help_index(request: Request, user=Depends(optional_user)):
    pages, others = _split(request)
    return templates.TemplateResponse(request, 'help.html', {'user': user, 'pages': pages, 'others': others,
                                                             'slug': None})


@router.get('/help/{slug}')
def help_page(request: Request, slug: str, user=Depends(optional_user)):
    if not _SLUG.fullmatch(slug) or slug not in dict(PAGES):
        raise HTTPException(status_code=404, detail='no such help page')
    html, toc = render(slug)
    return templates.TemplateResponse(request, 'help.html', {
        'user': user, 'pages': _split(request)[0], 'others': _split(request)[1], 'slug': slug,
        'title': dict(PAGES)[slug], 'body': html,
        'toc': toc[0]['children'] if toc and len(toc) == 1 else toc})
