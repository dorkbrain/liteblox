"""Add DNS from an IPAM row (4.7.1): an A record (and its PTR) in a zone picked on the page, published or left in
the draft, or sent as an update to a dynamic zone."""

import pytest

from liteblox.dns import dynamic
from liteblox.dns.drafts import Drafts
from liteblox.ipam import assign, model, names
from test_ipam import admin, post, viewer  # noqa: F401 (fixtures)
from test_search import add_zone, world  # noqa: F401 (fixture)

OTHER = """$TTL 3600
@\tIN\tSOA\tns1.lab.example. hostmaster.lab.example. 2026110101 3600 900 1209600 300
@\tIN\tNS\tns1.lab.example.
"""
BACK = '/ipam/networks/1?ip=192.0.2.30'


@pytest.fixture
def lab(conn, settings, world):  # noqa: F811
    """The search world (lab.example with 192.0.2.0/24's names, its reverse zone, a dynamic zone, a DHCP subnet)
    plus a second static zone, and 192.0.2.0/24 in IPAM."""
    add_zone(conn, settings, 'other.example', OTHER)
    return model.get(conn, model.add_network(conn, '192.0.2.0/24', 'Lab'))


def draft(conn, settings, zone):
    text, is_draft = Drafts(settings).load(conn.execute('SELECT * FROM zones WHERE name = ?', (zone,)).fetchone())
    return text if is_draft else ''


@pytest.fixture
def sent(monkeypatch, world):  # noqa: F811
    """dyn.lab.example's updates: each new text, which the world's AXFR then serves."""
    texts = []

    def send_edit(settings, conn, zone_row, old_text, new_text, author, message, transfer=None, send=None):
        if world.text is None:
            raise dynamic.DynamicError('the update to 192.0.2.53 got no answer: timed out')
        texts.append(new_text)
        world.text = new_text
        return new_text
    monkeypatch.setattr(dynamic, 'send_edit', send_edit)
    return texts


@pytest.fixture
def published(monkeypatch):
    calls = []

    def fake(settings, conn, zones, username, via, message):
        calls.append((sorted(zones), message))
        return [42], []
    monkeypatch.setattr(assign, '_publish', fake)
    return calls


def save(client, ip='192.0.2.30', **form):
    return post(client, f'/ipam/dns/{ip}', **{'zone': 'lab.example', 'publish': 'draft', 'ptr': '1', 'back': BACK,
                                               **form})


# ── the page ───────────────────────────────────────────────────────────────────

def test_the_page_offers_the_static_forward_zones(admin, conn, lab):
    page = admin.get(f'/ipam/dns/192.0.2.30?back={BACK}').text
    assert '<option value="lab.example" selected>' in page and '<option value="other.example">' in page
    assert '<option value="dyn.lab.example">dyn.lab.example (dynamic)</option>' in page
    assert 'in-addr.arpa' not in page.split('<select')[1].split('</select>')[0]
    assert 'Add the PTR record in 2.0.192.in-addr.arpa' in page and 'ptr: true' in page
    assert f'name="back" value="{BACK}"' in page


def test_the_likeliest_zone_is_the_one_the_network_uses(admin, conn, settings, lab):
    # lab.example holds 192.0.2.0/24's names; with more of them in other.example, that one is picked
    add_zone(conn, settings, 'more.example', OTHER + ''.join(f'h{i}\tIN\tA\t192.0.2.{i}\n' for i in range(1, 6)))
    assert '<option value="more.example" selected>' in admin.get('/ipam/dns/192.0.2.30').text
    # an address outside every IPAM network still gets a zone: the first static one
    assert '<option value="lab.example" selected>' in admin.get('/ipam/dns/198.51.100.7').text


def test_a_dynamic_zone_only_where_no_static_zone_has_names(admin, conn, lab, world):  # noqa: F811
    # 192.0.2.0/24: dyn.lab.example has a name there, but lab.example has more and is static
    assert '<option value="lab.example" selected>' in admin.get('/ipam/dns/192.0.2.30').text
    model.add_network(conn, '198.51.100.0/24', 'Far')
    world.text += 'far1\tIN\tA\t198.51.100.5\n'
    assert '<option value="dyn.lab.example" selected>' in admin.get('/ipam/dns/198.51.100.7').text


def test_the_name_starts_from_ipam_or_dhcp(admin, conn, lab):
    names.save(conn, '192.0.2.31', 'vm03', '', 'the new VM', 'alice')
    page = admin.get('/ipam/dns/192.0.2.31').text
    assert 'value="vm03"' in page and 'value="the new VM"' in page
    # the reservation's hostname; a lease's, in full when it's in a zone LiteBlox holds, else its first label
    assert 'name="name" value="printer"' in admin.get('/ipam/dns/192.0.2.60').text
    assert 'name="name" value="laptop.dyn.lab.example"' in admin.get('/ipam/dns/192.0.2.120').text
    # names already at the address are shown
    assert 'Already in DNS as' in admin.get('/ipam/dns/192.0.2.51').text


def test_admins_only_and_only_with_dns(admin, viewer, conn, lab):  # noqa: F811
    assert viewer.get('/ipam/dns/192.0.2.30').status_code == 403
    with conn:
        conn.execute('UPDATE modules SET dns = 0')
    assert viewer.get('/ipam/dns/192.0.2.30').status_code == 403


def test_404_with_dns_off(admin, conn, lab):
    with conn:
        conn.execute('UPDATE modules SET dns = 0')
    assert admin.get('/ipam/dns/192.0.2.30').status_code == 404
    assert save(admin, name='vm03').status_code == 404
    assert admin.get('/ipam/dns/not-an-ip').status_code == 400


# ── saving ─────────────────────────────────────────────────────────────────────

def test_leave_in_the_draft_with_its_ptr(admin, conn, settings, lab, published):
    r = save(admin, name='vm03', comment='lab VM')
    assert r.status_code == 303 and r.headers['location'].startswith('/ipam/networks/1?ip=192.0.2.30&done=')
    assert 'in%20the%20draft%20of%20lab.example' in r.headers['location']
    assert any(line.split()[:1] == ['vm03'] and '192.0.2.30' in line and 'lab VM' in line
               for line in draft(conn, settings, 'lab.example').splitlines())
    assert any(line.split()[:1] == ['30'] and 'vm03.lab.example.' in line
               for line in draft(conn, settings, '2.0.192.in-addr.arpa').splitlines())
    assert published == []
    row = conn.execute("SELECT * FROM audit WHERE action = 'record_add'").fetchone()
    assert row['detail'] == 'lab.example: vm03.lab.example A 192.0.2.30 (from IPAM)'


def test_publish_now(admin, conn, settings, lab, published):
    r = save(admin, name='vm04', publish='now')
    assert published == [(['lab.example'], 'vm04.lab.example → 192.0.2.30 (from IPAM)')]
    assert 'job=42' in r.headers['location'] and 'publishing%20it%20now' in r.headers['location']
    page = admin.get(r.headers['location']).text
    assert '<a href="/jobs/42">Its job</a>' in page


def test_no_ptr_when_unticked(admin, conn, settings, lab, published):
    save(admin, name='vm05', ptr='')
    assert 'vm05' in draft(conn, settings, 'lab.example')
    assert draft(conn, settings, '2.0.192.in-addr.arpa') == ''


def test_no_reverse_zone(admin, conn, settings, lab, published):
    page = admin.get('/ipam/dns/198.51.100.7').text
    assert 'No reverse zone in LiteBlox covers this address' in page and 'ptr: false' in page
    r = save(admin, ip='198.51.100.7', name='far')
    assert r.status_code == 303
    assert 'far' in draft(conn, settings, 'lab.example')


def test_a_full_name_goes_to_its_zone(admin, conn, settings, lab, published):
    save(admin, name='vm06.other.example', zone='lab.example')
    assert 'vm06' in draft(conn, settings, 'other.example') and draft(conn, settings, 'lab.example') == ''
    # a dotted name in no zone is relative to the zone picked
    save(admin, name='vm07.rack1', zone='other.example', ip='192.0.2.31')
    assert 'vm07.rack1' in draft(conn, settings, 'other.example')
    # a trailing dot outside every zone is refused
    r = save(admin, name='vm08.nowhere.', ip='192.0.2.32')
    assert r.status_code == 422 and "isn&#39;t in a zone in LiteBlox" in r.text


def test_refused(admin, conn, settings, lab, published):
    r = save(admin, name='')
    assert r.status_code == 422 and 'give a name' in r.text
    r = save(admin, name='bad name!')
    assert r.status_code == 422 and 'error-text' in r.text
    r = save(admin, name='www')          # a CNAME is there
    assert r.status_code == 422 and 'error-text' in r.text
    r = save(admin, name='x', zone='2.0.192.in-addr.arpa')
    assert r.status_code == 422 and 'pick a zone' in r.text
    r = save(admin, name='x.2.0.192.in-addr.arpa')
    assert r.status_code == 422 and 'is a forwarding or reverse zone' in r.text
    assert draft(conn, settings, 'lab.example') == ''
    # CSRF
    r = admin.post('/ipam/dns/192.0.2.30', data={'name': 'x', 'zone': 'lab.example'}, follow_redirects=False)
    assert r.status_code in (400, 403)
    # back only to IPAM or Search
    r = save(admin, name='vm09', back='https://evil.example/')
    assert r.headers['location'].startswith('/search?q=192.0.2.30')


# ── where it's offered ─────────────────────────────────────────────────────────

def test_the_row_link(admin, conn, settings, lab):
    names.save(conn, '192.0.2.31', 'vm03', '', '', 'alice')
    page = admin.get('/ipam/networks/1').text
    rows = {chunk.split('"', 1)[0]: chunk for chunk in page.split('<tr id="ip-')[1:]}
    assert '/ipam/dns/192.0.2.30?back=' in rows['192.0.2.30']        # free
    assert '/ipam/dns/192.0.2.31?back=' in rows['192.0.2.31']        # named in IPAM
    assert '/ipam/dns/192.0.2.51' not in rows['192.0.2.51']          # has an A record
    with conn:
        conn.execute('UPDATE modules SET dns = 0')
    assert '/ipam/dns/' not in admin.get('/ipam/networks/1').text


def test_the_name_page_links_to_it(admin, conn, lab):
    assert '/ipam/dns/192.0.2.30?back=' in admin.get('/ipam/names/192.0.2.30').text


def test_no_forward_zone_no_link(admin, conn, lab):
    with conn:
        conn.execute("UPDATE zones SET kind = 'forwarding' WHERE name NOT LIKE '%.arpa'")
    assert '/ipam/dns/' not in admin.get('/ipam/networks/1').text
    assert admin.get('/ipam/dns/192.0.2.30').status_code == 404


# ── a dynamic zone ─────────────────────────────────────────────────────────────

def test_a_single_dynamic_zone_install(admin, conn, settings, lab, sent, published):
    # its one forward zone takes DHCP's names: lab.example and other.example gone
    with conn:
        conn.execute("DELETE FROM zones WHERE name IN ('lab.example', 'other.example')")
    assert '/ipam/dns/192.0.2.30?back=' in admin.get('/ipam/networks/1').text
    assert '<option value="dyn.lab.example" selected>' in admin.get('/ipam/dns/192.0.2.30').text
    r = save(admin, name='vm03', zone='dyn.lab.example', ptr='', publish='now')
    assert r.status_code == 303 and 'done=vm03.dyn.lab.example%20%E2%86%92%20192.0.2.30%20is%20live%20in%20dyn.lab.example' in r.headers['location']
    assert 'job=' not in r.headers['location'] and published == []
    assert any(line.split()[:1] == ['vm03'] and '192.0.2.30' in line for line in sent[-1].splitlines())


def test_a_dynamic_zone_with_a_static_reverse_zone(admin, conn, settings, lab, sent, published):
    # the PTR lands in the static reverse zone's draft: Then publishes it, or leaves it there
    r = save(admin, name='vm03', zone='dyn.lab.example', publish='draft')
    assert 'its%20PTR%20is%20in%20the%20draft%20of%202.0.192.in-addr.arpa' in r.headers['location']
    assert 'vm03.dyn.lab.example.' in draft(conn, settings, '2.0.192.in-addr.arpa') and published == []
    r = save(admin, ip='192.0.2.31', name='vm04', zone='dyn.lab.example', publish='now')
    assert published == [(['2.0.192.in-addr.arpa'], 'vm04.dyn.lab.example → 192.0.2.31 (from IPAM)')]
    assert 'publishing%20its%20PTR' in r.headers['location'] and 'job=42' in r.headers['location']
    assert len(sent) == 2


def test_a_failed_update_adds_nothing(admin, conn, settings, lab, world, published, monkeypatch):  # noqa: F811
    def refused(*a, **k):
        raise dynamic.DynamicError('the update to 192.0.2.53 got no answer: timed out')
    monkeypatch.setattr(dynamic, 'send_edit', refused)
    r = save(admin, name='vm03', zone='dyn.lab.example')
    assert r.status_code == 409 and 'Nothing was added: the update to dyn.lab.example failed' in r.text
    world.text = None           # the primary can't even be read
    r = save(admin, name='vm03', zone='dyn.lab.example')
    assert r.status_code == 409 and 'Nothing was added' in r.text
    sent = []
    assert sent == [] and draft(conn, settings, '2.0.192.in-addr.arpa') == ''
    assert conn.execute("SELECT 1 FROM audit WHERE action = 'record_add'").fetchone() is None
