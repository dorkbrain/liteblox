"""DHCP → Settings → DNS registration → Test: does the other DNS server answer for the zones Kea will update?

A TSIG-signed SOA query per zone (each registering subnet's domain and reverse zones), sent the way D2 sends its
updates (UDP, to the server and port set, signed with the key). It shows the server knows the key and holds the
zone; whether its policy lets the key update the names is up to that server, so it can't be checked from here.
"""

import base64
import binascii

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig

TIMEOUT = 3.0
MAX_ZONES = 20


def check_key(key):
    """Errors for an external key {name, algorithm, secret}: {field: message}."""
    from ..keys import ALGORITHMS
    errors = {}
    try:
        dns.name.from_text((key.get('name') or '').strip().rstrip('.') + '.')
        if not (key.get('name') or '').strip():
            raise ValueError
    except (ValueError, dns.exception.DNSException):
        errors['ddns_key_name'] = "the key's name, as the DNS server knows it"
    if key.get('algorithm') not in ALGORITHMS:
        errors['ddns_key_algorithm'] = f"one of {', '.join(ALGORITHMS)}"
    try:
        if not base64.b64decode(key.get('secret') or '', validate=True):
            raise ValueError
    except (ValueError, binascii.Error):
        errors['ddns_key_secret'] = 'the base64 secret from the key file (secret "…";)'
    return errors


def soa(server, port, zone, key, timeout=TIMEOUT):
    """{zone, ok, text}: what the server said for zone's SOA, asked with the key."""
    q = dns.message.make_query(zone.rstrip('.') + '.', dns.rdatatype.SOA)
    q.flags &= ~dns.flags.RD
    q.use_tsig(dns.tsig.Key(key['name'], key['secret'], key['algorithm']))
    at = server if port == 53 else f'{server} port {port}'
    try:
        r = dns.query.udp(q, server, port=port, timeout=timeout)
    except dns.exception.Timeout:
        return {'zone': zone, 'ok': False, 'text': f'no answer from {at} in {timeout:g} s'}
    except dns.tsig.PeerBadKey:
        return {'zone': zone, 'ok': False, 'text': f"{at} doesn't know key {key['name']} (BADKEY)"}
    except dns.tsig.PeerBadSignature:
        return {'zone': zone, 'ok': False, 'text': f"{at} knows key {key['name']}, but not with this secret or "
                                                   'algorithm (BADSIG)'}
    except dns.tsig.PeerBadTime:
        return {'zone': zone, 'ok': False, 'text': f"{at}'s clock and LiteBlox's are too far apart (BADTIME)"}
    except (OSError, dns.exception.DNSException) as e:
        return {'zone': zone, 'ok': False, 'text': f'{at}: {e}'}
    rcode = r.rcode()
    if rcode == dns.rcode.NOERROR and r.flags & dns.flags.AA:
        rr = next((x for x in r.answer if x.rdtype == dns.rdatatype.SOA), None)
        if rr is not None:
            soa_rd = rr[0]
            return {'zone': zone, 'ok': True, 'text': f'{at} holds it (primary {soa_rd.mname.to_text().rstrip(".")}, '
                                                      f'serial {soa_rd.serial}) and accepted key {key["name"]}'}
    if rcode == dns.rcode.NOERROR and r.flags & dns.flags.AA:
        apex = next((x.name.to_text().rstrip('.') for x in r.authority if x.rdtype == dns.rdatatype.SOA), '?')
        return {'zone': zone, 'ok': False, 'text': f"{at} has it inside its zone {apex}, not as a zone: Kea updates "
                                                   f"zones, so give {apex}"}
    if rcode == dns.rcode.NOERROR and not r.flags & dns.flags.AA:
        return {'zone': zone, 'ok': False, 'text': f"{at} answered, but doesn't hold the zone itself: updates must go "
                                                   "to the zone's primary"}
    if rcode in (dns.rcode.NXDOMAIN, dns.rcode.NOTAUTH):
        return {'zone': zone, 'ok': False, 'text': f"{at} doesn't hold {zone}"}
    return {'zone': zone, 'ok': False, 'text': f'{at} answered {dns.rcode.to_text(rcode)}'}


SOA = soa           # tests put a fake here


def zones(subnets, config):
    """The forward domains and reverse zones the registering subnets update (at most MAX_ZONES)."""
    from .render import subnet_reverse_zones
    out = []
    for s in subnets:
        if not s.registers:
            continue
        for z in [s.ddns_domain, *subnet_reverse_zones(s, config)]:
            if z not in out:
                out.append(z)
    return out[:MAX_ZONES]


def run(dhcp_settings, subnets):
    """[{zone, ok, text}] for the external server, or [] when no subnet registers yet."""
    from .model import KeaConfig
    config = KeaConfig(settings=dhcp_settings, primary=dhcp_settings.ddns_server, ddns_port=dhcp_settings.ddns_port)
    for s in subnets:
        s.ddns_mode = dhcp_settings.ddns_mode
    return [SOA(dhcp_settings.ddns_server, dhcp_settings.ddns_port, z, dhcp_settings.ddns_external_key)
            for z in zones(subnets, config)]
