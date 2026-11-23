"""Record and zone validation: dnspython per record, named-checkzone per zone."""

import shutil
import subprocess
import tempfile

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype


class ToolMissing(RuntimeError):
    pass


def check_rdata(rtype, rdata, origin):
    """Return an error message if rdata isn't valid for rtype, else None."""
    try:
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), rdata,
                            origin=origin, relativize=False)
    except (dns.exception.DNSException, ValueError) as e:
        # dnspython says "Text input is malformed." for any bad address
        if rtype in ('A', 'AAAA'):
            return f"{rdata.strip() or 'an empty value'} isn't a valid IPv{4 if rtype == 'A' else 6} address"
        return str(e) or type(e).__name__
    return None


def check_records(zone):
    """[(record, error)] for every record whose data doesn't parse."""
    problems = []
    for rec in zone.records():
        error = check_rdata(rec.rtype, rec.rdata, rec.origin)
        if error:
            problems.append((rec, error))
    return problems


def named_checkzone(zone_name, text, timeout=15):
    """Run named-checkzone on zone text. Returns (ok, output)."""
    tool = shutil.which('named-checkzone')
    if tool is None:
        raise ToolMissing('named-checkzone not found (install bind9-utils)')
    with tempfile.NamedTemporaryFile('w', suffix='.zone', newline='') as tf:
        tf.write(text)
        tf.flush()
        result = subprocess.run([tool, '-k', 'fail', zone_name, tf.name],
                                capture_output=True, text=True, timeout=timeout)
    output = (result.stdout + result.stderr).replace(tf.name, zone_name)
    return result.returncode == 0, output.strip()
