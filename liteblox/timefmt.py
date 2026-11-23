"""Timestamps for people: stored in UTC, shown in the container's time zone (TZ)."""

from datetime import datetime, timezone


def local(value):
    """'2026-10-25 01:38:11' (SQLite UTC) or an ISO time with an offset (git) → local time with its zone name."""
    if not value:
        return ''
    try:
        dt = datetime.fromisoformat(str(value).replace(' ', 'T', 1))
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')


_UNITS = [('w', 604800), ('d', 86400), ('h', 3600), ('m', 60), ('s', 1)]


def duration(value):
    """Seconds as BIND writes durations: 3600 → '1h', 5400 → '1h30m', 1209600 → '2w'. Anything else passes through."""
    if value is None or value == '':
        return ''
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return str(value)
    if seconds <= 0:
        return str(seconds)
    parts = []
    for unit, size in _UNITS:
        count, seconds = divmod(seconds, size)
        if count:
            parts.append(f'{count}{unit}')
    return ''.join(parts)


def _parse(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    dt = datetime.fromisoformat(str(value).replace(' ', 'T', 1))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def ago(value, now=None):
    """'just now', '3 min ago', '5 h ago', 'yesterday', '4 days ago' for status times (UTC text or unix time);
    pages put the full local time in a title."""
    if value is None or value == '':
        return ''
    try:
        seconds = ((now or datetime.now(timezone.utc)) - _parse(value)).total_seconds()
    except (TypeError, ValueError):
        return str(value)
    if seconds < 45:
        return 'just now'       # also a little in the future: clocks differ
    if seconds < 3600:
        return f'{max(1, round(seconds / 60))} min ago'
    if seconds < 86400:
        return f'{int(seconds // 3600)} h ago'
    if seconds < 2 * 86400:
        return 'yesterday'
    if seconds < 30 * 86400:
        return f'{int(seconds // 86400)} days ago'
    return _parse(value).astimezone().strftime('%Y-%m-%d')


def offset(seconds, sign=True):
    """chrony's offset for people: µs, ms or s."""
    f = '+' if sign else ''
    a = abs(seconds)
    if a < 0.001:
        return f'{seconds * 1e6:{f}.0f} µs'
    if a < 1:
        return f'{seconds * 1e3:{f}.1f} ms'
    return f'{seconds:{f}.1f} s'


def reltime(value, now=None):
    """'3 min ago' in a <time> whose tooltip is the full local time; for status times (history keeps local())."""
    from markupsafe import Markup, escape
    if not value:
        return Markup('')
    try:
        when = _parse(value)
    except (TypeError, ValueError):
        return escape(str(value))
    return Markup('<time datetime="{}" title="{}">{}</time>').format(when.isoformat(), local(when.isoformat()), ago(value, now))
