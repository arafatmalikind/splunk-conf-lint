"""Cron expansion and Splunk relative time parsing, enough to compare a schedule with its time range."""

import re

_DOW = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}


def expand(field, lo, hi, names=None):
    out = set()
    for part in field.split(","):
        part = part.strip().lower()
        if names:
            for n, v in names.items():
                part = part.replace(n, str(v))
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) == 0:
                raise ValueError("bad step %r" % s)
            step = int(s)
        if part in ("*", ""):
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise ValueError("bad range %r" % part)
            a, b = int(x), int(y)
        elif part.isdigit():
            a = int(part)
            b = hi if step > 1 else a
        else:
            raise ValueError("bad value %r" % part)
        if a < lo or b > hi or a > b:
            raise ValueError("%r outside %d-%d" % (part, lo, hi))
        out.update(range(a, b + 1, step))
    return sorted(out)


def parse_cron(expr):
    f = expr.split()
    if len(f) != 5:
        raise ValueError("cron needs 5 fields, got %d" % len(f))
    return (expand(f[0], 0, 59), expand(f[1], 0, 23), expand(f[2], 1, 31), expand(f[3], 1, 12),
            expand(f[4].replace("7", "0"), 0, 6, _DOW), f)


def interval_minutes(expr):
    """Largest gap between consecutive runs within a day, or None when day fields restrict the schedule."""
    mins, hours, _, _, _, f = parse_cron(expr)
    if f[2] != "*" or f[3] != "*" or f[4] != "*":
        return None
    runs = sorted(h * 60 + m for h in hours for m in mins)
    if len(runs) == 1:
        return 1440
    gaps = [b - a for a, b in zip(runs, runs[1:])] + [runs[0] + 1440 - runs[-1]]
    return max(gaps)


_UNITS = {"s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "m": 60, "min": 60, "mins": 60, "minute": 60,
          "minutes": 60, "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "d": 86400, "day": 86400,
          "days": 86400, "w": 604800, "week": 604800, "weeks": 604800, "mon": 2592000, "month": 2592000}


def relative_seconds(t):
    """'-15m', '-1h@h', '-24h', 'now', '' -> seconds before now, or None if not understood."""
    t = (t or "").strip().lower()
    if t in ("now", "0", ""):
        return 0 if t else None
    t = t.split("@", 1)[0]
    if t.startswith("rt"):
        t = t[2:]
    if not t:
        return 0
    m = re.fullmatch(r"-(\d*)([a-z]+)", t)
    if not m or m.group(2) not in _UNITS:
        return None
    return int(m.group(1) or 1) * _UNITS[m.group(2)]
