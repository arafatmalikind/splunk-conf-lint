import os
import re
from dataclasses import dataclass, asdict

from . import timeutil

SEVERITY = {"error": 0, "warning": 1, "info": 2}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    stanza: str
    message: str

    def row(self):
        return asdict(self)


RULES = {
    "P001": ("warning", "line breaking is implicit: set LINE_BREAKER and SHOULD_LINEMERGE = false"),
    "P002": ("warning", "timestamp extraction is implicit: set TIME_PREFIX and TIME_FORMAT"),
    "P003": ("info", "TIME_FORMAT without MAX_TIMESTAMP_LOOKAHEAD"),
    "P004": ("info", "no TRUNCATE: events are cut at the default 10000 bytes"),
    "P005": ("warning", "SHOULD_LINEMERGE = true together with LINE_BREAKER: line merging is slow and rarely needed"),
    "P006": ("error", "regular expression does not compile"),
    "P007": ("error", "LINE_BREAKER needs a capturing group; its text is discarded between events"),
    "P008": ("error", "references a transforms.conf stanza that does not exist"),
    "P009": ("warning", "EXTRACT regex has no named capture group, so it extracts nothing"),
    "P010": ("warning", "INDEXED_EXTRACTIONS = json with search-time KV_MODE: fields are extracted twice"),
    "T001": ("error", "regular expression does not compile"),
    "T002": ("error", "FORMAT refers to a capture group the REGEX does not have"),
    "T003": ("error", "routes to an index without FORMAT"),
    "T004": ("error", "lookup file is missing from the app's lookups folder"),
    "T005": ("info", "transform is not referenced by any props.conf stanza in this app"),
    "S001": ("error", "cron_schedule does not parse"),
    "S002": ("info", "runs at minute 0; many searches start together at the top of the hour"),
    "S003": ("warning", "time range is shorter than the schedule interval: events between runs are never searched"),
    "S004": ("info", "time range is much longer than the schedule interval: the same events are searched repeatedly"),
    "S005": ("warning", "scheduled search does not name an index"),
    "S006": ("warning", "searches index=*"),
    "S007": ("warning", "scheduled search uses a real-time time range"),
    "S008": ("warning", "scheduled search has no dispatch.earliest_time, so it searches all time"),
    "I001": ("warning", "input has no index; data goes to the default index"),
    "I002": ("warning", "monitor input has no sourcetype; Splunk will guess one"),
    "I003": ("info", "crcSalt = <SOURCE> re-indexes files when they are renamed or rotated"),
    "O001": ("info", "output group without useACK = true; data in flight can be lost on restart"),
    "O002": ("warning", "TLS certificate verification is disabled"),
    "X001": ("info", "no frozenTimePeriodInSecs; the default keeps data for about six years"),
    "X002": ("error", "index in a cluster bundle without repFactor = auto is not replicated"),
    "A001": ("warning", "local/ folder in an app package; Splunkbase and deployers expect settings in default/"),
    "A002": ("warning", "stanza is defined more than once in the same file"),
    "A003": ("warning", "setting appears more than once in a stanza; the last one wins"),
    "A004": ("error", "cleartext secret in configuration"),
    "A005": ("warning", "no default/app.conf"),
}


def _f(rule, conf_path, line, stanza, detail=""):
    sev, msg = RULES[rule]
    return Finding(rule, sev, conf_path, line, stanza, msg + (": " + detail if detail else ""))


def _at(rule, stanza, key=None, detail=""):
    """Finding located at a setting (or the stanza header when key is None or missing)."""
    if key and key in stanza.settings:
        return _f(rule, stanza.file_of(key), stanza.line_of(key), stanza.name, detail)
    return _f(rule, stanza.file, stanza.line, stanza.name, detail)


def pcre_to_python(rx):
    rx = re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", rx)
    rx = re.sub(r"\(\?'([A-Za-z_]\w*)'", r"(?P<\1>", rx)
    rx = rx.replace("\\Q", "").replace("\\E", "")
    return rx


# PCRE constructs that Python's re lacks (or only has from 3.11): possessive quantifiers,
# atomic groups, recursion, \K, branch reset, and backtracking verbs.
_PCRE_ONLY = re.compile(r"(?<!\\)(?:[*+?}]\+|\(\?>|\(\?R\)|\(\?\d|\(\?\||\\K|\(\*[A-Z])")


def compile_rx(rx):
    """(compiled, None), (None, error) or (None, None) when the regex uses PCRE-only syntax."""
    if _PCRE_ONLY.search(rx):
        return None, None
    try:
        return re.compile(pcre_to_python(rx)), None
    except re.error as e:
        if "look-behind" in str(e):
            return None, None  # PCRE allows some variable-width look-behinds Python rejects
        return None, str(e)


def _is_sourcetype(name):
    return name != "default" and not name.startswith(("source::", "host::", "delayedrule::", "rule::"))


def check_props(cf, transforms):
    out = []
    for s in cf.stanzas:
        if s.name == "default":
            continue
        st = _is_sourcetype(s.name)
        indexed = s.get("INDEXED_EXTRACTIONS")
        if st and not indexed:
            if not s.get("LINE_BREAKER") or s.get("SHOULD_LINEMERGE", "true").lower() not in ("false", "0"):
                out.append(_at("P001", s, None))
            if not (s.get("TIME_PREFIX") or s.get("TIME_FORMAT") or s.get("DATETIME_CONFIG")):
                out.append(_at("P002", s, None))
            if s.get("TIME_FORMAT") and not s.get("MAX_TIMESTAMP_LOOKAHEAD"):
                out.append(_at("P003", s, "TIME_FORMAT"))
            if not s.get("TRUNCATE"):
                out.append(_at("P004", s, None))
        if s.get("SHOULD_LINEMERGE", "").lower() in ("true", "1") and s.get("LINE_BREAKER"):
            out.append(_at("P005", s, "SHOULD_LINEMERGE"))
        for key in ["LINE_BREAKER", "TIME_PREFIX"] + list(s.prefixed("EXTRACT-")):
            if not s.get(key):
                continue
            val = s.get(key)
            if key.startswith("EXTRACT-"):
                val = re.sub(r"\s+in\s+\w+\s*$", "", val)
            rx, err = compile_rx(val)
            if err:
                out.append(_at("P006", s, key, "%s: %s" % (key, err)))
            elif rx is not None:
                if key == "LINE_BREAKER" and rx.groups == 0:
                    out.append(_at("P007", s, key))
                if key.startswith("EXTRACT-") and not rx.groupindex:
                    out.append(_at("P009", s, key, key))
        for key, setting in list(s.prefixed("REPORT-").items()) + list(s.prefixed("TRANSFORMS-").items()) + \
                list(s.prefixed("LOOKUP-").items()):
            refs = setting.value.split()[:1] if key.startswith("LOOKUP-") else setting.value.split(",")
            for ref in [x.strip() for x in refs if x.strip()]:
                if ref not in transforms:
                    out.append(_at("P008", s, key, "%s -> %s" % (key, ref)))
        if (indexed or "").lower() == "json" and s.get("KV_MODE", "auto").lower() not in ("none", "false"):
            out.append(_at("P010", s, "INDEXED_EXTRACTIONS"))
    return out


def check_transforms(cf, referenced, lookups_dir):
    out = []
    for s in cf.stanzas:
        if s.name == "default":
            continue
        is_lookup = bool(s.get("filename") or s.get("external_type") or s.get("collection"))
        rxs = s.get("REGEX")
        if rxs:
            rx, err = compile_rx(rxs)
            if err:
                out.append(_at("T001", s, "REGEX", err))
            elif rx is not None and s.get("FORMAT"):
                used = [int(n) for n in re.findall(r"\$(\d+)", s.get("FORMAT"))]
                if used and max(used) > rx.groups:
                    out.append(_at("T002", s, "FORMAT",
                                  "uses $%d, REGEX has %d group(s)" % (max(used), rx.groups)))
        if s.get("DEST_KEY") == "_MetaData:Index" and not s.get("FORMAT"):
            out.append(_at("T003", s, "DEST_KEY"))
        fn = s.get("filename")
        if fn and lookups_dir is not None and not os.path.exists(os.path.join(lookups_dir, fn)):
            out.append(_at("T004", s, "filename", fn))
        if not is_lookup and s.name not in referenced:
            out.append(_at("T005", s, None))
    return out


def check_savedsearches(cf):
    out = []
    for s in cf.stanzas:
        if s.name == "default" or s.get("disabled", "0").lower() in ("1", "true"):
            continue
        if s.get("enableSched", "0").lower() not in ("1", "true"):
            continue
        cron = s.get("cron_schedule", "")
        interval = None
        try:
            interval = timeutil.interval_minutes(cron)
            mins = timeutil.parse_cron(cron)[0]
            if mins == [0] or (len(mins) > 1 and mins[0] == 0 and cron.split()[0].startswith("*/")):
                if not s.get("schedule_window") and s.get("allow_skew", "0") in ("0", ""):
                    out.append(_at("S002", s, "cron_schedule", cron))
        except ValueError as e:
            out.append(_at("S001", s, "cron_schedule", "%r: %s" % (cron, e)))
        earliest = s.get("dispatch.earliest_time")
        if earliest is None:
            out.append(_at("S008", s, None))
        elif earliest.strip().lower().startswith("rt"):
            out.append(_at("S007", s, "dispatch.earliest_time", earliest))
        elif interval:
            e = timeutil.relative_seconds(earliest)
            l = timeutil.relative_seconds(s.get("dispatch.latest_time", "now"))
            if e is not None and l is not None:
                window = (e - l) / 60.0
                if window < interval:
                    out.append(_at("S003", s, "dispatch.earliest_time",
                                  "searches %g min every %d min" % (window, interval)))
                elif window >= 4 * interval and interval < 1440:
                    out.append(_at("S004", s, "dispatch.earliest_time",
                                  "searches %g min every %d min" % (window, interval)))
        q = s.get("search", "")
        if q and not q.lstrip().startswith("|"):
            if re.search(r"\bindex\s*=\s*\*", q):
                out.append(_at("S006", s, "search"))
            elif not re.search(r"\bindex\s*(=|IN\b)", q, re.I) and "`" not in q and "eventtype" not in q:
                out.append(_at("S005", s, "search"))
    return out


def check_inputs(cf):
    out = []
    for s in cf.stanzas:
        kind = s.name.split("://", 1)[0]
        if kind not in ("monitor", "tcp", "udp", "script", "splunktcp", "http", "batch", "WinEventLog", "journald"):
            continue
        if s.get("disabled", "0").lower() in ("1", "true"):
            continue
        if kind not in ("splunktcp",) and not s.get("index"):
            out.append(_at("I001", s, None))
        if kind in ("monitor", "batch") and not s.get("sourcetype"):
            out.append(_at("I002", s, None))
        if (s.get("crcSalt") or "").upper() == "<SOURCE>":
            out.append(_at("I003", s, "crcSalt"))
    return out


def check_outputs(cf):
    out = []
    for s in cf.stanzas:
        if s.name.startswith("tcpout:") and s.get("useACK", "false").lower() not in ("true", "1"):
            out.append(_at("O001", s, None))
        if s.get("sslVerifyServerCert", "").lower() in ("false", "0"):
            out.append(_at("O002", s, "sslVerifyServerCert"))
    return out


def check_indexes(cf, cluster_bundle):
    out = []
    for s in cf.stanzas:
        if s.name in ("default", "volume") or s.name.startswith("volume:") or s.name.startswith("provider"):
            continue
        if s.get("homePath") is None and s.get("coldPath") is None and s.get("datatype") is None:
            continue
        if not s.get("frozenTimePeriodInSecs"):
            out.append(_at("X001", s, None))
        if cluster_bundle and (s.get("repFactor") or "").lower() != "auto":
            out.append(_at("X002", s, None))
    return out


SECRET_KEYS = re.compile(r"^(password|pass4SymmKey|sslPassword|sslKeysfilePassword|token|api_key|secret|bindDNpassword)$", re.I)


def check_generic(cf):
    out = []
    if cf.layer == "local":
        out.append(_f("A001", cf.path, 1, "-"))
    for d in cf.duplicate_stanzas:
        out.append(_f("A002", cf.path, d.line, d.name))
    for s in cf.stanzas:
        for d in s.duplicates:
            out.append(_f("A003", cf.path, d.line, s.name, d.key))
        for k, v in s.settings.items():
            if SECRET_KEYS.match(k) and v.value and not v.value.startswith("$7$") and not v.value.startswith("$"):
                out.append(_f("A004", cf.path, v.line, s.name, k))
    return out
