"""Walk one or more Splunk apps and run the rules."""

import os

from . import conf, rules


def find_apps(path):
    """An app is a folder with default/ or local/. A folder of apps is also accepted."""
    if any(os.path.isdir(os.path.join(path, d)) for d in ("default", "local")):
        return [path]
    out = []
    for name in sorted(os.listdir(path)):
        p = os.path.join(path, name)
        if os.path.isdir(p) and any(os.path.isdir(os.path.join(p, d)) for d in ("default", "local")):
            out.append(p)
    return out


def lint_app(app, base=None):
    base = base or os.path.dirname(os.path.abspath(app))
    rel = lambda p: os.path.relpath(p, base).replace(os.sep, "/")
    files = []
    for layer in ("default", "local"):
        d = os.path.join(app, layer)
        if os.path.isdir(d):
            for name in sorted(os.listdir(d)):
                if name.endswith(".conf"):
                    files.append(conf.parse(os.path.join(d, name), rel(os.path.join(d, name))))
    by = {}
    for cf in files:
        by.setdefault(cf.name, []).append(cf)
    merged = {name: conf.merge(cfs) for name, cfs in by.items()}
    transforms = {s.name for s in merged["transforms"].stanzas} if "transforms" in merged else set()
    referenced = set()
    if "props" in merged:
        for s in merged["props"].stanzas:
            for setting in list(s.prefixed("REPORT-").values()) + list(s.prefixed("TRANSFORMS-").values()):
                referenced.update(x.strip() for x in setting.value.split(","))
            for setting in s.prefixed("LOOKUP-").values():
                referenced.update(setting.value.split()[:1])
    lookups = os.path.join(app, "lookups")
    cluster_bundle = any(p in os.path.abspath(app).replace(os.sep, "/").split("/") for p in ("manager-apps", "master-apps"))
    out = []
    if not os.path.exists(os.path.join(app, "default", "app.conf")) and not cluster_bundle:
        out.append(rules._f("A005", rel(app), 0, "-"))
    local_reported = False
    for cf in files:
        for f in rules.check_generic(cf):
            if f.rule == "A001":
                if local_reported:
                    continue
                f.file = rel(os.path.join(app, "local"))
                local_reported = True
            out.append(f)
    for name, cf in merged.items():
        if name == "props":
            out += rules.check_props(cf, transforms)
        elif name == "transforms":
            out += rules.check_transforms(cf, referenced, lookups)
        elif name == "savedsearches":
            out += rules.check_savedsearches(cf)
        elif name == "inputs":
            out += rules.check_inputs(cf)
        elif name == "outputs":
            out += rules.check_outputs(cf)
        elif name == "indexes":
            out += rules.check_indexes(cf, cluster_bundle)
    return out


def lint(paths, ignore=()):
    out = []
    for p in paths:
        apps = find_apps(p)
        if not apps:
            raise ValueError("%s: no Splunk app found (expected default/ or local/)" % p)
        for app in apps:
            out += lint_app(app)
    out = [f for f in out if f.rule not in set(ignore)]
    out.sort(key=lambda f: (rules.SEVERITY[f.severity], f.file, f.line, f.rule))
    return out
