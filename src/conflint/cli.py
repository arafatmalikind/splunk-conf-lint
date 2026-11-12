import argparse
import json
import sys
from collections import Counter

from . import __version__, rules
from .lint import lint


def sarif(findings):
    level = {"error": "error", "warning": "warning", "info": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "splunk-conf-lint", "version": __version__,
                                "rules": [{"id": k, "shortDescription": {"text": v[1]},
                                           "defaultConfiguration": {"level": level[v[0]]}} for k, v in sorted(rules.RULES.items())]}},
            "results": [{"ruleId": f.rule, "level": level[f.severity],
                         "message": {"text": "[%s] %s" % (f.stanza, f.message)},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                             "region": {"startLine": max(f.line, 1)}}}]} for f in findings],
        }],
    }


def md(findings):
    c = Counter(f.severity for f in findings)
    out = ["# splunk-conf-lint", "", "%d findings: %d errors, %d warnings, %d info." % (
        len(findings), c["error"], c["warning"], c["info"]), "",
        "| Severity | Rule | File | Line | Stanza | Message |", "|---|---|---|---|---|---|"]
    for f in findings:
        out.append("| %s | %s | %s | %s | `%s` | %s |" % (f.severity, f.rule, f.file, f.line or "", f.stanza,
                                                          f.message.replace("|", "\\|")))
    return "\n".join(out) + "\n"


def text(findings):
    return "".join("%s:%d: %s %s [%s] %s\n" % (f.file, f.line, f.severity, f.rule, f.stanza, f.message) for f in findings)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="splunk-conf-lint", description="Lint Splunk app .conf files.")
    ap.add_argument("paths", nargs="*", help="app folders, or folders containing apps")
    ap.add_argument("-f", "--format", choices=["text", "md", "json", "sarif"], default="text")
    ap.add_argument("-o", "--output")
    ap.add_argument("--ignore", action="append", default=[], help="rule id to skip (repeatable)")
    ap.add_argument("--min-severity", choices=["error", "warning", "info"], default="info")
    ap.add_argument("--fail-on", choices=["error", "warning", "never"], default="error")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    if args.list_rules:
        for k, (sev, msg) in sorted(rules.RULES.items()):
            print("%s  %-7s  %s" % (k, sev, msg))
        return 0
    if not args.paths:
        ap.error("give at least one app folder")
    try:
        found = lint(args.paths, args.ignore)
    except (OSError, ValueError) as e:
        print("splunk-conf-lint: %s" % e, file=sys.stderr)
        return 2
    found = [f for f in found if rules.SEVERITY[f.severity] <= rules.SEVERITY[args.min_severity]]
    if args.format == "md":
        body = md(found)
    elif args.format == "json":
        body = json.dumps([f.row() for f in found], indent=2) + "\n"
    elif args.format == "sarif":
        body = json.dumps(sarif(found), indent=2) + "\n"
    else:
        body = text(found)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
    else:
        sys.stdout.write(body)
    if args.fail_on != "never" and any(rules.SEVERITY[f.severity] <= rules.SEVERITY[args.fail_on] for f in found):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
