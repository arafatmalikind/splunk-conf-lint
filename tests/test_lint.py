import json
import os

import pytest

from conflint import conf, timeutil
from conflint.cli import main, sarif
from conflint.lint import lint

EX = os.path.join(os.path.dirname(__file__), "..", "examples", "apps")
BAD = os.path.join(EX, "TA-plant-historian")
GOOD = os.path.join(EX, "TA-clean-syslog")


def rules_for(findings, stanza=None):
    return {f.rule for f in findings if stanza is None or f.stanza == stanza}


def test_parser_continuation_duplicates_and_layers(tmp_path):
    d = tmp_path / "app" / "local"
    d.mkdir(parents=True)
    p = d / "props.conf"
    p.write_text("# c\n[a]\nX = 1\nY = one \\\ntwo\nX = 2\n[a]\nZ = 3\n")
    cf = conf.parse(str(p), "app/local/props.conf")
    a = cf.get("a")
    assert cf.layer == "local" and a.get("X") == "2" and a.get("Y") == "one \ntwo" and a.get("Z") == "3"
    assert [s.key for s in a.duplicates] == ["X"] and len(cf.duplicate_stanzas) == 1
    assert a.file_of("Z") == "app/local/props.conf"


def test_merge_local_over_default(tmp_path):
    base = tmp_path / "app"
    (base / "default").mkdir(parents=True)
    (base / "local").mkdir()
    (base / "default" / "props.conf").write_text("[s]\nA = 1\nB = 1\n")
    (base / "local" / "props.conf").write_text("[s]\nB = 2\n")
    m = conf.merge([conf.parse(str(base / "local" / "props.conf"), "app/local/props.conf"),
                    conf.parse(str(base / "default" / "props.conf"), "app/default/props.conf")])
    s = m.get("s")
    assert s.get("A") == "1" and s.get("B") == "2" and s.file_of("B") == "app/local/props.conf"


@pytest.mark.parametrize("cron,interval", [
    ("*/15 * * * *", 15), ("7-59/10 * * * *", 10), ("0 6 * * *", 1440), ("0 */4 * * *", 240),
    ("5,35 * * * *", 30), ("0 8-17 * * *", 900), ("* * * * *", 1), ("0 0 * * 1", None),
])
def test_cron_interval(cron, interval):
    assert timeutil.interval_minutes(cron) == interval


@pytest.mark.parametrize("bad", ["*/5 * * *", "61 * * * *", "*/0 * * * *", "a * * * *", "5-1 * * * *"])
def test_cron_errors(bad):
    with pytest.raises(ValueError):
        timeutil.parse_cron(bad)


@pytest.mark.parametrize("t,s", [("-15m", 900), ("-1h@h", 3600), ("-24h", 86400), ("-7d@d", 604800), ("now", 0),
                                 ("@m", 0), ("rt-5m", 300), ("-m", 60), ("garbage", None)])
def test_relative_time(t, s):
    assert timeutil.relative_seconds(t) == s


def test_clean_app_has_no_findings():
    assert lint([GOOD]) == []


def test_bad_app_findings():
    f = lint([BAD])
    assert rules_for(f, "historian:events") >= {"P007", "P008", "P005", "P003", "P001"}
    assert "P004" not in rules_for(f, "historian:events")          # TRUNCATE comes from local/
    assert rules_for(f, "historian:audit") >= {"P006", "P009", "P002", "P004"}
    assert rules_for(f, "historian:json") == {"P010"}
    assert rules_for(f, "route_alarms_to_ot") == {"T003"}
    assert rules_for(f, "mask_password") == {"T002", "T005"}
    assert rules_for(f, "tag_lookup") == {"T004"}
    assert rules_for(f, "Historian - Alarm flood") == {"S003", "S002"}
    assert rules_for(f, "Historian - Daily tag summary") == {"S008", "S005", "S002"}
    assert rules_for(f, "Historian - Everything") == {"S006", "S004", "S002"}
    assert rules_for(f, "Historian - Broken cron") == {"S001"}
    assert rules_for(f, "Historian - Realtime") == {"S007"}
    assert {"A001", "A003", "A004", "I001", "I002", "I003", "O001", "O002", "X001"} <= rules_for(f)
    assert sorted(f, key=lambda x: {"error": 0, "warning": 1, "info": 2}[x.severity]) == f


def test_cluster_bundle_requires_repfactor(tmp_path):
    app = tmp_path / "manager-apps" / "_cluster" / "default"
    app.mkdir(parents=True)
    (app / "indexes.conf").write_text("[ot]\nhomePath = x\ncoldPath = y\nthawedPath = z\nfrozenTimePeriodInSecs = 1\n"
                                      "[ot2]\nhomePath = x\ncoldPath = y\nthawedPath = z\nfrozenTimePeriodInSecs = 1\nrepFactor = auto\n")
    f = lint([str(tmp_path / "manager-apps" / "_cluster")])
    assert [(x.rule, x.stanza) for x in f] == [("X002", "ot")]


def test_encrypted_secret_not_flagged(tmp_path):
    d = tmp_path / "app" / "default"
    d.mkdir(parents=True)
    (d / "app.conf").write_text("[launcher]\nversion = 1\n")
    (d / "outputs.conf").write_text("[tcpout:g]\nuseACK = true\nsslPassword = $7$abcdef==\n")
    assert lint([str(tmp_path / "app")]) == []


def test_pcre_named_groups_and_unsupported_constructs(tmp_path):
    d = tmp_path / "app" / "default"
    d.mkdir(parents=True)
    (d / "app.conf").write_text("[launcher]\nversion = 1\n")
    (d / "props.conf").write_text("[s]\nSHOULD_LINEMERGE = false\nLINE_BREAKER = ([\\r\\n]+)\nTIME_PREFIX = ^\n"
                                  "TIME_FORMAT = %s\nMAX_TIMESTAMP_LOOKAHEAD = 10\nTRUNCATE = 1000\n"
                                  "EXTRACT-a = (?<user>\\w++)\nEXTRACT-b = (?'host'\\S+) in _raw\n")
    assert lint([str(tmp_path / "app")]) == []


@pytest.mark.parametrize("rx", [r"(?<u>\w++)", r"(?>abc)", r"a*+", r"x{2}+", r"foo\Kbar", r"(?|a|b)", r"(*FAIL)"])
def test_pcre_only_syntax_is_skipped(rx):
    from conflint.rules import compile_rx
    assert compile_rx(rx) == (None, None)


def test_real_errors_still_reported():
    from conflint.rules import compile_rx
    assert compile_rx("(abc")[1] and compile_rx(r"a\+")[0] is not None


def test_cli_formats(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    assert main([EX, "-f", "sarif", "-o", str(out)]) == 1
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0" and doc["runs"][0]["results"]
    assert main([GOOD, "--fail-on", "warning"]) == 0
    assert main([BAD, "--min-severity", "error", "--ignore", "P006", "-f", "json", "-o", str(tmp_path / "j")]) == 1
    rows = json.loads((tmp_path / "j").read_text())
    assert rows and all(r["severity"] == "error" and r["rule"] != "P006" for r in rows)
    assert main(["--list-rules"]) == 0
