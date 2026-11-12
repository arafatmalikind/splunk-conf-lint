# splunk-conf-lint

A linter for Splunk app configuration that catches the problems that cost you at 2 a.m.: events merged or split wrongly, timestamps guessed, a `REPORT-` that points at a transform nobody defined, an alert that searches 5 minutes of data every 15 minutes, an index in a cluster bundle that is not replicated.

Splunk AppInspect checks whether an app is safe and packaged correctly for Splunkbase. This tool checks whether the configuration **does what you meant**: data onboarding quality, references between files, and scheduler hygiene. Use both.

```
$ splunk-conf-lint examples/apps
TA-plant-historian/default/props.conf:3: error P007 [historian:events] LINE_BREAKER needs a capturing group; its text is discarded between events
TA-plant-historian/default/props.conf:5: error P008 [historian:events] references a transforms.conf stanza that does not exist: REPORT-fields -> historian_tagname
TA-plant-historian/default/transforms.conf:11: error T002 [mask_password] FORMAT refers to a capture group the REGEX does not have: uses $3, REGEX has 2 group(s)
TA-plant-historian/default/savedsearches.conf:4: warning S003 [Historian - Alarm flood] time range is shorter than the schedule interval: events between runs are never searched: searches 5 min every 15 min
TA-plant-historian/local/passwords.conf:2: error A004 [credential::historian_api:] cleartext secret in configuration: password
...
```

The example folder holds a deliberately broken add-on and a clean one. The clean one produces no findings. Full report: [docs/sample-report.md](docs/sample-report.md).

## What it understands

- `default/` and `local/` are merged the way Splunk merges them before checks run, so a `TRUNCATE` in `local/props.conf` counts for the stanza in `default/`. Findings point at the file and line that actually holds the setting.
- Line continuations with a trailing backslash, comments, repeated stanzas and repeated keys.
- Regexes are compiled after translating PCRE named groups (`(?<name>...)`, `(?'name'...)`) to Python syntax. PCRE-only constructs Python lacks, such as possessive quantifiers, are skipped rather than reported as errors.
- Cron schedules are expanded (`*/15`, `7-59/10`, `0 8-17 * * *`, lists, ranges) and compared with `dispatch.earliest_time` and `dispatch.latest_time`, including snap-to (`-10m@m`).

## Rules

```
splunk-conf-lint --list-rules
```

| Rule | Severity | Checks |
|---|---|---|
| **props.conf** | | |
| P001 | warning | sourcetype without explicit `LINE_BREAKER` and `SHOULD_LINEMERGE = false` |
| P002 | warning | sourcetype without `TIME_PREFIX`, `TIME_FORMAT` or `DATETIME_CONFIG` |
| P003 | info | `TIME_FORMAT` without `MAX_TIMESTAMP_LOOKAHEAD` |
| P004 | info | no `TRUNCATE` |
| P005 | warning | `SHOULD_LINEMERGE = true` together with `LINE_BREAKER` |
| P006 | error | regex in `LINE_BREAKER`, `TIME_PREFIX` or `EXTRACT-` does not compile |
| P007 | error | `LINE_BREAKER` without a capturing group |
| P008 | error | `REPORT-`, `TRANSFORMS-` or `LOOKUP-` references a missing transforms stanza |
| P009 | warning | `EXTRACT-` regex without a named group |
| P010 | warning | `INDEXED_EXTRACTIONS = json` while search-time `KV_MODE` still extracts |
| **transforms.conf** | | |
| T001 | error | `REGEX` does not compile |
| T002 | error | `FORMAT` uses `$N` beyond the number of groups |
| T003 | error | `DEST_KEY = _MetaData:Index` without `FORMAT` |
| T004 | error | lookup `filename` missing from the app's `lookups/` |
| T005 | info | transform not referenced from props.conf |
| **savedsearches.conf** (scheduled, enabled) | | |
| S001 | error | `cron_schedule` does not parse |
| S002 | info | runs at minute 0 with no `schedule_window` or `allow_skew` |
| S003 | warning | time range shorter than the interval: coverage gaps |
| S004 | info | time range four or more times the interval: repeated work |
| S005 | warning | no index in the search |
| S006 | warning | `index=*` |
| S007 | warning | real-time time range on a scheduled search |
| S008 | warning | no `dispatch.earliest_time`, so it searches all time |
| **inputs, outputs, indexes** | | |
| I001 / I002 / I003 | warning / warning / info | input without `index`, monitor without `sourcetype`, `crcSalt = <SOURCE>` |
| O001 / O002 | info / warning | output group without `useACK`, `sslVerifyServerCert = false` |
| X001 | info | index without `frozenTimePeriodInSecs` |
| X002 | error | index in `manager-apps/` or `master-apps/` without `repFactor = auto` |
| **app** | | |
| A001 | warning | `local/` in an app package |
| A002 / A003 | warning | stanza or setting repeated within a file |
| A004 | error | cleartext `password`, `pass4SymmKey`, `sslPassword`, `token` and similar (values encrypted by Splunk, `$7$...`, are fine) |
| A005 | warning | no `default/app.conf` |

## Usage

```
splunk-conf-lint APP_DIR                      # one app
splunk-conf-lint $SPLUNK_HOME/etc/apps        # every app in a folder
splunk-conf-lint APP_DIR -f md -o report.md   # markdown
splunk-conf-lint APP_DIR -f sarif -o lint.sarif
splunk-conf-lint APP_DIR --ignore P004 --ignore S002 --fail-on warning
```

Exit code 1 when a finding at or above `--fail-on` (default `error`) is present, 2 on usage errors.

### In CI, with GitHub code scanning

```yaml
- run: pip install git+https://github.com/arafatmalikind/splunk-conf-lint
- run: splunk-conf-lint apps/ -f sarif -o lint.sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: lint.sarif
```

Findings then show up as annotations on the pull request, on the exact line.

### Before a deployer or cluster manager push

Run it on `$SPLUNK_HOME/etc/shcluster/apps` or `$SPLUNK_HOME/etc/manager-apps` before `apply shcluster-bundle` or `apply cluster-bundle`. X002 alone has saved many people from an index that exists on only one peer.

## Limits

- It reads configuration, not data. It cannot tell you that `TIME_FORMAT` does not match your events; for that, test with `| makeresults` or the Add Data preview.
- Python's regex engine is close to PCRE but not identical. Constructs it cannot represent are skipped silently.
- It does not resolve settings across apps (global precedence). Lint each app, then review cross-app precedence with `splunk btool <conf> list --debug`.

## Development

```
pip install -e .[test]
pytest
```

No third-party runtime dependencies. The example apps are fictional.

## License

MIT. See [LICENSE](LICENSE).
