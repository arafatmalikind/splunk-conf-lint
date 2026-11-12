# splunk-conf-lint

34 findings: 8 errors, 16 warnings, 10 info.

| Severity | Rule | File | Line | Stanza | Message |
|---|---|---|---|---|---|
| error | P007 | TA-plant-historian/default/props.conf | 3 | `historian:events` | LINE_BREAKER needs a capturing group; its text is discarded between events |
| error | P008 | TA-plant-historian/default/props.conf | 5 | `historian:events` | references a transforms.conf stanza that does not exist: REPORT-fields -> historian_tagname |
| error | P006 | TA-plant-historian/default/props.conf | 10 | `historian:audit` | regular expression does not compile: EXTRACT-action: missing ), unterminated subpattern at position 7 |
| error | S001 | TA-plant-historian/default/savedsearches.conf | 22 | `Historian - Broken cron` | cron_schedule does not parse: '*/5 * * *': cron needs 5 fields, got 4 |
| error | T003 | TA-plant-historian/default/transforms.conf | 7 | `route_alarms_to_ot` | routes to an index without FORMAT |
| error | T002 | TA-plant-historian/default/transforms.conf | 11 | `mask_password` | FORMAT refers to a capture group the REGEX does not have: uses $3, REGEX has 2 group(s) |
| error | T004 | TA-plant-historian/default/transforms.conf | 15 | `tag_lookup` | lookup file is missing from the app's lookups folder: historian_tags.csv |
| error | A004 | TA-plant-historian/local/passwords.conf | 2 | `credential::historian_api:` | cleartext secret in configuration: password |
| warning | I002 | TA-plant-historian/default/inputs.conf | 1 | `monitor:///var/log/historian/audit.log` | monitor input has no sourcetype; Splunk will guess one |
| warning | I001 | TA-plant-historian/default/inputs.conf | 5 | `tcp://5514` | input has no index; data goes to the default index |
| warning | O002 | TA-plant-historian/default/outputs.conf | 3 | `tcpout:ot_indexers` | TLS certificate verification is disabled |
| warning | P001 | TA-plant-historian/default/props.conf | 1 | `historian:events` | line breaking is implicit: set LINE_BREAKER and SHOULD_LINEMERGE = false |
| warning | P005 | TA-plant-historian/default/props.conf | 4 | `historian:events` | SHOULD_LINEMERGE = true together with LINE_BREAKER: line merging is slow and rarely needed |
| warning | P001 | TA-plant-historian/default/props.conf | 8 | `historian:audit` | line breaking is implicit: set LINE_BREAKER and SHOULD_LINEMERGE = false |
| warning | P002 | TA-plant-historian/default/props.conf | 8 | `historian:audit` | timestamp extraction is implicit: set TIME_PREFIX and TIME_FORMAT |
| warning | P009 | TA-plant-historian/default/props.conf | 9 | `historian:audit` | EXTRACT regex has no named capture group, so it extracts nothing: EXTRACT-user |
| warning | P010 | TA-plant-historian/default/props.conf | 13 | `historian:json` | INDEXED_EXTRACTIONS = json with search-time KV_MODE: fields are extracted twice |
| warning | S003 | TA-plant-historian/default/savedsearches.conf | 4 | `Historian - Alarm flood` | time range is shorter than the schedule interval: events between runs are never searched: searches 5 min every 15 min |
| warning | S008 | TA-plant-historian/default/savedsearches.conf | 9 | `Historian - Daily tag summary` | scheduled search has no dispatch.earliest_time, so it searches all time |
| warning | S005 | TA-plant-historian/default/savedsearches.conf | 12 | `Historian - Daily tag summary` | scheduled search does not name an index |
| warning | S006 | TA-plant-historian/default/savedsearches.conf | 18 | `Historian - Everything` | searches index=* |
| warning | S007 | TA-plant-historian/default/savedsearches.conf | 28 | `Historian - Realtime` | scheduled search uses a real-time time range: rt-1m |
| warning | A001 | TA-plant-historian/local | 1 | `-` | local/ folder in an app package; Splunkbase and deployers expect settings in default/ |
| warning | A003 | TA-plant-historian/local/props.conf | 2 | `historian:events` | setting appears more than once in a stanza; the last one wins: TRUNCATE |
| info | X001 | TA-plant-historian/default/indexes.conf | 1 | `ot` | no frozenTimePeriodInSecs; the default keeps data for about six years |
| info | I003 | TA-plant-historian/default/inputs.conf | 3 | `monitor:///var/log/historian/audit.log` | crcSalt = <SOURCE> re-indexes files when they are renamed or rotated |
| info | O001 | TA-plant-historian/default/outputs.conf | 1 | `tcpout:ot_indexers` | output group without useACK = true; data in flight can be lost on restart |
| info | P003 | TA-plant-historian/default/props.conf | 2 | `historian:events` | TIME_FORMAT without MAX_TIMESTAMP_LOOKAHEAD |
| info | P004 | TA-plant-historian/default/props.conf | 8 | `historian:audit` | no TRUNCATE: events are cut at the default 10000 bytes |
| info | S002 | TA-plant-historian/default/savedsearches.conf | 3 | `Historian - Alarm flood` | runs at minute 0; many searches start together at the top of the hour: */15 * * * * |
| info | S002 | TA-plant-historian/default/savedsearches.conf | 11 | `Historian - Daily tag summary` | runs at minute 0; many searches start together at the top of the hour: 0 6 * * * |
| info | S002 | TA-plant-historian/default/savedsearches.conf | 16 | `Historian - Everything` | runs at minute 0; many searches start together at the top of the hour: */5 * * * * |
| info | S004 | TA-plant-historian/default/savedsearches.conf | 17 | `Historian - Everything` | time range is much longer than the schedule interval: the same events are searched repeatedly: searches 1440 min every 5 min |
| info | T005 | TA-plant-historian/default/transforms.conf | 9 | `mask_password` | transform is not referenced by any props.conf stanza in this app |
