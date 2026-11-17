---
name: detection-engineering
description: How the detection_engineer builds a detection - from the observed behavior, data confirmed first, Sigma with full metadata converted per SIEM, back-tested both ways, tuned with the narrowest exclusion, delivered with a triage note - and how to tune a noisy rule. Always on for detection_engineer.
expert: detection_engineer
source: Mordecai built-in
---

# Build a detection

## 1. What to detect
- Start from the behavior seen in this case: the technique (ATT&CK id) and the procedure (the exact command line,
  parent process, registry key, service path, network pattern). Read the case findings and the queries that found it.
- Aim at what the adversary cannot cheaply change: the parent -> child relationship, the command-line structure, the
  registry location, the protocol behavior. Not the tool's file name, which can be renamed.
- `memory_search` for existing rules, field names and known false positives.

## 2. Confirm the data
- The data source exists for the target SIEM and the fields are populated: `field_values`, `list_data_streams` /
  `list_indices`, `data_inventory` / `field_summary` (Splunk).
- Note the logging the rule needs (Sysmon event types, 4688 with command line, PowerShell 4104) and whether it is on.
  A rule on a field that is never populated never fires.

## 3. Write it in Sigma
- Fields: title, id (a new UUID), status experimental, description (what it detects and why it matters), references
  (the case finding ids), author, date, tags (attack.<tactic>, attack.tXXXX), logsource, detection, falsepositives,
  level.
- Logic: the narrowest condition that still catches the variants: case-insensitive contains, startswith or endswith
  on the parts the adversary cannot easily change; combine the image with the command line or the parent.
- `local_sigma_check`, then `local_sigma_convert` for each deployed SIEM (splunk; esql, eql or lucene for Elastic
  and Security Onion).
- Network behavior: a Suricata rule or a Zeek-based query. Files: YARA, tested with `local_yara_scan` on the sample.

## 4. Back-test both ways
- Elastic and Security Onion: `sigma_backtest` (security_onion__ or elastic__) takes the Sigma YAML itself, converts
  it with the pipelines you name and returns total hits, hits per day, the top hosts / users / processes / parents
  and samples. Pick the pipeline for the data: `ecs_windows` for Elastic Agent / Winlogbeat Windows events,
  `ecs_zeek_beats` for Zeek; none when the rule already uses ECS field names (process.executable, event.type).
  Point `index` at the stream that holds the data (`list_data_streams`). Splunk: the converted SPL with
  `splunk__search`.
- **Catches it:** run it over the window of the real activity (`start` / `end`). It must hit. If it does not, fix
  the rule before anything else.
- **Noise:** run it over a normal window (`days`, 30 by default, at most 90). Report the hit count, the average a day
  and what the hits were (the top values it returns).
- **No hits at all is not "quiet" until proven:** check the fields in the returned query exist in that stream
  (`field_values`); a wrong pipeline gives field names the data does not have. Prove the rule can match with a
  known-good window or a positive control.
- Tune with the narrowest exclusion: a specific parent and path, a specific service account on a specific host.
  Never a broad one an adversary could hide in: a whole directory, a process name alone, a whole subnet. Re-run both
  tests after each change.
- No historical true positive: mark the rule untested, and say how to test it (the emulation plan step or Atomic Red Team
  test for that technique, by reference).

## 5. Deliver each rule
- `case_save_artifact`, one rule per file: sigma_<name>.yml and the native queries (spl_<name>.spl,
  esql_<name>.esql, eql_<name>.eql, lucene_<name>.txt), suricata_<name>.rules, yara_<name>.yar.
- A triage note in the report: what the analyst checks first when it fires, and the benign cause to rule out.
- A `query` memory for each validated native query.

# Coverage: what the rules cover against what was seen
- `security_onion__detection_coverage`: enabled rules per ATT&CK technique (Sigma tags, Suricata metadata, YARA
  meta), and how many enabled rules carry no ATT&CK id (coverage a layer cannot show).
- `security_onion__alert_techniques` (default the last 30 days): the techniques alerts actually pointed at.
- `attack_coverage_layer` with both (pass their `techniques` objects as coverage and observed; include_case adds
  this case's findings). Red = seen with no enabled rule: those gaps are the first detections to write. Report the
  layer path, the gap list and the rule counts; enabled is not the same as firing, so back-test before claiming
  coverage of a technique.

# Tune a noisy rule
1. Show the noise: counts by host, user, process, parent and command line over the window.
2. Find what the benign hits share that the attack would not.
3. Propose the narrowest exclusion; show the before and after counts, and that known true positives still hit.
4. Say what the exclusion could hide, so the analyst decides with the risk in view.
