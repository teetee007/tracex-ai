# TraceX AI — Project Plan

Course: Ethical Hacking and Penetration Testing (CS3405) hackathon · 23–29 Oct 2026 · 3 h/day (21 h)
Demo: 7-minute slot (1 min problem, **3 min live demo**, 2 min tests + mitigation, 1 min questions).

## The one rule

**Every conclusion links back to evidence.** Each event carries a `raw_ref` (e.g. `auth.csv:17`)
pointing at the original log line, and every finding, graph edge, ATT&CK mapping and AI sentence
must cite the `raw_ref`s it relies on. Anything not directly observed is labelled a *hypothesis*.

## Schedule

| Day | Date | Work | Done when |
|---|---|---|---|
| 1 | 23 Oct | Threat model, scope, success criteria · data schema · synthetic logs · parsers | App loads 3 sources into one table ✅ |
| 2 | 24 Oct | Normalization checks, data validation, chronological timeline, file upload | Unified timeline with source filter; bad rows flagged |
| 3 | 25 Oct | Correlation rules, suspicious-pattern detection, attack-sequence reconstruction | Attack chain with evidence refs (protect this day) |
| 4 | 26 Oct | Attack graph, MITRE ATT&CK mapping, AI explanation + rule-based fallback | Clickable graph; mappings with evidence |
| 5 | 27 Oct | Run TC-01..TC-05, record expected vs actual · gaps, impact, severity | Test results table in `docs/TEST_RESULTS.md` |
| 6 | 28 Oct | **Mitigation:** generate a detection rule, retest before/after · report draft · README | Before/after evidence; report draft |
| 7 | 29 Oct | Bug fixes, 4 slides, finish report, rehearse 7-minute demo, backup deploy | Demo-ready |

If a day slips: simplify the AI layer and styling first. Never cut correlation, evidence links or tests.

## Feature scope (trimmed from the original 20)

Core: log upload (CSV/JSON, 3 sources) · normalization · validation · unified timeline ·
cross-source correlation · suspicious-sequence detection · attack reconstruction ·
attack graph · ATT&CK mapping with evidence · evidence viewer · AI explanation with
fact vs. hypothesis · one **Findings** panel (gaps + impact + severity + next steps) ·
detection-rule mitigation with retest · Markdown report export · test suite.

Cut: investigation comparison (#19).

## Rubric mapping (30 marks)

| Criterion | Marks | Where we earn it |
|---|---|---|
| Problem, scope, threat model | 5 | `THREAT_MODEL.md` |
| Prototype functionality | 8 | Days 1–4 engine + app |
| Testing methodology | 5 | TC-01..05, `ground_truth.json`, expected vs actual |
| Security value + validated mitigation | 5 | Day 6 detection rule, before/after retest |
| Innovation + appropriate AI use | 3 | Evidence-restricted AI, fallback, AI answers checked against cited refs |
| Demo, report, understanding | 3 | Report (10–15 pp), 4 slides, rehearsal |
| Ethics | 1 | Synthetic data only, RFC 5737 IPs, no real credentials |

## Test cases

| ID | Scenario | Expected |
|---|---|---|
| TC-01 | Password guessing → success → admin export → SSH → discovery, persistence, exfil | Chain reconstructed with linked evidence |
| TC-02 | Benign activity only | No attack invented |
| TC-03 | Suspicious login, system logs missing | Gap flagged, impact not asserted |
| TC-04 | Mixed / conflicting timestamps | Valid ones normalized, conflicts flagged |
| TC-05 | Unrelated events with similar IPs or times | Not forced into the chain |

Report real measurements only. `data/<scenario>/ground_truth.json` lists which events
are truly part of the attack, so recall / false positives can be computed honestly.

## Progress log

- **Day 1 (23 Oct):** project structure, threat model, event schema, TC-01 dataset
  (generator + ground truth), parsers for all 3 sources, minimal Streamlit viewer, tests.
- **Day 2 (started early, 23 Oct):** validation (parse errors, bad IPs, duplicates, out-of-order
  clocks), source coverage, Plotly timeline, log upload (CSV / JSON / JSON Lines), app tabs
  (Timeline · Events · Data quality · Evidence viewer).
- **Day 3 (done early, 23 Oct):** 9 detection rules (`tracex/detections.py`, R1–R9), cross-source
  links labelled observed / inferred (`tracex/correlate.py`), incident reconstruction from
  high-severity detections, evaluation against ground truth (`tracex/evaluation.py`),
  Investigation + Evaluation tabs. TC-01: 27/27 attack events linked, 0 false positives,
  scanner decoy kept out. 18 tests pass.
- **Next — Day 4:** attack graph (NetworkX + PyVis), MITRE ATT&CK mapping per event with evidence,
  AI explanation (evidence-restricted, rule-based fallback).
