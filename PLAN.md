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
- **UI redesign (23 Oct):** dark SOC "command center": KPI strip, threat-score gauge with point
  breakdown, entity attack graph (labelled edges with chain steps, dashed = inferred, offline
  vis-network), attack-progression stepper, activity chart, incident facts. 24 tests pass.
- **Interactive tabs (23 Oct):** click-to-inspect timeline with incident halos and zoom slider;
  detection cards with severity filters and evidence; Evidence explorer (search, filters,
  forensic record card showing chain step, link reason, detections, original fields); data-quality
  health ring, coverage chart, clickable issues; evaluation rings, confusion matrix, per-source bars.
  25 tests pass.
- **Professional theme (23 Oct):** monochrome HUD (thin frames, corner brackets, monospaced
  numbers, grid background, status footer). Colour carries meaning only: white/grey neutral,
  green normal, orange warning/medium, red critical/attacker.
- **Live visuals (23 Oct):** threat score and quality/evaluation rings animate (ease-in-out count-up,
  moving arc head, ticks light up) whenever they scroll into view or their tab opens; KPIs count up;
  progression steps slide in; attack graph has "Replay attack" (edges revealed in chain order with a
  step caption and progress bar), auto-played the first time it is on screen. 26 tests pass.
- **Master build (27 Oct):** TC-02..TC-05 generated (TC-01 byte-identical). Clock-skew investigation
  (`tracex/clock.py`): TC-04 recall 81% -> 100%, 2 incidents -> 1, no change to other scenarios.
  ATT&CK mapping with evidence (8/8 expected techniques), typed and citation-checked explanation with
  gap detection, lockout / external-SSH mitigation replay (0 legitimate logins blocked), evaluation lab +
  docs/TEST_RESULTS.md, offline 3D investigation graph with inspector and synchronized replay. 76 tests.
- **Forensic credibility pack + 3 pages (27 Oct):** Investigate / Evidence / Validate pages; chain of custody
  (sealed SHA-256 manifests, record-level tamper detection, in-app tamper simulation); Sigma, ATT&CK
  Navigator and STIX 2.1 exports; incident report (Markdown + HTML). 99 tests.
- **Remaining for 29 Oct:** report (10-15 pp), 4 slides, rehearse docs/DEMO_SCRIPT.md. Optional: LLM narrative.
- **Was next — Day 4 (remaining):** MITRE ATT&CK mapping per event with evidence; AI explanation
  (evidence-restricted, rule-based fallback, fact vs hypothesis).
