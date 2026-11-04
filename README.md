# TraceX AI

Evidence-first cyberattack timeline reconstruction. TraceX AI correlates synthetic authentication, web
and system logs, reconstructs a possible attack sequence, and explains how it was detected — while
labelling every link as **observed** (a shared identifier in the logs) or **inferred** (reasoning), and
checking whether the timestamps it relies on can be trusted.

Built for the CS3405 Ethical Hacking and Penetration Testing hackathon by **Tanya Karthikeyan (1RUA24CSE0497)** and **Anjana S (1RUA24CSE0056)**. See [PLAN.md](PLAN.md),
[THREAT_MODEL.md](THREAT_MODEL.md), [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md) and
[docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

The detection engine is **rule-based** (rules R1–R9), so every conclusion can be explained and checked. **AI
(Google Gemini, free tier, or Anthropic Claude) is optional** and used where it helps without deciding anything: mapping the columns of unfamiliar
uploaded logs, and rewriting the cited explanation as a narrative. Both are validated by code before use.

## Setup (Windows)

Requires Python 3.10+. Dependencies (all in `requirements.txt`): pandas, Streamlit, Plotly, NetworkX, PyVis, pytest, and the optional `anthropic` SDK (Gemini needs no package). Nothing else is needed; everything the 3D view needs ships
in the repository, so the app runs offline.

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Run

```bash
python scripts/generate_synthetic_logs.py    # (re)creates data/tc01..tc05 (TC-01 is byte-identical every run)
python -m streamlit run app.py                # opens http://localhost:8501
python -m pytest                              # 137 tests
python scripts/run_evaluation.py              # all scenarios, baseline vs clock-aware -> docs/TEST_RESULTS.md
```

## What it does

| Stage | Module | Notes |
| --- | --- | --- |
| Parse + normalize | `tracex/parsers.py`, `schema.py` | 15-field event schema; every event keeps `raw_ref` (e.g. `auth.csv:17`) |
| Validate | `tracex/validation.py` | Bad timestamps, IPs, duplicates, out-of-order rows; nothing dropped |
| **Clock check** | `tracex/clock.py` | Estimates host clock offsets from login → command ordering; raw times preserved |
| Detect | `tracex/detections.py` | R1–R9, each citing the records that triggered it |
| Correlate + reconstruct | `tracex/correlate.py` | Observed / inferred links; incidents grown from high-severity detections |
| ATT&CK | `tracex/attack.py` | Rule + evidence → technique, `mapped` or `candidate`, with rationale and limitation |
| Explain | `tracex/explain.py` | Typed statements (observed / inferred / uncertainty / next step), citations checked |
| Mitigation | `tracex/mitigation.py` | Account lockout and external-SSH policies replayed over the logs, before / after |
| Evaluate | `tracex/evaluation.py`, `lab.py` | Ground-truth scoring for every scenario, both modes |
| 3D investigation | `tracex/scene.py`, `scene3d.py`, `frontend/scene3d/` | Data contract + offline 3D graph, inspector, timeline replay |
| **Chain of custody** | `tracex/custody.py` | SHA-256 per file + per record, hash-chained; sealed at generation (`custody.json`), verified on every load; pinpoints deleted / modified / inserted records |
| **Exports** | `tracex/exports.py` | Sigma rules (R1 correlation, R3, R8, R9), ATT&CK Navigator layer, STIX 2.1 bundle (deterministic IDs) |
| **Incident report** | `tracex/report.py` | Markdown + self-contained HTML: integrity, timeline with raw_refs, ATT&CK, IOCs, gaps, mitigation, next steps |

`tracex/pipeline.py` runs the whole engine once per dataset and mode; the app caches it, so UI
interactions never rerun the analysis.

## Your own logs (Upload logs mode)

Upload any number of files at once. TraceX checks each one:

| Input | What happens |
| --- | --- |
| Apache / Nginx combined access log | Parsed natively as web events |
| Linux `auth.log` / `secure` | sshd logins (accepted, failed, invalid user) and `sudo` commands |
| CSV / TSV / JSON / JSON Lines from any tool | Columns mapped by name *and* by their values (timestamps, IPs, HTTP status, outcomes); the mapping is shown for review |
| Unusual tables | Optional: *Ask Gemini / Claude to map* — the proposal is re-tested on the values before use |
| PDF, Office files, images, archives, binaries | Rejected: "this is a PDF document, not a log file" |
| Tables of other data (grades, recipes, sales) | Rejected with the missing signals (no timestamp / no user or IP / no action) |
| Prose (notes, essays) | Rejected: "looks like prose, not log records" |

`python scripts/make_samples.py` writes real-format samples (and two non-log files) to `samples/`.

### Turning on the AI assist (optional)

Free option — Google Gemini (key from https://aistudio.google.com/apikey, no card needed):

```bash
$env:GEMINI_API_KEY="AIza..."   # PowerShell; nothing to install
python -m streamlit run app.py
```

Or Anthropic Claude:

```bash
python -m pip install -r requirements.txt   # includes the anthropic SDK
set ANTHROPIC_API_KEY=sk-ant-...            # PowerShell: $env:ANTHROPIC_API_KEY="sk-ant-..."
python -m streamlit run app.py
```

Gemini uses `gemini-flash-latest` (override with `TRACEX_GEMINI_MODEL`); if both keys are set Gemini is used unless `TRACEX_AI_PROVIDER=claude`. Claude uses `claude-opus-5-5` (override with `TRACEX_AI_MODEL`) with structured JSON output and server-side
fallback. Log content is sent to the model as fenced data and never followed as instructions; only column names
and five sample rows are sent for mapping. Never commit a key.

## Pages

| Page | Tabs |
| --- | --- |
| Investigate | Investigation (3D + kill-chain ribbon), Before / after, Explanation (+ AI narrative), Command center (+ blast radius) |
| Evidence | Evidence explorer, Timeline, Detections, ATT&CK (matrix + details), Data quality, Chain of custody |
| Validate | Mitigation, Report & exports, Evaluation |

The header shows the evidence integrity status on every page; a failed check raises a banner. Every feature has a one-line *What this does* description. **Presenter mode** (sidebar) walks through the demo in 7 steps, loading the right dataset and page for each.

## Using the Investigation tab

- **3D graph:** x = time (idle gaps over 150 s compressed), height = log source (web / auth / system),
  depth = actor (IP or user). Drag to rotate, scroll or pinch to zoom, right-drag or Shift-drag to pan.
- **Click** an event to inspect its original record, rule matches, ATT&CK techniques and why it is in the
  incident; **double-click** to fly to it. *Focus* chooses direct links, the connected component,
  precursors or follow-on events; *Isolate* hides everything else.
- **Explode** separates the sources into layers; **2D** flattens the view; **Fit** / **Reset** restore it.
- **Timeline:** Play, step, scrub, change speed, filter by rule or "flagged only". Replay and graph stay in
  sync; a pulse runs along the link to each next step.
- **Clock skew:** corrected events get an amber ring; on the timeline a hollow dot marks the logged time,
  a dashed line leads to the corrected time, and an amber band shows the uncertainty.
- Keyboard: arrows rotate, `+`/`-` zoom, `F` fit, `R` reset, `N`/`P` step, Space play/pause, Esc clear.
- *Send to explorer* opens the selected record in the Evidence explorer tab.
- The sidebar toggle **Clock-aware correlation** switches between the corrected and the original
  (raw-time) behaviour for a live before/after.

The 3D view is a custom perspective renderer on HTML Canvas (no WebGL or Three.js download needed), so it
also works where WebGL is unavailable. The original 2D entity graph remains in the Command center tab.

## Scenarios and measured results

| Scenario | What it tests | Clock-aware result |
| --- | --- | --- |
| TC-01 | Full attack across all three logs | 1 incident, 27/27 events, 0 false positives |
| TC-02 | Benign activity | 0 incidents |
| TC-03 | System log missing | 1 incident (20/20 available events); gaps flagged: missing source, unverified host |
| TC-04 | web-01 clock 5 min behind, web log in IST | 1 incident, 27/27 (baseline: split into 2, 22/27) |
| TC-05 | Look-alike decoys | 1 incident, 27/27, both decoys excluded |

Full table: [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).

## Data and ethics

- All logs are synthetic, generated with a fixed seed; external IPs are from RFC 5737 documentation ranges.
- No real users, credentials or production logs. API keys are read from environment variables only and never stored in the repository.
- Mitigations are simulated over recorded logs; nothing touches a live system.

## Limitations

- Rules and thresholds were written for these scenarios; slow attacks below 5 failures in 10 minutes are
  not detected. Results show the method works on known cases, not real-world accuracy.
- Clock skew is detected only when a host's commands appear before the login that must precede them,
  and needs two independent sessions to apply a correction; a clock running ahead is not detectable this way.
- Host commands are linked to a login by user + host + time (inferred): the system log has no session ID.
- Graph connectivity shows shared evidence, not proven causation.
- AI assist needs a Gemini or Anthropic API key and network access (the free Gemini tier can be briefly overloaded; TraceX retries and falls back to lighter models); without them everything else works offline.
- Real-format support covers Apache/Nginx, Linux auth.log and mappable CSV/JSON; Windows event logs
  (EVTX) and packet captures are not supported.
- A custody manifest proves integrity since sealing, but cannot detect its own replacement; store or sign it separately.
- Sigma field names follow TraceX's synthetic schema and must be mapped to a real SIEM's fields.
- After editing code in `tracex/`, restart the app; cached analysis otherwise stays stale.
