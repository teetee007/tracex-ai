# TraceX AI — Problem, Scope and Threat Model

## 1. Problem

After a security incident, the evidence is spread across separate log sources: the
authentication server, the web server and the operating system. Each one shows only a
fragment. An analyst has to line them up by hand, guess which events belong together, and
often overstates what the evidence proves.

**TraceX AI** ingests these logs, normalizes them into one timeline, links related events
across sources, reconstructs a plausible attack sequence, and explains it — while keeping
every conclusion traceable to the original log lines and clearly separating observed facts
from hypotheses.

## 2. Users

- **SOC analyst / incident responder** — needs to know quickly what happened and what to do next.
- **Forensic investigator** — needs every claim backed by a specific log record.

TraceX is a post-incident *analysis* tool. It does not scan, exploit, or block anything.

## 3. Scenario environment (fictional)

A small company runs:

| Component | Log source | File |
|---|---|---|
| Single sign-on server (web portal + SSH logins) | Authentication log | `auth.csv` |
| Customer web portal on host `web-01` | Web access log | `web_access.json` |
| Linux host `web-01` | Process / command log | `system.csv` |

## 4. Assets

| Asset | Why it matters |
|---|---|
| Customer database export (`customers.sql`) | Confidential data; its theft is the worst-case impact |
| User accounts (especially admin-capable ones) | Compromise gives the attacker legitimate-looking access |
| Host `web-01` | Runs the portal and stores backups |
| The logs themselves | Our only evidence; their completeness and integrity limit what we can prove |

## 5. Attacker assumptions

- External attacker with network access to the portal and SSH.
- Goal: obtain customer data.
- Techniques in scope: password guessing, use of valid accounts, remote login (SSH),
  discovery commands, local account creation for persistence, data exfiltration.
- Out of scope: insider threats, kernel-level rootkits, attackers who fully delete or
  forge logs (we can detect *gaps*, not perfect forgeries).

## 6. Evidence assumptions

- Logs are authentic but may be **incomplete** (a source may be missing or cut short).
- Sources use **different timestamp formats**; the system log (syslog style) has **no year**,
  so the year is supplied by the analyst (configured per dataset).
- All times are assumed UTC unless a source states an offset. Clock skew between hosts is possible.
- Identifiers differ per source: the web log has session IDs, the system log does not.
  Some links can only be inferred from user + host + time, and are labelled as inferences.

## 7. Threats to TraceX itself (and our controls)

| Threat | Control |
|---|---|
| **Prompt injection** — a log field contains text like "ignore previous instructions" aimed at the AI | Log text is passed to the LLM as quoted data, never as instructions; AI output is checked so every cited `raw_ref` exists |
| **AI hallucination** — the model invents events or overstates certainty | AI may only cite events from the dataset; uncited claims are marked unsupported; a rule-based explanation is used if the AI is unavailable |
| **Malformed or hostile input files** | Parsers never crash on bad rows: they keep the row and record a `parse_issues` note |
| **Leaking sensitive data** | Synthetic data only; external IPs from RFC 5737 documentation ranges; no API keys in code (environment variables only) |
| **Forcing unrelated events into a story** | Correlation rules require explicit shared identifiers; weak links are labelled as such (tested by TC-05) |

## 8. Scope

**In scope:** CSV and JSON logs from the three sources above; synthetic scenarios TC-01..TC-05;
offline analysis on a single laptop.

**Out of scope:** live log collection, real production logs, automatic blocking or
response actions, Windows event logs, network packet captures.

## 9. Success criteria (measured on Day 5, results reported honestly)

| # | Criterion | Target |
|---|---|---|
| S1 | All three sources load; malformed rows are flagged, not dropped | 100% of rows accounted for |
| S2 | TC-01: share of ground-truth attack events placed in the reconstructed chain (recall) | ≥ 90% |
| S3 | TC-01 / TC-05: benign or unrelated events wrongly placed in the chain | 0 |
| S4 | TC-02: incidents reported on benign-only data | 0 |
| S5 | TC-03: missing system logs reported as an investigation gap | Gap flagged; no unproven impact claimed |
| S6 | Every finding, ATT&CK mapping and AI statement cites ≥ 1 existing `raw_ref` | 100% |
| S7 | Mitigation: generated detection rule fires on TC-01 and not on TC-02 | Before/after evidence recorded |
