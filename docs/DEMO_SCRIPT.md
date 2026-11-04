# TraceX AI — 2-minute demo script

Before the slot: run `python -m streamlit run app.py`, open http://localhost:8501, collapse the sidebar,
start on **TC-02**, Investigation tab. Keep the sidebar one click away for switching datasets.

| Time | Do | Say |
| --- | --- | --- |
| 0:00 | TC-02 open, Investigation tab | "Our problem: evidence of an attack is split across auth, web and system logs that use different formats and clocks. TraceX reconstructs the attack — and tells you how far to trust it. First, a normal day: 81 events, two noisy detections, **zero incidents**. Activity alone doesn't become an attack." |
| 0:15 | Switch to **TC-01**; press ▶ Play | "Now a real intrusion. The replay walks the reconstructed chain: 14 password guesses, the successful login, an automated tool exporting the customer table, then SSH into the server." |
| 0:35 | Click the SSH login node | "Every event shows *why* it's here. This login is linked by a shared IP — **observed**. These dashed links to the server commands are **inferred**: the system log has no session ID, so we say so instead of pretending." |
| 0:50 | Open **Explanation** tab | "The explanation is generated from rules, not an LLM, and every sentence cites the log line it rests on — the citation check passes." |
| 1:00 | Switch to **TC-05** (Investigation) | "Decoys in the same minutes — a neighbouring IP guessing 'admin', a travelling employee — stay **outside** the chain. Shared evidence, not time proximity." |
| 1:10 | Switch to **TC-04**; point at the amber badge and the timeline | "Here web-01's clock runs 5 minutes behind. Its commands appear *before* the login that must precede them. TraceX detects that from two independent sessions, bounds the offset at 4.2–9 minutes, and corrects by the minimum — keeping the raw times." |
| 1:30 | Sidebar: toggle **Clock-aware correlation** off, then on | "Without it: two incidents and 5 missed events, 81% recall. With it: one incident, 27 of 27. Measured, not claimed — the Evaluation tab has every scenario." |
| 1:40 | **Evidence → Chain of custody**, press *Tamper and re-verify* | "Forensics starts with trusted evidence. Every log line is hashed and chained when collected. Delete one line in memory — TraceX names exactly which record vanished." |
| 1:50 | **Mitigation** tab | "And the fix, validated: replaying an account-lockout policy over these logs stops the chain at the compromised login, before any data access, with zero legitimate users locked out." |
| 2:05 | **Report & exports** (point only) | "And it plugs into real tooling: an incident report, Sigma rules for a SIEM, an ATT&CK Navigator layer and a STIX bundle. Questions?" |

## Likely questions — short answers

- **Is it AI / machine learning?** The detection and correlation are rule-based on purpose, so every result is explainable. AI is only planned for wording the explanation, and it would be checked against the same citations.
- **Why trust 100%?** It's 100% on scenarios we designed; that shows the method works on known cases. The honest result is TC-04's baseline failure and how we fixed it — plus the limitations listed in the report.
- **What if both clocks are wrong?** We use the SSO server as the reference. If the host clock runs *ahead*, our method can't detect it, and we say that.
- **Why not just widen the time window?** That would also pull unrelated events in. We only shift a host's times when two independent sessions prove its clock is behind, and every adjusted link is marked.
