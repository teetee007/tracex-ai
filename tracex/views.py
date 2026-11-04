"""Interactive tabs of the Streamlit app (everything except the command center)."""
import pandas as pd
import streamlit as st

from . import ui, widgets
from .assessment import PHASES
from .attack import TACTIC_ORDER, coverage, map_techniques
from .schema import SOURCES
from .timeline import coverage_figure, per_source_figure, timeline_figure
from .validation import source_coverage

SEVERITY_DOT = {"high": "🔴", "medium": "🟠", "low": "⚪"}


class Context:
    """Everything the tabs need, plus lookups from a raw_ref to its chain position and detections."""

    def __init__(self, events, detections, incidents, issues, info, analysis=None):
        self.events, self.detections, self.incidents, self.issues, self.info = events, detections, incidents, issues, info
        self.analysis = analysis
        self.chain_info = {}
        for inc in incidents:
            for _, r in inc.chain.iterrows():
                self.chain_info[r["raw_ref"]] = {"incident": inc.incident_id, "step": int(r["step"]),
                                                 "linked_by": r["linked_by"], "basis": r["link_basis"]}
        self.rules_by_ref = {}
        for d in detections:
            for ref in d.refs:
                self.rules_by_ref.setdefault(ref, []).append(d)
        self.by_ref = events.set_index("raw_ref", drop=False)

    def record(self, ref):
        """Render the forensic card for one raw_ref."""
        if ref is None or ref not in self.by_ref.index:
            ui.record_card(None, placeholder=True)
            return
        row = self.by_ref.loc[ref]
        if isinstance(row, pd.DataFrame):
            row = row.iloc[0]
        titles = [f"{d.rule} · {d.title}" for d in self.rules_by_ref.get(ref, [])]
        ui.record_card(row, self.chain_info.get(ref), titles)


def timeline(ctx, window_range):
    c1, c2 = st.columns([3, 1])
    with c1:
        sources = st.pills("Sources", SOURCES, selection_mode="multi", default=list(SOURCES), key="tl_sources")
    with c2:
        highlight = st.toggle("Highlight incident", value=True, key="tl_highlight")
    view = ctx.events[ctx.events["source"].isin(sources or [])]
    left, right = st.columns([2.4, 1])
    with left, st.container(border=True):
        ui.panel_title("Unified timeline", "click a dot to inspect · drag the slider to zoom")
        if view["timestamp"].notna().any():
            refs = ctx.chain_info.keys() if highlight else ()
            event = st.plotly_chart(timeline_figure(view, window_range if highlight else None, refs),
                                    on_select="rerun", selection_mode="points", key="tl_chart",
                                    config={"displayModeBar": False, "scrollZoom": True})
            points = event.selection.points if event and event.selection else []
            if points:
                st.session_state["tl_ref"] = points[0]["customdata"][0]
        else:
            st.caption("No timed events for the selected sources.")
        untimed = view["timestamp"].isna().sum()
        if untimed:
            st.caption(f"{untimed} event(s) without a valid timestamp are not plotted; see Data quality.")
    with right:
        ui.panel_title("Selected event")
        ctx.record(st.session_state.get("tl_ref"))


def detections(ctx):
    if not ctx.detections:
        st.success("No suspicious patterns detected.")
        return
    counts = {s: sum(d.severity == s for d in ctx.detections) for s in ("high", "medium", "low")}
    c1, c2 = st.columns([3, 1])
    with c1:
        options = [f"{SEVERITY_DOT[s]} {s} ({n})" for s, n in counts.items() if n]
        chosen = st.pills("Severity", options, selection_mode="multi", default=options, key="det_sev")
        wanted = {o.split()[1] for o in chosen or []}
    with c2:
        only_incident = st.toggle("In an incident only", key="det_inc")

    shown = [d for d in ctx.detections if d.severity in wanted
             and (not only_incident or any(r in ctx.chain_info for r in d.refs))]
    if not shown:
        st.caption("No detections match these filters.")
    cols = st.columns(2)
    for i, d in enumerate(shown):
        rows = ctx.events[ctx.events["raw_ref"].isin(d.refs)].sort_values("timestamp")
        times = rows["timestamp"].dropna()
        span = f"{times.min():%H:%M:%S}–{times.max():%H:%M:%S}" if len(times) > 1 else (
            f"{times.min():%H:%M:%S}" if len(times) else "no time")
        incident = next((ctx.chain_info[r]["incident"] for r in d.refs if r in ctx.chain_info), None)
        with cols[i % 2], st.container(border=True):
            st.markdown(ui.detection_card(d, PHASES.get(d.rule, "Activity"), incident, span), unsafe_allow_html=True)
            with st.expander(f"Evidence · {len(d.refs)} record{'s' if len(d.refs) != 1 else ''}"):
                st.dataframe(rows[["timestamp", "source", "user", "src_ip", "action", "raw_ref"]], hide_index=True,
                             column_config={"timestamp": st.column_config.DatetimeColumn("time", format="HH:mm:ss"),
                                            "action": st.column_config.TextColumn(width="large")})
    unlinked = [d for d in ctx.detections if not any(r in ctx.chain_info for r in d.refs)]
    if unlinked:
        st.caption(f"{len(unlinked)} detection(s) are standalone: no shared session, IP or user/host evidence "
                   "links them to an incident, so they are reported separately.")


def explorer(ctx):
    events = ctx.events
    c1, c2, c3, c4 = st.columns([2.2, 1.6, 1, 1])
    with c1:
        query = st.text_input("Search", placeholder="IP, user, command, path, raw_ref…", key="ex_q")
    with c2:
        sources = st.pills("Sources", SOURCES, selection_mode="multi", default=list(SOURCES), key="ex_sources")
    with c3:
        only_incident = st.toggle("Incident events", key="ex_inc")
    with c4:
        only_flagged = st.toggle("Flagged only", key="ex_flag")

    table = events.sort_values("timestamp", na_position="last").copy()
    table["flag"] = [" ".join(sorted({SEVERITY_DOT[d.severity] + d.rule for d in ctx.rules_by_ref.get(r, [])}))
                     + (" ⚠" if issue else "") for r, issue in zip(table["raw_ref"], table["parse_issues"])]
    table["step"] = [ctx.chain_info[r]["step"] if r in ctx.chain_info else None for r in table["raw_ref"]]
    table = table[table["source"].isin(sources or [])]
    if query:
        haystack = table[["user", "src_ip", "host", "session_id", "action", "details", "raw_ref"]].agg(" ".join, axis=1)
        table = table[haystack.str.contains(query, case=False, regex=False)]
    if only_incident:
        table = table[table["step"].notna()]
    if only_flagged:
        table = table[table["flag"] != ""]

    left, right = st.columns([2.3, 1])
    with left:
        st.caption(f"{len(table)} of {len(events)} events · click a row to inspect it · "
                   "pulsing rings = rule matches (red high, amber medium, grey low)")
        from .evtable import evtable, rows_for
        data_key = f"{st.session_state.get('state_key', '')}|{query}|{','.join(sources or [])}|{only_incident}|{only_flagged}"
        clicked = evtable(rows_for(table, ctx.rules_by_ref, ctx.chain_info), key="ex_evtable", data_key=data_key,
                          selected=st.session_state.get("ex_pick"))
        if clicked and clicked.get("t") != st.session_state.get("ex_click_t"):
            st.session_state["ex_click_t"] = clicked["t"]
            st.session_state["ex_pick"] = clicked["ref"]
    with right:
        ui.panel_title("Evidence record")
        refs = set(table["raw_ref"])
        sent = st.session_state.get("explorer_ref")   # a record sent from the 3D graph's inspector
        pick = st.session_state.get("ex_pick")
        if sent and sent in refs and sent != st.session_state.get("ex_sent_seen"):
            st.session_state["ex_sent_seen"] = sent       # a new hand-off from the graph wins once
            pick = st.session_state["ex_pick"] = sent
            st.caption(f"Showing {sent}, sent from the Investigation graph.")
        if pick not in refs:
            pick = table["raw_ref"].iloc[0] if len(table) else None
        ctx.record(pick)


def data_quality(ctx):
    events, issues = ctx.events, ctx.issues
    flagged = issues["raw_ref"].nunique() if not issues.empty else 0
    clean = 100 * (len(events) - flagged) / len(events) if len(events) else 0
    coverage = source_coverage(events)

    left, right = st.columns([1, 2.4])
    with left, st.container(border=True):
        ui.panel_title("Evidence health")
        widgets.ring_row([(clean, "%", "clean records", "", ui.GREEN if clean >= 95 else ui.ORANGE)])
        ui.facts([("Records", len(events)), ("Flagged", flagged),
                  ("Untimed", int(events["timestamp"].isna().sum())),
                  ("Missing sources", ", ".join(ctx.info.get("missing_sources", [])) or "none")])
    with right, st.container(border=True):
        ui.panel_title("Source coverage", "when each log has records")
        if not coverage.empty:
            st.plotly_chart(coverage_figure(coverage), config={"displayModeBar": False})
        st.dataframe(coverage, hide_index=True, column_config={
            "first": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
            "last": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
            "untimed_records": st.column_config.NumberColumn("untimed")})

    st.markdown("")
    left, right = st.columns([2.3, 1])
    with left, st.container(border=True):
        ui.panel_title("Issues", "records are kept, but evidence from them is weaker · click to inspect")
        if issues.empty:
            st.success("No data-quality issues found.")
            rows = []
        else:
            shown = issues.assign(severity=issues["severity"].map({"error": "⛔ error", "warning": "⚠ warning"}))
            event = st.dataframe(shown, hide_index=True, on_select="rerun", selection_mode="single-row",
                                 key="dq_table", column_config={"message": st.column_config.TextColumn(width="large")})
            rows = event.selection.rows if event and event.selection else []
    with right:
        ui.panel_title("Flagged record")
        pick = rows[0] if rows else (0 if not issues.empty else None)
        ctx.record(None if pick is None else issues.iloc[pick]["raw_ref"])


def evaluation(ctx, result):
    truth = {ref for refs in ctx.info["ground_truth"]["attack_events"].values() for ref in refs}
    found = {ref for inc in ctx.incidents for ref in inc.chain["raw_ref"]}
    tp, fp, fn = len(truth & found), len(found - truth), len(truth - found)
    tn = len(ctx.events) - tp - fp - fn
    recall, precision = result["recall"], result["precision"]

    left, middle, right = st.columns([1.25, 1, 1.4])
    with left, st.container(border=True):
        ui.panel_title("Reconstruction quality", "vs ground_truth.json")
        widgets.ring_row([
            (None if recall is None else recall * 100, "%", "found", "Recall", ui.GREEN),
            (None if precision is None else precision * 100, "%", "real", "Precision", ui.GREEN),
        ])
    with middle, st.container(border=True):
        ui.panel_title("Confusion matrix", f"{len(ctx.events)} events")
        ui.confusion(tp, fp, fn, tn)
    with right, st.container(border=True):
        ui.panel_title("Per source")
        rows = []
        for source, refs in ctx.info["ground_truth"]["attack_events"].items():
            rows += [{"source": source, "kind": "ground truth", "events": len(refs)},
                     {"source": source, "kind": "correctly linked", "events": len(set(refs) & found)}]
        st.plotly_chart(per_source_figure(pd.DataFrame(rows)), config={"displayModeBar": False})

    with st.container(border=True):
        ui.panel_title("Errors")
        st.markdown("**Missed:** " + (", ".join(f"`{r}`" for r in result["missed"]) or "none") + "  \n"
                    "**False positives:** " + (", ".join(f"`{r}`" for r in result["false_positives"]) or "none"))
        st.caption("Measured on one synthetic scenario that we designed. Results on the other test cases "
                   "(benign, incomplete, clock problems, unrelated events) are reported separately.")


def clock_panel(a):
    """What the clock check found, per host, with its evidence."""
    status_kind = {"skew_detected": "medium", "possible_skew": "medium", "consistent": "ok", "insufficient_evidence": "low"}
    with st.container(border=True):
        ui.panel_title("Evidence reliability · clock check",
                       "clock-aware correlation ON" if a.clock_aware else "clock-aware correlation OFF (raw times)")
        if not a.clock:
            st.caption("No host system log in this dataset, so there are no host clocks to check.")
            return
        for f in a.clock:
            st.markdown(f"{ui.pill(f.status.replace('_', ' '), status_kind[f.status])} &nbsp;**{ui.esc(f.host)}** "
                        f"<span style='color:#8a8a8a'>vs the SSO clock</span>", unsafe_allow_html=True)
            st.write(f.explanation)
            if f.anchors:
                st.dataframe(pd.DataFrame([{
                    "user": x.user, "login": x.login_ref, "first command": x.first_ref,
                    "logged gap": f"{x.delta.total_seconds() / 60:+.1f} min",
                    "verdict": "recorded BEFORE its login" if x.violates else "after login (consistent)",
                } for x in f.anchors]), hide_index=True)
            if f.status == "skew_detected" and not a.clock_aware:
                st.caption("Correction NOT applied: switch on clock-aware correlation in the sidebar to use it.")
        st.caption("Method: a host command must follow its user's login. Sessions recorded before their login bound "
                   "how far behind the host clock is. A correction needs at least two independent sessions; "
                   "raw timestamps are never overwritten. A clock running ahead cannot be detected this way.")


def attack(ctx, inc):
    """ATT&CK techniques for the selected incident, each with its rule, evidence and limitation."""
    refs = set(inc.chain["raw_ref"]) if inc is not None else set()
    hits = map_techniques(ctx.events, ctx.detections, refs if inc is not None else None)
    if inc is None:
        st.info("No incident reconstructed. Techniques below come from standalone detections only.")
    if not hits:
        st.success("No ATT&CK technique is supported by the detections in this dataset.")
        return
    expected = (ctx.info.get("ground_truth") or {}).get("expected_techniques")
    if expected is not None and inc is not None:
        cov = coverage(hits, expected)
        st.caption(f"Ground-truth check (synthetic data only): {len(cov['matched'])}/{len(cov['expected'])} expected "
                   f"techniques proposed" + (f"; extra: {', '.join(cov['extra'])}" if cov["extra"] else "")
                   + (f"; missing: {', '.join(cov['missing'])}" if cov["missing"] else "") + ".")
    from .features import attack_matrix_html
    with st.container(border=True):
        html, lit = attack_matrix_html(ctx.events, ctx.detections, refs if inc is not None else None)
        ui.panel_title("ATT&CK matrix", f"{lit} technique(s) supported by evidence · hover a cell")
        st.markdown(html, unsafe_allow_html=True)
    st.markdown("<div class='tx-panel-title'><h4>Technique details</h4><small>rule → evidence → technique</small></div>",
                unsafe_allow_html=True)
    tactics = [t for t in TACTIC_ORDER if any(h.tactic == t for h in hits)]
    cols = st.columns(len(tactics))
    for col, tactic in zip(cols, tactics):
        with col:
            st.markdown(f"<div class='tx-panel-title'><h4 style='white-space:normal;line-height:1.3'>{ui.esc(tactic)}"
                        "</h4></div>", unsafe_allow_html=True)
            for h in (h for h in hits if h.tactic == tactic):
                with st.container(border=True):
                    st.markdown(f"{ui.pill(h.confidence, 'inferred' if h.confidence == 'candidate' else 'observed')} "
                                f"**{ui.esc(h.technique)}**<br>{ui.esc(h.name)}", unsafe_allow_html=True)
                    st.caption(f"Event → {h.rule} → {len(h.refs)} record(s) → {h.technique}")
                    with st.expander("Evidence and rationale"):
                        st.write(h.rationale)
                        st.markdown("**Limitation:** " + h.limitation)
                        more = f"\n… +{len(h.refs) - 12}" if len(h.refs) > 12 else ""
                        st.code("\n".join(h.refs[:12]) + more, language=None)
    st.caption("mapped = the logged behaviour is the technique's defining behaviour. candidate = consistent with the "
               "technique, but other explanations remain. R4 (automated user agent) has no defensible technique and is "
               "left unmapped.")


def mitigation_view(ctx):
    """Before / after replay of each security policy against the recorded logs."""
    from . import mitigation
    results = mitigation.validate(ctx.events, ctx.incidents)
    st.caption("Each policy is replayed against the recorded logs. What it would have rejected is computed from "
               "the events; what that prevents follows the evidence chain (sessions and recorded links).")
    cols = st.columns(len(results))
    for col, r in zip(cols, results):
        with col, st.container(border=True):
            ui.panel_title(r.name, "simulated policy")
            st.write(r.description)
            if r.chain_before:
                ok = not r.data_loss_before
                st.markdown(f"{ui.pill('validated' if ok else 'partial', 'ok' if ok else 'medium')} "
                            f"&nbsp;{ui.esc(r.verdict)}", unsafe_allow_html=True)
                widgets.ring_row([
                    (100 * r.chain_after / r.chain_before, "%", f"{r.chain_after} of {r.chain_before} steps remain", "attack chain after",
                     ui.GREEN if ok else ui.ORANGE),
                ])
            else:
                st.markdown(ui.pill(r.verdict, "low"), unsafe_allow_html=True)
            ui.facts([
                ("Logins rejected", ", ".join(r.blocked) or "none"),
                ("Steps prevented", len(r.prevented)),
                ("Legit logins hit", ", ".join(r.legit_blocked) or "none (0)"),
                ("Lockouts", "; ".join(f"{u} at {s:%H:%M:%S} (trigger {ref})" for u, s, _, ref in r.lockouts) or "none"),
            ])
            st.caption("Limitation: " + r.limitation)
    st.caption("Legit logins hit = rejected logins that are not part of any reconstructed incident. Run TC-02 "
               "(benign) to see each policy's false-positive cost on normal activity.")


KIND_STYLE = {"observed": ("observed", "OBSERVED"), "inferred": ("inferred", "INFERRED"),
              "uncertainty": ("medium", "UNCERTAIN"), "next_step": ("low", "NEXT STEP")}


def explanation(ctx):
    """Deterministic, typed, cited incident explanation."""
    from .explain import check, explain
    a, info = ctx.analysis, ctx.info
    statements = explain(a, info)
    problems = check(statements, a.view, a.incidents[0] if a.incidents else None)
    st.caption("Generated by rules from the evidence: no AI involved. OBSERVED = read from log records; "
               "INFERRED = depends on an inferred link; UNCERTAIN = a gap or clock problem; NEXT STEP = what to check. "
               "Every citation is verified against the dataset.")
    if problems:
        st.error("Citation check failed: " + "; ".join(problems))
    else:
        st.markdown(ui.pill(f"citation check passed · {sum(len(s.refs) for s in statements)} references", "ok"),
                    unsafe_allow_html=True)
    for title, kinds in [("What happened", ("observed", "inferred")), ("What limits these conclusions", ("uncertainty",)),
                         ("What to do next", ("next_step",))]:
        group = [s for s in statements if s.kind in kinds]
        if not group:
            continue
        with st.container(border=True):
            ui.panel_title(title)
            for s in group:
                cls, label = KIND_STYLE[s.kind]
                cites = (" &nbsp;<span style='color:#8a8a8a;font-family:monospace;font-size:.72rem'>"
                         + ui.esc(", ".join(s.refs[:4]) + (f" +{len(s.refs) - 4}" if len(s.refs) > 4 else "")) + "</span>"
                         if s.refs else "")
                st.markdown(f"{ui.pill(label, cls)} &nbsp;{ui.esc(s.text)}{cites}", unsafe_allow_html=True)
    ai_narrative(statements)


def ai_narrative(statements):
    """Optional: an AI model rewrites the findings as prose; every paragraph is checked against them."""
    from . import ai
    ok, msg = ai.status()
    who = ai.name()
    key = f"narrative|{st.session_state.get('state_key', '')}"
    with st.container(border=True):
        ui.panel_title("AI narrative", f"optional · {who} · citation-checked")
        st.caption(f"{who} turns the findings above into readable paragraphs for a report. It receives only those "
                   "findings, may cite only their evidence, and every paragraph is checked before it is shown. "
                   "Detection and correlation never depend on it.")
        if not ok:
            st.caption(msg)
            return
        if st.button(f"Write narrative with {who}", key="ai-narrate"):
            try:
                with st.spinner(f"{who} is writing…"):
                    st.session_state[key] = ai.verify_narrative(ai.narrate(statements), statements)
            except ai.AIError as e:
                st.error(str(e))
        for p in st.session_state.get(key, []):
            badge = ui.pill("verified", "ok") if p["supported"] else ui.pill("not verified", "high")
            kind = ui.pill(p["kind"].replace("_", " "), "inferred" if p["kind"] == "hypothesis" else "neutral")
            st.markdown(f"{badge} {kind} &nbsp;{ui.esc(p['text'])} <span style='color:#8a8a8a;font-family:monospace;"
                        f"font-size:.72rem'>{ui.esc(', '.join(p['refs'][:5]))}</span>", unsafe_allow_html=True)
            for problem in p["problems"]:
                st.caption("⚠ " + problem)


def lab_view(df):
    """All scenarios, both modes: the measured before / after."""
    from .timeline import lab_figure
    with st.container(border=True):
        ui.panel_title("Evaluation lab · all scenarios", "baseline = raw timestamps · clock-aware = with skew correction")
        st.plotly_chart(lab_figure(df), config={"displayModeBar": False})
        show = df[["scenario", "mode", "incidents", "expected incidents", "fragmentation", "linked", "attack events",
                   "missed", "false positives", "recall", "precision", "techniques", "gaps found"]]
        st.dataframe(show, hide_index=True, column_config={
            "recall": st.column_config.NumberColumn(format="percent"),
            "precision": st.column_config.NumberColumn(format="percent")})
        st.caption("Measured by `scripts/run_evaluation.py` against each scenario's ground truth (also written to "
                   "docs/TEST_RESULTS.md). TC-02 has no attack events, so recall and precision do not apply; its "
                   "pass condition is zero incidents.")


def custody_view(files, manifest, result):
    """Integrity of the evidence: per-file hashes, record-level verification, and a safe tamper demo."""
    import json
    from . import custody
    status = result["status"]
    kind = {"verified": "ok", "tampered": "high", "unsealed": "medium"}[status]
    with st.container(border=True):
        ui.panel_title("Chain of custody", "SHA-256 per file and per record, hash-chained")
        msg = {"verified": f"All files match the manifest sealed at {result['sealed_at']}.",
               "tampered": "The evidence no longer matches its sealed manifest. Treat every conclusion as unreliable.",
               "unsealed": "No custody manifest: integrity cannot be confirmed. Download one below to seal this evidence now."}
        st.markdown(f"{ui.pill(status, kind)} &nbsp;{ui.esc(msg[status])}", unsafe_allow_html=True)
        if result["files"]:
            st.dataframe(pd.DataFrame([{"file": f["file"], "status": f["status"], "sha256": f.get("sha256", ""),
                                        "detail": f["detail"]} for f in result["files"]]), hide_index=True,
                         column_config={"detail": st.column_config.TextColumn(width="large")})
        if manifest is None and files:
            fresh = {"manifest_version": 1, "algorithm": "SHA-256",
                     "files": [custody.describe(n, b) for n, b in files.items()]}
            st.download_button("Download a custody manifest for these files", json.dumps(fresh, indent=1),
                               "custody.json", "application/json")
        st.caption("A manifest proves the logs are unchanged since it was sealed. It cannot detect its own replacement, "
                   "so in practice it is stored or signed separately from the evidence.")

    if manifest is None or not files:
        return
    with st.container(border=True):
        ui.panel_title("Tamper simulation", "in memory only · files on disk are never changed")
        c1, c2, c3, c4 = st.columns([1.3, 1.2, 1, 1])
        name = c1.selectbox("Log file", sorted(files), key="tamper_file")
        recs = custody.records(name, files[name])
        action = c2.selectbox("Change", ["delete a record", "modify a record", "insert a fake record"], key="tamper_action")
        idx = int(c3.number_input("Record #", 1, len(recs), min(18, len(recs)), key="tamper_idx",
                                  help="Position in the file (1 = first record after any header)"))
        c4.write("")
        if c4.button("Tamper and re-verify", type="primary"):
            data = files[name]
            if name.endswith(".csv"):
                lines = data.splitlines(keepends=True)        # lines[0] is the header, lines[idx] = record idx
                if action.startswith("delete"):
                    del lines[idx]
                elif action.startswith("modify"):
                    lines[idx] = lines[idx].replace(b"1", b"7", 1) if b"1" in lines[idx] else lines[idx] + b"x"
                else:
                    lines.insert(idx, lines[idx])
                tampered = b"".join(lines)
            else:
                items = json.loads(data)
                if action.startswith("delete"):
                    del items[idx - 1]
                elif action.startswith("modify"):
                    items[idx - 1]["bytes"] = 1
                else:
                    items.insert(idx - 1, dict(items[idx - 1], path="/admin/backdoor"))
                tampered = json.dumps(items, indent=1).encode()
            r = custody.verify({**files, name: tampered}, manifest)
            st.session_state["tamper_result"] = r
            hit = next(f for f in r["files"] if f["file"] == name)
            st.markdown(f"{ui.pill(r['status'], 'high' if r['status'] == 'tampered' else 'ok')} &nbsp;"
                        f"**{ui.esc(name)}**: {ui.esc(hit['detail'])}", unsafe_allow_html=True)
            for ch in hit["changes"]:
                st.write(f"- **{ch['op']}** — sealed record(s): {', '.join(ch['sealed_records']) or '—'}; "
                         f"current record(s): {', '.join(ch['current_records']) or '—'}")

    from .viz3d import custody_helix
    simulated = st.session_state.get("tamper_result")
    with st.container(border=True):
        ui.panel_title("Hash chain (3D)", "simulated tampering shown" if simulated else "as verified now")
        fig = custody_helix(manifest, simulated or result)
        if fig is not None:
            st.plotly_chart(fig, config={"displaylogo": False})
        st.caption("Each helix is one log file; each point is one record's SHA-256, chained to the previous one in "
                   "sealed order. Green = matches its seal. Red = modified, red X = deleted, red diamond = inserted. "
                   "Drag to rotate, scroll to zoom, hover a record for its hash.")
        if simulated and st.button("Clear simulation"):
            st.session_state.pop("tamper_result", None)
            st.rerun()


def exports_view(ctx, scenario, custody_result):
    """Incident report and machine-readable exports."""
    import io
    import zipfile
    from . import exports, report
    a = ctx.analysis
    inc = a.incidents[0] if a.incidents else None
    doc = report.build(a, ctx.info, scenario, custody_result)
    md, html = report.to_markdown(doc), report.to_html(doc)
    base = f"tracex_{scenario}_{inc.incident_id if inc else 'no-incident'}"

    c1, c2 = st.columns(2)
    with c1, st.container(border=True):
        ui.panel_title("Incident report", "for the case file / your submission")
        st.write("Integrity status, typed summary, full evidence timeline with raw_refs, ATT&CK, indicators, gaps, "
                 "mitigation replay, next steps and limitations.")
        b1, b2 = st.columns(2)
        b1.download_button("Report (HTML)", html, f"{base}_report.html", "text/html", width="stretch")
        b2.download_button("Report (Markdown)", md, f"{base}_report.md", "text/markdown", width="stretch")
        st.caption("Open the HTML in a browser and print to PDF for a paper copy.")
    rules = exports.sigma_rules()
    bundle = exports.to_json(exports.stix_bundle(a.view, a.detections, inc, scenario))
    with c2, st.container(border=True):
        ui.panel_title("Detection & intelligence exports", "for SIEM / CTI tooling")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, t in rules.items():
                z.writestr(n, t)
        layer = exports.to_json(exports.navigator_layer(a.view, a.detections, inc, scenario))
        b1, b2, b3 = st.columns(3)
        b1.download_button(f"Sigma rules ({len(rules)})", buf.getvalue(), "tracex_sigma_rules.zip", "application/zip",
                           width="stretch")
        b2.download_button("ATT&CK Navigator", layer, f"{base}_attack_layer.json", "application/json", width="stretch")
        b3.download_button("STIX 2.1 bundle", bundle, f"{base}_stix.json", "application/json", width="stretch",
                           disabled=inc is None)
        st.caption("Sigma: convert with sigma-cli for Splunk / Elastic (field names follow TraceX's schema). "
                   "Navigator: open in MITRE ATT&CK Navigator → Open Existing Layer. STIX: import into a TIP such as OpenCTI.")

    with st.expander("Preview: report"):
        st.markdown(md)
    with st.expander("Preview: Sigma rules"):
        for n, t in rules.items():
            st.caption(n)
            st.code(t, language="yaml")
    with st.expander("Preview: STIX bundle"):
        st.code(bundle, language="json")
