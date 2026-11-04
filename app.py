"""TraceX AI — Streamlit interface.  Run:  python -m streamlit run app.py"""
import os
from datetime import date
from pathlib import Path

import streamlit as st

from tracex import custody, features, graph, scene, ui, views
from tracex.assessment import progression, threat_score
from tracex.evaluation import evaluate
from tracex.parsers import load_dataset
from tracex.pipeline import analyse
from tracex.scene3d import scene3d
from tracex.schema import SOURCES
from tracex.timeline import activity_figure
from tracex.upload_view import run_uploads
from tracex.viz3d import activity_terrain

DATA_DIR = Path(__file__).parent / "data"

st.set_page_config(page_title="TraceX AI", page_icon="🔎", layout="wide", initial_sidebar_state="collapsed")
ui.inject_css()


@st.cache_data(show_spinner="Running all scenarios…")
def cached_lab():
    from tracex import lab
    return lab.run(DATA_DIR)


@st.cache_data(show_spinner="Reconstructing…")
def cached_analysis(folder, clock_aware):
    """Parsing + the whole engine, cached per dataset and mode: UI interactions never rerun it."""
    events, info = load_dataset(folder)
    return analyse(events, clock_aware), info


# ---------- Presenter mode: a scripted walk through the demo ----------
STEPS = features.PRESENTER_STEPS


def _go(step):
    """Button callback (runs before widgets are drawn, so it may set their values)."""
    s = STEPS[step]
    st.session_state.update({"presenter_step": step, "mode": "Bundled dataset", "dataset": s["dataset"],
                             "clock_aware": s["clock"], "presenter_goto": s["page"]})


# ---------- Choose the evidence ----------
st.sidebar.markdown("### Evidence")
mode = st.sidebar.radio("Logs", ["Bundled dataset", "Upload logs"], label_visibility="collapsed", key="mode")
clock_aware = st.sidebar.toggle(
    "Clock-aware correlation", value=True, key="clock_aware",
    help="Estimate host clock offsets from login/command ordering and correlate on corrected times. "
         "Switch off to see the original raw-time behaviour.")

if mode == "Bundled dataset":
    scenarios = sorted(p.name for p in DATA_DIR.iterdir() if p.is_dir()) if DATA_DIR.exists() else []
    if not scenarios:
        st.error("No datasets found. Run `python scripts/generate_synthetic_logs.py` first.")
        st.stop()
    scenario = st.sidebar.selectbox("Dataset", scenarios, key="dataset")
    a, info = cached_analysis(str(DATA_DIR / scenario), clock_aware)
    a_base, a_aware = (cached_analysis(str(DATA_DIR / scenario), m)[0] for m in (False, True))
    # Integrity is re-checked on every run (not cached), so a changed file is caught immediately.
    evidence_files = custody.read_files(DATA_DIR / scenario)
    manifest = custody.load_manifest(DATA_DIR / scenario)
else:
    scenario = "uploaded"
    year = st.sidebar.number_input("Year for syslog timestamps (logs without a year)", 2000, 2100, date.today().year)
    uploaded, info, evidence_files = run_uploads(year)
    manifest = None
    a = analyse(uploaded, clock_aware)
    a_base, a_aware = (a, analyse(uploaded, True)) if not clock_aware else (analyse(uploaded, False), a)

st.sidebar.divider()
presenter = st.sidebar.toggle("Presenter mode", key="presenter",
                              help="A step-by-step script for the live demo: each step loads the right dataset and page.")
st.sidebar.caption("All analysis runs locally. Conclusions cite the original log line (`raw_ref`).")

# ---------- Analyse ----------
events, issues, detections, incidents = a.view, a.issues, a.detections, a.incidents
score, band, breakdown = threat_score(detections)

# A different dataset or mode must not inherit selections made in the previous one.
state_key = f"{scenario}|{clock_aware}"
if st.session_state.get("state_key") != state_key:
    for k in ("explorer_ref", "tl_ref", "ex_pick", "ex_sent_seen", "tamper_result"):
        st.session_state.pop(k, None)
    st.session_state["state_key"] = state_key

timed = events["timestamp"].dropna()
present = [s for s in SOURCES if s in set(events["source"])]
window = f"{timed.min():%H:%M}–{timed.max():%H:%M} UTC" if not timed.empty else "—"
custody_result = custody.verify(evidence_files, manifest)
ui.header([("Dataset", scenario), ("Sources", f"{len(present)}/{len(SOURCES)}"),
           ("Window", window), ("Events", len(events)),
           ("Integrity", {"verified": "verified ✓", "tampered": "TAMPERED", "unsealed": "unsealed"}[custody_result["status"]])])

if presenter:
    step = st.session_state.get("presenter_step", 0)
    s = STEPS[step]
    ui.presenter_banner(step + 1, len(STEPS), s["title"], s["say"], f"{s['page'].title()} → {s['tab']}")
    b1, b2, b3, _ = st.columns([1, 1, 1, 5])
    b1.button("◀ Back", disabled=step == 0, on_click=_go, args=(max(0, step - 1),), width="stretch")
    b2.button("Next ▶" if step < len(STEPS) - 1 else "Restart", type="primary", on_click=_go,
              args=((step + 1) % len(STEPS),), width="stretch")
    b3.button("Load this step", on_click=_go, args=(step,), width="stretch",
              help="Load the dataset and page for this step")

if custody_result["status"] == "tampered":
    st.error("Evidence integrity check FAILED: the logs differ from their sealed custody manifest. "
             "See Evidence → Chain of custody.")
if info["missing_sources"]:
    st.warning(f"Missing log sources: {', '.join(info['missing_sources'])}. "
               "Conclusions involving them cannot be verified.")

inc = None
if incidents:
    if len(incidents) > 1:
        chosen = st.selectbox("Incident", [f"{i.incident_id} · {i.title}" for i in incidents])
        inc = incidents[[f"{i.incident_id} · {i.title}" for i in incidents].index(chosen)]
    else:
        inc = incidents[0]
window_range = (inc.entities["start"], inc.entities["end"]) if inc else None

high = sum(d.severity == "high" for d in detections)
ui.kpis([
    ("Events ingested", len(events), f"{len(present)} log sources", ui.WHITE),
    ("Incidents", len(incidents), "reconstructed from evidence", ui.RED if incidents else ui.GREEN),
    ("Linked evidence", len(inc.chain) if inc else 0, "events in the attack chain", ui.ORANGE),
    ("High-severity detections", high, f"{len(detections)} detections in total", ui.RED if high else ui.GREEN),
    ("External IPs", len(inc.entities["external_ips"]) if inc else 0, "involved in the incident", ui.RED if inc and inc.entities["external_ips"] else ui.WHITE),
    ("Data-quality issues", len(issues), "records flagged, none dropped", ui.ORANGE if len(issues) else ui.GREEN),
])

ctx = views.Context(events, detections, incidents, issues, info, analysis=a)


# ---------- Page 1 · Investigate: what happened? ----------
def page_investigate():
    t_inv, t_ba, t_exp, t_cc = st.tabs(["Investigation", "Before / after", "Explanation", "Command center"])
    with t_inv:
        ui.about("Rebuilds the incident in 3D from the real log records: time runs left to right, each log source is a "
                 "layer, each actor has its own depth. Press ▶ Play to replay the attack step by step while the "
                 "kill-chain ribbon lights up each ATT&CK stage; click any event to see its original record and why it "
                 "belongs to the incident.")
        data = scene.build(a, scenario, inc)
        picked = scene3d(data, key=f"scene3d-{state_key}")
        if picked and picked.get("data_id") == data["data_id"] and picked["ref"] != st.session_state.get("explorer_ref"):
            st.session_state["explorer_ref"] = picked["ref"]
            st.switch_page(PAGES["evidence"])
        views.clock_panel(a)
    with t_ba:
        ui.about("Runs the same evidence twice, with raw timestamps and with clock-aware correlation, and draws both "
                 "side by side. When a host clock is wrong, raw times split the attack and drop events; the corrected "
                 "view shows what the clock check recovers. Numbers are measured, not claimed.")
        before_after_view()
    with t_exp:
        ui.about("Explains the incident in sentences, each labelled observed, inferred, uncertain or next step and "
                 "citing the exact log lines it rests on. A checker verifies every citation; an AI model (Gemini or Claude) can optionally "
                 "rewrite it as a narrative, which is checked the same way.")
        views.explanation(ctx)
    with t_cc:
        command_center()


def before_after_view():
    fig, rows = features.before_after(a_base, a_aware, info.get("ground_truth"))
    if fig is None:
        st.success("No incident in either mode: there is nothing to compare for this dataset.")
        return
    skewed = [f for f in a_aware.clock if f.status in ("skew_detected", "possible_skew")]
    c = st.columns(len(rows))
    for col, r in zip(c, rows):
        with col, st.container(border=True):
            ui.panel_title(r["mode"])
            vals = [("Incidents", r["incidents"])]
            if r["recall"] is not None:
                vals += [("Attack events linked", f"{r['linked']} ({r['recall']:.0%})"), ("Missed", r["missed"])]
            ui.facts(vals)
    with st.container(border=True):
        ui.panel_title("Same evidence, two clocks", "each dot = one attack-related record · ✕ = not linked to any incident")
        st.plotly_chart(fig, config={"displayModeBar": False})
        if skewed:
            st.caption(skewed[0].explanation)
        else:
            st.caption("No clock problem was detected in this dataset, so both views are the same. "
                       "Load tc04_clock_skew to see the difference.")


def command_center():
    main, side = st.columns([2.35, 1.2])
    with main, st.container(border=True):
        if inc:
            ui.panel_title(f"Attack graph · {inc.incident_id}", "drag nodes · hover an edge for evidence")
            ui.about("A 2D entity view: who (IPs, accounts) did what to which system, each edge labelled with the "
                     "chain steps that prove it. ▶ Replay attack rebuilds it in time order.")
            nodes, edges = graph.build(inc, detections)
            st.iframe(graph.render_html(nodes, edges, height=600), height=610)
            ui.graph_legend()
        else:
            ui.panel_title("Attack graph")
            st.success("No incident reconstructed: no high-severity pattern links these events together.")
    with side:
        with st.container(border=True):
            ui.panel_title("Threat score", "rule-based")
            ui.about("Adds fixed points per distinct rule that fired (20 high, 8 medium, 2 low), capped at 100.")
            ui.threat_card(score, band, breakdown)
        with st.container(border=True):
            steps = progression(inc) if inc else []
            ui.panel_title("Attack progression", f"{len(steps)} stages")
            ui.about("Each detection placed on the attack lifecycle in time order, with its chain steps.")
            if steps:
                ui.progression(steps)
            else:
                st.caption("Nothing to show.")
    if inc:
        with st.container(border=True):
            ui.panel_title("Blast radius", "what the attacker reached")
            ui.about("Follows the incident from the attacker's address to the accounts it used, the systems it reached "
                     "and the impact: data accessed, data sent out, persistence. Every box comes from cited events.")
            br = features.blast_radius(inc, events)
            st.markdown(features.blast_radius_svg(br), unsafe_allow_html=True)
            if br["impact"]:
                st.caption("Evidence: " + " · ".join(f"{w} — {ref}" for w, _, ref, _ in br["impact"]))
    bottom_left, bottom_right = st.columns([2.35, 1.2])
    with bottom_left, st.container(border=True):
        ui.panel_title("Activity terrain (3D)", "events per 15 min × log source · incident window in red")
        ui.about("A 3D bar chart of how busy each log source was over time; the attack window is red. Drag to rotate.")
        terrain = activity_terrain(events, window_range)
        if terrain is not None:
            st.plotly_chart(terrain, config={"displaylogo": False})
        with st.expander("2D view"):
            st.plotly_chart(activity_figure(events, window_range), config={"displayModeBar": False})
    with bottom_right, st.container(border=True):
        ui.panel_title("Incident facts", "observed in the logs")
        if inc:
            ent = inc.entities
            minutes = (ent["end"] - ent["start"]).total_seconds() / 60
            at_risk = inc.chain[inc.chain["detections"].str.contains("R6|R9")]["action"].tolist()
            ui.facts([
                ("Incident", f"{inc.incident_id} · {inc.severity.upper()}"),
                ("Attacker IP", ", ".join(ent["external_ips"]) or "—"),
                ("Account used", ", ".join(ent["users"]) or "—"),
                ("Hosts touched", ", ".join(ent["hosts"]) or "—"),
                ("Sessions", ", ".join(ent["sessions"]) or "—"),
                ("Window", f"{ent['start']:%H:%M:%S} → {ent['end']:%H:%M:%S} UTC ({minutes:.0f} min)"),
                ("Data at risk", " | ".join(at_risk) or "none observed"),
            ])
        else:
            st.caption("No incident.")
    if inc:
        with st.expander(f"Evidence chain — {len(inc.chain)} steps, each linked to its original log record"):
            st.dataframe(
                inc.chain[["step", "timestamp", "source", "user", "src_ip", "host", "action",
                           "detections", "link_basis", "linked_by", "raw_ref"]],
                hide_index=True)
            st.caption("**observed** = linked by an identifier written in both logs (session ID, IP address). "
                       "**inferred** = linked by reasoning (same user on the same host soon after a login); "
                       "treat as a hypothesis until confirmed.")


# ---------- Page 2 · Evidence: how do we know? ----------
def page_evidence():
    t_exp, t_tl, t_det, t_att, t_dq, t_cus = st.tabs(
        ["Evidence explorer", "Timeline", "Detections", "ATT&CK", "Data quality", "Chain of custody"])
    with t_exp:
        ui.about("Every normalized event with search and filters. Pulsing rings mark rule matches (red high, amber "
                 "medium, grey low); click a row to open the original log record, its chain step and its detections.")
        views.explorer(ctx)
    with t_tl:
        ui.about("All sources on one time axis. Ringed dots belong to the incident; click a dot to inspect it.")
        views.timeline(ctx, window_range)
    with t_det:
        ui.about("The nine detection rules (R1–R9) that fired, each with what triggered it and the exact records as "
                 "evidence. Detections not linked to the incident are shown as standalone.")
        views.detections(ctx)
    with t_att:
        ui.about("Maps rule matches to MITRE ATT&CK techniques. Lit cells are supported by evidence (red = mapped, amber "
                 "= candidate); grey cells are techniques TraceX can recognise but did not see. Hover a cell for its "
                 "evidence.")
        views.attack(ctx, inc)
    with t_dq:
        ui.about("Checks the evidence itself: unreadable timestamps, bad IPs, duplicates, out-of-order rows and clock "
                 "skew. Problem records are kept and flagged, never silently dropped.")
        views.data_quality(ctx)
    with t_cus:
        ui.about("Proves the logs were not altered: every file and every record is SHA-256 hashed and chained when "
                 "sealed, then re-verified on every load. The simulator shows how a deleted or edited line is caught.")
        views.custody_view(evidence_files, manifest, custody_result)


# ---------- Page 3 · Validate: does the fix work, and how good is the tool? ----------
def page_validate():
    names = ["Mitigation", "Report & exports"] + (["Evaluation"] if info.get("ground_truth") else [])
    tabs = st.tabs(names)
    with tabs[0]:
        ui.about("Replays security policies (account lockout, blocking external SSH) against the recorded logs and "
                 "shows which attack steps could not have happened, and whether any legitimate user would be hit.")
        views.mitigation_view(ctx)
    with tabs[1]:
        ui.about("Downloads an incident report (HTML / Markdown) and machine-readable exports for real security "
                 "tools: Sigma rules for a SIEM, an ATT&CK Navigator layer and a STIX 2.1 threat-intel bundle.")
        views.exports_view(ctx, scenario, custody_result)
    if len(tabs) > 2:
        with tabs[2]:
            ui.about("Scores TraceX against each scenario's ground truth in both modes: precision, recall, missed events, "
                     "false positives and incident fragmentation. All numbers are measured.")
            views.lab_view(cached_lab())
            st.markdown("")
            ui.panel_title(f"This dataset · {scenario}", "clock-aware" if clock_aware else "baseline")
            views.evaluation(ctx, evaluate(incidents, info["ground_truth"]))


START = os.environ.get("TRACEX_START_PAGE", "investigate")   # lets tests open each page directly
PAGES = {
    "investigate": st.Page(page_investigate, title="Investigate", icon=":material/radar:", url_path="investigate",
                           default=START == "investigate"),
    "evidence": st.Page(page_evidence, title="Evidence", icon=":material/fingerprint:", url_path="evidence",
                        default=START == "evidence"),
    "validate": st.Page(page_validate, title="Validate", icon=":material/verified_user:", url_path="validate",
                        default=START == "validate"),
}
nav = st.navigation(list(PAGES.values()), position="top")
goto = st.session_state.pop("presenter_goto", None)
if goto and PAGES[goto] is not nav:
    st.switch_page(PAGES[goto])
nav.run()

ui.footer([
    ("TraceX // evidence engine", ""),
    (f"{len(events)} events · {len(present)} sources", "ok"),
    (f"{len(detections)} detections · {high} high", "bad" if high else "ok"),
    (f"{len(incidents)} incident{'s' if len(incidents) != 1 else ''}", "bad" if incidents else "ok"),
    ("synthetic data only" if mode == "Bundled dataset" else "uploaded data · stays on this machine", "ok"),
    ("every conclusion cites a raw_ref", ""),
])
