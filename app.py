"""TraceX AI — Streamlit interface.  Run:  streamlit run app.py"""
from datetime import date
from pathlib import Path

import pandas as pd
import streamlit as st

from tracex.correlate import reconstruct
from tracex.detections import run_all
from tracex.evaluation import evaluate
from tracex.parsers import SOURCE_FILES, combine, load_dataset, parse_source
from tracex.schema import SOURCES
from tracex.timeline import timeline_figure
from tracex.validation import source_coverage, validate

DATA_DIR = Path(__file__).parent / "data"

st.set_page_config(page_title="TraceX AI", page_icon="🔎", layout="wide")
st.title("🔎 TraceX AI")
st.caption("Evidence-first cross-source log investigation · synthetic data only")


@st.cache_data
def cached_load(folder):
    return load_dataset(folder)


# ---------- Choose the evidence ----------
mode = st.sidebar.radio("Logs", ["Bundled dataset", "Upload logs"])

if mode == "Bundled dataset":
    scenarios = sorted(p.name for p in DATA_DIR.iterdir() if p.is_dir()) if DATA_DIR.exists() else []
    if not scenarios:
        st.error("No datasets found. Run `python scripts/generate_synthetic_logs.py` first.")
        st.stop()
    scenario = st.sidebar.selectbox("Dataset", scenarios)
    events, info = cached_load(str(DATA_DIR / scenario))
else:
    st.sidebar.caption("Upload any of the three sources. Use synthetic or redacted logs only.")
    uploads = {
        "auth": st.sidebar.file_uploader("Authentication log (CSV)", type="csv"),
        "web": st.sidebar.file_uploader("Web access log (JSON / JSON Lines)", type=["json", "jsonl"]),
        "system": st.sidebar.file_uploader("System log (CSV)", type="csv"),
    }
    year = st.sidebar.number_input("Year for syslog timestamps", 2000, 2100, date.today().year)
    frames, info = [], {"name": "Uploaded logs", "missing_sources": []}
    for source, file in uploads.items():
        if file is None:
            info["missing_sources"].append(source)
            continue
        try:
            frames.append(parse_source(source, file, file.name, year=year))
        except Exception as exc:  # a broken file must not take the app down
            st.sidebar.error(f"Could not read {file.name}: {exc}")
            info["missing_sources"].append(source)
    if not frames:
        st.info("Upload at least one log file in the sidebar, or switch to the bundled dataset. "
                f"Expected formats match `data/tc01_attack/` ({', '.join(SOURCE_FILES.values())}).")
        st.stop()
    events = combine(frames)

issues = validate(events)
detections = run_all(events)
incidents = reconstruct(events, detections)
SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}

# ---------- Overview ----------
st.subheader(info.get("name", "Dataset"))
if info.get("description"):
    st.write(info["description"])
if info["missing_sources"]:
    st.warning(f"Missing log sources: {', '.join(info['missing_sources'])}. "
               "Conclusions involving them cannot be verified.")

counts = events["source"].value_counts()
c = st.columns(5)
c[0].metric("Events", len(events))
c[1].metric("Auth", int(counts.get("auth", 0)))
c[2].metric("Web", int(counts.get("web", 0)))
c[3].metric("System", int(counts.get("system", 0)))
c[4].metric("Data-quality issues", len(issues))

selected = st.multiselect("Sources", SOURCES, default=[s for s in SOURCES if s in counts])
view = events[events["source"].isin(selected)].sort_values("timestamp", na_position="last")

tab_names = ["Investigation", "Timeline", "Events", "Data quality", "Evidence viewer"]
if info.get("ground_truth"):
    tab_names.append("Evaluation")
tabs = dict(zip(tab_names, st.tabs(tab_names)))
tab_timeline, tab_events, tab_quality, tab_evidence = (
    tabs["Timeline"], tabs["Events"], tabs["Data quality"], tabs["Evidence viewer"])

with tabs["Investigation"]:
    if not incidents:
        st.success("No incident reconstructed: no high-severity pattern was found in these logs.")
    for inc in incidents:
        ent = inc.entities
        st.markdown(f"### {SEVERITY_ICON[inc.severity]} {inc.incident_id} · {inc.title}")
        st.caption(f"{ent['start']:%Y-%m-%d %H:%M:%S} → {ent['end']:%H:%M:%S} UTC · "
                   f"users: {', '.join(ent['users']) or '—'} · external IPs: {', '.join(ent['external_ips']) or '—'} · "
                   f"hosts: {', '.join(ent['hosts']) or '—'} · sessions: {', '.join(ent['sessions']) or '—'}")
        observed = sum(l.basis == "observed" for l in inc.links)
        m = st.columns(4)
        m[0].metric("Events in chain", len(inc.chain))
        m[1].metric("Sources involved", inc.chain["source"].nunique())
        m[2].metric("Observed links", observed)
        m[3].metric("Inferred links", len(inc.links) - observed)
        st.dataframe(
            inc.chain[["step", "timestamp", "source", "user", "src_ip", "host", "action",
                       "detections", "link_basis", "linked_by", "raw_ref"]],
            hide_index=True)
        st.caption("**observed** = linked by an identifier written in both logs (session ID, IP address). "
                   "**inferred** = linked by reasoning (same user on the same host soon after a login); "
                   "treat as a hypothesis until confirmed.")

    st.markdown("#### Detections")
    in_incident = {ref for inc in incidents for ref in inc.chain["raw_ref"]}
    if detections:
        st.dataframe(pd.DataFrame([{
            "severity": f"{SEVERITY_ICON[d.severity]} {d.severity}",
            "rule": d.rule,
            "finding": d.title,
            "summary": d.summary,
            "in incident": "yes" if set(d.refs) & in_incident else "no",
            "evidence": ", ".join(d.refs[:4]) + (f" … (+{len(d.refs) - 4})" if len(d.refs) > 4 else ""),
        } for d in detections]), hide_index=True)
        unlinked = [d for d in detections if not set(d.refs) & in_incident]
        if unlinked:
            st.caption(f"{len(unlinked)} detection(s) are not linked to any incident: no shared session, "
                       "IP or user/host evidence connects them, so they are reported separately.")
    else:
        st.write("No suspicious patterns detected.")

if "Evaluation" in tabs:
    with tabs["Evaluation"]:
        result = evaluate(incidents, info["ground_truth"])
        st.markdown("Reconstructed chain compared with this dataset's `ground_truth.json`.")
        e = st.columns(4)
        e[0].metric("Attack events (truth)", result["ground_truth_events"])
        e[1].metric("Correctly linked", result["correctly_linked"])
        e[2].metric("Recall", "—" if result["recall"] is None else f"{result['recall']:.0%}")
        e[3].metric("Precision", "—" if result["precision"] is None else f"{result['precision']:.0%}")
        st.write("**Missed:**", ", ".join(result["missed"]) or "none")
        st.write("**False positives:**", ", ".join(result["false_positives"]) or "none")
        st.caption("Measured on one synthetic scenario that we designed. Results on the other test cases "
                   "(benign, incomplete, clock problems, unrelated events) are reported separately.")

with tab_timeline:
    if view["timestamp"].notna().any():
        st.plotly_chart(timeline_figure(view))
    untimed = view["timestamp"].isna().sum()
    if untimed:
        st.caption(f"{untimed} event(s) without a valid timestamp are not plotted; see Data quality.")

with tab_events:
    st.dataframe(view.drop(columns=["raw"]), hide_index=True)

with tab_quality:
    st.markdown("**Source coverage**")
    st.dataframe(source_coverage(events), hide_index=True)
    st.markdown("**Issues** — records are kept, but evidence from them is weaker.")
    if issues.empty:
        st.success("No data-quality issues found.")
    else:
        st.dataframe(issues, hide_index=True)

with tab_evidence:
    ref = st.selectbox("Original record", view["raw_ref"])
    if ref:
        row = view.loc[view["raw_ref"] == ref].iloc[0]
        st.write(f"**{row['source']}** · {row['raw_timestamp'] or '(no timestamp)'} · {row['action']}")
        st.json(row["raw"])
