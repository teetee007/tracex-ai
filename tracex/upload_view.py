"""Upload mode: any number of files in any format, each recognised, mapped or rejected with a reason."""
import pandas as pd
import streamlit as st

from . import ai, ui
from .ingest import apply_mapping, ingest
from .parsers import combine
from .schema import SOURCES

FORMATS = ("Apache / Nginx access logs, Linux auth.log (sshd, sudo), and CSV / JSON / JSON Lines exports from any "
           "tool — columns are recognised by name and by their values (timestamps, IPs, HTTP codes, outcomes).")


def run_uploads(year):
    """Returns (events or None, info, evidence_files). Renders the per-file upload report."""
    files = st.sidebar.file_uploader("Log files (any format, several at once)", accept_multiple_files=True,
                                     help=FORMATS)
    st.sidebar.caption("Use synthetic or redacted logs only. Try the files in samples/ (real formats + two non-logs).")
    info = {"name": "Uploaded logs", "missing_sources": []}
    if not files:
        ui.header([("Dataset", "upload")])
        with st.container(border=True):
            ui.panel_title("Upload your own logs", "any format · checked file by file")
            st.write("Add one or more files in the sidebar. Supported: " + FORMATS)
            st.caption("Files that are not security logs (documents, spreadsheets of other data, images, prose) are "
                       "rejected with an explanation instead of producing misleading results.")
        st.stop()

    ai_ok, ai_msg = ai.status()
    who = ai.name()
    overrides = st.session_state.setdefault("ai_mapping", {})
    reports, evidence = [], {}
    for f in files:
        data = f.getvalue()
        rep = ingest(f.name, data, year)
        if f.name in overrides and rep.columns:
            rep = apply_mapping(rep, data, overrides[f.name]["mapping"], "ai")
            rep.notes.append(f"{overrides[f.name].get('by', who)}: {overrides[f.name]['reason']}")
        reports.append((rep, data))
        if rep.status == "accepted":
            evidence[f.name] = data

    accepted = [r for r, _ in reports if r.status == "accepted"]
    with st.expander(f"Upload report · {len(accepted)} of {len(reports)} file(s) accepted", expanded=not accepted or
                     len(accepted) < len(reports)):
        for rep, data in reports:
            ok = rep.status == "accepted"
            n = len(rep.events) if rep.events is not None else 0
            st.markdown(f"{ui.pill('accepted' if ok else 'rejected', 'ok' if ok else 'high')} &nbsp;**{ui.esc(rep.name)}** "
                        f"<span style='color:#8a8a8a'>· {ui.esc(rep.format)}"
                        f"{' · ' + ui.esc(rep.kind) + ' events' if ok else ''}{f' · {n} records' if ok else ''}</span>",
                        unsafe_allow_html=True)
            st.caption(rep.reason)
            for note in rep.notes:
                st.caption("• " + note)
            if rep.mapping:
                st.dataframe(pd.DataFrame([{"TraceX field": k, "your column": v,
                                            "mapped by": {"ai": f"{who} (validated)", "rules": "name + values"}[rep.mapped_by]}
                                           for k, v in rep.mapping.items()]), hide_index=True)
            if rep.columns and rep.status == "rejected" or (rep.columns and rep.mapped_by == "rules" and len(rep.mapping) < 4):
                if ai_ok:
                    if st.button(f"Ask {who} to map {rep.name}", key=f"ai-{rep.name}"):
                        try:
                            with st.spinner(f"Asking {who}…"):
                                prop = ai.propose_mapping(rep.columns, rep.sample)
                        except ai.AIError as e:
                            st.error(str(e))
                        else:
                            if not prop["relevant"]:
                                st.warning(f"{who} also judges this is not security log data: {prop['reason']}")
                            else:
                                overrides[rep.name] = {**prop, "by": who}
                                st.rerun()
                    st.caption(f"Sends this file's column names and 5 sample rows to {who}. The proposal is checked "
                               "against the values before it is used.")
                else:
                    st.caption(ai_msg)
            st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)

    if not accepted:
        ui.header([("Dataset", "upload")])
        st.error("None of the uploaded files look like security logs, so there is nothing to investigate. "
                 "See the upload report above for the reason for each file.")
        st.stop()
    events = combine([r.events for r in accepted])
    # Several files can feed the same source; keep event IDs unique across all of them.
    events["event_id"] = [f"{s}-{i:04d}" for i, s in enumerate(events["source"])]
    present = set(events["source"])
    info["missing_sources"] = [s for s in SOURCES if s not in present]
    info["name"] = f"Uploaded logs · {len(accepted)} file(s)"
    return events, info, evidence
