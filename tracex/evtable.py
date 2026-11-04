"""Evidence table component: rows with pulsing severity markers; clicking a row returns its raw_ref.

Streamlit's built-in data grid is drawn on a canvas, so its cells cannot animate. This small offline
component (same iframe protocol as the 3D view) renders the explorer table instead.
"""
from pathlib import Path

import pandas as pd
import streamlit.components.v1 as components

_component = components.declare_component("tracex_evtable", path=str(Path(__file__).parent / "frontend" / "evtable"))
SEV_RANK = {"high": 3, "medium": 2, "low": 1}


def rows_for(table, rules_by_ref, chain_info):
    out = []
    for _, r in table.iterrows():
        ds = rules_by_ref.get(r["raw_ref"], [])
        sev = max((d.severity for d in ds), key=SEV_RANK.get, default="")
        ts = r["timestamp"]
        out.append({
            "ref": r["raw_ref"], "time": "—" if pd.isna(ts) else ts.strftime("%H:%M:%S"), "source": r["source"],
            "user": r["user"], "ip": r["src_ip"], "host": r["host"], "action": r["action"], "outcome": r["outcome"],
            "step": chain_info[r["raw_ref"]]["step"] if r["raw_ref"] in chain_info else None,
            "sev": sev, "rules": " ".join(sorted({d.rule for d in ds}, key=lambda x: int(x[1:]))),
            "issue": bool(r["parse_issues"]),
        })
    return out


def evtable(rows, key, data_key, selected=None, height=520):
    return _component(rows=rows, data_key=data_key, selected=selected, height=height, key=key, default=None)
