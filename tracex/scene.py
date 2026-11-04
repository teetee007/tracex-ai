"""Data contract between Python and the 3D investigation component (version 1).

Python sends ONE JSON object per render; the component never invents data. Shape:

  {version, data_id, title, ordering, skew: [...], nodes: [...], edges: [...], untimed: int}

  node = {id (= event_id, stable), ref (= raw_ref), source, event_type, t (ms, ordering time),
          t_raw (ms, as logged), correction_s, uncertainty_s (null = unknown), user, src_ip, host,
          session_id, action, outcome, details, in_chain, step, linked_by, link_basis,
          severity (high|medium|low|none), trigger (completed a detection), rules [{rule,title,severity}],
          techniques [{id,name,confidence,tactic}],
          raw {original record fields}}
  edge = {a, b (node ids), basis (observed|inferred), reason, time_adjusted}

`validate()` checks the contract before it is sent; the tests call it for every scenario.
"""
import hashlib
import json
import math

from .attack import map_techniques, techniques_by_ref
from .detections import SEVERITY_RANK

VERSION = 1
SEVERITY_NAME = {3: "high", 2: "medium", 1: "low", 0: "none"}


def _ms(ts):
    return None if ts is None or str(ts) == "NaT" else int(ts.value // 1_000_000)


def _num(x):
    return None if x is None or (isinstance(x, float) and math.isnan(x)) else float(x)


def build(analysis, scenario, incident=None):
    view = analysis.view
    chain = {} if incident is None else {r["raw_ref"]: r for _, r in incident.chain.iterrows()}
    hits = techniques_by_ref(map_techniques(view, analysis.detections))
    rules = {}
    for d in analysis.detections:
        for ref in d.refs:
            rules.setdefault(ref, []).append(d)
    # The record that completed each detection (e.g. the login after the guesses): the one place it pulses.
    triggers = {d.refs[-1] for d in analysis.detections if d.severity in ("high", "medium")}

    nodes, ref_to_id, untimed = [], {}, 0
    for _, e in view.iterrows():
        if str(e["timestamp"]) == "NaT":
            untimed += 1
            continue
        ref = e["raw_ref"]
        ds = rules.get(ref, [])
        c = chain.get(ref)
        ref_to_id[ref] = e["event_id"]
        nodes.append({
            "id": e["event_id"], "ref": ref, "source": e["source"], "event_type": e["event_type"],
            "t": _ms(e["timestamp"]), "t_raw": _ms(e["timestamp_raw"]),
            "correction_s": _num(e["time_correction_s"]), "uncertainty_s": _num(e["time_uncertainty_s"]),
            "user": e["user"], "src_ip": e["src_ip"], "host": e["host"], "session_id": e["session_id"],
            "action": e["action"], "outcome": e["outcome"], "details": e["details"],
            "in_chain": c is not None, "step": int(c["step"]) if c is not None else None,
            "linked_by": c["linked_by"] if c is not None else "", "link_basis": c["link_basis"] if c is not None else "",
            "severity": SEVERITY_NAME[max((SEVERITY_RANK[d.severity] for d in ds), default=0)],
            "trigger": ref in triggers,
            "rules": [{"rule": d.rule, "title": d.title, "severity": d.severity} for d in ds],
            "techniques": [{"id": h.technique, "name": h.name, "confidence": h.confidence, "tactic": h.tactic}
                           for h in hits.get(ref, [])],
            "raw": json.loads(e["raw"]),
        })

    edges = [{"a": ref_to_id[l.source_ref], "b": ref_to_id[l.target_ref], "basis": l.basis,
              "reason": l.reason, "time_adjusted": l.time_adjusted}
             for l in analysis.links if l.source_ref in ref_to_id and l.target_ref in ref_to_id]

    skew = [{"host": f.host, "source": f.source, "status": f.status, "explanation": f.explanation,
             "correction_s": f.correction.total_seconds() if f.correction is not None else None}
            for f in analysis.clock if f.status != "consistent"]

    key = f"{scenario}|{analysis.clock_aware}|{incident.incident_id if incident else '-'}|{len(nodes)}|{len(edges)}"
    return {
        "version": VERSION,
        "data_id": hashlib.sha1(key.encode()).hexdigest()[:12],
        "title": incident.title if incident else "No incident reconstructed",
        "incident_id": incident.incident_id if incident else None,
        "ordering": ("Events are ordered by their analysis time: the logged time, plus the estimated clock "
                     "correction where one was applied. Ties keep log order."),
        "skew": skew, "nodes": nodes, "edges": edges, "untimed": untimed,
    }


def validate(data):
    """Raise ValueError if the contract is broken (stale ids, dangling edges, non-JSON values)."""
    if data.get("version") != VERSION:
        raise ValueError("unknown contract version")
    ids = [n["id"] for n in data["nodes"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate node ids")
    known = set(ids)
    for e in data["edges"]:
        if e["a"] not in known or e["b"] not in known:
            raise ValueError(f"edge points at unknown node: {e}")
        if e["basis"] not in ("observed", "inferred"):
            raise ValueError(f"bad edge basis: {e['basis']}")
    steps = sorted(n["step"] for n in data["nodes"] if n["in_chain"])
    if steps != list(range(1, len(steps) + 1)):
        raise ValueError("chain steps are not 1..n")
    json.dumps(data, allow_nan=False)   # NaN would break the browser's JSON.parse
    return data
