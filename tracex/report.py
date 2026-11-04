"""Incident report: one structured document, rendered to Markdown and to self-contained HTML.

Built only from the analysis, the custody check and the mitigation replay; every evidence row carries
its raw_ref, so the report can be checked against the original logs line by line.
"""
from datetime import datetime, timezone
from html import escape

from . import mitigation
from .attack import map_techniques
from .explain import explain


def build(analysis, info, scenario, custody_result):
    a, inc = analysis, (analysis.incidents[0] if analysis.incidents else None)
    statements = explain(a, info)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = {"title": f"TraceX incident report — {inc.incident_id + ': ' + inc.title if inc else 'no incident'}",
           "meta": [("Dataset", f"{scenario} — {info.get('name', '')}"), ("Generated", now),
                    ("Correlation", "clock-aware" if a.clock_aware else "baseline (raw timestamps)"),
                    ("Engine", "rule-based (R1–R9); no machine learning")],
           "sections": []}
    add = lambda title, *blocks: doc["sections"].append((title, list(blocks)))

    status = custody_result["status"]
    rows = [(f["file"], f["status"], f.get("sha256", "—")[:16] + "…" if f.get("sha256") else "—", f["detail"])
            for f in custody_result["files"]]
    add("1. Evidence integrity",
        ("p", {"verified": f"All log files match the custody manifest sealed at {custody_result.get('sealed_at')}.",
               "tampered": "WARNING: the logs no longer match the sealed custody manifest. Conclusions below rest on "
                           "altered evidence; see the per-file detail.",
               "unsealed": "No custody manifest was found: integrity cannot be confirmed."}[status]),
        ("table", ["File", "Status", "SHA-256", "Detail"], rows) if rows else ("p", ""))

    add("2. Summary", ("list", [f"[{s.kind}] {s.text}" + (f" ({', '.join(s.refs[:4])})" if s.refs else "")
                                for s in statements if s.kind in ("observed", "inferred")]))

    if inc is not None:
        chain_rows = []
        for _, r in inc.chain.iterrows():
            t = f"{r['timestamp']:%H:%M:%S}"
            if r.get("time_correction_s"):
                t += f" (logged {r['timestamp_raw']:%H:%M:%S})"
            chain_rows.append((f"E{r['step']}", t, r["source"], r["action"], r["detections"] or "—", r["link_basis"],
                               r["raw_ref"]))
        add("3. Reconstructed timeline",
            ("p", "Ordered by analysis time (logged time plus any clock correction). observed = linked by an identifier "
                  "shared between logs; inferred = linked by reasoning (user + host + time)."),
            ("table", ["Step", "Time (UTC)", "Source", "Action", "Rules", "Link", "Evidence"], chain_rows))

        hits = map_techniques(a.view, a.detections, set(inc.chain["raw_ref"]))
        add("4. MITRE ATT&CK",
            ("table", ["Technique", "Name", "Tactic", "Confidence", "Rule", "Evidence"],
             [(h.technique, h.name, h.tactic, h.confidence, h.rule, ", ".join(h.refs[:4]) + (" …" if len(h.refs) > 4 else ""))
              for h in hits]))

        ent = inc.entities
        add("5. Indicators and affected assets",
            ("table", ["Type", "Value"],
             [("External IP", ", ".join(ent["external_ips"]) or "—"), ("Account used", ", ".join(ent["users"]) or "—"),
              ("Hosts", ", ".join(ent["hosts"]) or "—"), ("Sessions", ", ".join(ent["sessions"]) or "—")]))

    add("6. Gaps and uncertainty",
        ("list", [s.text + (f" ({', '.join(s.refs[:3])})" if s.refs else "") for s in statements if s.kind == "uncertainty"]
         or ["No gaps found."]))

    pols = mitigation.validate(a.view, a.incidents)
    add("7. Mitigation (replayed against these logs)",
        ("table", ["Policy", "Verdict", "Logins rejected", "Steps prevented", "Legitimate logins blocked"],
         [(p.name, p.verdict, ", ".join(p.blocked) or "none", str(len(p.prevented)), str(len(p.legit_blocked)))
          for p in pols]))

    add("8. Recommended next steps", ("list", [s.text for s in statements if s.kind == "next_step"] or ["None."]))
    add("9. Limitations",
        ("list", ["Synthetic data; rules and thresholds were written for these scenarios.",
                  "Graph links show shared evidence, not proven causation; inferred links are hypotheses.",
                  "Clock correction is the minimum consistent shift; a clock running ahead is not detectable.",
                  "Mitigation results are a replay over recorded logs; an adapting attacker is not modelled."]))
    return doc


def to_markdown(doc):
    out = [f"# {doc['title']}", ""] + [f"- **{k}:** {v}" for k, v in doc["meta"]] + [""]
    for title, blocks in doc["sections"]:
        out += [f"## {title}", ""]
        for b in blocks:
            if b[0] == "p" and b[1]:
                out += [b[1], ""]
            elif b[0] == "list":
                out += [f"- {x}" for x in b[1]] + [""]
            elif b[0] == "table":
                cell = lambda x: str(x).replace("|", "\\|")
                out += ["| " + " | ".join(b[1]) + " |", "|" + " --- |" * len(b[1])]
                out += ["| " + " | ".join(cell(x) for x in row) + " |" for row in b[2]] + [""]
    return "\n".join(out)


CSS = """body{font:14px/1.55 'Segoe UI',system-ui,sans-serif;color:#111;max-width:1000px;margin:32px auto;padding:0 20px}
h1{font-size:22px;border-bottom:2px solid #111;padding-bottom:8px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}th,td{border:1px solid #ccc;padding:5px 7px;text-align:left;vertical-align:top}
th{background:#f2f2f2}td:last-child,code{font-family:Consolas,monospace}.meta{color:#555}
@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}"""


def to_html(doc):
    e = lambda x: escape(str(x))
    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{e(doc['title'])}</title>"
             f"<style>{CSS}</style></head><body><h1>{e(doc['title'])}</h1><ul class='meta'>"]
    parts += [f"<li><b>{e(k)}:</b> {e(v)}</li>" for k, v in doc["meta"]] + ["</ul>"]
    for title, blocks in doc["sections"]:
        parts.append(f"<h2>{e(title)}</h2>")
        for b in blocks:
            if b[0] == "p" and b[1]:
                parts.append(f"<p>{e(b[1])}</p>")
            elif b[0] == "list":
                parts.append("<ul>" + "".join(f"<li>{e(x)}</li>" for x in b[1]) + "</ul>")
            elif b[0] == "table":
                parts.append("<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in b[1]) + "</tr>"
                             + "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in b[2])
                             + "</table>")
    parts.append("</body></html>")
    return "".join(parts)
