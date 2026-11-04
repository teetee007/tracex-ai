"""Investigation views: before/after comparison, ATT&CK matrix, blast radius, and the presenter script."""
from html import escape

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from .attack import MAPPINGS, TACTIC_ORDER, map_techniques
from .detections import IP_IN_TEXT, is_external
from .evaluation import evaluate
from .timeline import _style
from .ui import GREY, ORANGE, RED, WHITE

INC_COLORS = [RED, ORANGE, "#a78bfa", "#38bdf8"]


# ---------------------------------------------------------------- 1. before / after
def before_after(base, aware, truth=None):
    """Two lanes of the same evidence: raw timestamps (baseline) vs clock-aware. Returns (figure, rows)."""
    truth_refs = {r for refs in (truth or {}).get("attack_events", {}).values() for r in refs}
    focus = set(truth_refs)
    for a in (base, aware):
        for inc in a.incidents:
            focus |= set(inc.chain["raw_ref"])
    if not focus:
        return None, []
    fig = make_subplots(rows=2, cols=1, shared_xaxes=False, vertical_spacing=0.18,
                        subplot_titles=("BEFORE · raw timestamps", "AFTER · clock-aware correlation"))
    rows = []
    for row, a in ((1, base), (2, aware)):
        member = {r: inc.incident_id for inc in a.incidents for r in inc.chain["raw_ref"]}
        v = a.view[a.view["raw_ref"].isin(focus)].dropna(subset=["timestamp"])
        groups = sorted(set(member.values())) + ["not linked"]
        for k, g in enumerate(groups):
            part = v[v["raw_ref"].map(lambda r: member.get(r, "not linked")) == g]
            if part.empty:
                continue
            missed = g == "not linked"
            fig.add_trace(go.Scatter(
                x=part["timestamp"], y=part["source"], mode="markers", name=f"{'before' if row == 1 else 'after'}: {g}",
                legendgroup=f"{row}{g}", showlegend=True,
                marker=dict(size=11 if not missed else 10, color=GREY if missed else INC_COLORS[k % len(INC_COLORS)],
                            symbol="x" if missed else "circle", line=dict(width=1, color="#0a0a0a")),
                customdata=part[["raw_ref", "action"]].values,
                hovertemplate="<b>%{customdata[1]}</b><br>%{x|%H:%M:%S} · %{customdata[0]}<extra>" + g + "</extra>"),
                row=row, col=1)
        r = evaluate(a.incidents, truth) if truth else None
        rows.append({"mode": "baseline (raw times)" if row == 1 else "clock-aware", "incidents": len(a.incidents),
                     "linked": None if r is None else r["correctly_linked"],
                     "missed": None if r is None else len(r["missed"]),
                     "recall": None if r is None else r["recall"]})
    fig.update_yaxes(categoryorder="array", categoryarray=["system", "auth", "web"])
    fig = _style(fig, 430)
    fig.update_annotations(font=dict(color=WHITE, size=12, family="JetBrains Mono, monospace"), x=0, xanchor="left")
    fig.update_layout(legend=dict(orientation="h", y=-0.12))
    return fig, rows


# ---------------------------------------------------------------- 4. ATT&CK matrix
def attack_matrix_html(events, detections, refs=None):
    """Tactic columns; every technique TraceX can map is a cell, lit when the evidence supports it."""
    hits = {h.technique: h for h in map_techniques(events, detections, refs)}
    catalogue = {}
    for m in MAPPINGS:
        catalogue.setdefault(m["tactic"], {})[m["technique"]] = m["name"]
    cols = []
    for tactic in TACTIC_ORDER:
        cells = []
        for tid, name in catalogue.get(tactic, {}).items():
            h = hits.get(tid)
            cls = "" if h is None else ("mapped" if h.confidence == "mapped" else "candidate")
            tip = (f"{tid} {name} — not observed" if h is None else
                   f"{tid} {name} — {h.confidence} via {h.rule}; {len(h.refs)} record(s): {', '.join(h.refs[:4])}")
            count = f"<span class='n'>{len(h.refs)}</span>" if h else ""
            cells.append(f"<div class='cell {cls}' title='{escape(tip, quote=True)}'><span class='id'>{escape(tid)}</span>"
                         f"<span class='nm'>{escape(name)}</span>{count}</div>")
        lit = sum(1 for tid in catalogue.get(tactic, {}) if tid in hits)
        cols.append(f"<div class='col{' on' if lit else ''}'><div class='tac'>{escape(tactic)}<small>{lit}/{len(catalogue.get(tactic, {}))}</small></div>"
                    + "".join(cells) + "</div>")
    css = """<style>
.tx-matrix{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:6px;margin:6px 0 4px}
.tx-matrix .tac{font:600 .66rem 'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.06em;color:#8a8a8a;
  padding:6px 4px;border-bottom:1px solid rgba(255,255,255,.12);margin-bottom:6px;min-height:44px}
.tx-matrix .col.on .tac{color:#ececec;border-bottom-color:#e5484d}
.tx-matrix .tac small{display:block;font-weight:400;color:#8a8a8a;margin-top:2px}
.tx-matrix .cell{border:1px solid rgba(255,255,255,.08);padding:6px;margin-bottom:6px;font:.7rem/1.3 Inter,sans-serif;
  color:#666;position:relative;background:rgba(255,255,255,.015)}
.tx-matrix .cell .id{display:block;font:500 .66rem 'JetBrains Mono',monospace;margin-bottom:2px}
.tx-matrix .cell .nm{display:block;overflow-wrap:anywhere}
.tx-matrix .cell .n{position:absolute;top:4px;right:6px;font:600 .66rem 'JetBrains Mono',monospace}
.tx-matrix .cell.mapped{color:#fff;background:rgba(229,72,77,.22);border-color:#e5484d;box-shadow:0 0 12px rgba(229,72,77,.25)}
.tx-matrix .cell.candidate{color:#fff;background:rgba(240,140,46,.16);border-color:#f08c2e;border-style:dashed}
@media (max-width:900px){.tx-matrix{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>"""
    return css + "<div class='tx-matrix'>" + "".join(cols) + "</div>", len(hits)


# ---------------------------------------------------------------- 5. blast radius
def blast_radius(incident, events):
    """What the attacker reached, column by column, each item tied to its evidence."""
    chain = incident.chain
    attackers = [ip for ip in incident.entities["external_ips"]]
    accounts = sorted(set(chain.loc[(chain["source"] == "auth") & (chain["outcome"] == "success"), "user"]) - {""})
    hosts = sorted(set(chain["host"]) - {"", "unknown-host"})
    impact = []
    for _, r in chain.iterrows():
        rules = set(r["detections"].split(", ")) - {""}
        if "R6" in rules:
            impact.append(("data accessed", r["action"].split(" ", 1)[-1], r["raw_ref"], r["host"]))
        if "R9" in rules:
            target = next((ip for ip in IP_IN_TEXT.findall(r["action"]) if is_external(ip)), "")
            files = [w for w in r["action"].split() if "/" in w and "@" not in w]
            impact.append(("data sent out", (files[0].rsplit("/", 1)[-1] if files else "file") + f" → {target}", r["raw_ref"], r["host"]))
        if "R8" in rules:
            impact.append(("persistence", "account " + r["action"].split()[-1], r["raw_ref"], r["host"]))
    return {"attackers": attackers, "accounts": accounts, "hosts": hosts, "impact": impact}


def blast_radius_svg(br):
    cols = [("ATTACKER", [(a, "external source") for a in br["attackers"]], RED),
            ("ACCOUNTS USED", [(u, "logged in successfully") for u in br["accounts"]], ORANGE),
            ("SYSTEMS REACHED", [(h, "activity recorded") for h in br["hosts"]], ORANGE),
            ("IMPACT", [(f"{what}: {item}", ref) for what, item, ref, _ in br["impact"]], RED)]
    n = max(1, max(len(c[1]) for c in cols))
    W, colw, boxh, gap = 760, 168, 46, 12
    H = 50 + n * (boxh + gap) + 10
    xs = [12 + i * (colw + 26) for i in range(4)]
    parts = [f"<svg viewBox='0 0 {W} {H}' width='100%' role='img' aria-label='Blast radius of the incident' "
             "style='font-family:JetBrains Mono,monospace'>",
             "<defs><marker id='br-a' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='6' markerHeight='6' orient='auto'>"
             "<path d='M0 0L10 5L0 10z' fill='rgba(255,255,255,.35)'/></marker></defs>"]
    centers = []
    for i, (title, items, color) in enumerate(cols):
        x = xs[i]
        parts.append(f"<text x='{x}' y='22' fill='#8a8a8a' font-size='10.5' letter-spacing='1.5'>{escape(title)}</text>")
        cs = []
        for k, (label, sub) in enumerate(items or [("none observed", "")]):
            y = 36 + k * (boxh + gap)
            empty = not items
            stroke = "rgba(255,255,255,.15)" if empty else color
            parts.append(f"<rect x='{x}' y='{y}' width='{colw}' height='{boxh}' rx='3' fill='rgba(255,255,255,.02)' "
                         f"stroke='{stroke}' stroke-width='1.2'/>")
            short = label if len(label) <= 24 else label[:23] + "…"
            parts.append(f"<text x='{x + 10}' y='{y + 19}' fill='{'#666' if empty else '#ececec'}' font-size='11.5'>"
                         f"<title>{escape(label)}</title>{escape(short)}</text>")
            if sub:
                parts.append(f"<text x='{x + 10}' y='{y + 35}' fill='#8a8a8a' font-size='9.5'>{escape(sub[:28])}</text>")
            cs.append((x, y + boxh / 2))
        centers.append(cs)
    for i in range(3):
        for (x1, y1) in centers[i]:
            for (x2, y2) in centers[i + 1]:
                parts.append(f"<path d='M{x1 + colw} {y1} C{x1 + colw + 14} {y1} {x2 - 14} {y2} {x2 - 2} {y2}' fill='none' "
                             "stroke='rgba(255,255,255,.22)' stroke-width='1' marker-end='url(#br-a)'/>")
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------- 3. presenter script
PRESENTER_STEPS = [
    {"dataset": "tc02_benign", "clock": True, "page": "investigate", "tab": "Investigation",
     "title": "A normal day is not an attack",
     "say": "Benign logins, a mistyped password, an admin session and internet noise: TraceX flags two minor "
            "detections but reconstructs zero incidents."},
    {"dataset": "tc01_attack", "clock": True, "page": "investigate", "tab": "Investigation",
     "title": "Replay the intrusion",
     "say": "Press ▶ Play. The kill-chain ribbon lights up stage by stage: password guessing, the stolen login, the admin "
            "export, SSH, discovery, a new account, exfiltration. Click any node to see its original log line."},
    {"dataset": "tc01_attack", "clock": True, "page": "investigate", "tab": "Explanation",
     "title": "Every sentence cites evidence",
     "say": "Facts, inferences and uncertainties are labelled, and every citation is checked against the logs."},
    {"dataset": "tc05_unrelated", "clock": True, "page": "investigate", "tab": "Investigation",
     "title": "Look-alikes stay out",
     "say": "A neighbouring IP guessing 'admin' and a travelling employee in the same minutes are NOT pulled into the "
            "chain: links need shared evidence, not just similar times."},
    {"dataset": "tc04_clock_skew", "clock": True, "page": "investigate", "tab": "Before / after",
     "title": "We check whether the evidence can be trusted",
     "say": "web-01's clock runs 5 minutes behind. Raw times split the attack and miss 5 events; TraceX proves the skew "
            "from two independent sessions, corrects it, and recovers 27 of 27."},
    {"dataset": "tc01_attack", "clock": True, "page": "evidence", "tab": "Chain of custody",
     "title": "Tampering is detected to the record",
     "say": "Press 'Tamper and re-verify': every record is hash-chained, so a deleted line is named exactly."},
    {"dataset": "tc01_attack", "clock": True, "page": "validate", "tab": "Mitigation",
     "title": "The fix is validated, not guessed",
     "say": "Replaying an account-lockout policy stops the chain at the stolen login, before any data access, with zero "
            "legitimate users locked out. Report & exports hands it to real tools (Sigma, ATT&CK Navigator, STIX)."},
]
