"""Visual styling and small HTML building blocks for the Streamlit app.

Design: monochrome "situation room" HUD. Only four colours carry meaning:
  white/grey = neutral information, GREEN = normal / success, ORANGE = warning / medium / inferred,
  RED = critical / attacker. Nothing else is coloured.

Everything that reaches HTML from log data goes through `esc()`, because log fields are
attacker-controlled text.
"""
import json
import math
from html import escape

import streamlit as st

WHITE, GREY, DIM, MUTED = "#ececec", "#9a9a9a", "#666666", "#8a8a8a"
RED, ORANGE, GREEN = "#e5484d", "#f08c2e", "#46a758"
SEVERITY_COLOR = {"high": RED, "medium": ORANGE, "low": GREY}
BAND_COLOR = {"Critical": RED, "High": RED, "Medium": ORANGE, "Low": GREEN}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
:root { --bg:#0a0a0a; --panel:#0f0f0f; --line:rgba(255,255,255,.12); --line-soft:rgba(255,255,255,.06);
        --white:#ececec; --accent:#67e8f9; --grey:#9a9a9a; --muted:#8a8a8a; --red:#e5484d; --orange:#f08c2e; --green:#46a758;
        --mono:'JetBrains Mono', ui-monospace, monospace;
        --corner: linear-gradient(var(--white),var(--white)); }
html, body, .stApp { font-family: 'Inter', sans-serif; }
.stApp {
  background:
    radial-gradient(1200px 700px at 50% 40%, rgba(255,255,255,.035), transparent 70%),
    repeating-linear-gradient(0deg, rgba(255,255,255,.018) 0 1px, transparent 1px 48px),
    repeating-linear-gradient(90deg, rgba(255,255,255,.018) 0 1px, transparent 1px 48px),
    var(--bg);
}
header[data-testid="stHeader"] { background: transparent; }
[data-testid="stAppDeployButton"], footer { display: none; }
.block-container { padding-top: 3.4rem; max-width: 1560px; }
[data-testid="stSidebar"] { background: #0c0c0c; border-right: 1px solid var(--line); }

/* Panels: thin frame with white corner brackets */
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]),
div[data-testid="stVerticalBlock"][data-border="true"] {
  border: 1px solid var(--line) !important; border-radius: 2px;
  background:
    var(--corner) top left / 12px 1px no-repeat, var(--corner) top left / 1px 12px no-repeat,
    var(--corner) top right / 12px 1px no-repeat, var(--corner) top right / 1px 12px no-repeat,
    var(--corner) bottom left / 12px 1px no-repeat, var(--corner) bottom left / 1px 12px no-repeat,
    var(--corner) bottom right / 12px 1px no-repeat, var(--corner) bottom right / 1px 12px no-repeat,
    rgba(15,15,15,.88);
}

/* Tabs */
[data-baseweb="tab-list"] { gap: 2px; border-bottom: 1px solid var(--line); }
[data-baseweb="tab"] { color: var(--muted); padding: 8px 16px; font-size:.8rem; text-transform:uppercase; letter-spacing:.08em; }
[data-baseweb="tab"]:hover { color: var(--white); }
[data-baseweb="tab"][aria-selected="true"] { color: var(--accent); }
[data-baseweb="tab-highlight"] { background: var(--accent); height: 2px; }
[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 2px; }
[data-testid="stExpander"] details { border: 1px solid var(--line); border-radius: 2px; background: rgba(15,15,15,.7); }
.stButton button, [data-testid="stBaseButton-pills"], [data-testid="stBaseButton-pillsActive"] { border-radius: 2px !important; }

/* Header */
.tx-header { display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;
  padding-bottom:12px; border-bottom:1px solid var(--line); position:relative; }
.tx-header::after { content:""; position:absolute; left:0; bottom:-1px; width:180px; height:2px; background:var(--accent); }
.tx-brand { display:flex; align-items:center; gap:14px; }
.tx-logo { width:42px; height:42px; display:grid; place-items:center; border:1px solid var(--line); background:#111; }
.tx-kicker { font-family:var(--mono); font-size:.62rem; color:var(--muted); letter-spacing:.22em; text-transform:uppercase; }
.tx-title { font-size:1.55rem; font-weight:700; letter-spacing:.02em; color:var(--white); line-height:1.15; }
.tx-title span { font-weight:400; color:var(--accent); }
.tx-subtitle { color:var(--muted); font-size:.8rem; margin-top:2px; }
.tx-chips { display:flex; gap:0; flex-wrap:wrap; border:1px solid var(--line); }
.tx-chip { padding:6px 14px; font-size:.72rem; color:var(--muted); font-family:var(--mono); border-right:1px solid var(--line); }
.tx-chip:last-child { border-right:none; }
.tx-chip b { color:var(--white); font-weight:500; }
.tx-live { color: var(--green); }
.tx-live::before { content:""; display:inline-block; width:6px; height:6px; background:var(--green); margin-right:8px;
  vertical-align:middle; animation: txpulse 2s infinite; }
@keyframes txpulse { 50% { opacity:.3; } }

/* KPI strip */
.tx-kpis { display:grid; grid-template-columns: repeat(3, 1fr); gap:0; margin:16px 0 10px; border:1px solid var(--line); }
@media (max-width: 520px) { .tx-kpis { grid-template-columns: repeat(2, 1fr); } }
@media (min-width: 1100px) { .tx-kpis { grid-template-columns: repeat(6, 1fr); } }
.tx-kpi { padding:14px 18px; border-right:1px solid var(--line); border-bottom:1px solid var(--line-soft); position:relative; }
.tx-kpi:last-child { border-right:none; }
.tx-kpi .label { color:var(--muted); font-size:.66rem; text-transform:uppercase; letter-spacing:.12em; display:flex; align-items:center; gap:8px; }
.tx-kpi .label::before { content:""; width:6px; height:6px; background:var(--accent); flex:none; }
.tx-kpi .value { color:var(--white); font-family:var(--mono); font-size:2rem; font-weight:500; margin-top:6px; letter-spacing:.02em; }
.tx-kpi .sub { color:var(--muted); font-size:.7rem; margin-top:2px; }

/* Panel headings: title + underline rule, like an instrument label */
.tx-panel-title { display:flex; justify-content:space-between; align-items:baseline; gap:10px; margin-bottom:10px;
  padding-bottom:6px; border-bottom:1px solid var(--line); position:relative; }
.tx-panel-title::after { content:""; position:absolute; left:0; bottom:-1px; width:36px; height:2px; background:var(--accent); }
.tx-panel-title h4 { margin:0; padding:0; font-size:.8rem; font-weight:600; color:var(--white); white-space:nowrap;
  text-transform:uppercase; letter-spacing:.12em; }
.tx-panel-title small { color:var(--muted); font-size:.68rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-family:var(--mono); }

/* Tags */
.tx-pill { display:inline-block; max-width:100%; padding:1px 8px; font-size:.64rem; font-weight:500; font-family:var(--mono);
  text-transform:uppercase; letter-spacing:.06em; border:1px solid currentColor; white-space:nowrap; border-radius:2px; }
.tx-pill.observed { color: var(--white); }
.tx-pill.inferred { color: var(--orange); border-style: dashed; }
.tx-pill.high, .tx-pill.critical { color: var(--red); }
.tx-pill.medium { color: var(--orange); }
.tx-pill.low, .tx-pill.neutral { color: var(--grey); }
.tx-pill.ok { color: var(--green); }

/* Ring gauges */
.tx-gauge svg { width:100%; height:auto; display:block; overflow:visible; }
.tx-gauge .num { font: 500 44px 'JetBrains Mono', monospace; fill: var(--white); }
.tx-gauge .den { font: 500 11px 'JetBrains Mono', monospace; fill: var(--muted); letter-spacing:1px; }
.tx-gauge .tick { stroke: rgba(255,255,255,.25); stroke-width: 1; }
.tx-threat { display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.tx-threat .tx-gauge { flex: 0 0 150px; max-width: 150px; }
.tx-threat-info { flex: 1 1 140px; min-width: 140px; }
.tx-band { font-family:var(--mono); font-size:1.3rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
.tx-threat-info .counts { display:flex; gap:6px; flex-wrap:wrap; margin:8px 0 6px; }
.tx-threat-info .note { color:var(--muted); font-size:.7rem; line-height:1.4; }
.tx-details { margin-top:10px; border-top:1px solid var(--line); padding-top:8px; }
.tx-details summary { color:var(--muted); font-size:.72rem; cursor:pointer; list-style:none; font-family:var(--mono); text-transform:uppercase; letter-spacing:.08em; }
.tx-details summary::before { content:"+ "; color:var(--white); }
.tx-details[open] summary::before { content:"− "; }
.tx-score { display:grid; gap:5px; margin-top:8px; }
.tx-score-row { display:grid; grid-template-columns: 26px 1fr auto; gap:8px; font-size:.74rem; align-items:baseline; }
.tx-score-row .r, .tx-score-row .p { font-family:var(--mono); color:var(--muted); }
.tx-score-row .f { color:var(--white); }
.tx-rings { display:flex; gap:18px; flex-wrap:wrap; align-items:flex-start; }
.tx-ring { text-align:center; }
.tx-ring .tx-gauge { width:150px; max-width:150px; }
.tx-ring .t { color:var(--muted); font-size:.66rem; text-transform:uppercase; letter-spacing:.12em; margin-top:-4px; }

/* Count-up numbers (CSS only) */
@property --n { syntax: '<integer>'; inherits: false; initial-value: 0; }
.tx-kpi .value.count { counter-reset: n var(--n); animation: txcount 1.6s cubic-bezier(.65,0,.35,1) both; }
.tx-kpi .value.count::after { content: counter(n); }
@keyframes txcount { from { --n: 0; } }

/* Attack progression */
.tx-steps { position:relative; margin-top:6px; }
.tx-step { display:grid; grid-template-columns: 26px 1fr auto; gap:10px; align-items:start; position:relative; padding-bottom:14px;
  animation: txin .45s ease-out both; animation-delay: calc(var(--i) * 140ms + 200ms); }
@keyframes txin { from { opacity:0; transform: translateX(-10px); } }
.tx-step:not(:last-child)::before { content:""; position:absolute; left:12px; top:26px; bottom:2px; width:1px; background:var(--line); }
.tx-dot { width:26px; height:26px; display:grid; place-items:center; font:500 .68rem var(--mono);
  border:1px solid var(--c); color:var(--c); background:#0c0c0c; }
.tx-step .phase { color:var(--c); font-size:.62rem; text-transform:uppercase; letter-spacing:.12em; font-family:var(--mono); }
.tx-step .name { color:var(--white); font-size:.82rem; margin-top:1px; }
.tx-step .meta { color:var(--muted); font-size:.68rem; margin-top:3px; font-family:var(--mono); }

/* Facts */
.tx-facts { display:grid; gap:0; margin-top:4px; }
.tx-fact { display:grid; grid-template-columns: 110px 1fr; gap:10px; font-size:.78rem; border-bottom:1px solid var(--line-soft); padding:7px 0; }
.tx-fact .k { color:var(--muted); text-transform:uppercase; font-size:.66rem; letter-spacing:.08em; padding-top:2px; }
.tx-fact .v { color:var(--white); font-family:var(--mono); font-size:.75rem; word-break:break-word; }

/* Detection cards */
.tx-det { border-left:2px solid var(--c); padding:2px 2px 2px 14px; }
.tx-det .top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.tx-det .rule { font-family:var(--mono); color:var(--white); font-size:.75rem; }
.tx-det .phase { color:var(--muted); font-size:.64rem; text-transform:uppercase; letter-spacing:.1em; font-family:var(--mono); }
.tx-det .sp { flex:1; }
.tx-det .title { color:var(--white); font-weight:600; font-size:.95rem; margin-top:8px; }
.tx-det .sum { color:#bdbdbd; font-size:.8rem; margin-top:4px; line-height:1.45; }
.tx-det .meta { color:var(--muted); font-size:.68rem; margin-top:8px; font-family:var(--mono); }

/* Forensic record card */
.tx-rec { border:1px solid var(--line); border-radius:2px; padding:14px 16px; background: rgba(15,15,15,.9); }
.tx-rec.empty { color:var(--muted); font-size:.8rem; text-align:center; padding:40px 16px; border-style:dashed; }
.tx-rec .hd { display:flex; gap:10px; align-items:center; }
.tx-rec .ref { font-family:var(--mono); color:var(--white); font-size:.78rem; }
.tx-rec .act { color:var(--white); font-weight:500; font-size:.95rem; margin-top:10px; word-break:break-word; font-family:var(--mono); }
.tx-rec .when { color:var(--muted); font-size:.7rem; margin-top:4px; font-family:var(--mono); }
.tx-rec .box { margin-top:10px; border-left:2px solid var(--c); background:rgba(255,255,255,.025); padding:8px 10px; font-size:.76rem; color:var(--white); }
.tx-rec .box span { color:#bdbdbd; }
.tx-rec .dets { display:flex; flex-direction:column; align-items:flex-start; gap:6px; margin-top:10px; }
.tx-rec .dets .tx-pill { white-space:normal; max-width:100%; line-height:1.45; padding:3px 8px; overflow-wrap:anywhere; }
.tx-rec .sec { color:var(--muted); font-size:.62rem; text-transform:uppercase; letter-spacing:.14em; margin:14px 0 6px;
  padding-bottom:4px; border-bottom:1px solid var(--line-soft); }
.tx-kv { display:grid; grid-template-columns:auto 1fr; gap:4px 12px; font-family:var(--mono); font-size:.73rem; }
.tx-kv .k { color:var(--muted); }
.tx-kv .v { color:var(--white); word-break:break-all; }

/* Confusion matrix */
.tx-cm { display:grid; grid-template-columns:1fr 1fr; gap:0; border:1px solid var(--line); }
.tx-cm .c { padding:12px 14px; border-right:1px solid var(--line); border-bottom:1px solid var(--line); }
.tx-cm .c:nth-child(2n) { border-right:none; }
.tx-cm .c:nth-child(n+3) { border-bottom:none; }
.tx-cm .n { font:500 1.6rem var(--mono); color:var(--c); }
.tx-cm .l { color:var(--white); font-size:.74rem; text-transform:uppercase; letter-spacing:.08em; }
.tx-cm .s { color:var(--muted); font-size:.68rem; }

/* Graph legend */
.tx-legend { display:flex; gap:16px; flex-wrap:wrap; font-size:.66rem; color:var(--muted); margin-top:6px;
  font-family:var(--mono); text-transform:uppercase; letter-spacing:.06em; }
.tx-legend i { display:inline-block; width:20px; height:0; border-top:1px solid var(--c); vertical-align:middle; margin-right:6px; }
.tx-legend i.dash { border-top-style: dashed; }
.tx-legend b { display:inline-block; width:9px; height:9px; border-radius:50%; border:1px solid var(--c); vertical-align:middle; margin-right:6px; }

/* "What this does" descriptions */
.tx-about { border-left:2px solid var(--accent); padding:4px 0 4px 10px; margin:0 0 12px; color:#a3a3a3;
  font-size:.78rem; line-height:1.5; max-width:980px; }
.tx-about b { color:var(--white); font-weight:600; }

/* Presenter banner */
.tx-present { border:1px solid rgba(103,232,249,.45); background:linear-gradient(90deg, rgba(103,232,249,.10), rgba(103,232,249,.02));
  padding:12px 16px; margin:10px 0 6px; }
.tx-present .k { font:600 .7rem var(--mono); color:var(--accent); letter-spacing:.14em; text-transform:uppercase; }
.tx-present .t { font-size:1.25rem; font-weight:700; color:var(--white); margin-top:3px; }
.tx-present .s { color:#d4d4d4; font-size:.95rem; margin-top:4px; line-height:1.5; }
.tx-present .w { color:#8a8a8a; font:.75rem var(--mono); margin-top:6px; }

/* Footer ticker */
.tx-footer { display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px; margin-top:22px; padding-top:10px;
  border-top:1px solid var(--line); font:500 .64rem var(--mono); color:var(--muted); letter-spacing:.1em; text-transform:uppercase; }
.tx-footer span::before { content:"■ "; color:var(--grey); }
.tx-footer span.ok::before { color:var(--green); }
.tx-footer span.bad::before { color:var(--red); }
</style>
"""

LOGO = ('<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ececec" stroke-width="1.6" '
        'stroke-linecap="square"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l5 5"/>'
        '<path d="M8 11h2l1-2 1.5 4 1-2h1.5"/></svg>')

# 270° arc, centre (100, 95), radius 72.
GAUGE_ARC = "M 49.09 145.91 A 72 72 0 1 1 150.91 145.91"
# Tick marks every 10% along the arc (135° to 405°).
_ANGLES = [math.radians(135 + 27 * i) for i in range(11)]


def esc(value):
    return escape(str(value), quote=True)


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def header(chips):
    chip_html = "".join(f'<div class="tx-chip">{esc(k)} <b>{esc(v)}</b></div>' for k, v in chips)
    st.markdown(f"""
<div class="tx-header">
  <div class="tx-brand">
    <div class="tx-logo">{LOGO}</div>
    <div><div class="tx-kicker">Digital forensics · investigation console</div>
    <div class="tx-title">TRACEX <span>AI</span></div>
    <div class="tx-subtitle">Evidence-first cross-source incident investigation</div></div>
  </div>
  <div class="tx-chips"><div class="tx-chip tx-live">ENGINE READY</div>{chip_html}</div>
</div>""", unsafe_allow_html=True)


def kpis(items):
    """items: (label, value, sub, accent colour). The accent is a small square, not a fill."""
    cards = "".join(
        f'<div class="tx-kpi" style="--accent:{c}"><div class="label">{esc(l)}</div>'
        + (f'<div class="value count" style="--n:{int(v)}"></div>' if isinstance(v, int) else f'<div class="value">{esc(v)}</div>')
        + f'<div class="sub">{esc(s)}</div></div>'
        for l, v, s, c in items)
    st.markdown(f'<div class="tx-kpis">{cards}</div>', unsafe_allow_html=True)


def panel_title(title, note=""):
    st.markdown(f'<div class="tx-panel-title"><h4>{esc(title)}</h4><small>{esc(note)}</small></div>',
                unsafe_allow_html=True)


def pill(text, kind):
    return f'<span class="tx-pill {esc(kind)}">{esc(text)}</span>'


def detection_card(d, phase, incident_id, span):
    color = SEVERITY_COLOR[d.severity]
    where = pill(incident_id, "high") if incident_id else pill("standalone", "neutral")
    return f"""<div class="tx-det" style="--c:{color}">
  <div class="top">{pill(d.severity, d.severity)}<span class="rule">{esc(d.rule)}</span>
    <span class="phase">{esc(phase)}</span><span class="sp"></span>{where}</div>
  <div class="title">{esc(d.title)}</div>
  <div class="sum">{esc(d.summary)}</div>
  <div class="meta">{len(d.refs)} evidence record{'s' if len(d.refs) != 1 else ''} · {esc(span)}</div>
</div>"""


def record_card(row, chain_info=None, rule_titles=(), placeholder=False):
    """Forensic view of one original log record: provenance, links, detections, raw fields."""
    if placeholder or row is None:
        st.markdown('<div class="tx-rec empty">Select an event to inspect its original log record.</div>',
                    unsafe_allow_html=True)
        return
    raw = json.loads(row["raw"])
    when = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC") if str(row["timestamp"]) != "NaT" else "no valid timestamp"
    correction = row.get("time_correction_s", 0) or 0
    if correction and str(row.get("timestamp_raw")) != "NaT":
        when = (f"logged {row['timestamp_raw']:%H:%M:%S} · corrected {row['timestamp']:%H:%M:%S} UTC "
                f"(+{correction / 60:.1f} min host clock correction)")
    link = ""
    if chain_info:
        link = (f'<div class="box" style="--c:{RED}"><b>{esc(chain_info["incident"])} · step {esc(chain_info["step"])}</b>'
                f' {pill(chain_info["basis"], chain_info["basis"])}<br><span>{esc(chain_info["linked_by"])}</span></div>')
    dets = "".join(pill(t, "medium") for t in rule_titles)
    issue = (f'<div class="box" style="--c:{ORANGE}"><b>Data-quality issue</b><br><span>{esc(row["parse_issues"])}</span></div>'
             if row["parse_issues"] else "")
    fields = "".join(f'<div class="k">{esc(k)}</div><div class="v">{esc(v)}</div>' for k, v in raw.items())
    st.markdown(f"""<div class="tx-rec">
  <div class="hd">{pill(row["source"], "neutral")}<span class="ref">{esc(row["raw_ref"])}</span></div>
  <div class="act">{esc(row["action"])}</div>
  <div class="when">{esc(when)}</div>
  {link}{issue}
  {f'<div class="dets">{dets}</div>' if dets else ''}
  <div class="sec">Original record</div>
  <div class="tx-kv">{fields}</div>
</div>""", unsafe_allow_html=True)


def confusion(tp, fp, fn, tn):
    cells = [("True positives", tp, "attack events linked", GREEN), ("False positives", fp, "benign events linked", RED),
             ("Missed", fn, "attack events not linked", ORANGE), ("True negatives", tn, "benign events left out", WHITE)]
    html = "".join(f'<div class="c" style="--c:{c}"><div class="n">{esc(n)}</div><div class="l">{esc(l)}</div>'
                   f'<div class="s">{esc(s)}</div></div>' for l, n, s, c in cells)
    st.markdown(f'<div class="tx-cm">{html}</div>', unsafe_allow_html=True)


def threat_card(score, band, breakdown):
    """Ring gauge + band + where the points came from. Pure SVG, so it scales with its column."""
    color = BAND_COLOR[band]
    by_level = {"high": 0, "medium": 0, "low": 0}
    for b in breakdown:
        by_level[{20: "high", 8: "medium", 2: "low"}[b["points"]]] += 1
    counts = "".join(pill(f"{n} {level}", level) for level, n in by_level.items() if n)
    rows = "".join(
        f'<div class="tx-score-row"><span class="r">{esc(b["rule"])}</span>'
        f'<span class="f">{esc(b["finding"])}</span><span class="p">+{esc(b["points"])}</span></div>'
        for b in breakdown)
    from .widgets import threat_gauge  # widgets imports ui, so import here to avoid a cycle
    threat_gauge(score, band, color, counts or pill("no detections", "ok"), flash=band in ("Critical", "High"))
    st.markdown(f"""<details class="tx-details"><summary>Score breakdown · {len(breakdown)} rules</summary>
  <div class="tx-score">{rows or '<span class="note">Nothing detected.</span>'}</div></details>
""", unsafe_allow_html=True)


def progression(steps):
    """steps: dicts with phase, title, time, refs_label, basis, severity."""
    rows = "".join(
        f'<div class="tx-step" style="--c:{SEVERITY_COLOR.get(s["severity"], WHITE)};--i:{i}">'
        f'<div class="tx-dot">{i:02d}</div>'
        f'<div><div class="phase">{esc(s["phase"])}</div><div class="name">{esc(s["title"])}</div>'
        f'<div class="meta">{esc(s["time"])} · {esc(s["refs_label"])}</div></div>'
        f'<div>{pill(s["basis"], s["basis"])}</div></div>'
        for i, s in enumerate(steps, 1))
    st.markdown(f'<div class="tx-steps">{rows}</div>', unsafe_allow_html=True)


def facts(items):
    """items: (key, value) pairs shown as a two-column fact sheet."""
    rows = "".join(f'<div class="tx-fact"><div class="k">{esc(k)}</div><div class="v">{esc(v)}</div></div>'
                   for k, v in items)
    st.markdown(f'<div class="tx-facts">{rows}</div>', unsafe_allow_html=True)


def graph_legend():
    st.markdown(f"""<div class="tx-legend">
<span><b style="--c:{RED}"></b>attacker</span><span><b style="--c:{ORANGE}"></b>compromised</span>
<span><b style="--c:{WHITE}"></b>entity</span>
<span><i style="--c:{RED}"></i>high severity</span><span><i style="--c:{ORANGE}"></i>medium</span>
<span><i style="--c:{GREY}"></i>no detection</span><span><i class="dash" style="--c:{WHITE}"></i>inferred link</span>
<span>(E5) = chain step 5</span></div>""", unsafe_allow_html=True)


def footer(items):
    """items: (text, state) with state 'ok', 'bad' or ''."""
    spans = "".join(f'<span class="{esc(s)}">{esc(t)}</span>' for t, s in items)
    st.markdown(f'<div class="tx-footer">{spans}</div>', unsafe_allow_html=True)


def about(text):
    """One-line description of what a feature does, shown under its title."""
    st.markdown(f'<div class="tx-about"><b>What this does:</b> {esc(text)}</div>', unsafe_allow_html=True)


def presenter_banner(step, total, title, say, where):
    st.markdown(f"""<div class="tx-present"><div class="k">Presenter · step {step} of {total}</div>
<div class="t">{esc(title)}</div><div class="s">{esc(say)}</div><div class="w">Show: {esc(where)}</div></div>""",
                unsafe_allow_html=True)
