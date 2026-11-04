"""Entity attack graph: who (IP, user) did what to which system, with evidence on every edge.

Nodes are entities (IP addresses, accounts, hosts). Edges are groups of chain events, labelled
with what happened and which chain steps prove it, e.g. "Failed portal login ×14 (E1–E14)".
Rendered with vis-network, loaded from the copy bundled inside pyvis, so it works offline.
"""
import json
from pathlib import Path
from urllib.parse import quote

import pyvis

from .detections import IP_IN_TEXT, SEVERITY_RANK, is_external
from .ui import GREY, ORANGE, RED, WHITE

VIS_JS = Path(pyvis.__file__).parent / "lib" / "vis-9.1.2" / "vis-network.min.js"

GLYPHS = {  # 24x24 line icons
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/>',
    "host": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/>'
            '<path d="M7 6.5h.01M7 17.5h.01"/>',
    "external": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9'
                'c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>',
    "internal": '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19h20"/>',
}
EDGE_COLOR = {3: RED, 2: ORANGE, 1: GREY, 0: GREY}


def _icon(kind, ring):
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
           f'<circle cx="32" cy="32" r="29" fill="#0c0c0c" stroke="{ring}" stroke-width="2"/>'
           f'<circle cx="32" cy="32" r="24" fill="none" stroke="{ring}" stroke-opacity="0.35" stroke-width="1"/>'
           f'<g transform="translate(20 20)" fill="none" stroke="{ring}" stroke-width="1.8" '
           f'stroke-linecap="round" stroke-linejoin="round">{GLYPHS[kind]}</g></svg>')
    return "data:image/svg+xml;charset=utf-8," + quote(svg)


def step_ranges(steps):
    """[1,2,3,5] -> 'E1–E3, E5'."""
    steps, parts, i = sorted(steps), [], 0
    while i < len(steps):
        j = i
        while j + 1 < len(steps) and steps[j + 1] == steps[j] + 1:
            j += 1
        parts.append(f"E{steps[i]}" if i == j else f"E{steps[i]}–E{steps[j]}")
        i = j + 1
    return ", ".join(parts)


def _short_command(action, limit=26):
    words = action.split()
    files = [Path(w).name for w in words if "/" in w and "@" not in w]
    text = f"{words[0]} {files[0]}" if words and files else action
    return text if len(text) <= limit else text[:limit - 1] + "…"


def build(incident, detections):
    """Return (nodes, edges) as vis-network dictionaries for one incident."""
    rule_severity = {d.rule: SEVERITY_RANK[d.severity] for d in detections}
    chain = incident.chain
    compromised_users = set(chain.loc[chain["source"] == "system", "user"]) | {
        u for u in chain.loc[(chain["source"] == "auth") & (chain["outcome"] == "success"), "user"]}
    attacked_hosts = set(chain.loc[chain["source"] == "system", "host"])

    nodes, edges = {}, {}

    def node(kind, value):
        node_id = f"{kind}:{value}"
        if node_id not in nodes:
            if kind == "ip":
                ext = is_external(value)
                icon, ring, what = ("external", RED, "External IP") if ext else ("internal", WHITE, "Internal IP")
            elif kind == "user":
                icon, what = "user", "Account"
                ring = ORANGE if value in compromised_users else WHITE
            else:
                icon, what = "host", "Host"
                ring = ORANGE if value in attacked_hosts else WHITE
            nodes[node_id] = {"id": node_id, "label": value, "shape": "image", "image": _icon(icon, ring),
                              "size": 26, "title": f"{what}: {value}", "_events": 0,
                              "shadow": {"enabled": False}}
        nodes[node_id]["_events"] += 1
        return node_id

    def edge(src, dst, label, row):
        key = (src, dst, label)
        e = edges.setdefault(key, {"steps": [], "refs": [], "actions": [], "rules": set(), "bases": set()})
        e["steps"].append(int(row["step"]))
        e["refs"].append(row["raw_ref"])
        e["actions"].append(f"E{row['step']} {row['action']}")
        e["rules"] |= {r for r in row["detections"].split(", ") if r}
        e["bases"].add(row["link_basis"])

    for _, row in chain.iterrows():
        rules = set(row["detections"].split(", ")) - {""}
        if row["source"] == "auth":
            method = "SSH" if " ssh " in f" {row['action']} " else "portal"
            ok = row["outcome"] == "success"
            ip, user = node("ip", row["src_ip"]), node("user", row["user"])
            edge(ip, user, "Successful login" if ok else f"Failed login ({method})", row)
            if ok:
                edge(user, node("host", row["host"]), f"{method} session", row)
        elif row["source"] == "web":
            label = row["action"] if "R6" in rules else "Web requests"
            edge(node("ip", row["src_ip"]), node("host", row["host"]), label, row)
        else:
            host, user = node("host", row["host"]), node("user", row["user"])
            targets = [ip for ip in IP_IN_TEXT.findall(row["action"]) if is_external(ip)]
            if "R9" in rules and targets:
                edge(host, node("ip", targets[0]), f"Exfiltration: {_short_command(row['action'])}", row)
            elif "R8" in rules:
                new_account = row["action"].split()[-1]
                compromised_users.add(new_account)
                edge(user, node("user", new_account), f"Created account on {row['host']}", row)
            else:
                edge(user, host, "Commands", row)

    vis_edges = []
    for (src, dst, label), e in edges.items():
        rank = max((rule_severity.get(r, 0) for r in e["rules"]), default=0)
        inferred = e["bases"] == {"inferred"}
        count = f" ×{len(e['steps'])}" if len(e["steps"]) > 1 else ""
        color = EDGE_COLOR[rank]
        refs = ", ".join(e["refs"][:6]) + (f" … (+{len(e['refs']) - 6})" if len(e["refs"]) > 6 else "")
        shown = e["actions"][:8] + ([f"… (+{len(e['actions']) - 8} more)"] if len(e["actions"]) > 8 else [])
        vis_edges.append({
            "from": src, "to": dst, "order": min(e["steps"]),
            "caption": f"E{min(e['steps'])} · {label}{count}",
            "label": f"{label}{count} ({step_ranges(e['steps'])})",
            "color": {"color": color, "highlight": color, "hover": color, "opacity": 0.9},
            "dashes": inferred, "width": 1 + min(len(e["steps"]), 10) * 0.15,
            "shadow": {"enabled": False},
            "title": f"{label}{count}\n" + "\n".join(shown) +
                     f"\n\nEvidence: {refs}\nRules: {', '.join(sorted(e['rules'])) or 'none'}\n"
                     f"Link: {'inferred (hypothesis)' if inferred else 'observed'}",
        })

    # Fan out edges between the same two entities so neither the curves nor the labels overlap.
    pair_count = {}
    for e in vis_edges:
        pair = tuple(sorted((e["from"], e["to"])))
        k = pair_count.get(pair, 0)
        pair_count[pair] = k + 1
        forward = e["from"] == pair[0]
        clockwise = (k % 2 == 0) == forward
        e["smooth"] = {"enabled": True, "type": "curvedCW" if clockwise else "curvedCCW",
                       "roundness": 0.1 + 0.22 * ((k + 1) // 2)}

    vis_nodes = []
    for n in nodes.values():
        n["title"] += f"\nEvents in chain: {n.pop('_events')}"
        vis_nodes.append(n)
    return vis_nodes, vis_edges


OPTIONS = {
    "nodes": {"font": {"color": "#ececec", "face": "JetBrains Mono, monospace", "size": 12, "vadjust": 4,
                       "strokeWidth": 4, "strokeColor": "#0a0a0a"},
              "shapeProperties": {"interpolation": True}},
    "edges": {"arrows": {"to": {"enabled": True, "scaleFactor": 0.55}},
              "font": {"color": "#bdbdbd", "size": 11, "face": "JetBrains Mono, monospace", "strokeWidth": 5,
                       "strokeColor": "#0a0a0a", "align": "horizontal"},
              "selectionWidth": 1.5},
    "physics": {"solver": "forceAtlas2Based",
                "forceAtlas2Based": {"gravitationalConstant": -260, "springLength": 330, "springConstant": 0.04,
                                     "avoidOverlap": 1},
                "stabilization": {"iterations": 600}},
    "layout": {"randomSeed": 7},
    "interaction": {"hover": True, "tooltipDelay": 120, "zoomView": True},
}


def render_html(nodes, edges, height=520):
    data = json.dumps({"nodes": nodes, "edges": edges, "options": OPTIONS}).replace("</", "<\\/")
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
html,body{{margin:0;background:transparent;overflow:hidden}}
#net{{width:100%;height:{height}px;
  background-image:radial-gradient(rgba(255,255,255,.07) 1px, transparent 1px);background-size:24px 24px;}}
div.vis-tooltip{{position:absolute;background:#0c0c0c;color:#ececec;border:1px solid rgba(255,255,255,.25);
  border-radius:2px;padding:8px 10px;font:11px 'JetBrains Mono',monospace;white-space:pre-line;max-width:340px;
  box-shadow:0 8px 24px rgba(0,0,0,.55)}}
#hud{{position:absolute;top:8px;right:8px;display:flex;gap:8px;align-items:center;font:500 10px 'JetBrains Mono',monospace}}
#hud button{{background:#0c0c0c;color:#ececec;border:1px solid rgba(255,255,255,.3);border-radius:2px;padding:5px 10px;
  font:inherit;letter-spacing:.1em;text-transform:uppercase;cursor:pointer}}
#hud button:hover{{border-color:#ececec}}
#cap{{position:absolute;left:10px;bottom:10px;font:500 11px 'JetBrains Mono',monospace;color:#ececec;
  letter-spacing:.06em;background:rgba(10,10,10,.85);border:1px solid rgba(255,255,255,.15);padding:5px 10px;
  opacity:0;transition:opacity .3s}}
#cap.on{{opacity:1}} #cap b{{color:#e5484d;font-weight:500}}
#bar{{position:absolute;left:0;bottom:0;height:2px;background:#e5484d;width:0;transition:width .3s}}
</style><script>{VIS_JS.read_text(encoding="utf-8")}</script></head><body>
<div id="net"></div><div id="hud"><button id="play">▶ Replay attack</button><button id="all">Show all</button></div>
<div id="cap"></div><div id="bar"></div><script>
const d = {data};
const nodes = new vis.DataSet(d.nodes), edges = new vis.DataSet(d.edges);
const net = new vis.Network(document.getElementById("net"), {{nodes, edges}}, d.options);
const seq = edges.get().sort((a, b) => a.order - b.order);
const cap = document.getElementById("cap"), bar = document.getElementById("bar");
let timer = null, played = false;

function showAll() {{
  clearTimeout(timer);
  nodes.update(nodes.get().map(n => ({{id: n.id, hidden: false}})));
  edges.update(seq.map(e => ({{id: e.id, hidden: false}})));
  cap.className = ""; bar.style.width = "0";
}}
// Reveal the attack edge by edge, in the order the evidence happened.
function replay() {{
  clearTimeout(timer);
  nodes.update(nodes.get().map(n => ({{id: n.id, hidden: true}})));
  edges.update(seq.map(e => ({{id: e.id, hidden: true}})));
  let i = 0;
  const next = () => {{
    if (i >= seq.length) {{ timer = setTimeout(() => {{ cap.className = ""; bar.style.width = "0"; }}, 1800); return; }}
    const e = seq[i++];
    nodes.update([{{id: e.from, hidden: false}}, {{id: e.to, hidden: false}}]);
    edges.update({{id: e.id, hidden: false}});
    net.selectEdges([e.id]);
    cap.innerHTML = ""; const b = document.createElement("b"); b.textContent = e.caption.split(" · ")[0];
    cap.append(b, " · " + e.caption.split(" · ").slice(1).join(" · "));
    cap.className = "on"; bar.style.width = (100 * i / seq.length) + "%";
    timer = setTimeout(next, 900);
  }};
  next();
}}
document.getElementById("play").onclick = replay;
document.getElementById("all").onclick = () => {{ net.unselectAll(); showAll(); }};
net.once("stabilizationIterationsDone", () => {{
  net.setOptions({{physics: false}}); net.fit({{animation: {{duration: 500}}}});
  // Play once automatically the first time the graph is on screen.
  new IntersectionObserver(es => es.forEach(x => {{ if (x.isIntersecting && !played) {{ played = true; setTimeout(replay, 600); }} }}),
                           {{threshold: 0.4}}).observe(document.body);
}});
</script></body></html>"""
