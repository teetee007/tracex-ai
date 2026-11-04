"""Plotly 3D views built only from real data (Plotly's WebGL bundle ships with Streamlit, so they work offline).

  activity_terrain – 3D bars: events per time slice (x) per log source (y), height = count; slices inside the
                     incident window are drawn in red.
  custody_helix    – each log file as a helix of hash-chained records; a record that no longer matches its seal
                     turns red (modified), shows a red X (deleted) or a red diamond (inserted).
"""
import math

import pandas as pd
import plotly.graph_objects as go

from .ui import DIM, GREEN, GREY, RED, WHITE

SOURCES = ["auth", "web", "system"]
SOURCE_COLOR = {"auth": "#a78bfa", "web": "#38bdf8", "system": "#e2e8f0"}
SCENE = dict(bgcolor="rgba(0,0,0,0)",
             xaxis=dict(gridcolor="rgba(255,255,255,.08)", zerolinecolor="rgba(255,255,255,.12)", color="#9a9a9a",
                        showbackground=False),
             yaxis=dict(gridcolor="rgba(255,255,255,.08)", zerolinecolor="rgba(255,255,255,.12)", color="#9a9a9a",
                        showbackground=False),
             zaxis=dict(gridcolor="rgba(255,255,255,.08)", zerolinecolor="rgba(255,255,255,.12)", color="#9a9a9a",
                        showbackground=False))


def _layout(fig, height, eye):
    fig.update_layout(height=height, paper_bgcolor="rgba(0,0,0,0)", margin=dict(l=0, r=0, t=0, b=0),
                      font=dict(family="JetBrains Mono, monospace", color="#9a9a9a", size=11),
                      legend=dict(orientation="h", y=1.0, x=0, bgcolor="rgba(0,0,0,0)"),
                      hoverlabel=dict(bgcolor="#0c0c0c", bordercolor=GREY, font=dict(color=WHITE)),
                      scene={**SCENE, "camera": dict(eye=eye)})
    return fig


def _box(x0, x1, y0, y1, z):
    """Vertices and triangles of one closed cuboid from (x0,y0,0) to (x1,y1,z)."""
    xs = [x0, x1, x1, x0, x0, x1, x1, x0]
    ys = [y0, y0, y1, y1, y0, y0, y1, y1]
    zs = [0, 0, 0, 0, z, z, z, z]
    i = [0, 0, 4, 4, 0, 0, 1, 1, 2, 2, 3, 3]
    j = [1, 2, 5, 6, 1, 5, 2, 6, 3, 7, 0, 4]
    k = [2, 3, 6, 7, 5, 4, 6, 5, 7, 6, 4, 7]
    return xs, ys, zs, i, j, k


def activity_terrain(events, window=None, bin_minutes=15):
    timed = events.dropna(subset=["timestamp"]).copy()
    if timed.empty:
        return None
    timed["bin"] = timed["timestamp"].dt.floor(f"{bin_minutes}min")
    bins = sorted(timed["bin"].unique())
    pos = {b: n for n, b in enumerate(bins)}
    counts = timed.groupby(["bin", "source"]).size()
    fig = go.Figure()
    for hot in (False, True):
        for src in SOURCES:
            X, Y, Z, I, J, K, text = [], [], [], [], [], [], []
            for (b, s), c in counts.items():
                if s != src:
                    continue
                inside = window is not None and window[0].floor(f"{bin_minutes}min") <= b <= window[1]
                if inside != hot:
                    continue
                x, y = pos[b], SOURCES.index(src)
                xs, ys, zs, i, j, k = _box(x + .12, x + .88, y + .15, y + .85, c)
                base = len(X)
                X += xs; Y += ys; Z += zs
                I += [v + base for v in i]; J += [v + base for v in j]; K += [v + base for v in k]
                text += [f"{src} · {b:%H:%M}–{(b + pd.Timedelta(minutes=bin_minutes)):%H:%M} UTC · {c} events"
                         + (" · incident window" if hot else "")] * 8
            if not X:
                continue
            fig.add_trace(go.Mesh3d(x=X, y=Y, z=Z, i=I, j=J, k=K, flatshading=True, opacity=1 if hot else 0.85,
                                    color=RED if hot else SOURCE_COLOR[src], name=f"{src}{' (incident)' if hot else ''}",
                                    showlegend=True, hovertext=text, hoverinfo="text",
                                    lighting=dict(ambient=.55, diffuse=.7, specular=.2, roughness=.6)))
    step = max(1, len(bins) // 8)
    fig.update_layout(scene=dict(
        xaxis=dict(title="time (UTC)", tickvals=[n + .5 for n in range(0, len(bins), step)],
                   ticktext=[f"{bins[n]:%H:%M}" for n in range(0, len(bins), step)]),
        yaxis=dict(title="", tickvals=[.5, 1.5, 2.5], ticktext=SOURCES),
        zaxis=dict(title=f"events / {bin_minutes} min"),
        aspectratio=dict(x=2.4, y=.9, z=.7)))
    return _layout(fig, 360, eye=dict(x=1.5, y=-1.7, z=1.0))


def custody_helix(manifest, result):
    """One helix per file, records in sealed order; tampering from `result` is marked on the record."""
    if not manifest:
        return None
    by_file = {f["file"]: f for f in result.get("files", [])}
    fig = go.Figure()
    for n, f in enumerate(manifest["files"]):
        name, count = f["file"], f["records"]
        marks = {}
        for ch in by_file.get(name, {}).get("changes", []):
            for loc in ch["sealed_records"]:
                marks[loc] = ch["op"]
        loc = (lambda k: f"{name}:{k + 2}") if name.endswith(".csv") else (lambda k: f"{name}#{k}")
        cx, R = n * 4.0, 1.0
        xs = [cx + R * math.cos(k * .55) for k in range(count)]
        ys = [R * math.sin(k * .55) for k in range(count)]
        zs = list(range(count))
        colors = [RED if marks.get(loc(k)) else GREEN for k in range(count)]
        symbols = ["x" if marks.get(loc(k)) == "deleted" else "circle" for k in range(count)]
        hover = [f"{loc(k)}<br>record sha256 {f['record_sha256'][k][:16]}…<br>"
                 + (f"<b>{marks[loc(k)].upper()} since sealing</b>" if marks.get(loc(k)) else "matches seal")
                 for k in range(count)]
        fig.add_trace(go.Scatter3d(x=xs, y=ys, z=zs, mode="lines", line=dict(color="rgba(103,232,249,.45)", width=3),
                                   hoverinfo="skip", showlegend=False))
        fig.add_trace(go.Scatter3d(x=xs, y=ys, z=zs, mode="markers", name=name,
                                   marker=dict(size=[7 if marks.get(loc(k)) else 3.5 for k in range(count)],
                                               color=colors, symbol=symbols, line=dict(width=0)),
                                   hovertext=hover, hoverinfo="text"))
        fig.add_trace(go.Scatter3d(x=[cx], y=[0], z=[count + 3], mode="text", text=[name], showlegend=False,
                                   textfont=dict(color=WHITE, size=11), hoverinfo="skip"))
        inserted = [c for c in by_file.get(name, {}).get("changes", []) if c["op"] == "inserted"]
        if inserted:
            fig.add_trace(go.Scatter3d(x=[cx + 1.6], y=[0], z=[count / 2], mode="markers+text", text=["inserted record(s)"],
                                       marker=dict(size=8, color=RED, symbol="diamond"), textfont=dict(color=RED),
                                       name="inserted", hoverinfo="text",
                                       hovertext=", ".join(r for c in inserted for r in c["current_records"])))
    fig.update_layout(scene=dict(xaxis=dict(visible=False), yaxis=dict(visible=False),
                                 zaxis=dict(title="record order (sealed)", color=DIM), aspectmode="data"),
                      showlegend=False)
    return _layout(fig, 420, eye=dict(x=1.2, y=-1.9, z=.55))
