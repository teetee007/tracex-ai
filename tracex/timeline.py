"""Charts: unified timeline and activity histogram (dark theme)."""
import plotly.express as px

from .ui import DIM, GREEN, GREY, RED, WHITE

OUTCOME_COLORS = {"success": GREEN, "failure": RED, "unknown": GREY}
SOURCE_COLORS = {"auth": WHITE, "web": GREY, "system": DIM}
SOURCE_ORDER = ["auth", "web", "system"]


def _style(fig, height):
    fig.update_layout(
        template="plotly_dark", height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin={"l": 10, "r": 10, "t": 10, "b": 10}, font={"family": "JetBrains Mono, monospace", "color": "#9a9a9a", "size": 11},
        legend={"orientation": "h", "y": 1.12, "x": 0, "title": None, "bgcolor": "rgba(0,0,0,0)"},
        hoverlabel={"bgcolor": "#0c0c0c", "bordercolor": GREY, "font": {"color": WHITE, "family": "JetBrains Mono, monospace"}},
    )
    fig.update_xaxes(gridcolor="rgba(255,255,255,.06)", zeroline=False, linecolor="rgba(255,255,255,.18)")
    fig.update_yaxes(gridcolor="rgba(255,255,255,.06)", zeroline=False)
    return fig


HOVER = ("<b>%{customdata[1]}</b><br>%{x|%H:%M:%S} · %{customdata[2]}<br>"
         "user: %{customdata[3]}  ip: %{customdata[4]}<br><span style='color:#9a9a9a'>%{customdata[0]}</span>"
         "<extra></extra>")


def timeline_figure(events, highlight=None, incident_refs=()):
    """One lane per source, one dot per event, coloured by outcome. Incident events get a glowing ring.
    Points carry their raw_ref in customdata[0] so a click can open the original record."""
    timed = events.dropna(subset=["timestamp"]).sort_values("timestamp").copy()
    timed["in_incident"] = timed["raw_ref"].isin(set(incident_refs))
    custom = ["raw_ref", "action", "outcome", "user", "src_ip"]
    fig = px.scatter(timed, x="timestamp", y="source", color="outcome", color_discrete_map=OUTCOME_COLORS,
                     custom_data=custom, category_orders={"source": SOURCE_ORDER})
    fig.update_traces(marker={"size": 9, "opacity": 0.75, "line": {"width": 1, "color": "#0a0a0a"}},
                      hovertemplate=HOVER)
    hot = timed[timed["in_incident"]]
    if not hot.empty:
        fig.add_scatter(x=hot["timestamp"], y=hot["source"], mode="markers", name="incident event",
                        customdata=hot[custom].values, hovertemplate=HOVER,
                        marker={"size": 17, "color": "rgba(0,0,0,0)", "line": {"width": 1.5, "color": RED}})
    if highlight:
        fig.add_vrect(x0=highlight[0], x1=highlight[1], fillcolor=RED, opacity=0.07, line_width=0)
    fig.update_layout(xaxis_title=None, yaxis_title=None, clickmode="event+select", dragmode="pan",
                      xaxis={"rangeslider": {"visible": True, "thickness": 0.07, "bgcolor": "rgba(255,255,255,.03)"}})
    return _style(fig, 400)


def coverage_figure(coverage):
    """Bar per source from its first to its last timestamp: gaps and missing sources stand out."""
    cov = coverage.copy()
    cov["label"] = cov["records"].astype(str) + " records"
    fig = px.timeline(cov, x_start="first", x_end="last", y="source", color="source", text="label",
                      color_discrete_map=SOURCE_COLORS, category_orders={"source": SOURCE_ORDER})
    fig.update_traces(marker_line_width=0, opacity=0.85, textposition="inside", insidetextanchor="middle",
                      hovertemplate="%{y}: %{base|%H:%M} → %{x|%H:%M}<extra></extra>")
    fig.update_layout(showlegend=False, xaxis_title=None, yaxis_title=None, bargap=0.45)
    return _style(fig, 200)


def per_source_figure(rows):
    """Grouped bars: attack events in the ground truth vs correctly linked, per source."""
    fig = px.bar(rows, x="source", y="events", color="kind", barmode="group",
                 color_discrete_map={"ground truth": "rgba(255,255,255,.22)", "correctly linked": GREEN},
                 category_orders={"source": SOURCE_ORDER})
    fig.update_traces(marker_line_width=0)
    fig.update_layout(xaxis_title=None, yaxis_title="attack events", bargap=0.35)
    return _style(fig, 260)


def activity_figure(events, highlight=None, bin_minutes=15):
    """Stacked bars: events per time bin, per source."""
    timed = events.dropna(subset=["timestamp"]).copy()
    timed["bin"] = timed["timestamp"].dt.floor(f"{bin_minutes}min")
    counts = timed.groupby(["bin", "source"]).size().reset_index(name="events")
    fig = px.bar(counts, x="bin", y="events", color="source", color_discrete_map=SOURCE_COLORS,
                 category_orders={"source": SOURCE_ORDER})
    fig.update_traces(marker_line_width=0, opacity=0.9)
    if highlight:
        fig.add_vrect(x0=highlight[0], x1=highlight[1], fillcolor=RED, opacity=0.10, line_width=0)
    fig.update_layout(bargap=0.25, xaxis_title=None, yaxis_title=f"events / {bin_minutes} min")
    return _style(fig, 250)


def lab_figure(df):
    """Recall per scenario, baseline vs clock-aware (scenarios with attack events only)."""
    d = df[df["recall"].notna()].copy()
    d["recall %"] = d["recall"] * 100
    d["label"] = d["recall %"].round(0).astype(int).astype(str) + "%"
    fig = px.bar(d, x="scenario", y="recall %", color="mode", barmode="group", text="label",
                 color_discrete_map={"baseline": "rgba(255,255,255,.28)", "clock-aware": GREEN})
    fig.update_traces(marker_line_width=0, textposition="outside")
    fig.update_layout(yaxis_range=[0, 112], xaxis_title=None, yaxis_title="attack events recovered (%)", bargap=0.3)
    return _style(fig, 280)
