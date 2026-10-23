"""Unified chronological timeline chart."""
import plotly.express as px

OUTCOME_COLORS = {"success": "#2e7d32", "failure": "#c62828", "unknown": "#757575"}


def timeline_figure(events):
    """One row per source, one dot per event, coloured by outcome. Untimed events are left out."""
    timed = events.dropna(subset=["timestamp"]).sort_values("timestamp")
    fig = px.scatter(
        timed, x="timestamp", y="source", color="outcome", color_discrete_map=OUTCOME_COLORS,
        hover_data={"raw_ref": True, "user": True, "src_ip": True, "action": True,
                    "timestamp": "|%Y-%m-%d %H:%M:%S", "source": False, "outcome": False},
        category_orders={"source": ["auth", "web", "system"]},
    )
    fig.update_traces(marker={"size": 9, "opacity": 0.8})
    fig.update_layout(height=320, margin={"l": 10, "r": 10, "t": 10, "b": 10},
                      xaxis_title="Time (UTC)", yaxis_title=None, legend_title="Outcome")
    return fig
