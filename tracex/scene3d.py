"""Streamlit wrapper for the 3D investigation component (tracex/frontend/scene3d/index.html).

A bidirectional component built on Streamlit's documented iframe protocol, with no npm build step and no
CDN: everything it needs ships in the repository, so it works offline. It returns
{"selected": event_id, "ref": raw_ref, "data_id": ...} only when the investigator presses
"Send to explorer"; ordinary clicks stay inside the component, so they never rerun the app.
"""
from pathlib import Path

import streamlit.components.v1 as components

from . import scene

_component = components.declare_component(
    "tracex_scene3d", path=str(Path(__file__).parent / "frontend" / "scene3d"))


def scene3d(data, key="scene3d"):
    scene.validate(data)
    return _component(data=data, key=key, default=None)
