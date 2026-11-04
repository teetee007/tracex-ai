from pathlib import Path

from tracex.assessment import progression, threat_score
from tracex.correlate import reconstruct
from tracex.detections import run_all
from tracex.graph import build, render_html, step_ranges
from tracex.parsers import load_dataset

DATASET = Path(__file__).resolve().parent.parent / "data" / "tc01_attack"


def _tc01():
    events, _ = load_dataset(DATASET)
    detections = run_all(events)
    return detections, reconstruct(events, detections)[0]


def test_step_ranges():
    assert step_ranges([3, 1, 2, 5, 7, 8]) == "E1–E3, E5, E7–E8"


def test_graph_edges_cover_every_chain_step_once():
    detections, inc = _tc01()
    nodes, edges = build(inc, detections)
    ids = {n["id"] for n in nodes}
    assert {"ip:203.0.113.45", "user:jsmith", "host:web-01", "host:portal"} <= ids
    assert all(e["from"] in ids and e["to"] in ids for e in edges)
    labels = " ".join(e["label"] for e in edges)
    assert "Failed login (portal) ×14 (E1–E14)" in labels
    assert any(e["label"].startswith("Exfiltration") and e["to"] == "ip:203.0.113.45" for e in edges)


def test_inferred_links_are_drawn_dashed():
    detections, inc = _tc01()
    _, edges = build(inc, detections)
    commands = next(e for e in edges if e["label"].startswith("Commands"))
    assert commands["dashes"] is True
    assert "whoami" in commands["title"]  # each command is listed in the hover tooltip


def test_replay_order_follows_the_evidence_chain():
    detections, inc = _tc01()
    _, edges = build(inc, detections)
    first = min(edges, key=lambda e: e["order"])
    last = max(edges, key=lambda e: e["order"])
    assert first["caption"].startswith("E1 · Failed login")
    assert last["caption"].startswith("E27 · Exfiltration")


def test_rendered_html_escapes_script_tags():
    html = render_html([{"id": "x", "label": "</script><b>"}], [])
    assert "</script><b>" not in html


def test_threat_score_and_progression():
    detections, inc = _tc01()
    score, band, breakdown = threat_score(detections)
    assert (score, band) == (100, "Critical")
    assert {b["rule"] for b in breakdown} >= {"R1", "R9"}
    phases = [s["phase"] for s in progression(inc)]
    assert phases[0] == "Initial access" and phases[-1] == "Exfiltration"


def test_benign_detections_score_low():
    score, band, _ = threat_score([])
    assert (score, band) == (0, "Low")
