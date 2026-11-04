from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from tracex import features
from tracex.parsers import load_dataset
from tracex.pipeline import analyse

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def _load(name):
    if not (DATA / name).exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    events, info = load_dataset(DATA / name)
    return analyse(events, False), analyse(events, True), info


def test_before_after_reports_the_measured_tc04_numbers():
    base, aware, info = _load("tc04_clock_skew")
    fig, rows = features.before_after(base, aware, info["ground_truth"])
    assert [(r["incidents"], r["missed"]) for r in rows] == [(2, 5), (1, 0)]
    names = {t.name for t in fig.data}
    assert "before: INC-02" in names and "after: INC-01" in names and "before: not linked" in names


def test_before_after_is_identical_when_clocks_agree():
    base, aware, info = _load("tc01_attack")
    _, rows = features.before_after(base, aware, info["ground_truth"])
    assert rows[0]["incidents"] == rows[1]["incidents"] == 1 and rows[0]["missed"] == rows[1]["missed"] == 0


def test_before_after_has_nothing_to_show_without_incidents():
    base, aware, info = _load("tc02_benign")
    assert features.before_after(base, aware, info["ground_truth"]) == (None, [])


def test_matrix_lights_only_supported_techniques():
    _, a, _ = _load("tc01_attack")
    html, lit = features.attack_matrix_html(a.view, a.detections, set(a.incidents[0].chain["raw_ref"]))
    assert lit == 9
    assert html.count("class='cell mapped'") + html.count("class='cell candidate'") == 9
    assert "class='cell '" in html                          # catalogue techniques not seen stay grey


def test_blast_radius_comes_from_cited_events():
    _, a, _ = _load("tc01_attack")
    br = features.blast_radius(a.incidents[0], a.view)
    assert br["attackers"] == ["203.0.113.45"] and br["accounts"] == ["jsmith"]
    assert set(br["hosts"]) == {"portal", "web-01"}
    assert {w for w, *_ in br["impact"]} == {"data accessed", "data sent out", "persistence"}
    refs = set(a.incidents[0].chain["raw_ref"])
    assert all(ref in refs for _, _, ref, _ in br["impact"])
    svg = features.blast_radius_svg(br)
    assert svg.startswith("<svg") and "backup_svc" in svg


def test_presenter_steps_point_at_real_datasets_and_pages():
    for s in features.PRESENTER_STEPS:
        assert (DATA / s["dataset"]).is_dir() and s["page"] in {"investigate", "evidence", "validate"}
        assert s["title"] and s["say"] and s["tab"]


def test_presenter_mode_renders_and_advances(monkeypatch):
    monkeypatch.setenv("TRACEX_START_PAGE", "investigate")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=90)
    at.session_state["presenter"] = True
    at.run()
    assert not at.exception
    page = " ".join(m.value for m in at.markdown)
    assert "Presenter · step 1 of" in page and "What this does" in page
    next(b for b in at.button if b.label.startswith("Next")).click().run()
    assert not at.exception
    assert at.session_state["presenter_step"] == 1 and at.session_state["dataset"] == "tc01_attack"
