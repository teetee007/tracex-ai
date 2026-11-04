import shutil
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parent.parent / "app.py"


def _page(text_page, monkeypatch, app=APP):
    monkeypatch.setenv("TRACEX_START_PAGE", text_page)
    at = AppTest.from_file(str(app), default_timeout=90).run()
    assert not at.exception, at.exception
    return at, " ".join(m.value for m in at.markdown)


def test_investigate_page_shows_the_incident(monkeypatch):
    at, page = _page("investigate", monkeypatch)
    assert "Events ingested" in page and "--n:111" in page          # shared header + KPIs
    assert "Attack graph · INC-01" in page and "Exfiltration" in page
    assert "citation check passed" in page                          # Explanation tab


def test_evidence_page_renders_explorer_and_detections(monkeypatch):
    _, page = _page("evidence", monkeypatch)
    assert "Original record" in page                                 # explorer shows the top record
    assert "Password guessing followed by successful login" in page  # detection cards
    assert "Initial Access" in page                                  # ATT&CK tactics
    assert "Chain of custody" in page and "verified" in page         # integrity tab


def test_validate_page_renders_mitigation_and_lab(monkeypatch):
    _, page = _page("validate", monkeypatch)
    assert "Account lockout" in page and "Evaluation lab" in page
    assert "Incident report" in page and "intelligence exports" in page


@pytest.mark.parametrize("start", ["investigate", "evidence", "validate"])
def test_every_page_works_when_a_source_is_missing(start, tmp_path, monkeypatch):
    data = tmp_path / "data" / "tc03_partial"
    data.mkdir(parents=True)
    src = APP.parent / "data" / "tc01_attack"
    for name in ("auth.csv", "web_access.json", "dataset.json"):
        shutil.copy(src / name, data / name)
    shutil.copy(APP, tmp_path / "app.py")
    shutil.copytree(APP.parent / "tracex", tmp_path / "tracex")
    at, _ = _page(start, monkeypatch, tmp_path / "app.py")
    assert any("Missing log sources: system" in w.value for w in at.warning)
