from pathlib import Path

import pytest

from tracex import custody, viz3d
from tracex.parsers import load_dataset
from tracex.pipeline import analyse
from tracex.widgets import _ring

DATA = Path(__file__).resolve().parent.parent / "data" / "tc01_attack"


@pytest.fixture(scope="module")
def tc01():
    if not (DATA / "custody.json").exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    events, _ = load_dataset(DATA)
    return analyse(events)


def test_terrain_bar_heights_sum_to_the_timed_events(tc01):
    inc = tc01.incidents[0]
    fig = viz3d.activity_terrain(tc01.view, (inc.entities["start"], inc.entities["end"]))
    total = sum(max(t.z[i:i + 8]) for t in fig.data for i in range(0, len(t.z), 8))   # 8 vertices per bar
    assert total == tc01.view["timestamp"].notna().sum()
    assert any("(incident)" in t.name for t in fig.data)


def test_terrain_handles_empty_input(tc01):
    assert viz3d.activity_terrain(tc01.view.iloc[0:0]) is None


def test_helix_marks_only_tampered_records():
    m = custody.load_manifest(DATA)
    files = custody.read_files(DATA)
    clean = viz3d.custody_helix(m, custody.verify(files, m))
    red = lambda fig: sum(c == viz3d.RED for t in fig.data if t.mode == "markers" for c in (t.marker.color or []))
    assert red(clean) == 0
    lines = files["auth.csv"].splitlines(keepends=True)
    del lines[18]
    files["auth.csv"] = b"".join(lines)
    assert red(viz3d.custody_helix(m, custody.verify(files, m))) == 1
    assert viz3d.custody_helix(None, {}) is None


def test_ring_puts_long_captions_below_the_dial():
    long = _ring(52, 52, "%", "14 of 27 steps remain", "attack chain after", "#fff")
    short = _ring(100, 100, "", "/ 100", "", "#fff")
    assert '<div class="sub">14 of 27 steps remain</div>' in long and 'class="unit"' not in long
    assert '<div class="unit">/ 100</div>' in short
    assert 'class="num long"' in _ring(100, 100, "%", "x", "", "#fff")      # "100%" uses the smaller size
