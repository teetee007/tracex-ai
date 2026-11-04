from pathlib import Path

import pytest

from tracex.lab import run, to_markdown

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def df():
    if not (DATA / "tc04_clock_skew").exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    return run(DATA)


def test_lab_covers_every_scenario_in_both_modes(df):
    assert len(df) == 10 and set(df["mode"]) == {"baseline", "clock-aware"}


def test_tc04_before_and_after_are_the_reported_numbers(df):
    row = lambda mode: df[(df["scenario"] == "tc04_clock_skew") & (df["mode"] == mode)].iloc[0]
    before, after = row("baseline"), row("clock-aware")
    assert (before["incidents"], before["missed"], before["fragmentation"]) == (2, 5, "split into 2")
    assert (after["incidents"], after["missed"], after["recall"], after["precision"]) == (1, 0, 1.0, 1.0)


def test_clock_awareness_changes_nothing_else(df):
    cols = ["incidents", "linked", "missed", "false positives"]
    for name in set(df["scenario"]) - {"tc04_clock_skew"}:
        b = df[(df["scenario"] == name) & (df["mode"] == "baseline")][cols].values.tolist()
        a = df[(df["scenario"] == name) & (df["mode"] == "clock-aware")][cols].values.tolist()
        assert a == b, name


def test_no_false_positives_and_no_false_incidents_anywhere(df):
    aware = df[df["mode"] == "clock-aware"]
    assert (aware["false positives"] == 0).all()
    assert (aware["incidents"] == aware["expected incidents"]).all()
    assert (aware["gaps found"] == aware["gaps expected"]).all()


def test_markdown_report_is_generated(df):
    md = to_markdown(df)
    assert "| tc04_clock_skew | baseline | 2 (1) | split into 2 |" in md and "Known limitations" in md
