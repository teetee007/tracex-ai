from pathlib import Path

import pytest

from tracex.explain import Statement, check, explain, gaps
from tracex.parsers import load_dataset
from tracex.pipeline import analyse

DATA = Path(__file__).resolve().parent.parent / "data"
SCENARIOS = ["tc01_attack", "tc02_benign", "tc03_incomplete", "tc04_clock_skew", "tc05_unrelated"]


def _run(name):
    if not (DATA / name).exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    events, info = load_dataset(DATA / name)
    return analyse(events), info


@pytest.mark.parametrize("name", SCENARIOS)
def test_every_citation_exists(name):
    a, info = _run(name)
    st = explain(a, info)
    assert st and check(st, a.view, a.incidents[0] if a.incidents else None) == []
    assert {s.kind for s in st} <= {"observed", "inferred", "uncertainty", "next_step"}


@pytest.mark.parametrize("name", ["tc03_incomplete", "tc04_clock_skew"])
def test_detected_gaps_match_ground_truth(name):
    a, info = _run(name)
    assert sorted(k for k, _ in gaps(a, info)) == sorted(info["ground_truth"]["expected_gaps"])


def test_benign_explanation_claims_no_incident():
    a, info = _run("tc02_benign")
    st = explain(a, info)
    assert "no high-severity pattern" in st[0].text
    assert not any(s.kind == "inferred" for s in st)


def test_host_commands_are_labelled_inferred_not_observed():
    a, info = _run("tc01_attack")
    discovery = [s for s in explain(a, info) if s.text.startswith("Discovery")]
    assert discovery and all(s.kind == "inferred" for s in discovery)


def test_checker_catches_invented_evidence():
    a, _ = _run("tc01_attack")
    bad = [Statement("observed", "The attacker used 10.9.9.9", ["auth.csv:999"])]
    assert check(bad, a.view, a.incidents[0])
