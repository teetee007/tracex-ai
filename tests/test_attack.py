from pathlib import Path

import pytest

from tracex.attack import MAPPINGS, coverage, map_techniques, techniques_by_ref
from tracex.detections import run_all
from tracex.parsers import load_dataset
from tracex.pipeline import analyse

DATA = Path(__file__).resolve().parent.parent / "data"
RULES = {f"R{i}" for i in range(1, 10)}


def _incident(name):
    if not (DATA / name).exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    events, info = load_dataset(DATA / name)
    a = analyse(events)
    return a, info, set(a.incidents[0].chain["raw_ref"]) if a.incidents else set()


def test_mapping_table_is_well_formed():
    for m in MAPPINGS:
        assert m["rule"] in RULES
        assert m["technique"].startswith("T") and m["confidence"] in ("mapped", "candidate")
        assert m["rationale"] and m["limitation"]
    assert "R4" not in {m["rule"] for m in MAPPINGS}   # no defensible technique for a user agent


@pytest.mark.parametrize("name", ["tc01_attack", "tc04_clock_skew", "tc05_unrelated"])
def test_all_expected_techniques_found_with_evidence(name):
    a, info, refs = _incident(name)
    hits = map_techniques(a.view, a.detections, refs)
    cov = coverage(hits, info["ground_truth"]["expected_techniques"])
    assert cov["missing"] == []
    assert set(cov["extra"]) <= {"T1213"}                      # the one extra is a labelled candidate
    assert all(h.refs and set(h.refs) <= refs for h in hits)   # every technique cites incident evidence


def test_incomplete_logs_still_map_what_is_visible():
    a, info, refs = _incident("tc03_incomplete")
    cov = coverage(map_techniques(a.view, a.detections, refs), info["ground_truth"]["expected_techniques"])
    assert cov["missing"] == []          # SSH login is flagged even without web-01's system log


def test_benign_scenario_maps_no_incident_techniques():
    a, _, refs = _incident("tc02_benign")
    assert refs == set()
    assert all(h.tactic == "Reconnaissance" for h in map_techniques(a.view, a.detections))  # only the scanner


def test_discovery_commands_map_to_specific_techniques():
    a, _, refs = _incident("tc01_attack")
    by_ref = techniques_by_ref(map_techniques(a.view, a.detections, refs))
    actions = a.view.set_index("raw_ref")["action"]
    for ref, hits in by_ref.items():
        if actions[ref] == "cat /etc/passwd":
            assert [h.technique for h in hits] == ["T1087.001"]
        if actions[ref] == "whoami":
            assert [h.technique for h in hits] == ["T1033"]


def test_failed_logins_never_map_to_valid_accounts():
    a, _, refs = _incident("tc01_attack")
    outcome = a.view.set_index("raw_ref")["outcome"]
    t1078 = [h for h in map_techniques(a.view, a.detections, refs) if h.technique == "T1078"]
    assert t1078 and all(outcome[r] == "success" for h in t1078 for r in h.refs)
