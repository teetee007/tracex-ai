import json
from pathlib import Path

import pytest

from tracex.parsers import load_dataset
from tracex.schema import COLUMNS

DATASET = Path(__file__).resolve().parent.parent / "data" / "tc01_attack"


@pytest.fixture(scope="module")
def loaded():
    if not DATASET.exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    return load_dataset(DATASET)


def test_all_sources_load_with_common_columns(loaded):
    events, info = loaded
    assert info["missing_sources"] == []
    assert set(events["source"]) == {"auth", "web", "system"}
    assert list(events.columns) == list(COLUMNS)


def test_every_record_is_kept(loaded):
    events, _ = loaded
    import csv
    with open(DATASET / "auth.csv", encoding="utf-8") as f:
        auth_rows = sum(1 for _ in csv.DictReader(f))
    with open(DATASET / "system.csv", encoding="utf-8") as f:
        system_rows = sum(1 for _ in csv.DictReader(f))
    web_rows = len(json.loads((DATASET / "web_access.json").read_text(encoding="utf-8")))
    counts = events["source"].value_counts()
    assert (counts["auth"], counts["web"], counts["system"]) == (auth_rows, web_rows, system_rows)


def test_malformed_rows_are_flagged_not_dropped(loaded):
    events, _ = loaded
    flagged = events[events["parse_issues"] != ""]
    assert len(flagged) == 3
    assert flagged["timestamp"].isna().all()


def test_valid_timestamps_normalized_to_utc(loaded):
    events, _ = loaded
    good = events[events["parse_issues"] == ""]
    assert good["timestamp"].notna().all()
    assert str(good["timestamp"].dt.tz) == "UTC"


def test_ground_truth_refs_exist(loaded):
    events, _ = loaded
    truth = json.loads((DATASET / "ground_truth.json").read_text(encoding="utf-8"))
    refs = set(events["raw_ref"])
    for source_refs in truth["attack_events"].values():
        assert set(source_refs) <= refs


def test_attacker_visible_in_every_source(loaded):
    """The raw material for cross-source correlation is there."""
    events, _ = loaded
    attacker = events[(events["src_ip"] == "203.0.113.45") | events["action"].str.contains("203.0.113.45")]
    assert set(attacker["source"]) == {"auth", "web", "system"}
