import json
import re
from pathlib import Path

import pytest

from tracex import custody, exports, report
from tracex.parsers import load_dataset
from tracex.pipeline import analyse

DATA = Path(__file__).resolve().parent.parent / "data"
SCENARIOS = ["tc01_attack", "tc02_benign", "tc03_incomplete", "tc04_clock_skew", "tc05_unrelated"]


def _need(name):
    if not (DATA / name / "custody.json").exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    return DATA / name


# ---------------- chain of custody ----------------

@pytest.mark.parametrize("name", SCENARIOS)
def test_bundled_evidence_verifies(name):
    d = _need(name)
    assert custody.verify(custody.read_files(d), custody.load_manifest(d))["status"] == "verified"


def test_deleted_record_is_pinpointed():
    d = _need("tc01_attack")
    files = custody.read_files(d)
    lines = files["auth.csv"].splitlines(keepends=True)
    del lines[18]                                     # line 19 of the file = the attacker's SSH login
    files["auth.csv"] = b"".join(lines)
    r = custody.verify(files, custody.load_manifest(d))
    auth = next(f for f in r["files"] if f["file"] == "auth.csv")
    assert r["status"] == "tampered" and auth["changes"] == [
        {"op": "deleted", "sealed_records": ["auth.csv:19"], "current_records": []}]


def test_modified_and_inserted_records_are_pinpointed():
    d = _need("tc01_attack")
    files = custody.read_files(d)
    files["web_access.json"] = files["web_access.json"].replace(b"4812330", b"48123")
    files["system.csv"] = files["system.csv"] + b"Oct 20 03:00:00,web-01,root,1,rm,rm -rf /tmp/x\n"
    r = {f["file"]: f for f in custody.verify(files, custody.load_manifest(d))["files"]}
    assert [c["op"] for c in r["web_access.json"]["changes"]] == ["modified"]
    assert r["web_access.json"]["changes"][0]["sealed_records"] == ["web_access.json#9"]
    assert [c["op"] for c in r["system.csv"]["changes"]] == ["inserted"]
    assert r["auth.csv"]["status"] == "verified"


def test_missing_file_and_missing_manifest():
    d = _need("tc01_attack")
    files = custody.read_files(d)
    del files["system.csv"]
    assert any(f["status"] == "missing" for f in custody.verify(files, custody.load_manifest(d))["files"])
    assert custody.verify(files, None)["status"] == "unsealed"


def test_chain_head_commits_to_record_order():
    a = custody.describe("x.csv", b"h\nr1\nr2\n")
    b = custody.describe("x.csv", b"h\nr2\nr1\n")
    assert sorted(a["record_sha256"]) == sorted(b["record_sha256"]) and a["chain_head"] != b["chain_head"]


# ---------------- exports ----------------

def _tc01():
    events, info = load_dataset(_need("tc01_attack"))
    a = analyse(events)
    return a, a.incidents[0]


def test_sigma_rules_are_structurally_complete():
    rules = exports.sigma_rules()
    assert len(rules) == 5
    ids = set()
    for name, text in rules.items():
        assert name.endswith(".yml") and "\t" not in text
        for key in ("title:", "id:", "status:", "level:"):
            assert re.search(rf"^{key}", text, re.M), (name, key)
        assert re.search(r"^logsource:", text, re.M) or re.search(r"^correlation:", text, re.M)
        ids.add(re.search(r"^id: (\S+)", text, re.M).group(1))
    assert len(ids) == 5                                      # unique, deterministic UUIDs
    assert exports.sigma_rules() == rules


def test_navigator_layer_matches_mapped_techniques():
    a, inc = _tc01()
    layer = exports.navigator_layer(a.view, a.detections, inc, "tc01_attack")
    json.dumps(layer)
    assert layer["versions"]["layer"] == "4.5" and layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110.001", "T1021.004", "T1136.001", "T1048"} <= ids
    assert all("evidence:" in t["comment"] for t in layer["techniques"])


def test_stix_bundle_is_self_consistent():
    a, inc = _tc01()
    b = exports.stix_bundle(a.view, a.detections, inc, "tc01_attack")
    objs = b["objects"]
    ids = {o["id"] for o in objs}
    assert b["type"] == "bundle" and len(ids) == len(objs)
    assert all(re.fullmatch(r"[a-z0-9-]+--[0-9a-f-]{36}", o["id"]) and o["id"].startswith(o["type"] + "--") for o in objs)
    assert all(o.get("spec_version") == "2.1" for o in objs)
    refs = [r for o in objs for r in o.get("object_refs", []) + [o.get(k) for k in ("source_ref", "target_ref", "created_by_ref")] if r]
    assert set(refs) <= ids
    patterns = {o["pattern"] for o in objs if o["type"] == "indicator"}
    assert patterns == {"[ipv4-addr:value = '203.0.113.45']", "[user-account:user_id = 'backup_svc']"}
    assert exports.stix_bundle(a.view, a.detections, inc, "tc01_attack") == b   # deterministic


def test_no_incident_exports_are_empty_not_invented():
    events, _ = load_dataset(_need("tc02_benign"))
    a = analyse(events)
    assert exports.stix_bundle(a.view, a.detections, None, "tc02_benign")["objects"] == []


# ---------------- incident report ----------------

@pytest.mark.parametrize("name", SCENARIOS)
def test_report_renders_for_every_scenario(name):
    d = _need(name)
    events, info = load_dataset(d)
    a = analyse(events)
    doc = report.build(a, info, name, custody.verify(custody.read_files(d), custody.load_manifest(d)))
    md, html = report.to_markdown(doc), report.to_html(doc)
    assert "Evidence integrity" in md and "<h2>1. Evidence integrity</h2>" in html
    if a.incidents:
        assert all(ref in md for ref in a.incidents[0].chain["raw_ref"])   # every chain step cites its evidence


def test_report_html_escapes_log_content():
    events, info = load_dataset(_need("tc01_attack"))
    a = analyse(events)
    a.incidents[0].chain.loc[0, "action"] = "<script>alert(1)</script>"
    html = report.to_html(report.build(a, info, "x", {"status": "unsealed", "files": [], "sealed_at": None}))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
