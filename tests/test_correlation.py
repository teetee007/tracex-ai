import io
from pathlib import Path

import pytest

from tracex.correlate import reconstruct
from tracex.detections import run_all
from tracex.evaluation import evaluate
from tracex.parsers import combine, load_dataset, parse_auth, parse_system

DATASET = Path(__file__).resolve().parent.parent / "data" / "tc01_attack"
AUTH_HEADER = "time,username,source_ip,target_host,method,result,session\n"
SYSTEM_HEADER = "Timestamp,Host,Account,PID,Process,CommandLine\n"


def analyse(auth_csv="", system_csv=""):
    frames = []
    if auth_csv:
        frames.append(parse_auth(io.StringIO(AUTH_HEADER + auth_csv)))
    if system_csv:
        frames.append(parse_system(io.StringIO(SYSTEM_HEADER + system_csv), year=2026))
    events = combine(frames)
    detections = run_all(events)
    return detections, reconstruct(events, detections)


@pytest.fixture(scope="module")
def tc01():
    events, info = load_dataset(DATASET)
    detections = run_all(events)
    return events, info, detections, reconstruct(events, detections)


def test_tc01_full_chain_reconstructed(tc01):
    _, info, _, incidents = tc01
    assert len(incidents) == 1
    result = evaluate(incidents, info["ground_truth"])
    assert result["missed"] == []
    assert result["false_positives"] == []
    assert set(incidents[0].chain["source"]) == {"auth", "web", "system"}


def test_tc01_every_chain_event_explains_why_it_is_included(tc01):
    chain = tc01[3][0].chain
    assert chain["linked_by"].iloc[0] == "start of chain"
    assert (chain["linked_by"].iloc[1:] != "start of chain").all()
    assert set(chain["link_basis"]) == {"observed", "inferred"}
    # system commands without an IP are only attributable by user + host + time
    assert (chain.loc[chain["action"] == "whoami", "link_basis"] == "inferred").all()


def test_tc01_decoy_scanner_detected_but_not_linked(tc01):
    _, _, detections, incidents = tc01
    scanner = [d for d in detections if d.entities.get("ip") == "198.51.100.77"]
    assert scanner
    chain_refs = set(incidents[0].chain["raw_ref"])
    assert all(not set(d.refs) & chain_refs for d in scanner)


def test_single_typo_is_not_brute_force():
    detections, incidents = analyse(
        "2026-10-20T08:00:00Z,bob,10.0.1.12,portal,web,failure,\n"
        "2026-10-20T08:00:09Z,bob,10.0.1.12,portal,web,success,s1\n")
    assert detections == [] and incidents == []


def test_benign_admin_activity_creates_no_incident():
    detections, incidents = analyse(
        "2026-10-20T08:45:00Z,alice,10.0.1.11,web-01,ssh,success,ssh-1\n",
        "Oct 20 08:46:00,web-01,alice,100,systemctl,systemctl status nginx\n"
        "Oct 20 08:47:00,web-01,alice,101,id,id\n")
    assert incidents == []


def test_failures_without_success_are_medium_not_an_incident():
    rows = "".join(f"2026-10-20T02:10:{s:02d}Z,jsmith,203.0.113.45,portal,web,failure,\n" for s in range(0, 60, 10))
    detections, incidents = analyse(rows)
    assert [d.rule for d in detections] == ["R2"]
    assert incidents == []


def test_unrelated_external_ip_is_not_pulled_into_chain():
    attack = "".join(f"2026-10-20T02:10:{s:02d}Z,jsmith,203.0.113.45,portal,web,failure,\n" for s in range(0, 60, 10))
    attack += "2026-10-20T02:11:00Z,jsmith,203.0.113.45,portal,web,success,s1\n"
    other = "2026-10-20T02:11:30Z,carol,203.0.113.99,portal,web,success,s2\n"
    _, incidents = analyse(attack + other)
    assert len(incidents) == 1
    assert "203.0.113.99" not in set(incidents[0].chain["src_ip"])


def test_command_attributed_only_within_login_window():
    _, incidents = analyse(
        "2026-10-20T02:00:00Z,jsmith,203.0.113.45,web-01,ssh,success,ssh-9\n",
        "Oct 20 02:05:00,web-01,jsmith,200,sudo,sudo useradd evil\n"
        "Oct 20 05:00:00,web-01,jsmith,201,whoami,whoami\n")
    actions = list(incidents[0].chain["action"])
    assert "sudo useradd evil" in actions and "whoami" not in actions
