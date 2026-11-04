from pathlib import Path

import pytest

from tracex import mitigation
from tracex.parsers import load_dataset
from tracex.pipeline import analyse

DATA = Path(__file__).resolve().parent.parent / "data"


def _results(name):
    if not (DATA / name).exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    events, _ = load_dataset(DATA / name)
    a = analyse(events)
    return {r.name: r for r in mitigation.validate(a.view, a.incidents)}, a


def test_lockout_stops_tc01_before_any_access():
    r, a = _results("tc01_attack")
    lock = r["Account lockout"]
    assert lock.blocked and lock.stopped_before == "E15"           # the login that used the guessed password
    assert lock.chain_after == 14                                  # only the 14 failed guesses remain
    assert lock.data_loss_before == [] and "before any data access" in lock.verdict
    assert lock.legit_blocked == []


def test_ssh_block_is_reported_as_partial():
    r, _ = _results("tc01_attack")
    ssh = r["Block external SSH"]
    assert ssh.stopped_before == "E20"
    assert ssh.data_loss_before == ["E19"]                         # the admin export already happened
    assert "data access still happens" in ssh.verdict


@pytest.mark.parametrize("name", ["tc01_attack", "tc02_benign", "tc03_incomplete", "tc04_clock_skew", "tc05_unrelated"])
def test_policies_never_block_legitimate_logins(name):
    r, _ = _results(name)
    assert all(p.legit_blocked == [] for p in r.values())


def test_benign_typo_does_not_lock_anyone():
    r, _ = _results("tc02_benign")
    assert r["Account lockout"].lockouts == [] and r["Account lockout"].verdict == "no incident to stop"


@pytest.mark.parametrize("name", ["tc01_attack", "tc02_benign"])
def test_every_policy_reports_its_limitation(name):
    r, _ = _results(name)
    assert all(p.limitation and p.data_loss_before in ([], ["E19"]) for p in r.values())


def test_prevented_events_are_all_in_the_incident():
    r, a = _results("tc04_clock_skew")
    chain = set(a.incidents[0].chain["raw_ref"])
    assert all(set(p.prevented) <= chain for p in r.values())
