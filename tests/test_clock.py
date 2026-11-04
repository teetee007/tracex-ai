import io
import math
from pathlib import Path

import pandas as pd
import pytest

from tracex import clock
from tracex.evaluation import evaluate
from tracex.parsers import combine, load_dataset, parse_auth, parse_system
from tracex.pipeline import analyse
from tracex.schema import COLUMNS

DATA = Path(__file__).resolve().parent.parent / "data"
AUTH_HEADER = "time,username,source_ip,target_host,method,result,session\n"
SYSTEM_HEADER = "Timestamp,Host,Account,PID,Process,CommandLine\n"


def events(auth_csv, system_csv):
    return combine([parse_auth(io.StringIO(AUTH_HEADER + auth_csv)),
                    parse_system(io.StringIO(SYSTEM_HEADER + system_csv), year=2026)])


def load(name):
    if not (DATA / name).exists():
        pytest.skip("run scripts/generate_synthetic_logs.py first")
    return load_dataset(DATA / name)


# ---------- detection on the scenarios ----------

def test_tc04_skew_detected_and_true_offset_inside_interval():
    e, _ = load("tc04_clock_skew")
    [f] = clock.assess(e)
    assert f.status == "skew_detected"
    true_offset = pd.Timedelta(minutes=-5)
    assert f.offset_low <= true_offset <= f.offset_high
    assert f.offset_high < -clock.JITTER                       # zero is excluded
    assert f.correction == -f.offset_high                      # smallest consistent shift
    assert len([a for a in f.anchors if a.violates]) >= clock.MIN_ANCHORS


@pytest.mark.parametrize("name", ["tc01_attack", "tc02_benign", "tc05_unrelated"])
def test_no_skew_claimed_on_synchronised_scenarios(name):
    e, _ = load(name)
    assert all(f.status == "consistent" and f.correction is None for f in clock.assess(e))


def test_no_system_log_means_no_clock_finding():
    e, _ = load("tc03_incomplete")
    assert clock.assess(e) == []


# ---------- raw timestamps are preserved ----------

def test_raw_timestamps_preserved_and_input_untouched():
    e, _ = load("tc04_clock_skew")
    before = e.copy()
    a = analyse(e)
    pd.testing.assert_frame_equal(e, before)                   # parser output not modified
    assert list(a.events.columns) == list(COLUMNS)
    pd.testing.assert_series_equal(a.view["timestamp_raw"], e["timestamp"], check_names=False)
    shifted = a.view["time_correction_s"] != 0
    assert set(a.view.loc[shifted, "source"]) == {"system"}
    assert ((a.view.loc[shifted, "timestamp"] - a.view.loc[shifted, "timestamp_raw"])
            == clock.assess(e)[0].correction).all()


# ---------- false hypotheses and insufficient evidence ----------

def test_single_anchor_is_flagged_but_not_corrected():
    e = events("2026-10-20T02:00:00Z,jsmith,203.0.113.45,web-01,ssh,success,s1\n",
               "Oct 20 01:57:00,web-01,jsmith,1,whoami,whoami\nOct 20 01:57:40,web-01,jsmith,2,id,id\n")
    [f] = clock.assess(e)
    assert f.status == "possible_skew" and f.correction is None
    view = clock.apply(e, [f])
    assert view.loc[view["source"] == "system", "time_uncertainty_s"].isna().all()
    assert (view["timestamp"] == view["timestamp_raw"]).all()


def test_two_anchors_that_disagree_do_not_produce_a_confident_interval():
    # One session 4 min "before" its login, another 20 min after its login: the hard bound still says
    # the clock is behind, but the soft lower bound conflicts, so only a one-sided bound is reported.
    e = events("2026-10-20T02:00:00Z,jsmith,203.0.113.45,web-01,ssh,success,s1\n"
               "2026-10-20T05:00:00Z,alice,10.0.1.11,web-01,ssh,success,s2\n",
               "Oct 20 01:56:00,web-01,jsmith,1,whoami,whoami\n"
               "Oct 20 05:20:00,web-01,alice,2,uptime,uptime\n")
    [f] = clock.assess(e)
    assert f.status == "possible_skew"           # only one violating anchor
    assert f.offset_low is None and f.uncertainty is None


def test_slow_user_is_not_mistaken_for_a_clock_running_ahead():
    e = events("2026-10-20T02:00:00Z,alice,10.0.1.11,web-01,ssh,success,s1\n"
               "2026-10-20T05:00:00Z,alice,10.0.1.11,web-01,ssh,success,s2\n",
               "Oct 20 02:25:00,web-01,alice,1,uptime,uptime\nOct 20 05:28:00,web-01,alice,2,df,df -h\n")
    [f] = clock.assess(e)
    assert f.status == "consistent" and f.correction is None


def test_commands_without_any_login_give_insufficient_evidence():
    e = events("2026-10-20T08:00:00Z,bob,10.0.1.12,portal,web,success,s1\n",
               "Oct 20 02:00:02,web-01,root,1,cron,/usr/local/bin/backup.sh\n")
    [f] = clock.assess(e)
    assert f.status == "insufficient_evidence" and f.correction is None


def test_out_of_order_rows_alone_do_not_trigger_skew():
    e = events("2026-10-20T02:00:00Z,alice,10.0.1.11,web-01,ssh,success,s1\n",
               "Oct 20 02:03:00,web-01,alice,1,uptime,uptime\nOct 20 02:01:00,web-01,alice,2,id,id\n")
    assert clock.assess(e)[0].status == "consistent"


# ---------- correlation under uncertainty ----------

def test_tc04_links_through_corrected_events_are_marked():
    e, _ = load("tc04_clock_skew")
    a = analyse(e)
    adjusted = [l for l in a.links if l.time_adjusted]
    assert adjusted and all("corrected by +" in l.reason for l in adjusted)
    chain = a.incidents[0].chain
    assert (chain.loc[chain["source"] == "system", "time_correction_s"] > 0).all()


# ---------- regression: all five scenarios, baseline vs clock-aware ----------

EXPECTED = {  # scenario: (incidents, recall, precision) with clock-aware correlation
    "tc01_attack": (1, 1.0, 1.0),
    "tc02_benign": (0, None, None),
    "tc03_incomplete": (1, 1.0, 1.0),
    "tc04_clock_skew": (1, 1.0, 1.0),
    "tc05_unrelated": (1, 1.0, 1.0),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_scenario_regression(name):
    e, info = load(name)
    a = analyse(e)
    r = evaluate(a.incidents, info["ground_truth"])
    assert (len(a.incidents), r["recall"], r["precision"]) == EXPECTED[name]
    assert len(a.incidents) == info["ground_truth"]["expected_incidents"]


def test_tc04_baseline_still_shows_the_original_failure():
    """Keeps the 'before' number honest: without clock awareness TC-04 fragments and misses events."""
    e, info = load("tc04_clock_skew")
    a = analyse(e, clock_aware=False)
    r = evaluate(a.incidents, info["ground_truth"])
    assert len(a.incidents) == 2 and len(r["missed"]) == 5 and math.isclose(r["recall"], 22 / 27)
