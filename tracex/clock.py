"""Clock-skew investigation: is a host's system-log clock out of step with the SSO clock?

Evidence used, and nothing else: a command recorded in a host's system log by user U must have
happened AFTER a successful login of U to that host. Each "episode" of commands that can be anchored
to such a login constrains the host clock's offset s (recorded system time − SSO time):

    hard:  s <= delta                 delta = first command of the episode (recorded) − its login
    soft:  s >= delta − MAX_FIRST_COMMAND_GAP   (people usually start typing within a few minutes)

Policy, deliberately conservative:
  * The SSO (auth) log is the reference clock; web timestamps carry an explicit UTC offset.
  * Only the hard constraint is used to DETECT skew. Positive deltas are ambiguous (a user may just
    wait), so a clock running ahead cannot be detected this way; that is reported as a limitation.
  * Skew is reported when anchored episodes start more than JITTER before their login.
  * A correction is applied only with at least MIN_ANCHORS independent violating episodes; with one,
    the events are flagged as uncertain and left uncorrected.
  * The correction is the SMALLEST shift that satisfies every hard constraint. Raw timestamps are
    never modified: corrected times live in separate columns of an analysis copy.
"""
from dataclasses import dataclass, field

import pandas as pd

EPISODE_GAP = pd.Timedelta(minutes=10)            # commands closer than this form one working session
SEARCH_WINDOW = pd.Timedelta(minutes=30)          # how far from an episode to look for its login
MAX_FIRST_COMMAND_GAP = pd.Timedelta(minutes=5)   # assumed upper bound, login -> first command
JITTER = pd.Timedelta(seconds=60)                 # offsets within ±60 s are normal write jitter
MIN_ANCHORS = 2


@dataclass
class Anchor:
    host: str
    user: str
    login_ref: str
    login_time: pd.Timestamp
    first_ref: str
    first_time: pd.Timestamp
    episode_refs: list
    delta: pd.Timedelta          # first command (recorded) − login

    @property
    def violates(self):
        return self.delta < -JITTER


@dataclass
class ClockFinding:
    source: str
    host: str
    status: str                  # consistent | skew_detected | possible_skew | insufficient_evidence
    anchors: list = field(default_factory=list)
    offset_high: pd.Timedelta = None   # s <= offset_high (hard constraints)
    offset_low: pd.Timedelta = None    # s >= offset_low (soft constraint), None if it conflicts
    correction: pd.Timedelta = None    # added to recorded times when applied; None = not applied
    explanation: str = ""

    @property
    def affected_refs(self):
        return [r for a in self.anchors for r in a.episode_refs]

    @property
    def uncertainty(self):
        """Width of the offset interval, or None when only a bound is known."""
        if self.offset_low is None or self.offset_high is None:
            return None
        return self.offset_high - self.offset_low


def _minutes(td):
    return f"{abs(td.total_seconds()) / 60:.1f} min"


def _episodes(commands):
    """Split one user's commands on one host into working sessions."""
    episode, prev = [], None
    for _, row in commands.sort_values("timestamp").iterrows():
        if prev is not None and row["timestamp"] - prev > EPISODE_GAP:
            yield episode
            episode = []
        episode.append(row)
        prev = row["timestamp"]
    if episode:
        yield episode


def find_anchors(events):
    """Pair each command episode with the nearest successful login of the same user to the same host."""
    timed = events[events["timestamp"].notna()]
    system = timed[(timed["source"] == "system") & (timed["user"] != "")]
    logins = timed[(timed["event_type"] == "auth_login") & (timed["outcome"] == "success")]
    anchors = []
    for (host, user), cmds in system.groupby(["host", "user"], sort=False):
        own = logins[(logins["user"] == user) & (logins["host"] == host)]
        for episode in _episodes(cmds):
            first = episode[0]
            near = own[(own["timestamp"] - first["timestamp"]).abs() <= SEARCH_WINDOW]
            if near.empty:
                continue  # e.g. cron jobs or console logins: no anchor, no constraint
            login = near.loc[(near["timestamp"] - first["timestamp"]).abs().idxmin()]
            anchors.append(Anchor(host, user, login["raw_ref"], login["timestamp"], first["raw_ref"],
                                  first["timestamp"], [r["raw_ref"] for r in episode],
                                  first["timestamp"] - login["timestamp"]))
    return anchors


def assess(events, min_anchors=MIN_ANCHORS):
    """One finding per host that has a system log."""
    findings = []
    anchors = find_anchors(events)
    hosts = sorted(set(events.loc[events["source"] == "system", "host"]) - {""})
    for host in hosts:
        own = [a for a in anchors if a.host == host]
        if not own:
            findings.append(ClockFinding("system", host, "insufficient_evidence", explanation=(
                f"No command on {host} can be paired with a login of the same user, so its clock "
                "cannot be checked against the SSO log.")))
            continue
        high = min(a.delta for a in own)
        low = max(a.delta - MAX_FIRST_COMMAND_GAP for a in own)
        low = low if low <= high else None
        violating = [a for a in own if a.violates]
        f = ClockFinding("system", host, "consistent", own, high, low)
        if not violating:
            f.explanation = (f"All {len(own)} anchored command session(s) on {host} start after their login: "
                             "no evidence that its clock is behind the SSO clock.")
        elif len(violating) >= min_anchors:
            f.status = "skew_detected"
            f.correction = -high
            bound = f"between {_minutes(high)} and {_minutes(low)}" if low is not None else f"at least {_minutes(high)}"
            f.explanation = (
                f"{len(violating)} independent command sessions on {host} are recorded before the login "
                f"that must precede them, so {host}'s clock is {bound} behind the SSO clock. Its events are "
                f"shifted by the smallest amount that satisfies every session ({_minutes(f.correction)}); "
                "raw timestamps are kept.")
        else:
            f.status = "possible_skew"
            f.explanation = (
                f"One command session on {host} ({violating[0].first_ref}) is recorded "
                f"{_minutes(violating[0].delta)} before its login. One anchor is not enough to estimate an "
                "offset, so no correction is applied; links to these events are marked uncertain.")
        findings.append(f)
    return findings


def apply(events, findings):
    """Analysis copy with corrected times. Adds timestamp_raw, time_correction_s, time_uncertainty_s.

    `timestamp` in the copy is the time used for ordering and correlation; the original stays in
    `timestamp_raw`, and the input frame is not modified.
    """
    view = events.copy()
    view["timestamp_raw"] = view["timestamp"]
    view["time_correction_s"] = 0.0
    view["time_uncertainty_s"] = 0.0
    for f in findings:
        rows = (view["source"] == f.source) & (view["host"] == f.host)
        if f.correction is not None:
            view.loc[rows, "timestamp"] = view.loc[rows, "timestamp"] + f.correction
            view.loc[rows, "time_correction_s"] = f.correction.total_seconds()
            width = f.uncertainty
            view.loc[rows, "time_uncertainty_s"] = width.total_seconds() if width is not None else float("nan")
        elif f.status == "possible_skew":
            view.loc[view["raw_ref"].isin(f.affected_refs), "time_uncertainty_s"] = float("nan")
    return view


def issues(findings):
    """Validation-style rows for the Data quality tab."""
    rows = []
    for f in findings:
        if f.status in ("skew_detected", "possible_skew"):
            for a in f.anchors:
                if a.violates:
                    rows.append({"raw_ref": a.first_ref, "source": f.source, "severity": "warning",
                                 "check": "clock_skew",
                                 "message": f"recorded {_minutes(a.delta)} before login {a.login_ref}; "
                                            f"{f.host} clock {'corrected' if f.correction is not None else 'uncertain'}"})
    return rows
