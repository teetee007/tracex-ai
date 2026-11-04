"""Mitigation validation: replay a security policy against the recorded logs (before / after).

Each policy decides which recorded logins it would have rejected. What those rejections prevent is
derived from the evidence, not assumed:
  * a rejected login creates no session, so events carrying that session ID could not have happened;
  * chain events whose link to the incident runs through a rejected login (linked_by "→ <its ref>")
    lose their only path in, and so do events downstream of them along the chain.
The same replay over activity outside any incident counts LEGITIMATE logins the policy would block,
so a control that stops the attack by locking out staff is visible as such.

This is a simulation over logs, not a test against live systems; an attacker who adapts (slower
guessing, a different account) is not modelled. Limitations are returned with every result.
"""
import re
from dataclasses import dataclass, field

import pandas as pd

from .detections import is_external


@dataclass
class PolicyResult:
    name: str
    description: str
    blocked: list = field(default_factory=list)            # raw_refs of logins the policy rejects
    prevented: list = field(default_factory=list)          # incident events that could not have happened
    legit_blocked: list = field(default_factory=list)      # rejected logins that are NOT part of any incident
    lockouts: list = field(default_factory=list)           # (user, start, end, trigger ref)
    chain_before: int = 0
    chain_after: int = 0
    stopped_before: str = ""                               # first prevented step, e.g. "E15"
    data_loss_before: list = field(default_factory=list)   # data-access steps (R6/R9) that still happen first
    limitation: str = ""

    @property
    def verdict(self):
        if not self.chain_before:
            return "no incident to stop"
        if not self.prevented:
            return "does not stop this attack"
        if self.data_loss_before:
            return (f"cuts the chain at {self.stopped_before}, but data access still happens before that "
                    f"({', '.join(self.data_loss_before)})")
        return f"cuts the chain at {self.stopped_before}, before any data access"


def _auth(events):
    return events[(events["source"] == "auth") & events["timestamp"].notna()].sort_values("timestamp")


def account_lockout(events, threshold=5, window=pd.Timedelta(minutes=10), duration=pd.Timedelta(minutes=15)):
    """Lock an account after `threshold` failures within `window`; reject every login during `duration`."""
    blocked, lockouts = [], []
    for user, rows in _auth(events).groupby("user", sort=False):
        failures, locked_until = [], None
        for _, r in rows.iterrows():
            t = r["timestamp"]
            if locked_until is not None and t < locked_until:
                if r["outcome"] == "success":
                    blocked.append(r["raw_ref"])
                continue
            if r["outcome"] == "failure":
                failures = [f for f in failures if t - f[0] <= window] + [(t, r["raw_ref"])]
                if len(failures) >= threshold:
                    locked_until = t + duration
                    lockouts.append((user, t, locked_until, r["raw_ref"]))
                    failures = []
    desc = (f"Lock an account for {int(duration.total_seconds() // 60)} min after {threshold} failed logins "
            f"within {int(window.total_seconds() // 60)} min.")
    lim = ("Slower guessing below the threshold is not stopped, and lockouts can be abused to deny service "
           "to real users; MFA is the stronger control.")
    return "Account lockout", desc, blocked, lockouts, lim


def block_external_ssh(events):
    """Reject SSH logins to servers from addresses outside the internal ranges."""
    auth = _auth(events)
    hits = auth[auth["action"].str.contains(" ssh login ", regex=False) & auth["src_ip"].apply(is_external)
                & (auth["outcome"] == "success")]
    return ("Block external SSH", "Allow SSH to servers only from internal addresses (VPN / bastion).",
            hits["raw_ref"].tolist(), [],
            "Remote staff then need a VPN or bastion; web-portal abuse (the admin export) is not affected.")


POLICIES = [account_lockout, block_external_ssh]


def _prevented(blocked, events, chain):
    if chain is None or chain.empty:
        return []
    blocked = set(blocked)
    sessions = set(events.loc[events["raw_ref"].isin(blocked), "session_id"]) - {""}
    out = set(blocked & set(chain["raw_ref"]))
    out |= set(chain.loc[chain["session_id"].isin(sessions), "raw_ref"])
    # Follow the chain: an event whose recorded link into the incident runs through a prevented event
    # is prevented too. linked_by ends with "→ <raw_ref>".
    changed = True
    while changed:
        changed = False
        for _, r in chain.iterrows():
            m = re.search(r"→ (\S+)$", r["linked_by"])
            if r["raw_ref"] not in out and m and m.group(1) in out and r["raw_ref"] not in blocked:
                # an observed IP link to a *later* attacker action does not depend on the blocked login
                if r["link_basis"] == "inferred" or m.group(1) in blocked or r["session_id"] in sessions:
                    out.add(r["raw_ref"]); changed = True
    return sorted(out, key=lambda ref: int(chain.loc[chain["raw_ref"] == ref, "step"].iloc[0]))


def validate(events, incidents):
    """Replay every policy; returns one PolicyResult each."""
    chain = incidents[0].chain if incidents else None
    in_any = set().union(*(set(i.chain["raw_ref"]) for i in incidents)) if incidents else set()
    results = []
    for policy in POLICIES:
        name, desc, blocked, lockouts, lim = policy(events)
        prevented = _prevented(blocked, events, chain)
        r = PolicyResult(name=name, description=desc, blocked=blocked, prevented=prevented,
                         legit_blocked=[b for b in blocked if b not in in_any], lockouts=lockouts,
                         chain_before=len(chain) if chain is not None else 0, limitation=lim)
        if chain is not None:
            r.chain_after = r.chain_before - len(prevented)
            if prevented:
                first = int(chain.loc[chain["raw_ref"] == prevented[0], "step"].iloc[0])
                r.stopped_before = f"E{first}"
                data = chain[chain["detections"].str.contains(r"\bR6\b|\bR9\b") & ~chain["raw_ref"].isin(prevented)]
                r.data_loss_before = [f"E{int(s)}" for s in data["step"] if s < first]
        results.append(r)
    return results
