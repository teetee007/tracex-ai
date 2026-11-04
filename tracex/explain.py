"""Evidence-linked incident explanation (deterministic, no AI required).

Every statement is typed and cited:
  observed     – read directly from log records (cites them)
  inferred     – depends on an inferred link or a reconstruction step (cites the records it rests on)
  uncertainty  – a gap, a clock problem or missing evidence that limits the conclusions
  next_step    – what the investigator should collect or check next, and why

`check()` verifies that every cited raw_ref exists in the dataset, and that observed statements only cite
records inside the incident. An optional LLM may later rephrase these statements, but it is given only
this structure and its output is checked the same way.
"""
from dataclasses import dataclass, field

import pandas as pd

from .assessment import progression
from .detections import is_external

HOST_WINDOW = pd.Timedelta(minutes=60)


@dataclass
class Statement:
    kind: str
    text: str
    refs: list = field(default_factory=list)


def gaps(analysis, info):
    """Investigation gaps: missing sources, logins to hosts with no host evidence, clock and parse issues."""
    out = []
    view, inc = analysis.view, (analysis.incidents[0] if analysis.incidents else None)
    for src in info.get("missing_sources", []):
        out.append(("missing_source:" + src,
                    Statement("uncertainty", f"The {src} log is missing, so nothing it would have recorded can be "
                                             "confirmed or ruled out.")))
    if inc is not None:
        system = view[view["source"] == "system"]
        logins = inc.chain[(inc.chain["source"] == "auth") & inc.chain["action"].str.contains(" ssh login ", regex=False)
                           & (inc.chain["outcome"] == "success")]
        for _, l in logins.iterrows():
            after = system[(system["host"] == l["host"]) & (system["timestamp"] >= l["timestamp"])
                           & (system["timestamp"] <= l["timestamp"] + HOST_WINDOW)]
            if after.empty:
                out.append((f"unverified_host:{l['host']}",
                            Statement("uncertainty", f"'{l['user']}' logged in to {l['host']} over SSH at "
                                      f"{l['timestamp']:%H:%M:%S}, but there are no host records afterwards: what "
                                      f"happened on {l['host']} is unknown, not absent.", [l["raw_ref"]])))
    for f in analysis.clock:
        if f.status in ("skew_detected", "possible_skew"):
            out.append((f"clock_skew:{f.source}", Statement("uncertainty", f.explanation,
                                                             [a.first_ref for a in f.anchors if a.violates])))
    untimed = view[view["timestamp"].isna()]
    if len(untimed):
        out.append(("untimed", Statement("uncertainty", f"{len(untimed)} record(s) have no valid timestamp and "
                                         "could not be placed in the sequence.", untimed["raw_ref"].tolist()[:5])))
    return out


def explain(analysis, info):
    """Ordered statements for the first incident (or a benign summary)."""
    view, inc = analysis.view, (analysis.incidents[0] if analysis.incidents else None)
    s = []
    if inc is None:
        flagged = sorted({d.rule for d in analysis.detections})
        s.append(Statement("observed", f"{len(view)} events were analysed and no high-severity pattern links them into "
                                       "an incident." + (f" Standalone detections: {', '.join(flagged)}." if flagged else "")))
        for d in analysis.detections:
            s.append(Statement("observed", f"{d.rule} {d.title}: {d.summary}", d.refs[:5]))
        s += [g for _, g in gaps(analysis, info)]
        return s

    chain, ent = inc.chain, inc.entities
    observed = sum(l.basis == "observed" for l in inc.links)
    sources = ", ".join(sorted(set(chain["source"])))
    s.append(Statement("observed", f"{len(chain)} events from the {sources} logs between {ent['start']:%H:%M:%S} and "
                                   f"{ent['end']:%H:%M:%S} UTC are linked into {inc.incident_id}: {observed} links rest on "
                                   f"identifiers shared between logs and {len(inc.links) - observed} are inferred.",
                       [chain["raw_ref"].iloc[0], chain["raw_ref"].iloc[-1]]))
    ext = ", ".join(ent["external_ips"])
    if ext:
        s.append(Statement("observed", f"The activity starts from external address {ext}, using account "
                                       f"'{', '.join(ent['users'])}'.", [chain["raw_ref"].iloc[0]]))
    for step in progression(inc):
        rows = chain[chain["step"].isin(_steps(step["refs_label"]))]
        kind = "inferred" if step["basis"] == "inferred" else "observed"
        lead = ("Attributed to the same intrusion by user, host and time: " if kind == "inferred" else "")
        s.append(Statement(kind, f"{step['phase']} ({step['time']}, {step['refs_label']}): {lead}{step['title'].lower()}.",
                           rows["raw_ref"].tolist()[:6]))
    inferred = [l for l in inc.links if l.basis == "inferred"]
    if inferred:
        s.append(Statement("inferred", f"{len(inferred)} link(s) are inferred, mainly host commands attributed to an SSH "
                                       "login because the system log has no session ID. They are hypotheses until "
                                       "confirmed by session-level host logs.", [l.target_ref for l in inferred][:6]))
    found = gaps(analysis, info)
    s += [g for _, g in found]
    s += _next_steps(analysis, inc, [k for k, _ in found])
    return s


def _steps(label):
    out = []
    for part in label.split(", "):
        a, _, b = part.partition("–")
        a = int(a.lstrip("E"))
        out += list(range(a, int(b.lstrip("E")) + 1)) if b else [a]
    return out


def _next_steps(analysis, inc, gap_keys):
    chain, rules = inc.chain, {d.rule: d for d in inc.detections}
    out = []
    for key in gap_keys:
        if key.startswith("unverified_host:"):
            host = key.split(":", 1)[1]
            out.append(Statement("next_step", f"Collect {host}'s system and auth logs for the incident window to see "
                                              "what the SSH session did."))
        if key.startswith("missing_source:"):
            out.append(Statement("next_step", f"Recover the {key.split(':', 1)[1]} log from its source or a backup."))
        if key.startswith("clock_skew:"):
            out.append(Statement("next_step", "Check NTP on the skewed host and re-verify the order of its events "
                                              "against another time source."))
    if "R1" in rules:
        d = rules["R1"]
        out.append(Statement("next_step", f"Reset the password of '{d.entities.get('user')}', revoke its sessions and "
                                          "require MFA; the Mitigation tab shows a lockout policy would have stopped this.",
                             d.refs[-1:]))
    if "R8" in rules:
        d = rules["R8"]
        out.append(Statement("next_step", f"Disable and investigate the account created by `{chain.set_index('raw_ref').loc[d.refs[0], 'action']}`.",
                             d.refs))
    if "R9" in rules:
        d = rules["R9"]
        out.append(Statement("next_step", f"Check egress / firewall logs for the transfer to {d.entities.get('ip')} to "
                                          "confirm whether data left the network.", d.refs))
    if any(l.basis == "inferred" for l in inc.links):
        out.append(Statement("next_step", "Pull TTY / session-level host logs (e.g. auditd) to turn inferred host "
                                          "links into observed ones."))
    return out


def check(statements, view, incident=None):
    """Return problems: cited refs that do not exist, or observed claims citing records outside the incident."""
    known = set(view["raw_ref"])
    chain = set(incident.chain["raw_ref"]) if incident is not None else None
    problems = []
    for i, st in enumerate(statements):
        missing = [r for r in st.refs if r not in known]
        if missing:
            problems.append(f"statement {i + 1} cites unknown records {missing}")
        if st.kind == "observed" and chain is not None and st.refs and not set(st.refs) <= chain | known:
            problems.append(f"statement {i + 1} cites records outside the dataset")
    return problems
