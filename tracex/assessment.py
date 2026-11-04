"""Transparent threat score and attack progression, derived only from detections and the chain."""
from .graph import step_ranges

RULE_POINTS = {"high": 20, "medium": 8, "low": 2}   # each rule counts once
BANDS = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]

# Which stage of an attack each rule describes.
PHASES = {
    "R5": "Reconnaissance", "R2": "Initial access", "R1": "Initial access", "R4": "Tooling",
    "R6": "Collection", "R3": "Remote access", "R7": "Discovery", "R8": "Persistence", "R9": "Exfiltration",
}


def threat_score(detections):
    """Score 0–100: 20 points per distinct high rule, 8 per medium, 2 per low, capped at 100."""
    per_rule = {}
    for d in detections:
        points = RULE_POINTS[d.severity]
        if points > per_rule.get(d.rule, (0, ""))[0]:
            per_rule[d.rule] = (points, d.title)
    breakdown = [{"rule": r, "finding": t, "points": p} for r, (p, t) in sorted(per_rule.items())]
    score = min(100, sum(p for p, _ in per_rule.values()))
    band = next(label for floor, label in BANDS if score >= floor)
    return score, band, breakdown


def progression(incident):
    """One step per detection in the incident, in time order, with its evidence and link basis."""
    chain = incident.chain
    steps = []
    for d in incident.detections:
        rows = chain[chain["raw_ref"].isin(d.refs)]
        if rows.empty:
            continue
        steps.append({
            "phase": PHASES.get(d.rule, "Activity"),
            "title": d.title,
            "start": rows["timestamp"].min(),
            "time": rows["timestamp"].min().strftime("%H:%M:%S"),
            "refs_label": step_ranges(rows["step"].tolist()),
            "basis": "inferred" if (rows["link_basis"] == "inferred").all() else "observed",
            "severity": d.severity,
        })
    return sorted(steps, key=lambda s: s["start"])
