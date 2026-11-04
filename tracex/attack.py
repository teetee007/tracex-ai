"""MITRE ATT&CK mapping: detection rule + matching evidence -> candidate technique.

The chain is always Event -> Rule -> Evidence -> Technique. A technique is only proposed for an event
that a rule already flagged, and only when the event's own content matches the mapping's pattern.
Rules with no defensible technique (R4, automated user agent) are deliberately left unmapped.

confidence:
  "mapped"    – the logged behaviour is the technique's defining behaviour
  "candidate" – consistent with the technique, but the logs cannot rule out other explanations
"""
import re
from dataclasses import dataclass, field

MAPPINGS = [
    # rule, technique, name, tactic, confidence, event pattern (None = every event of the rule), rationale, limitation
    {"rule": "R1", "technique": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access",
     "confidence": "mapped", "outcome": "failure",
     "rationale": "Repeated failed logins for one account from one source in a short window.",
     "limitation": "Cannot distinguish guessing from a misconfigured client retrying a stale password."},
    {"rule": "R1", "technique": "T1078", "name": "Valid Accounts", "tactic": "Initial Access",
     "confidence": "candidate", "outcome": "success",
     "rationale": "The guessing ended in a successful login, after which the account was used normally.",
     "limitation": "The logs show a successful login, not that the password was obtained by guessing."},
    {"rule": "R2", "technique": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access",
     "confidence": "mapped", "outcome": "failure",
     "rationale": "Repeated failed logins for one account from one source; no success observed.",
     "limitation": "An unsuccessful attempt; no access is implied."},
    {"rule": "R3", "technique": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement",
     "confidence": "mapped",
     "rationale": "Interactive SSH login to a server from an address outside the internal ranges.",
     "limitation": "External SSH may be legitimate remote work; context decides."},
    {"rule": "R5", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning", "tactic": "Reconnaissance",
     "confidence": "candidate",
     "rationale": "A burst of requests for common admin and config paths that do not exist.",
     "limitation": "Internet background scanning is constant; it is rarely targeted."},
    {"rule": "R6", "technique": "T1213", "name": "Data from Information Repositories", "tactic": "Collection",
     "confidence": "candidate",
     "rationale": "Bulk export from the portal's admin interface.",
     "limitation": "Admins export data legitimately; the account's normal behaviour is not known."},
    {"rule": "R7", "technique": "T1033", "name": "System Owner/User Discovery", "tactic": "Discovery",
     "confidence": "mapped", "pattern": r"^(whoami|id)$",
     "rationale": "whoami / id reveal the current user and groups.", "limitation": "Common in admin work."},
    {"rule": "R7", "technique": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "Discovery",
     "confidence": "mapped", "pattern": r"/etc/(passwd|group|shadow)",
     "rationale": "Reading the local account database lists the host's users.", "limitation": "Common in admin work."},
    {"rule": "R7", "technique": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery",
     "confidence": "mapped", "pattern": r"^ls ",
     "rationale": "Listing directories that hold backups or credentials.", "limitation": "Common in admin work."},
    {"rule": "R7", "technique": "T1082", "name": "System Information Discovery", "tactic": "Discovery",
     "confidence": "mapped", "pattern": r"^(hostname|uname)",
     "rationale": "Host name and kernel details.", "limitation": "Common in admin work."},
    {"rule": "R8", "technique": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence",
     "confidence": "mapped",
     "rationale": "A new local account was created on the host.",
     "limitation": "Account creation by an admin is routine; who requested it is not in the logs."},
    {"rule": "R9", "technique": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
     "confidence": "mapped",
     "rationale": "A file-transfer command sent data to an external address.",
     "limitation": "The logs show the command, not whether the transfer completed or what it contained."},
]


@dataclass
class TechniqueHit:
    technique: str
    name: str
    tactic: str
    confidence: str
    rule: str
    rationale: str
    limitation: str
    refs: list = field(default_factory=list)


def _applies(mapping, row):
    if "outcome" in mapping and row["outcome"] != mapping["outcome"]:
        return False
    if "pattern" in mapping and not re.search(mapping["pattern"], row["action"].strip()):
        return False
    return True


def map_techniques(events, detections, refs=None):
    """Techniques supported by the given detections, optionally limited to a set of raw_refs (an incident)."""
    by_ref = events.set_index("raw_ref")
    hits = {}
    for d in detections:
        for m in (m for m in MAPPINGS if m["rule"] == d.rule):
            for ref in d.refs:
                if refs is not None and ref not in refs or ref not in by_ref.index:
                    continue
                row = by_ref.loc[ref]
                if not _applies(m, row):
                    continue
                key = (m["technique"], m["rule"])
                hit = hits.setdefault(key, TechniqueHit(m["technique"], m["name"], m["tactic"], m["confidence"],
                                                        m["rule"], m["rationale"], m["limitation"]))
                if ref not in hit.refs:
                    hit.refs.append(ref)
    return sorted(hits.values(), key=lambda h: (TACTIC_ORDER.index(h.tactic), h.technique))


def techniques_by_ref(hits):
    out = {}
    for h in hits:
        for ref in h.refs:
            out.setdefault(ref, []).append(h)
    return out


def coverage(hits, expected):
    """Compare proposed technique IDs with the scenario's expected list."""
    proposed = {h.technique for h in hits}
    expected = set(expected)
    return {"expected": sorted(expected), "proposed": sorted(proposed),
            "matched": sorted(proposed & expected), "missing": sorted(expected - proposed),
            "extra": sorted(proposed - expected)}


TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Persistence", "Exfiltration"]
