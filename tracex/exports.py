"""Exports for real security tooling: Sigma rules, an ATT&CK Navigator layer, a STIX 2.1 bundle.

Field names in the Sigma rules are TraceX's normalized synthetic schema (`username`, `source_ip`,
`result`, `method`, `CommandLine`); map them to your SIEM's fields before deployment. IDs are
deterministic (UUIDv5), so re-exporting the same incident yields identical files.
"""
import json
import uuid

from .attack import map_techniques
from .detections import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, INTERNAL_NETWORKS

NS = uuid.UUID("6f1b6c55-3c55-4a8e-9a49-2b1a1c7e7a01")      # TraceX namespace for deterministic IDs
INTERNAL = [str(n) for n in INTERNAL_NETWORKS]
TACTIC_SHORTNAME = {"Reconnaissance": "reconnaissance", "Initial Access": "initial-access",
                    "Credential Access": "credential-access", "Discovery": "discovery",
                    "Lateral Movement": "lateral-movement", "Collection": "collection",
                    "Persistence": "persistence", "Exfiltration": "exfiltration"}


def _id(*parts):
    return str(uuid.uuid5(NS, "|".join(parts)))


def _yaml_list(items, indent):
    return "".join(f"\n{' ' * indent}- '{i}'" for i in items)


# ---------------------------------------------------------------- Sigma
def sigma_rules():
    """{filename: YAML text} for the rules that translate to Sigma (R1, R3, R8, R9)."""
    win = int(BRUTE_FORCE_WINDOW.total_seconds() // 60)
    rules = {}
    rules["tracex_r1_failed_login.yml"] = f"""title: TraceX R1 building block - failed SSO login
id: {_id('sigma', 'r1-base')}
name: tracex_failed_login
status: experimental
description: Single failed login. Used by the TraceX R1 correlation rule below; not an alert on its own.
author: TraceX AI
logsource:
    product: tracex
    service: sso
detection:
    selection:
        result: failure
    condition: selection
level: informational
"""
    rules["tracex_r1_password_guessing.yml"] = f"""title: TraceX R1 - password guessing against one account
id: {_id('sigma', 'r1-correlation')}
status: experimental
description: |
    {BRUTE_FORCE_THRESHOLD}+ failed logins for one account from one source within {win} minutes (Sigma correlation).
    TraceX additionally raises severity when a success from the same source follows; express that
    second stage as a temporal correlation in your SIEM.
author: TraceX AI
correlation:
    type: event_count
    rules:
        - tracex_failed_login
    group-by:
        - username
        - source_ip
    timespan: {win}m
    condition:
        gte: {BRUTE_FORCE_THRESHOLD}
tags:
    - attack.credential-access
    - attack.t1110.001
level: high
"""
    rules["tracex_r3_external_ssh.yml"] = f"""title: TraceX R3 - successful SSH login from an external address
id: {_id('sigma', 'r3')}
status: experimental
description: Successful SSH login to a server from outside the internal address ranges.
author: TraceX AI
logsource:
    product: tracex
    service: sso
detection:
    selection:
        method: ssh
        result: success
    filter_internal:
        source_ip|cidr:{_yaml_list(INTERNAL, 12)}
    condition: selection and not filter_internal
falsepositives:
    - Legitimate remote administration without a VPN
tags:
    - attack.lateral-movement
    - attack.t1021.004
level: high
"""
    rules["tracex_r8_local_account_created.yml"] = f"""title: TraceX R8 - local account created
id: {_id('sigma', 'r8')}
status: experimental
description: A new local account was created on a Linux host.
author: TraceX AI
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'useradd '
            - 'adduser '
    condition: selection
falsepositives:
    - Administrators provisioning accounts
tags:
    - attack.persistence
    - attack.t1136.001
level: high
"""
    rules["tracex_r9_transfer_to_remote_host.yml"] = f"""title: TraceX R9 - file transfer command to a remote host
id: {_id('sigma', 'r9')}
status: experimental
description: |
    scp / rsync / sftp to a user@host destination. TraceX also requires the destination to be an
    external IP; Sigma cannot test that inside a command line, so expect more matches here.
author: TraceX AI
logsource:
    product: linux
    category: process_creation
detection:
    selection_tool:
        CommandLine|re: '\\b(scp|rsync|sftp)\\b'
    selection_remote:
        CommandLine|contains: '@'
    condition: selection_tool and selection_remote
falsepositives:
    - Backups to an internal server
tags:
    - attack.exfiltration
    - attack.t1048
level: high
"""
    return rules


# ---------------------------------------------------------------- ATT&CK Navigator
def navigator_layer(events, detections, incident, scenario):
    refs = set(incident.chain["raw_ref"]) if incident is not None else None
    hits = map_techniques(events, detections, refs)
    techniques = []
    for h in hits:
        techniques.append({
            "techniqueID": h.technique, "tactic": TACTIC_SHORTNAME[h.tactic],
            "score": 2 if h.confidence == "mapped" else 1,
            "color": "#e5484d" if h.confidence == "mapped" else "#f5a524",
            "comment": f"{h.confidence} via {h.rule}; evidence: {', '.join(h.refs[:8])}"
                       + (f" (+{len(h.refs) - 8})" if len(h.refs) > 8 else "") + f". Limitation: {h.limitation}",
            "enabled": True, "showSubtechniques": True,
        })
    return {
        "name": f"TraceX {incident.incident_id if incident is not None else 'detections'} · {scenario}",
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": "enterprise-attack",
        "description": "Techniques proposed by TraceX AI from rule matches with cited log evidence. "
                       "Red = mapped (defining behaviour observed); amber = candidate.",
        "sorting": 0, "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#f5a524", "#e5484d"], "minValue": 0, "maxValue": 2},
        "legendItems": [{"label": "mapped", "color": "#e5484d"}, {"label": "candidate", "color": "#f5a524"}],
        "showTacticRowBackground": True, "selectSubtechniquesWithParent": False,
    }


# ---------------------------------------------------------------- STIX 2.1
def stix_bundle(events, detections, incident, scenario):
    """Indicators (attacker IP, created account), attack patterns, relationships and a report."""
    if incident is None:
        return {"type": "bundle", "id": f"bundle--{_id('bundle', scenario, 'none')}", "objects": []}
    ts = incident.entities["end"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    first = incident.entities["start"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    ident = {"type": "identity", "spec_version": "2.1", "id": f"identity--{_id('identity', 'tracex')}",
             "created": ts, "modified": ts, "name": "TraceX AI", "identity_class": "system"}
    base = {"spec_version": "2.1", "created": ts, "modified": ts, "created_by_ref": ident["id"]}
    objs = [ident]
    indicators = []
    for ip in incident.entities["external_ips"]:
        indicators.append({**base, "type": "indicator", "id": f"indicator--{_id('ind-ip', scenario, ip)}",
                           "name": f"Attacker source address {ip}", "indicator_types": ["malicious-activity"],
                           "pattern": f"[ipv4-addr:value = '{ip}']", "pattern_type": "stix", "valid_from": first,
                           "description": f"Source of password guessing, portal access and SSH in {incident.incident_id}."})
    by_rule = {d.rule: d for d in incident.detections}
    if "R8" in by_rule:
        account = events.set_index("raw_ref").loc[by_rule["R8"].refs[0], "action"].split()[-1]
        indicators.append({**base, "type": "indicator", "id": f"indicator--{_id('ind-acct', scenario, account)}",
                           "name": f"Attacker-created local account '{account}'", "indicator_types": ["compromised"],
                           "pattern": f"[user-account:user_id = '{account}']", "pattern_type": "stix",
                           "valid_from": first, "description": f"Created by `{events.set_index('raw_ref').loc[by_rule['R8'].refs[0], 'action']}`."})
    objs += indicators
    patterns = []
    for h in map_techniques(events, detections, set(incident.chain["raw_ref"])):
        ap = {**base, "type": "attack-pattern", "id": f"attack-pattern--{_id('ap', h.technique)}", "name": h.name,
              "external_references": [{"source_name": "mitre-attack", "external_id": h.technique}],
              "description": f"{h.confidence} mapping via TraceX rule {h.rule}. {h.rationale}"}
        patterns.append(ap)
    objs += patterns
    rels = [{**base, "type": "relationship", "id": f"relationship--{_id('rel', i['id'], p['id'])}",
             "relationship_type": "indicates", "source_ref": i["id"], "target_ref": p["id"]}
            for i in indicators[:1] for p in patterns]
    objs += rels
    objs.append({**base, "type": "report", "id": f"report--{_id('report', scenario, incident.incident_id)}",
                 "name": f"TraceX {incident.incident_id}: {incident.title}", "report_types": ["attack-pattern", "indicator"],
                 "published": ts, "description": f"Reconstructed from {len(incident.chain)} log events "
                 f"({scenario}). Evidence references are in the TraceX incident report.",
                 "object_refs": [o["id"] for o in objs if o["type"] != "identity"]})
    return {"type": "bundle", "id": f"bundle--{_id('bundle', scenario, incident.incident_id)}", "objects": objs}


def to_json(obj):
    return json.dumps(obj, indent=2)
