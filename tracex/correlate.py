"""Link related events across sources and reconstruct attack chains.

Every link records *why* two events are connected and how strong that reason is:
  observed – the logs share an explicit identifier (session ID, IP address)
  inferred – the connection relies on reasoning (same user on the same host shortly after a login)
Events are never linked just because they happen close together in time.
"""
from dataclasses import dataclass, field

import networkx as nx
import pandas as pd

from .detections import IP_IN_TEXT, SEVERITY_RANK, is_external

IP_LINK_GAP = pd.Timedelta(minutes=30)          # same IP, consecutive events at most this far apart
SESSION_LINK_GAP = pd.Timedelta(hours=8)
HOST_ACTIVITY_WINDOW = pd.Timedelta(minutes=60)  # commands attributed to a login within this window


@dataclass
class Link:
    source_ref: str
    target_ref: str
    reason: str
    basis: str  # "observed" or "inferred"


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    chain: pd.DataFrame          # one row per event, in time order, with why it is included
    detections: list
    links: list
    entities: dict = field(default_factory=dict)


def _consecutive_links(events, key, max_gap, label):
    links = []
    for value, group in events[events[key] != ""].groupby(key, sort=False):
        prev = None
        for _, row in group.sort_values("timestamp").iterrows():
            if prev is not None and row["timestamp"] - prev["timestamp"] <= max_gap:
                links.append(Link(prev["raw_ref"], row["raw_ref"], f"same {label} {value}", "observed"))
            prev = row
    return links


def build_links(events):
    timed = events[events["timestamp"].notna()].sort_values("timestamp")
    links = _consecutive_links(timed, "session_id", SESSION_LINK_GAP, "session")
    links += _consecutive_links(timed, "src_ip", IP_LINK_GAP, "source IP")

    system = timed[timed["source"] == "system"]
    logins = timed[(timed["event_type"] == "auth_login") & (timed["outcome"] == "success")
                   & timed["host"].isin(set(system["host"]))]
    for _, cmd in system.iterrows():
        # The system log has no session ID, so a command is attributed to the latest login of the
        # same user to the same host. This is an inference and is labelled as one.
        prior = logins[(logins["user"] == cmd["user"]) & (logins["host"] == cmd["host"])
                       & (logins["timestamp"] <= cmd["timestamp"])
                       & (cmd["timestamp"] - logins["timestamp"] <= HOST_ACTIVITY_WINDOW)]
        if not prior.empty:
            login = prior.iloc[-1]
            minutes = (cmd["timestamp"] - login["timestamp"]).total_seconds() / 60
            links.append(Link(login["raw_ref"], cmd["raw_ref"],
                              f"same user '{cmd['user']}' on {cmd['host']}, {minutes:.0f} min after that login "
                              "(system log has no session ID)", "inferred"))

        # An IP address written inside a command line is an explicit identifier.
        for ip in set(IP_IN_TEXT.findall(cmd["action"])):
            earlier = timed[(timed["src_ip"] == ip) & (timed["timestamp"] <= cmd["timestamp"])]
            if not earlier.empty:
                links.append(Link(earlier.iloc[-1]["raw_ref"], cmd["raw_ref"],
                                  f"command line contains IP {ip}", "observed"))
    return links


def _graph(events, links):
    graph = nx.Graph()
    graph.add_nodes_from(events.loc[events["timestamp"].notna(), "raw_ref"])
    for link in links:
        graph.add_edge(link.source_ref, link.target_ref, link=link)
    return graph


def _chain_table(events, refs, graph, detections_by_ref):
    chain = events[events["raw_ref"].isin(refs)].sort_values("timestamp").reset_index(drop=True)
    position = {ref: i for i, ref in enumerate(chain["raw_ref"])}
    linked_by, basis = [], []
    for i, ref in enumerate(chain["raw_ref"]):
        earlier = [graph.edges[ref, other]["link"] for other in graph.neighbors(ref)
                   if other in position and position[other] < i]
        earlier.sort(key=lambda l: l.basis != "observed")       # prefer observed evidence
        if earlier:
            best = earlier[0]
            other = best.source_ref if best.target_ref == ref else best.target_ref
            linked_by.append(f"{best.reason} → {other}")
            basis.append(best.basis)
        else:
            linked_by.append("start of chain")
            basis.append("observed")
    chain.insert(0, "step", range(1, len(chain) + 1))
    chain["linked_by"] = linked_by
    chain["link_basis"] = basis
    chain["detections"] = [", ".join(detections_by_ref.get(r, [])) for r in chain["raw_ref"]]
    return chain


def reconstruct(events, detections, links=None):
    """Grow one incident from each high-severity detection by following links.

    Returns a list of Incident objects; an empty list means no incident was found.
    """
    links = build_links(events) if links is None else links
    graph = _graph(events, links)
    detections_by_ref = {}
    for d in detections:
        for ref in d.refs:
            detections_by_ref.setdefault(ref, []).append(d.rule)

    incidents, assigned = [], set()
    for seed in (d for d in detections if d.severity == "high"):
        refs = [r for r in seed.refs if r in graph]
        if not refs or refs[0] in assigned:
            continue
        component = set().union(*(nx.node_connected_component(graph, r) for r in refs))
        assigned |= component

        chain = _chain_table(events, component, graph, detections_by_ref)
        related = [d for d in detections if set(d.refs) & component]
        incident_links = [l for l in links if l.source_ref in component and l.target_ref in component]
        ips = sorted(set(chain["src_ip"]) - {""})
        entities = {
            "users": sorted(set(chain["user"]) - {""}),
            "external_ips": [ip for ip in ips if is_external(ip)],
            "internal_ips": [ip for ip in ips if not is_external(ip)],
            "hosts": sorted(set(chain["host"]) - {""}),
            "sessions": sorted(set(chain["session_id"]) - {""}),
            "start": chain["timestamp"].min(),
            "end": chain["timestamp"].max(),
        }
        who = f"'{seed.entities['user']}'" if seed.entities.get("user") else "unknown account"
        incidents.append(Incident(
            incident_id=f"INC-{len(incidents) + 1:02d}",
            title=f"Suspected compromise of {who} from {seed.entities.get('ip', 'unknown source')}",
            severity=max((d.severity for d in related), key=SEVERITY_RANK.get),
            chain=chain, detections=related, links=incident_links, entities=entities))
    return incidents
