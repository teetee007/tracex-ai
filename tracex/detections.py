"""Rule-based detection of suspicious events and sequences.

Each rule is small, documented and returns the exact records (`raw_ref`s) that triggered it,
so every alert can be checked by opening the original log lines.
"""
import ipaddress
import json
import re
from dataclasses import dataclass, field

import pandas as pd

INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

BRUTE_FORCE_THRESHOLD = 5                      # failed logins ...
BRUTE_FORCE_WINDOW = pd.Timedelta(minutes=10)  # ... within this window
SCAN_THRESHOLD = 3                             # error responses from one IP ...
SCAN_GAP = pd.Timedelta(minutes=5)             # ... each within this gap of the previous one
DISCOVERY_MIN_COMMANDS = 2                     # one `id` on its own is normal admin work
LARGE_RESPONSE_BYTES = 1_000_000

AUTOMATED_UA = re.compile(r"python-requests|curl/|wget/|go-http-client|zgrab|sqlmap|nikto|nmap", re.I)
SENSITIVE_PATH = re.compile(r"export|backup|dump|download", re.I)
DISCOVERY_CMD = re.compile(r"^(whoami|id|hostname|uname( -a)?|cat /etc/(passwd|shadow|group)"
                           r"|ls .*(/etc|/var/backups|/root|/home).*)$")
ACCOUNT_CREATION_CMD = re.compile(r"\b(?:useradd|adduser)\b|net user .* /add", re.I)
TRANSFER_CMD = re.compile(r"\b(?:scp|rsync|curl|wget|ftp|sftp|nc)\b")
IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Detection:
    rule: str
    title: str
    severity: str        # low / medium / high
    summary: str
    refs: list           # raw_refs of the records that triggered the rule
    entities: dict = field(default_factory=dict)


def is_external(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in INTERNAL_NETWORKS)


def _timed(events, source):
    return events[(events["source"] == source) & events["timestamp"].notna()].sort_values("timestamp")


def _t(ts):
    return ts.strftime("%H:%M:%S")


def _raw_field(frame, key):
    """One field of the original record for every row (works on empty frames too)."""
    return [json.loads(raw).get(key) for raw in frame["raw"]]


def brute_force(events):
    """R1/R2: at least 5 failed logins for one user from one IP within 10 minutes,
    with or without a successful login right after."""
    out = []
    for (user, ip), group in _timed(events, "auth").groupby(["user", "src_ip"], sort=False):
        failures = []
        for _, row in group.iterrows():
            failures = [f for f in failures if row["timestamp"] - f["timestamp"] <= BRUTE_FORCE_WINDOW]
            if row["outcome"] == "failure":
                failures.append(row)
                continue
            if row["outcome"] == "success" and len(failures) >= BRUTE_FORCE_THRESHOLD:
                out.append(Detection(
                    "R1", "Password guessing followed by successful login", "high",
                    f"{len(failures)} failed logins for '{user}' from {ip} between "
                    f"{_t(failures[0]['timestamp'])} and {_t(failures[-1]['timestamp'])}, "
                    f"then a successful login at {_t(row['timestamp'])}.",
                    [f["raw_ref"] for f in failures] + [row["raw_ref"]],
                    {"user": user, "ip": ip, "session": row["session_id"]}))
            failures = []
        if len(failures) >= BRUTE_FORCE_THRESHOLD:
            out.append(Detection(
                "R2", "Password guessing (no successful login observed)", "medium",
                f"{len(failures)} failed logins for '{user}' from {ip} ending at "
                f"{_t(failures[-1]['timestamp'])}.",
                [f["raw_ref"] for f in failures], {"user": user, "ip": ip}))
    return out


def external_remote_login(events):
    """R3: successful login to a server (not the web portal) from an address outside the company."""
    auth = _timed(events, "auth")
    system_hosts = set(events.loc[events["source"] == "system", "host"])
    hits = auth[(auth["outcome"] == "success") & auth["host"].isin(system_hosts) & auth["src_ip"].apply(is_external)]
    return [Detection("R3", "Remote login to a server from an external address", "high",
                      f"'{row['user']}' logged in to {row['host']} from {row['src_ip']} at {_t(row['timestamp'])}.",
                      [row["raw_ref"]], {"user": row["user"], "ip": row["src_ip"], "host": row["host"]})
            for _, row in hits.iterrows()]


def automated_client(events):
    """R4: web requests sent by a script or scanning tool instead of a browser."""
    web = _timed(events, "web").copy()
    web["ua"] = pd.Series([ua or "" for ua in _raw_field(web, "user_agent")], index=web.index, dtype=str)
    hits = web[web["ua"].str.contains(AUTOMATED_UA)]
    return [Detection("R4", "Automated tool used against the web portal", "medium",
                      f"{len(g)} requests from {ip} with user agent '{ua}'.",
                      g["raw_ref"].tolist(), {"ip": ip, "user_agent": ua})
            for (ip, ua), g in hits.groupby(["src_ip", "ua"], sort=False)]


def web_scanning(events):
    """R5: a burst of error responses from one IP (probing for pages that do not exist)."""
    out = []
    errors = _timed(events, "web")
    errors = errors[errors["outcome"] == "failure"]
    for ip, group in errors.groupby("src_ip", sort=False):
        cluster, prev = [], None
        for _, row in group.iterrows():
            if prev is not None and row["timestamp"] - prev > SCAN_GAP:
                cluster = []
            cluster.append(row)
            prev = row["timestamp"]
        if len(cluster) >= SCAN_THRESHOLD:
            out.append(Detection("R5", "Web scanning (burst of error responses)", "low",
                                 f"{len(cluster)} error responses for requests from {ip} ending at {_t(cluster[-1]['timestamp'])}.",
                                 [r["raw_ref"] for r in cluster], {"ip": ip}))
    return out


def sensitive_data_access(events):
    """R6: export/backup/download pages or unusually large responses."""
    web = _timed(events, "web").copy()
    web["bytes"] = pd.to_numeric(pd.Series(_raw_field(web, "bytes"), index=web.index, dtype=object),
                                 errors="coerce").fillna(0)
    path = web["action"].str.split(" ", n=1).str[-1]
    hits = web[(web["outcome"] == "success") & (path.str.contains(SENSITIVE_PATH) | (web["bytes"] > LARGE_RESPONSE_BYTES))]
    out = []
    for (ip, user), g in hits.groupby(["src_ip", "user"], sort=False):
        biggest = g.loc[g["bytes"].idxmax()]
        out.append(Detection("R6", "Sensitive data accessed through the portal", "medium",
                             f"{len(g)} request(s) by '{user or '?'}' from {ip}, largest: "
                             f"{biggest['action']} ({int(biggest['bytes']):,} bytes).",
                             g["raw_ref"].tolist(), {"ip": ip, "user": user}))
    return out


def discovery_commands(events):
    """R7: several reconnaissance commands by one user on one host."""
    system = _timed(events, "system")
    hits = system[system["action"].str.strip().str.match(DISCOVERY_CMD)]
    return [Detection("R7", "Discovery commands on a host", "medium",
                      f"'{user}' ran {len(g)} discovery commands on {host}: "
                      + ", ".join(f"`{a}`" for a in g["action"]) + ".",
                      g["raw_ref"].tolist(), {"user": user, "host": host})
            for (user, host), g in hits.groupby(["user", "host"], sort=False) if len(g) >= DISCOVERY_MIN_COMMANDS]


def account_creation(events):
    """R8: a new local account was created (common persistence step)."""
    system = _timed(events, "system")
    hits = system[system["action"].str.contains(ACCOUNT_CREATION_CMD)]
    return [Detection("R8", "Local account created", "high",
                      f"'{row['user']}' ran `{row['action']}` on {row['host']} at {_t(row['timestamp'])}.",
                      [row["raw_ref"]], {"user": row["user"], "host": row["host"]})
            for _, row in hits.iterrows()]


def external_transfer(events):
    """R9: a file-transfer command sending data to an external address."""
    out = []
    system = _timed(events, "system")
    for _, row in system[system["action"].str.contains(TRANSFER_CMD)].iterrows():
        external = [ip for ip in IP_IN_TEXT.findall(row["action"]) if is_external(ip)]
        if external:
            out.append(Detection("R9", "Possible data exfiltration to an external address", "high",
                                 f"'{row['user']}' ran `{row['action']}` on {row['host']} at {_t(row['timestamp'])}.",
                                 [row["raw_ref"]], {"user": row["user"], "host": row["host"], "ip": external[0]}))
    return out


RULES = [brute_force, external_remote_login, automated_client, web_scanning,
         sensitive_data_access, discovery_commands, account_creation, external_transfer]


def run_all(events):
    detections = [d for rule in RULES for d in rule(events)]
    return sorted(detections, key=lambda d: (-SEVERITY_RANK[d.severity], d.rule))
