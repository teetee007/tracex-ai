"""Smart ingestion: turn whatever the investigator uploads into TraceX events, or explain why not.

For each file:
  1. reject documents and binaries (PDF, Office, images, archives) by their magic bytes;
  2. detect the format: Apache/Nginx combined access log, Linux auth.log (sshd + sudo), CSV, JSON, JSON Lines,
     or plain text;
  3. parse known log formats natively; for tabular data, map columns to the TraceX schema by column NAME
     (synonyms) and by what the VALUES look like (timestamps, IPs, HTTP methods/status codes, outcomes);
  4. decide which log source it is (auth / web / system) and score how much it looks like security logs;
     files that do not are rejected with the reason.

An optional AI mapper (tracex/ai.py) can propose a mapping for unusual tabular files; its proposal is checked
here with the same value tests before it is used.
"""
import csv
import io
import json
import re
from dataclasses import dataclass, field

import pandas as pd

from .detections import IP_IN_TEXT
from .parsers import _event, _frame

MAGIC = [(b"%PDF", "a PDF document"), (b"PK\x03\x04", "a ZIP / Office document (docx, xlsx, pptx)"),
         (b"\x89PNG", "a PNG image"), (b"\xff\xd8\xff", "a JPEG image"), (b"GIF8", "a GIF image"),
         (b"\xd0\xcf\x11\xe0", "a legacy Office document"), (b"\x1f\x8b", "a gzip archive"),
         (b"Rar!", "a RAR archive"), (b"7z\xbc\xaf", "a 7-Zip archive"), (b"MZ", "a Windows executable")]

APACHE = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
                    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
SYSLOG_TS = r"(?P<time>\w{3}\s+\d{1,2} \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?)"
SSHD = re.compile(SYSLOG_TS + r" (?P<host>\S+) sshd\[\d+\]: (?:(?P<res>Failed|Accepted) (?P<auth>\S+) for "
                  r"(?:invalid user )?(?P<user>\S+)|Invalid user (?P<iuser>\S+)) from (?P<ip>[\d.a-fA-F:]+)")
SUDO = re.compile(SYSLOG_TS + r" (?P<host>\S+) sudo(?:\[\d+\])?: +(?P<user>\S+) : .*?COMMAND=(?P<cmd>.+)$")
SYSLOG_ANY = re.compile(SYSLOG_TS + r" \S+ \S+?(?:\[\d+\])?: ")

# Column-name synonyms per TraceX field (lower-case, compared after removing punctuation).
SYNONYMS = {
    "timestamp": ["timestamp", "time", "datetime", "date", "ts", "eventtime", "@timestamp", "logtime", "created",
                  "occurred", "when", "time_generated", "timegenerated", "event_time", "eventdate"],
    "user": ["user", "username", "account", "accountname", "login", "uid", "principal", "user.name", "subject",
             "targetusername", "actor", "upn", "useridentity"],
    "src_ip": ["src_ip", "srcip", "sourceip", "source_ip", "client", "clientip", "clientaddress", "ip", "remote_addr",
               "remoteaddr", "ipaddress", "source.ip", "client.ip", "c-ip", "callerip", "src"],
    "host": ["host", "hostname", "computer", "server", "device", "target", "dest_host", "host.name", "workstation",
             "machine", "targetserver", "destination"],
    "session_id": ["session", "sessionid", "session_id", "sid", "sessionkey", "logonid", "correlationid"],
    "outcome": ["result", "outcome", "status", "success", "event.outcome", "loginresult", "authresult", "state"],
    "method": ["method", "verb", "http_method", "httpmethod", "cs-method", "request_method", "channel", "authmethod",
               "logontype", "protocol"],
    "path": ["path", "url", "uri", "request", "endpoint", "cs-uri-stem", "url.path", "resource"],
    "status": ["status", "statuscode", "status_code", "http_status", "sc-status", "response_code", "code"],
    "bytes": ["bytes", "size", "bytes_sent", "sc-bytes", "response_size", "length"],
    "user_agent": ["useragent", "user_agent", "ua", "cs(user-agent)", "agent", "user_agent.original"],
    "command": ["command", "commandline", "cmd", "cmdline", "process.command_line", "command_line", "exec",
                "processcommandline"],
    "process": ["process", "image", "process.name", "exe", "program", "processname"],
}
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
SUCCESS = {"success", "succeeded", "successful", "ok", "accepted", "allow", "allowed", "pass", "passed", "true", "1",
           "granted", "logon", "loggedin", "authenticated"}
FAILURE = {"failure", "failed", "fail", "denied", "deny", "rejected", "error", "invalid", "false", "0", "blocked",
           "unauthorized", "badpassword", "locked"}


@dataclass
class FileReport:
    name: str
    status: str = "rejected"                 # accepted | rejected
    format: str = "unknown"
    kind: str = ""                           # auth | web | system
    reason: str = ""
    relevance: float = 0.0
    mapping: dict = field(default_factory=dict)
    mapped_by: str = ""                      # native | rules | ai
    columns: list = field(default_factory=list)
    sample: list = field(default_factory=list)
    events: pd.DataFrame = None
    notes: list = field(default_factory=list)


def _norm(name):
    return re.sub(r"[^a-z0-9@.]", "", str(name).lower())


# ---------------------------------------------------------------- value tests (also used to check AI proposals)
def _parse_times(series):
    s = series.dropna().astype(str).str.strip()
    s = s[s != ""]
    if s.empty:
        return pd.Series(dtype="datetime64[ns, UTC]"), 0.0
    num = pd.to_numeric(s, errors="coerce")
    if num.notna().mean() > .9:                                   # epoch seconds or milliseconds
        unit = "ms" if num.median() > 1e11 else "s"
        t = pd.to_datetime(num, unit=unit, utc=True, errors="coerce") if num.median() > 1e8 else pd.Series(pd.NaT, index=s.index)
    else:
        t = pd.to_datetime(s, utc=True, errors="coerce", format="mixed")
    return t, float(t.notna().mean())


def value_score(field_name, series):
    """0-1: how well a column's values fit a TraceX field."""
    s = series.dropna().astype(str).str.strip()
    s = s[s != ""].head(200)
    if s.empty:
        return 0.0
    if field_name == "timestamp":
        return _parse_times(s)[1]
    if field_name == "src_ip":
        return float(s.str.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{6,}").mean())
    if field_name == "status":
        n = pd.to_numeric(s, errors="coerce")
        return float(((n >= 100) & (n < 600)).mean())
    if field_name == "method":
        return float(s.str.upper().isin(HTTP_METHODS | {"SSH", "WEB", "RDP", "VPN", "SSO", "INTERACTIVE", "NETWORK"}).mean())
    if field_name == "outcome":
        return float(s.str.lower().str.replace(r"[^a-z0-9]", "", regex=True).isin(SUCCESS | FAILURE).mean())
    if field_name == "path":
        return float(s.str.startswith("/").mean())
    if field_name == "bytes":
        return float(pd.to_numeric(s, errors="coerce").notna().mean())
    if field_name == "user_agent":
        return float(s.str.contains(r"Mozilla|curl|python|Go-http|bot|Wget|zgrab", case=False).mean())
    if field_name == "command":
        return float(s.str.contains(r"^[\w./-]+(?:\s|$)").mean() * s.str.contains(r"\s").mean())
    if field_name in ("user", "host", "session_id", "process"):
        uniq = s.nunique() / len(s)
        short = (s.str.len() <= 64).mean()
        return float(short * (0.5 if uniq > .95 and field_name == "user" else 0.8))
    return 0.0


def map_columns(df):
    """Rule-based mapping {field: column}; each column used at most once, best scores first."""
    cand = []
    for col in df.columns:
        n = _norm(col)
        for fld, syn in SYNONYMS.items():
            name = 1.0 if n in {_norm(x) for x in syn} else (0.5 if any(_norm(x) in n for x in syn if len(x) > 3) else 0)
            if name == 0 and fld not in ("timestamp", "src_ip", "status", "path", "user_agent"):
                continue                                              # value tests alone are too weak for these
            v = value_score(fld, df[col])
            score = 0.6 * name + 0.4 * v if name else 0.75 * v
            if score >= 0.45:
                cand.append((score, fld, col))
    mapping, used = {}, set()
    for score, fld, col in sorted(cand, reverse=True):
        if fld not in mapping and col not in used:
            mapping[fld] = col
            used.add(col)
    return mapping


def classify(mapping, df):
    """Which log source a mapped table is, and a relevance score with reasons."""
    has = lambda f: f in mapping
    http_method = has("method") and df[mapping["method"]].astype(str).str.upper().isin(HTTP_METHODS).mean() > .5
    web = int(has("path")) + int(has("status")) + int(has("user_agent")) + int(http_method)
    system = 2 * int(has("command")) + int(has("process"))
    auth = 2 * int(has("outcome")) + int(has("user")) + int(has("src_ip") and not has("path"))
    kind = max([("web", web), ("system", system), ("auth", auth)], key=lambda x: x[1])
    signals = {"timestamp": has("timestamp"), "who (user or IP)": has("user") or has("src_ip"),
               "what (action, request, command or outcome)": has("path") or has("command") or has("outcome")}
    relevance = sum(signals.values()) / len(signals)
    return (kind[0] if kind[1] > 0 else ""), relevance, signals


# ---------------------------------------------------------------- building events
def _outcome(value, kind, status=None):
    if status is not None:
        try:
            return "success" if int(float(status)) < 400 else "failure"
        except (TypeError, ValueError):
            pass
    v = re.sub(r"[^a-z0-9]", "", str(value).lower())
    return "success" if v in SUCCESS else "failure" if v in FAILURE else "unknown"


def events_from_table(df, mapping, kind, name):
    times, _ = _parse_times(df[mapping["timestamp"]]) if "timestamp" in mapping else (None, 0)
    rows = []
    get = lambda r, f: "" if f not in mapping or pd.isna(r[mapping[f]]) else str(r[mapping[f]]).strip()
    for i, (idx, r) in enumerate(df.iterrows()):
        raw_ts = get(r, "timestamp")
        ts = times.get(idx, pd.NaT) if times is not None else pd.NaT
        issues = [] if pd.notna(ts) else (["missing timestamp"] if not raw_ts else [f"unparseable timestamp '{raw_ts}'"])
        ref = f"{name}:{i + 2}" if name.lower().endswith((".csv", ".tsv", ".txt")) else f"{name}#{i}"
        record = {k: (None if pd.isna(v) else v) for k, v in r.to_dict().items()}
        user = get(r, "user")
        user = "" if user in ("-", "none", "null", "nan") else user
        if kind == "auth":
            method = get(r, "method").lower() or "web"
            host = get(r, "host") or "unknown-host"
            out = _outcome(get(r, "outcome"), kind)
            word = {"success": "successful", "failure": "failed"}.get(out, "unknown")
            rows.append(_event("auth", i, ref, record, ts, raw_ts, issues, event_type="auth_login", user=user,
                               src_ip=get(r, "src_ip"), host=host, session_id=get(r, "session_id"),
                               action=f"{word} {method} login to {host}", outcome=out))
        elif kind == "web":
            status = get(r, "status")
            rows.append(_event("web", i, ref, record, ts, raw_ts, issues, event_type="web_request", user=user,
                               src_ip=get(r, "src_ip"), host=get(r, "host") or "web", session_id=get(r, "session_id"),
                               action=f"{get(r, 'method') or 'GET'} {get(r, 'path') or '/'}",
                               outcome=_outcome(get(r, "outcome"), kind, status or None),
                               details=f"status={status or '?'} bytes={get(r, 'bytes') or '?'} ua={get(r, 'user_agent')}"))
        else:
            rows.append(_event("system", i, ref, record, ts, raw_ts, issues, event_type="process_exec", user=user,
                               host=get(r, "host") or "unknown-host", src_ip=get(r, "src_ip"),
                               action=get(r, "command") or get(r, "process"), outcome="unknown",
                               details=f"process={get(r, 'process')}"))
    return _frame(rows)


def _syslog_time(value, year):
    if value[:4].isdigit():
        return pd.to_datetime(value, utc=True, errors="coerce")
    return pd.to_datetime(f"{year} {value}", format="%Y %b %d %H:%M:%S", utc=True, errors="coerce")


def parse_apache(lines, name):
    rows = []
    for i, line in enumerate(lines):
        m = APACHE.match(line)
        if not m:
            continue
        g = m.groupdict()
        ts = pd.to_datetime(g["time"], format="%d/%b/%Y:%H:%M:%S %z", utc=True, errors="coerce")
        rows.append(_event("web", i, f"{name}:{i + 1}", g, ts, g["time"],
                           [] if pd.notna(ts) else [f"unparseable timestamp '{g['time']}'"],
                           event_type="web_request", user="" if g["user"] == "-" else g["user"], src_ip=g["ip"],
                           host="web", action=f"{g['method']} {g['path']}",
                           outcome="success" if int(g["status"]) < 400 else "failure",
                           details=f"status={g['status']} bytes={g['bytes']} ua={g['ua'] or ''}"))
    return _frame(rows)


def parse_authlog(lines, name, year):
    rows = []
    for i, line in enumerate(lines):
        ref = f"{name}:{i + 1}"
        m = SSHD.match(line)
        if m:
            g = m.groupdict()
            ts = _syslog_time(g["time"], year)
            ok = g["res"] == "Accepted"
            user = g["user"] or g["iuser"]
            rows.append(_event("auth", i, ref, {"line": line}, ts, g["time"],
                               [] if pd.notna(ts) else ["unparseable timestamp"], event_type="auth_login", user=user,
                               src_ip=g["ip"], host=g["host"],
                               action=f"{'successful' if ok else 'failed'} ssh login to {g['host']}",
                               outcome="success" if ok else "failure", details=f"auth={g['auth'] or 'none'}"))
            continue
        m = SUDO.match(line)
        if m:
            g = m.groupdict()
            ts = _syslog_time(g["time"], year)
            rows.append(_event("system", i, ref, {"line": line}, ts, g["time"],
                               [] if pd.notna(ts) else ["unparseable timestamp"], event_type="process_exec",
                               user=g["user"], host=g["host"], action=f"sudo {g['cmd'].strip()}", outcome="unknown",
                               details="process=sudo"))
    return _frame(rows)


# ---------------------------------------------------------------- per-file entry point
def ingest(name, data, year=2026):
    rep = FileReport(name=name)
    head = data[:8]
    for magic, what in MAGIC:
        if head.startswith(magic):
            rep.format, rep.reason = "binary", f"This is {what}, not a log file. Export the logs as CSV, JSON or plain text."
            return rep
    if b"\x00" in data[:4096]:
        rep.format, rep.reason = "binary", "This file contains binary data, not text logs."
        return rep
    text = data.decode("utf-8", errors="replace")
    if text.count("\ufffd") > max(5, len(text) * 0.01):
        rep.reason = "This file is not readable UTF-8 text."
        return rep
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        rep.reason = "The file is empty."
        return rep
    sample = lines[:200]

    # native line formats
    apache = sum(bool(APACHE.match(l)) for l in sample) / len(sample)
    sshd = sum(bool(SSHD.match(l) or SUDO.match(l)) for l in sample) / len(sample)
    syslog = sum(bool(SYSLOG_ANY.match(l)) for l in sample) / len(sample)
    if apache >= .6:
        rep.events, rep.format, rep.kind, rep.mapped_by = parse_apache(lines, name), "Apache/Nginx access log", "web", "native"
    elif syslog >= .6 and sshd > 0:
        rep.events, rep.format, rep.kind, rep.mapped_by = parse_authlog(lines, name, year), "Linux auth.log (sshd, sudo)", "auth", "native"
        rep.notes.append(f"{len(rep.events)} of {len(lines)} lines are sshd logins or sudo commands; other lines skipped.")
        if (rep.events["source"] == "system").any():
            rep.kind = "auth + system"
    if rep.events is not None:
        rep.relevance = 1.0 if len(rep.events) else 0.0
        if not len(rep.events):
            rep.events, rep.reason = None, "Recognised the log format but found no login, request or command entries."
            return rep
        rep.status, rep.reason = "accepted", f"Parsed natively as {rep.format}."
        return rep

    # tabular formats
    df = _table(text)
    if df is None:
        prose = sum(len(l.split()) >= 8 and not IP_IN_TEXT.search(l) for l in sample) / len(sample)
        rep.format = "plain text"
        rep.reason = ("This looks like prose (a document or notes), not log records: "
                      f"{prose:.0%} of lines are sentences and none follow a known log format."
                      if prose > .3 else "No known log format, and no table or JSON records found.")
        return rep
    rep.format, rep.columns, rep.sample = df.attrs.get("fmt", "table"), [str(c) for c in df.columns], df.head(5).astype(str).to_dict("records")
    return _finish_table(rep, df, map_columns(df), "rules")


def _table(text):
    s = text.lstrip()
    try:
        if s.startswith("["):
            df = pd.json_normalize(json.loads(s))
            df.attrs["fmt"] = "JSON"
            return df if len(df.columns) >= 2 else None
        if s.startswith("{"):
            df = pd.json_normalize([json.loads(l) for l in s.splitlines() if l.strip()])
            df.attrs["fmt"] = "JSON Lines"
            return df if len(df.columns) >= 2 else None
    except (ValueError, TypeError):
        return None
    try:
        dialect = csv.Sniffer().sniff(s[:4096], delimiters=",;\t|")
        df = pd.read_csv(io.StringIO(s), sep=dialect.delimiter, dtype=str, keep_default_na=False)
        df.attrs["fmt"] = "CSV" if dialect.delimiter == "," else f"delimited ('{dialect.delimiter}')"
        return df if len(df.columns) >= 2 and len(df) else None
    except (csv.Error, pd.errors.ParserError, ValueError):
        return None


def _finish_table(rep, df, mapping, mapped_by):
    rep.mapping, rep.mapped_by = mapping, mapped_by
    kind, relevance, signals = classify(mapping, df)
    rep.relevance, rep.kind = relevance, kind
    missing = [k for k, ok in signals.items() if not ok]
    if relevance < 1 or not kind:
        rep.status = "rejected"
        rep.reason = ("This table does not look like security logs: no " + " and no ".join(missing) + " column was "
                      f"recognised among: {', '.join(rep.columns[:12])}{' …' if len(rep.columns) > 12 else ''}.")
        return rep
    rep.events = events_from_table(df, mapping, kind, rep.name)
    timed = rep.events["timestamp"].notna().mean()
    if timed < .5:
        rep.status, rep.events = "rejected", None
        rep.reason = f"The '{mapping['timestamp']}' column could not be read as times for most rows."
        return rep
    rep.status = "accepted"
    rep.reason = f"Mapped {len(mapping)} columns by {'AI (validated)' if mapped_by == 'ai' else 'name and value patterns'}; read as {kind} events."
    return rep


def apply_mapping(rep, data, mapping, mapped_by):
    """Re-run a tabular file with a different mapping (an AI proposal or a manual override), validated first."""
    df = _table(data.decode("utf-8", errors="replace"))
    clean = {}
    for fld, col in (mapping or {}).items():
        if fld in SYNONYMS and col in df.columns and col not in clean.values():
            if fld in ("timestamp", "src_ip", "status") and value_score(fld, df[col]) < .6:
                rep.notes.append(f"Ignored proposed {fld} → '{col}': its values do not look like a {fld}.")
                continue
            clean[fld] = col
    return _finish_table(rep, df, clean, mapped_by)
