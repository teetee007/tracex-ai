"""Turn each raw log source into rows of the common event format (see schema.py).

Parsers never drop a record and never crash on a bad one: problems are written to the
`parse_issues` column so validation and the investigator can see them.
"""
import json
from pathlib import Path

import pandas as pd

from .schema import COLUMNS

# Default file name for each source inside a dataset folder.
SOURCE_FILES = {"auth": "auth.csv", "web": "web_access.json", "system": "system.csv"}

AUTH_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"          # 2026-10-20T02:14:30Z
WEB_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"         # 20/Oct/2026:02:15:10 +0000
SYSLOG_TIME_FORMAT = "%Y %b %d %H:%M:%S"         # syslog has no year; we prepend it


def _parse_time(value, fmt):
    """Return (UTC timestamp or NaT, issue text or '')."""
    if value is None or str(value).strip() == "":
        return pd.NaT, "missing timestamp"
    try:
        return pd.to_datetime(str(value).strip(), format=fmt, utc=True), ""
    except (ValueError, TypeError):
        return pd.NaT, f"unparseable timestamp '{value}'"


def _missing(record, fields):
    return [f"missing field '{f}'" for f in fields if str(record.get(f, "")).strip() == ""]


def _event(source, index, raw_ref, record, timestamp, raw_timestamp, issues, **fields):
    row = {col: "" for col in COLUMNS}
    row.update(fields)
    row.update({
        "event_id": f"{source}-{index:04d}",
        "timestamp": timestamp,
        "source": source,
        "raw_timestamp": "" if raw_timestamp is None else str(raw_timestamp),
        "raw_ref": raw_ref,
        "raw": json.dumps(record, default=str),
        "parse_issues": "; ".join(i for i in issues if i),
    })
    return row


def _frame(rows):
    df = pd.DataFrame(rows, columns=list(COLUMNS))
    text = [c for c in COLUMNS if c != "timestamp"]
    # Keep text columns as strings even when a log is empty or a JSON field is null.
    df[text] = df[text].fillna("").astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def parse_auth(file, name="auth.csv"):
    """Authentication log (CSV): time, username, source_ip, target_host, method, result, session."""
    records = pd.read_csv(file, dtype=str, keep_default_na=False).to_dict("records")
    rows = []
    for i, r in enumerate(records):
        ts, ts_issue = _parse_time(r.get("time"), AUTH_TIME_FORMAT)
        result = r.get("result", "").strip().lower()
        rows.append(_event(
            "auth", i, f"{name}:{i + 2}", r, ts, r.get("time"),
            [ts_issue, *_missing(r, ["username", "source_ip", "result"])],
            event_type="auth_login",
            user=r.get("username", ""),
            src_ip=r.get("source_ip", ""),
            host=r.get("target_host", ""),
            session_id=r.get("session", ""),
            action=f"{ {'success': 'successful', 'failure': 'failed'}.get(result, result or '?')} "
                   f"{r.get('method', '?')} login to {r.get('target_host', '?')}",
            outcome=result if result in ("success", "failure") else "unknown",
        ))
    return _frame(rows)


def parse_web(file, name="web_access.json"):
    """Web access log (JSON array or JSON Lines): ts, client, user, verb, path, status, bytes, user_agent, sid."""
    text = file.read() if hasattr(file, "read") else Path(file).read_text(encoding="utf-8")
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    text = text.strip()
    if text.startswith("["):
        records = json.loads(text)
    else:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]

    rows = []
    for i, r in enumerate(records):
        ts, ts_issue = _parse_time(r.get("ts"), WEB_TIME_FORMAT)
        try:
            status = int(r.get("status"))
            outcome = "success" if status < 400 else "failure"
        except (TypeError, ValueError):
            status, outcome = r.get("status"), "unknown"
        user = r.get("user", "")
        rows.append(_event(
            "web", i, f"{name}#{i}", r, ts, r.get("ts"),
            [ts_issue, *_missing(r, ["client", "path"])],
            event_type="web_request",
            user="" if user in ("-", None) else user,
            src_ip=r.get("client", ""),
            host="portal",
            session_id=r.get("sid", "") or "",
            action=f"{r.get('verb', '?')} {r.get('path', '?')}",
            outcome=outcome,
            details=f"status={status} bytes={r.get('bytes', '?')} ua={r.get('user_agent', '')}",
        ))
    return _frame(rows)


def parse_system(file, name="system.csv", year=None):
    """System process log (CSV, syslog-style time without a year): Timestamp, Host, Account, PID, Process, CommandLine."""
    records = pd.read_csv(file, dtype=str, keep_default_na=False).to_dict("records")
    rows = []
    for i, r in enumerate(records):
        raw_ts = r.get("Timestamp", "")
        if year is None:
            ts, ts_issue = pd.NaT, "year unknown for syslog timestamp"
        elif raw_ts.strip() == "":
            ts, ts_issue = pd.NaT, "missing timestamp"
        else:
            ts, ts_issue = _parse_time(f"{year} {raw_ts}", SYSLOG_TIME_FORMAT)
        rows.append(_event(
            "system", i, f"{name}:{i + 2}", r, ts, raw_ts,
            [ts_issue, *_missing(r, ["Account", "CommandLine"])],
            event_type="process_exec",
            user=r.get("Account", ""),
            host=r.get("Host", ""),
            action=r.get("CommandLine", ""),
            outcome="unknown",  # a process log records that a command ran, not whether it succeeded
            details=f"process={r.get('Process', '')} pid={r.get('PID', '')}",
        ))
    return _frame(rows)


def parse_source(source, file, name, year=None):
    """Parse one log of a known source type. `file` is a path or a file-like object (e.g. an upload)."""
    if source == "auth":
        return parse_auth(file, name)
    if source == "web":
        return parse_web(file, name)
    if source == "system":
        return parse_system(file, name, year=year)
    raise ValueError(f"unknown source '{source}'")


def combine(frames):
    return pd.concat(frames, ignore_index=True) if frames else _frame([])


def load_dataset(folder):
    """Load every known source present in a dataset folder into one DataFrame.

    Returns (events, info) where info holds the dataset metadata and which sources were missing.
    """
    folder = Path(folder)
    meta_path = folder / "dataset.json"
    info = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    year = info.get("syslog_year")

    frames, missing = [], []
    for source, filename in SOURCE_FILES.items():
        path = folder / filename
        if not path.exists():
            missing.append(source)
            continue
        frames.append(parse_source(source, path, filename, year=year))

    events = combine(frames)
    info["missing_sources"] = missing
    truth_path = folder / "ground_truth.json"
    if truth_path.exists():
        info["ground_truth"] = json.loads(truth_path.read_text(encoding="utf-8"))
    return events, info
