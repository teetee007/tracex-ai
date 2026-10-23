"""Data-quality checks on normalized events.

Validation never changes or removes events. It produces a list of issues, each pointing at
the record (`raw_ref`) it concerns, so the investigator knows which evidence is weak.
"""
import ipaddress

import pandas as pd

ISSUE_COLUMNS = ["raw_ref", "source", "severity", "check", "message"]

# A source is expected to write records in time order. Going backwards by more than this
# suggests clock problems or tampering rather than normal write jitter.
OUT_OF_ORDER_TOLERANCE = pd.Timedelta(seconds=5)


def _issue(row, severity, check, message):
    return {"raw_ref": row["raw_ref"], "source": row["source"], "severity": severity,
            "check": check, "message": message}


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate(events):
    """Return a DataFrame of issues (one row per problem found)."""
    issues = []

    # 1. Problems the parsers already recorded (missing fields, bad timestamps).
    for _, row in events[events["parse_issues"] != ""].iterrows():
        for problem in row["parse_issues"].split("; "):
            severity = "error" if "timestamp" in problem else "warning"
            issues.append(_issue(row, severity, "parse", problem))

    # 2. Malformed IP addresses.
    for _, row in events[(events["src_ip"] != "") & ~events["src_ip"].apply(_valid_ip)].iterrows():
        issues.append(_issue(row, "warning", "ip_format", f"invalid IP address '{row['src_ip']}'"))

    # 3. Exact duplicate records within a source (possible double collection).
    dupes = events[events.duplicated(subset=["source", "raw"], keep="first")]
    for _, row in dupes.iterrows():
        issues.append(_issue(row, "warning", "duplicate", "identical to an earlier record in the same log"))

    # 4. Out-of-order timestamps within one log file (clock jumps or edited logs).
    for _, group in events.groupby("source", sort=False):
        times = group["timestamp"]  # original file order
        running_max = times.cummax()
        backwards = group[times < running_max - OUT_OF_ORDER_TOLERANCE]
        for idx, row in backwards.iterrows():
            gap = running_max.loc[idx] - row["timestamp"]
            issues.append(_issue(row, "warning", "clock_order",
                                 f"timestamp is {gap} earlier than a previous record in this log"))

    return pd.DataFrame(issues, columns=ISSUE_COLUMNS)


def source_coverage(events):
    """Time span covered by each source, so missing periods and sources are visible."""
    timed = events.dropna(subset=["timestamp"])
    if timed.empty:
        return pd.DataFrame(columns=["source", "records", "first", "last"])
    cov = timed.groupby("source")["timestamp"].agg(records="count", first="min", last="max").reset_index()
    untimed = events[events["timestamp"].isna()].groupby("source").size()
    cov["untimed_records"] = cov["source"].map(untimed).fillna(0).astype(int)
    return cov
