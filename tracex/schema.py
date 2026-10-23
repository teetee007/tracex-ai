"""The common event format every log source is converted into.

One row = one original log record. Nothing is merged or dropped at this stage, so every
later conclusion can point back to the exact record it came from via `raw_ref`.
"""

COLUMNS = {
    "event_id": "Unique ID within the dataset, e.g. 'auth-0007'",
    "timestamp": "Event time as a UTC pandas Timestamp; NaT if it could not be parsed",
    "source": "Which log it came from: 'auth', 'web' or 'system'",
    "event_type": "'auth_login', 'web_request' or 'process_exec'",
    "user": "Account name ('' if not recorded)",
    "src_ip": "Client / source IP address ('' if not recorded)",
    "host": "Target system, e.g. 'portal' or 'web-01'",
    "session_id": "Session identifier when the source has one ('' otherwise)",
    "action": "Short human-readable description of what happened",
    "outcome": "'success', 'failure' or 'unknown'",
    "details": "Extra source-specific information worth showing",
    "raw_timestamp": "The timestamp exactly as written in the original log",
    "raw_ref": "Pointer to the original record: 'auth.csv:17' (file line) or 'web_access.json#42' (record index)",
    "raw": "The original record as a JSON string, for the evidence viewer",
    "parse_issues": "Problems found while parsing ('' if none)",
}

SOURCES = ("auth", "web", "system")
