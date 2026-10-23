import io
import json

from tracex.parsers import combine, parse_auth, parse_web
from tracex.validation import source_coverage, validate

AUTH_CSV = """time,username,source_ip,target_host,method,result,session
2026-10-20T02:00:00Z,alice,10.0.1.11,portal,web,success,s1
2026-10-20T02:05:00Z,bob,10.0.1.12,portal,web,success,s2
2026-10-20T01:30:00Z,carol,10.0.1.13,portal,web,success,s3
2026-10-20T02:06:00Z,dave,999.1.1.1,portal,web,failure,
2026-10-20T02:06:00Z,dave,999.1.1.1,portal,web,failure,
"""


def test_validation_catches_clock_ip_and_duplicates():
    issues = validate(parse_auth(io.StringIO(AUTH_CSV)))
    checks = dict(zip(issues["raw_ref"] + "/" + issues["check"], issues["severity"]))
    assert "auth.csv:4/clock_order" in checks          # 01:30 after 02:05
    assert "auth.csv:5/ip_format" in checks
    assert "auth.csv:6/duplicate" in checks
    assert "auth.csv:2/clock_order" not in checks


def test_clean_data_has_no_issues():
    web = json.dumps([{"ts": "20/Oct/2026:02:15:10 +0000", "client": "10.0.1.11", "user": "alice",
                       "verb": "GET", "path": "/", "status": 200, "bytes": 10, "user_agent": "x", "sid": "s"}])
    events = combine([parse_web(io.StringIO(web))])
    assert validate(events).empty
    assert source_coverage(events)["records"].tolist() == [1]


def test_json_lines_and_timezone_offset_normalized():
    lines = '{"ts": "20/Oct/2026:07:45:10 +0530", "client": "10.0.1.11", "path": "/"}\n'
    events = parse_web(io.StringIO(lines))
    assert str(events["timestamp"].iloc[0]) == "2026-10-20 02:15:10+00:00"
