"""Write sample uploads in REAL-WORLD formats (plus two non-log files) to samples/.

The events are the TC-01 attack, re-expressed as the logs a real environment would produce:
  real_formats/access.log           Apache/Nginx combined log format (the portal's web server)
  real_formats/auth.log             Linux auth.log: sshd logins and sudo commands on web-01
  real_formats/sso_export.csv       an SSO export with its own column names (Account, ClientAddress, Outcome, …)
  real_formats/process_events.jsonl endpoint telemetry in Elastic Common Schema field names
  not_logs/recipe.csv               a recipe table (tabular, but not security logs)
  not_logs/meeting_notes.txt        prose
Upload any of them in "Upload logs" mode to see how TraceX recognises (or rejects) them.

Run:  python scripts/make_samples.py
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tracex.parsers import load_dataset  # noqa: E402

OUT = ROOT / "samples"


def main():
    events, _ = load_dataset(ROOT / "data" / "tc01_attack")
    events = events.dropna(subset=["timestamp"]).sort_values("timestamp")
    real = OUT / "real_formats"
    real.mkdir(parents=True, exist_ok=True)

    web = events[events["source"] == "web"]
    with open(real / "access.log", "w", encoding="utf-8", newline="\n") as f:
        for _, e in web.iterrows():
            raw = json.loads(e["raw"])
            f.write(f'{e["src_ip"]} - {e["user"] or "-"} [{e["timestamp"]:%d/%b/%Y:%H:%M:%S +0000}] '
                    f'"{raw["verb"]} {raw["path"]} HTTP/1.1" {raw["status"]} {raw["bytes"]} "-" "{raw["user_agent"]}"\n')

    auth = events[events["source"] == "auth"]
    with open(real / "sso_export.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["EventTime", "Account", "ClientAddress", "Target", "Channel", "Outcome", "SessionKey"])
        for _, e in auth[auth["host"] == "portal"].iterrows():
            w.writerow([f"{e['timestamp']:%Y-%m-%d %H:%M:%S}", e["user"], e["src_ip"], e["host"], "WEB",
                        "Success" if e["outcome"] == "success" else "Failed", e["session_id"]])

    pid = 4100
    with open(real / "auth.log", "w", encoding="utf-8", newline="\n") as f:
        lines = []
        for _, e in auth[auth["host"] != "portal"].iterrows():
            pid += 7
            verb = "Accepted password" if e["outcome"] == "success" else "Failed password"
            lines.append((e["timestamp"], f"{e['timestamp']:%b %d %H:%M:%S} {e['host']} sshd[{pid}]: {verb} for "
                                          f"{e['user']} from {e['src_ip']} port {52000 + pid % 900} ssh2"))
        system = events[events["source"] == "system"]
        for _, e in system[system["action"].str.startswith("sudo ")].iterrows():
            cmd = e["action"][5:]
            lines.append((e["timestamp"], f"{e['timestamp']:%b %d %H:%M:%S} {e['host']} sudo:   {e['user']} : "
                                          f"TTY=pts/0 ; PWD=/home/{e['user']} ; USER=root ; COMMAND=/usr/sbin/{cmd}"))
        lines.append((events["timestamp"].iloc[0], f"{events['timestamp'].iloc[0]:%b %d %H:%M:%S} web-01 CRON[901]: "
                                                    "pam_unix(cron:session): session opened for user root"))
        f.writelines(l + "\n" for _, l in sorted(lines))

    with open(real / "process_events.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for _, e in system.iterrows():
            f.write(json.dumps({"@timestamp": f"{e['timestamp']:%Y-%m-%dT%H:%M:%SZ}", "host.name": e["host"],
                                "user.name": e["user"], "process.name": json.loads(e["raw"])["Process"],
                                "process.command_line": e["action"]}) + "\n")

    # AI test: a vendor VPN/SSO export with cryptic column names and coded values. The offline rules cannot
    # tell what the columns mean, so the file is rejected until "Ask Claude to map" proposes a mapping.
    ai_dir = OUT / "ai_test"
    ai_dir.mkdir(parents=True, exist_ok=True)
    with open(ai_dir / "vendor_access_export.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rec_no", "ev_dt", "acct_nm", "orig_addr", "tgt_sys", "chnl", "res_cd", "sess_ref"])
        for n, (_, e) in enumerate(auth.iterrows(), 1):
            w.writerow([f"R{n:05d}", f"{e['timestamp']:%Y/%m/%d %H:%M:%S}", e["user"], e["src_ip"], e["host"],
                        "SSH" if " ssh " in f" {e['action']} " else "WEB",
                        "OK" if e["outcome"] == "success" else "DENY", e["session_id"] or "-"])
    with open(ai_dir / "office_inventory.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["asset_tag", "item", "location", "purchased", "owner_dept"])
        for row in [("A-1001", "laptop", "floor 2", "2025/03/14", "finance"), ("A-1002", "monitor", "floor 2", "2025/03/14", "finance"),
                    ("A-1003", "printer", "floor 1", "2024/11/02", "admin"), ("A-1004", "router", "server room", "2023/07/21", "it")]:
            w.writerow(row)

    junk = OUT / "not_logs"
    junk.mkdir(parents=True, exist_ok=True)
    with open(junk / "recipe.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["dish", "ingredient", "quantity", "unit", "calories"])
        for row in [("masala dosa", "rice", "2", "cups", "410"), ("masala dosa", "urad dal", "0.5", "cup", "180"),
                    ("masala dosa", "potato", "3", "pcs", "260"), ("sambar", "toor dal", "1", "cup", "350"),
                    ("sambar", "tamarind", "1", "tbsp", "20")]:
            w.writerow(row)
    (junk / "meeting_notes.txt").write_text(
        "Team meeting notes for the hackathon project.\n"
        "We agreed that the timeline view should be finished before the report is written.\n"
        "Someone needs to rehearse the demo at least twice before Thursday morning.\n"
        "The slides should explain the clock skew result in plain language for the judges.\n", encoding="utf-8")
    print(f"Wrote samples to {OUT}")


if __name__ == "__main__":
    main()
