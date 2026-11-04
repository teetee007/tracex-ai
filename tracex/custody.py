"""Chain of custody: seal the evidence when it is collected, verify it every time it is analysed.

The manifest holds, per log file:
  * the SHA-256 of the whole file (any change at all is detected),
  * a SHA-256 per record, computed from the file's own bytes (independent of the parser), and
  * a hash chain over those records: link_i = SHA-256(link_{i-1} + record_hash_i), so the chain head
    commits to every record AND their order.
On verification, the per-record hashes pinpoint exactly which records were changed, deleted or
inserted. The manifest proves integrity only relative to the moment it was sealed; if the manifest itself
is replaced, nothing here can tell (that needs it stored or signed elsewhere).
"""
import difflib
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .parsers import SOURCE_FILES

MANIFEST = "custody.json"
GENESIS = "0" * 64


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def records(name, data):
    """Split a log file into (locator, bytes) records using only its raw bytes."""
    if name.endswith(".csv"):
        lines = data.splitlines()
        return [(f"{name}:{i + 2}", line) for i, line in enumerate(lines[1:]) if line.strip()]
    text = data.decode("utf-8").strip()
    items = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
    return [(f"{name}#{i}", json.dumps(item, sort_keys=True, separators=(",", ":")).encode())
            for i, item in enumerate(items)]


def describe(name, data):
    recs = records(name, data)
    hashes = [_sha(b) for _, b in recs]
    head = GENESIS
    for h in hashes:
        head = _sha((head + h).encode())
    return {"file": name, "sha256": _sha(data), "bytes": len(data), "records": len(recs),
            "record_sha256": hashes, "chain_head": head}


def seal(folder, sealed_at=None, sealed_by="TraceX evidence generator"):
    """Write custody.json next to the logs. Returns the manifest."""
    folder = Path(folder)
    files = [describe(n, (folder / n).read_bytes()) for n in SOURCE_FILES.values() if (folder / n).exists()]
    manifest = {"manifest_version": 1, "algorithm": "SHA-256", "chain": "link_i = SHA256(link_{i-1} + record_i)",
                "sealed_at": sealed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "sealed_by": sealed_by, "files": files}
    (folder / MANIFEST).write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def load_manifest(folder):
    path = Path(folder) / MANIFEST
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def verify(file_bytes, manifest):
    """Compare current file contents {name: bytes} with a sealed manifest.

    Returns {"status": verified|tampered|unsealed, "files": [per-file result]}.
    """
    if manifest is None:
        return {"status": "unsealed", "files": [], "sealed_at": None}
    out, ok = [], True
    sealed = {f["file"]: f for f in manifest["files"]}
    for name in sorted(set(sealed) | set(file_bytes)):
        if name not in file_bytes:
            out.append({"file": name, "status": "missing", "detail": "file listed in the manifest is gone",
                        "changes": []}); ok = False; continue
        if name not in sealed:
            out.append({"file": name, "status": "unsealed", "detail": "file was not in the sealed manifest",
                        "changes": []}); ok = False; continue
        now, then = describe(name, file_bytes[name]), sealed[name]
        if now["sha256"] == then["sha256"]:
            out.append({"file": name, "status": "verified", "sha256": now["sha256"], "records": now["records"],
                        "detail": f"{now['records']} records, chain head {now['chain_head'][:12]}…", "changes": []})
            continue
        ok = False
        recs = records(name, file_bytes[name])
        changes = []
        sm = difflib.SequenceMatcher(a=then["record_sha256"], b=now["record_sha256"], autojunk=False)
        for op, i1, i2, j1, j2 in sm.get_opcodes():
            if op == "equal":
                continue
            # locators refer to positions in the original (sealed) file for deletions, the current file otherwise
            orig = [f"{name}:{k + 2}" if name.endswith(".csv") else f"{name}#{k}" for k in range(i1, i2)]
            cur = [recs[k][0] for k in range(j1, j2)]
            changes.append({"op": {"replace": "modified", "delete": "deleted", "insert": "inserted"}[op],
                            "sealed_records": orig, "current_records": cur})
        same = sum(b - a for op, a, b, _, _ in sm.get_opcodes() if op == "equal")
        detail = (f"file hash differs; {same} of {then['records']} sealed records unchanged; "
                  + "; ".join(f"{c['op']}: {', '.join(c['sealed_records'] or c['current_records'])}" for c in changes))
        out.append({"file": name, "status": "tampered", "detail": detail, "changes": changes,
                    "sha256": now["sha256"], "sealed_sha256": then["sha256"]})
    return {"status": "verified" if ok else "tampered", "files": out, "sealed_at": manifest.get("sealed_at")}


def read_files(folder):
    folder = Path(folder)
    return {n: (folder / n).read_bytes() for n in SOURCE_FILES.values() if (folder / n).exists()}
