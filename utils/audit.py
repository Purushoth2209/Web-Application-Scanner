import hashlib, json, os, time

AUDIT_FILE = os.path.join("reports", "audit_log.jsonl")

def _hash_entry(d: dict, prev_hash: str) -> str:
    m = hashlib.sha256()
    m.update((prev_hash or "").encode("utf-8"))
    m.update(json.dumps(d, sort_keys=True).encode("utf-8"))
    return m.hexdigest()

def append_audit(event: dict):
    os.makedirs("reports", exist_ok=True)
    prev = ""
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "rb") as f:
            try:
                last = f.read().splitlines()[-1]
                prev = json.loads(last.decode("utf-8")).get("hash", "")
            except Exception:
                prev = ""
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "prev": prev
    }
    entry["hash"] = _hash_entry(entry, prev)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
