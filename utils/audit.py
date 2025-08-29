import hashlib, json, os, time

AUDIT_FILE = "reports/audit_log.jsonl"

def _digest(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def append_audit(event: dict, out_path=AUDIT_FILE):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    prev = "0"*64
    if os.path.exists(out_path):
        with open(out_path, "rb") as f:
            try:
                last = f.readlines()[-1]
                prev = json.loads(last)["hash"]
            except Exception:
                prev = "0"*64
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "prev": prev
    }
    entry["hash"] = _digest(entry["prev"] + json.dumps(entry["event"], sort_keys=True) + entry["ts"])
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry["hash"]
