#!/usr/bin/env python3
# Auto-discover forms for CSRF testing (authorized targets only)

import argparse, json, re
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

DUMMY_VALUES = {
    "email": "attacker@example.com",
    "username": "attacker",
    "name": "attacker",
    "user": "attacker",
    "current": "CurrentPass123!",
    "old": "OldPass123!",
    "password": "NewPass123!",
    "new": "NewPass123!",
    "confirm": "NewPass123!",
    "phone": "9000000000",
    "mobile": "9000000000",
    "address": "123 Evil St",
    "token": "",  # intentionally omit CSRF tokens if present
}

def _dummy_for(field_name: str, default: str = "test"):
    n = (field_name or "").lower()
    for k,v in DUMMY_VALUES.items():
        if k in n:
            return v
    return default

def _same_origin(u, base_host):
    try:
        return (urlparse(u).hostname or base_host) == base_host
    except Exception:
        return False

def _collect_forms(url, html, include_get=False):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        if method not in ("POST", "GET"):
            continue
        if method == "GET" and not include_get:
            continue
        action = form.get("action") or ""
        inputs = {}
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name")
            if not name: continue
            if re.search(r"(csrf|authenticity|token)", name, re.I):
                continue
            t = (inp.get("type") or "").lower()
            if t in ("submit","button","image","file"):
                continue
            val = inp.get("value")
            if not val:
                val = _dummy_for(name, default="test")
            inputs[name] = val
        forms.append({
            "method": method,
            "action": action or url,
            "params": inputs
        })
    return forms

def discover(base_url: str, max_pages=12, include_get=False, timeout=10):
    base = base_url.rstrip("/")
    host = urlparse(base).hostname or base.split("://")[1].split("/")[0]
    seen, queue = set(), [base]
    results = []
    sess = requests.Session()
    sess.headers.update({"User-Agent": "WebSentinel-CSRF-Discover/1.0"})
    while queue and len(seen) < max_pages:
        cur = queue.pop(0)
        if cur in seen: continue
        seen.add(cur)
        try:
            r = sess.get(cur, timeout=timeout, allow_redirects=True)
        except Exception:
            continue
        if "text/html" not in (r.headers.get("Content-Type") or ""):
            continue
        forms = _collect_forms(cur, r.text, include_get=include_get)
        for f in forms:
            action_abs = urljoin(cur, f["action"])
            if not _same_origin(action_abs, host):
                continue
            results.append({
                "name": f"{f['method']}_{len(results)+1}",
                "method": f["method"],
                "url": action_abs,
                "params": f["params"]
            })
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            nxt = urljoin(cur, a["href"])
            if nxt.startswith(base) and nxt not in seen and len(queue) < max_pages:
                queue.append(nxt)
    dedup = {}
    for a in results:
        key = (a["method"], a["url"], tuple(sorted(a["params"].keys())))
        dedup[key] = a
    return list(dedup.values())

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Discover POST (and optional GET) forms")
    ap.add_argument("--base", required=True, help="Base URL, e.g. https://target/")
    ap.add_argument("--outfile", default="actions.json", help="Write actions.json here")
    ap.add_argument("--max-pages", type=int, default=12)
    ap.add_argument("--include-get", action="store_true", help="Also include GET forms")
    args = ap.parse_args()

    actions = discover(args.base, max_pages=args.max_pages, include_get=args.include_get)
    skeleton = {
        "base_url": args.base.rstrip("/"),
        "session_cookie": {
            "name": "session",
            "value": "REPLACE_WITH_VALID_VALUE",
            "domain": urlparse(args.base).hostname or args.base.split('://')[1].split('/')[0],
            "path": "/",
            "secure": args.base.lower().startswith("https"),
            "httpOnly": False,
            "sameSite": "Lax"
        },
        "actions": actions,
        "optional": { "bounce_url": args.base.rstrip("/"), "noreferrer": False }
    }
    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2)
    print(f"[+] Wrote {args.outfile} with {len(actions)} action(s).")
