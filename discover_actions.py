#!/usr/bin/env python3
import argparse, json, re
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup

def discover(base_url: str, max_pages=8):
    seen, todo = set(), [base_url.rstrip("/")]
    post_forms = []
    sess = requests.Session()
    while todo and len(seen) < max_pages:
        url = todo.pop(0)
        if url in seen: continue
        seen.add(url)
        try:
            r = sess.get(url, timeout=10)
        except Exception:
            continue
        soup = BeautifulSoup(r.text, "html.parser")

        # same-origin links
        host = base_url.split("://")[1].split("/")[0]
        for a in soup.find_all("a", href=True):
            href = a["href"]
            nxt = urljoin(url, href)
            if host not in (nxt.split("://")[1].split("/")[0] if "://" in nxt else host):
                continue
            if nxt.startswith(base_url) and nxt not in seen and len(todo) < max_pages:
                todo.append(nxt)

        # POST forms
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method != "POST": continue
            action = urljoin(url, form.get("action") or url)
            fields = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name: continue
                t = (inp.get("type") or "").lower()
                if t in ("submit","button","image"): continue
                if re.search(r"csrf|authenticity|token", name, re.I): continue
                fields[name] = inp.get("value") or ""
            post_forms.append({"name": f"POST_{len(post_forms)+1}", "method":"POST", "url": action, "params": fields})
    return post_forms

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Discover POST forms to build actions.json skeleton")
    ap.add_argument("--base", required=True, help="Base URL (e.g., https://target.host/)")
    ap.add_argument("--outfile", default="actions.json", help="Where to write actions.json")
    args = ap.parse_args()

    actions = discover(args.base)
    skeleton = {
        "base_url": args.base.rstrip("/"),
        "session_cookie": {
            "name": "session",
            "value": "REPLACE_WITH_VALID_SESSION_VALUE",
            "domain": args.base.split("://")[1].split("/")[0],
            "path": "/",
            "secure": True,
            "httpOnly": False,
            "sameSite": "Lax"
        },
        "actions": actions,
        "optional": {
            "bounce_url": args.base.rstrip("/"),
            "noreferrer": False   # ✅ fixed: Python boolean
        }
    }

    with open(args.outfile, "w", encoding="utf-8") as f:
        json.dump(skeleton, f, indent=2)

    print(f"[+] Wrote {args.outfile} with {len(actions)} POST actions discovered.")
