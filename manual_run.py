#!/usr/bin/env python3
# Interactive CSRF runner: you type base URL, auth, and actions each time.

import json, os, time
from urllib.parse import urlparse
from typing import Dict
from csrf_suite_cli import run_suite  # uses your existing engine

def parse_params(qs: str) -> Dict[str,str]:
    out = {}
    if not qs: return out
    for pair in qs.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def ask(prompt, default=None):
    s = input(f"{prompt}{' ['+default+']' if default else ''}: ").strip()
    return s if s else (default or "")

def main():
    print("\n=== WebSentinel+  |  Manual CSRF Runner ===\n")
    base_url = ask("Base URL (e.g., https://target.com or http://localhost:8080)").rstrip("/")
    if not base_url:
        print("Base URL is required. Exiting.")
        return

    # Auth mode
    print("\nAuth mode:")
    print("  1) Cookie (classic CSRF)")
    print("  2) Header (e.g., Authorization: Bearer <JWT>)")
    mode = ask("Choose 1 or 2", "2")

    session_cookie = None
    auth_header = None

    if mode == "1":
        name = ask("Cookie name (e.g., PHPSESSID / JSESSIONID)")
        value = ask("Cookie value")
        host = urlparse(base_url).hostname or "target"
        session_cookie = {
            "name": name, "value": value,
            "domain": host, "path": "/",
            "secure": base_url.lower().startswith("https"),
            "httpOnly": False, "sameSite": "Lax"
        }
    else:
        auth_header = ask('Header (e.g., Authorization: Bearer eyJ...)')

    # Options
    print("\nOptions:")
    bounce_url = ask("Bounce URL (for SameSite refresh; press Enter to use base)", base_url)
    noreferrer = ask("Enable rel=noreferrer vector? (y/n)", "y").lower().startswith("y")
    exploits_only = ask("Also write exploits-only report? (y/n)", "y").lower().startswith("y")

    # Actions
    actions = []
    print("\nAdd actions (endpoint + params). When finished, enter 0.")
    idx = 1
    while True:
        name = ask(f"Action {idx} name (0 to stop)", f"Action{idx}")
        if name == "0": break
        url = ask("  Full endpoint URL (e.g., https://target/rest/user/change-password)")
        method = ask("  Method (POST/GET)", "POST").upper()
        print("  Params format: key1=val1&key2=val2  (leave blank if none)")
        print("  NOTE: If your value contains ! or & use single quotes when launching Python, OR paste here normally.")
        qs = ask("  Params")
        params = parse_params(qs)
        actions.append({"name": name, "method": method, "url": url, "params": params})
        idx += 1
        more = ask("  Add another action? (y/n)", "n")
        if more.lower().startswith("n"):
            break

    if not actions:
        print("No actions entered. Exiting.")
        return

    cfg = {
        "base_url": base_url,
        "actions": actions,
        "optional": {
            "noreferrer": bool(noreferrer),
            "bounce_url": bounce_url
        }
    }
    if session_cookie:
        cfg["session_cookie"] = session_cookie
    if auth_header:
        cfg["optional"]["auth_header"] = auth_header

    os.makedirs("reports", exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    host = urlparse(base_url).hostname or "target"
    cfg_path = os.path.join("reports", f"{host}_manual_{ts}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"\n[+] Wrote config: {cfg_path}")

    print("[+] Running CSRF suite…")
    run_suite(cfg_path, out_dir="reports", exploits_only=exploits_only)
    print("[+] Done. Open your reports/ folder or serve it:")
    print("    python3 -m http.server 8000 --directory reports")
    print("    -> http://localhost:8000/\n")

if __name__ == "__main__":
    main()
