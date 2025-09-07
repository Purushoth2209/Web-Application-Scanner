import os
import time
import json
from pathlib import Path
from .crawler import crawl_site
from .auth import login
from .bac_tests import (
    test_idor, test_path_idor, test_unauthenticated_access,
    test_privilege, test_directory,
    test_method_bypass, test_force_browse, extract_forms,
    test_header_token, test_cookie_manipulation, test_cors,
)


def run(base_url: str, out_dir: Path, user_creds: dict | None = None, admin_creds: dict | None = None, max_depth: int = 3) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    print(f"[+] Starting BAC scan on {base_url} at {timestamp}...")

    # Determine hard runtime ceiling (default 8s within outer 10s API timeout)
    try:
        max_runtime = float(os.getenv("BAC_MAX_RUNTIME_SECONDS", "8"))
    except ValueError:
        max_runtime = 8.0
    start_overall = time.time()

    user_creds = user_creds or {"username": "dummy", "password": "dummy"}
    session = login(base_url, user_creds["username"], user_creds["password"])

    # Bound crawling to prevent long hangs
    crawl_errors: list[str] = []
    try:
        links = crawl_site(base_url, session, max_depth=max_depth)
    except Exception as e:
        crawl_errors.append(str(e))
        # Renderer timeout pattern
        if 'Timed out receiving message from renderer' in str(e):
            crawl_errors.append('renderer_timeout')
        links = []
    print(f"[+] Crawled {len(links)} links")

    # If still zero, inject baseline endpoints here as safety net (independent of crawler fallback)
    if not links:
        baseline = [f"{base_url.rstrip('/')}{p}" for p in ["/", "/login", "/admin", "/config", "/dashboard"]]
        links.extend(baseline)
        print(f"[!] Injected baseline endpoints for scan: {len(baseline)} seeds")

    results = {
        "site": base_url,
        "timestamp": timestamp,
        "crawled_links": len(links),
        "links_discovered": links,
        "tests": [],
        "crawl_errors": crawl_errors,
    }

    idor_results = []
    for l in links:
        # Early abort check
        if time.time() - start_overall > max_runtime:
            print("[!] BAC runtime ceiling reached during IDOR tests – stopping early.")
            break
        idor_results.extend(test_idor(l, session))
        for f in extract_forms(l, session):
            if f["method"] == "get":
                idor_results.extend(test_idor(f["url"], session))
    results["tests"].append({"type": "IDOR", "results": idor_results})

    # Path-based IDOR
    if time.time() - start_overall <= max_runtime:
        path_idor_results = []
        for l in links:
            if time.time() - start_overall > max_runtime:
                break
            path_idor_results.extend(test_path_idor(l, session))
        results["tests"].append({"type": "Path IDOR", "results": path_idor_results})
    else:
        results["tests"].append({"type": "Path IDOR", "results": [], "skipped": True})

    if time.time() - start_overall <= max_runtime:
        results["tests"].append({"type": "Privilege Escalation", "results": test_privilege(base_url, session, admin_creds)})
    else:
        results["tests"].append({"type": "Privilege Escalation", "results": [], "skipped": True})
    if time.time() - start_overall <= max_runtime:
        results["tests"].append({"type": "Directory Traversal", "results": test_directory(base_url, session)})
    else:
        results["tests"].append({"type": "Directory Traversal", "results": [], "skipped": True})

    method_results = []
    if time.time() - start_overall <= max_runtime:
        for l in links:
            if time.time() - start_overall > max_runtime:
                print("[!] Stopping Method Bypass enumeration early due to time budget.")
                break
            method_results.extend(test_method_bypass(l, session))
            for f in extract_forms(l, session):
                method_results.extend(test_method_bypass(f["url"], session))
        results["tests"].append({"type": "Method Bypass", "results": method_results})
    else:
        results["tests"].append({"type": "Method Bypass", "results": [], "skipped": True})

    # Remaining tests with time checks
    def timed_add(test_name, fn):
        if time.time() - start_overall <= max_runtime:
            try:
                results["tests"].append({"type": test_name, "results": fn})
            except Exception as e:
                results["tests"].append({"type": test_name, "results": [], "error": str(e)})
        else:
            results["tests"].append({"type": test_name, "results": [], "skipped": True})

    timed_add("Force Browsing", test_force_browse(base_url, session))
    timed_add("Header/Token Tampering", test_header_token(base_url, session))
    timed_add("Cookie Manipulation", test_cookie_manipulation(base_url, session))
    timed_add("CORS Misconfiguration", test_cors(base_url, session))

    # Unauthenticated access comparison (subset) – run near end to reuse links list
    if time.time() - start_overall <= max_runtime:
        try:
            import requests
            anon_session = requests.Session()
            subset = links[:25]
            unauth = test_unauthenticated_access(subset, session, anon_session, limit=15)
            results["tests"].append({"type": "Unauthenticated Access", "results": unauth})
        except Exception as e:
            results["tests"].append({"type": "Unauthenticated Access", "results": [], "error": str(e)})
    else:
        results["tests"].append({"type": "Unauthenticated Access", "results": [], "skipped": True})

    if time.time() - start_overall > max_runtime:
        results["partial"] = True
        results["time_elapsed"] = round(time.time() - start_overall, 2)
        results["time_budget"] = max_runtime

    report_file = out_dir / "bac_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return {"json": str(report_file)}
