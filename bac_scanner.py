import os, time, json
from crawler import crawl_site
from auth import login
from bac_tests import (
    test_idor, test_privilege, test_directory,
    test_method_bypass, test_force_browse, extract_forms,
    test_header_token, test_cookie_manipulation, test_cors  # ✅ new tests
)

def run_bac_scan(base_url, user_creds, admin_creds=None, max_depth=3):
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = base_url.replace("https://", "").replace("http://", "").replace("/", "_")
    report_dir = f"reports/{safe_name}/{timestamp}"
    os.makedirs(report_dir, exist_ok=True)

    session = login(base_url, user_creds["username"], user_creds["password"])
    if not session:
        return None

    links = crawl_site(base_url, session, max_depth=max_depth)
    print(f"[+] Crawled {len(links)} links")

    results = {
        "site": base_url,
        "timestamp": timestamp,
        "crawled_links": len(links),
        "links_discovered": links,
        "tests": []
    }

    # IDOR
    idor_results = []
    for l in links:
        idor_results.extend(test_idor(l, session))
        for f in extract_forms(l, session):
            if f["method"] == "get":
                idor_results.extend(test_idor(f["url"], session))
    results["tests"].append({"type": "IDOR", "results": idor_results})

    # Privilege Escalation
    results["tests"].append({"type": "Privilege Escalation", "results": test_privilege(base_url, session, admin_creds)})

    # Directory Traversal
    results["tests"].append({"type": "Directory Traversal", "results": test_directory(base_url, session)})

    # Method Bypass
    method_results = []
    for l in links:
        method_results.extend(test_method_bypass(l, session))
        for f in extract_forms(l, session):
            method_results.extend(test_method_bypass(f["url"], session))
    results["tests"].append({"type": "Method Bypass", "results": method_results})

    # Force Browsing
    results["tests"].append({"type": "Force Browsing", "results": test_force_browse(base_url, session)})

    # Header / Token Tampering
    results["tests"].append({"type": "Header/Token Tampering", "results": test_header_token(base_url, session)})

    # Cookie Manipulation
    results["tests"].append({"type": "Cookie Manipulation", "results": test_cookie_manipulation(base_url, session)})

    # CORS Misconfiguration
    results["tests"].append({"type": "CORS Misconfiguration", "results": test_cors(base_url, session)})

    report_file = f"{report_dir}/bac_report.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=4)
    return report_file

