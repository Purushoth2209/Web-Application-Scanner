import time
import json
from pathlib import Path
import requests

COMMON_SENSITIVE_PATHS = [
    "/admin", "/admin/login", "/admin/panel", "/dashboard", "/config", "/debug",
    "/manage", "/management", "/control", "/settings", "/user/admin", "/users/admin"
]

TRAVERSAL_PROBES = [
    "/../../etc/passwd", "/..%2f..%2fetc/passwd", "/..%2F..%2Fwindows/win.ini"
]

def quick_fallback_scan(base_url: str, out_dir: Path) -> dict:
    """Very fast BAC fallback scan executed after a timeout.
    Generates a minimal report structure compatible with the normal generator.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    session = requests.Session()

    force_browse_results = []
    for p in COMMON_SENSITIVE_PATHS:
        url = base_url.rstrip('/') + p
        try:
            r = session.get(url, timeout=3, allow_redirects=False)
            status = r.status_code
            vuln = False
            if status == 200 and any(seg in p for seg in ["admin", "config", "manage", "debug"]):
                vuln = True
            force_browse_results.append({
                "path": p,
                "url": url,
                "http_status": status,
                "status": "Vulnerable" if vuln else "Info"
            })
        except Exception as e:
            force_browse_results.append({"path": p, "url": url, "error": str(e), "status": "Error"})

    traversal_results = []
    for probe in TRAVERSAL_PROBES:
        url = base_url.rstrip('/') + probe
        try:
            r = session.get(url, timeout=3)
            ind = r.text.lower()
            vuln = False
            if "root:x:" in ind or "[extensions]" in ind:
                vuln = True
            traversal_results.append({
                "payload": probe,
                "url": url,
                "http_status": r.status_code,
                "status": "Vulnerable" if vuln else "Info"
            })
        except Exception as e:
            traversal_results.append({"payload": probe, "url": url, "error": str(e), "status": "Error"})

    data = {
        "site": base_url,
        "timestamp": ts,
        "crawled_links": 0,
        "links_discovered": [],
        "tests": [
            {"type": "Force Browsing (Quick)", "results": force_browse_results},
            {"type": "Directory Traversal (Quick)", "results": traversal_results},
        ],
        "fallback": True,
        "note": "Main BAC scan exceeded time budget. Quick fallback results only.",
    }
    report_file = out_dir / "bac_quick_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return {"json": str(report_file), "partial": True, "mode": "fallback"}
