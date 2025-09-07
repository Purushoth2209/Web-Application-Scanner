import json
from jinja2 import Template
from pathlib import Path


TEST_GUIDE = {
    "IDOR": "Use UUIDs or indirect references, enforce access checks on every request.",
    "POST IDOR": "Validate authorization on POST parameters and use indirect object references.",
    "Privilege Escalation": "Enforce server-side RBAC, never rely on client-side checks.",
    "Directory Traversal": "Sanitize inputs, deny '../', use path whitelisting.",
    "Method Bypass": "Restrict allowed HTTP methods, validate them server-side.",
    "Force Browsing": "Enforce authentication/authorization on all sensitive endpoints.",
    "Header/Token Tampering": "Validate tokens strictly server-side; never trust missing or forged headers.",
    "Cookie Manipulation": "Do not store roles in cookies; enforce all roles and permissions server-side.",
    "CORS Misconfiguration": "Restrict CORS Access-Control-Allow-Origin to trusted domains only.",
}


def generate_reports(json_file):
    with open(json_file) as f:
        data = json.load(f)

    if "crawled_links" in data and data["crawled_links"] == 0:
        if any(t.get("type") == "Force Browsing (Quick)" for t in data.get("tests", [])):
            data["crawl_note"] = (
                "No dynamic links discovered; results based on fallback dictionary & quick probes. "
                "Consider enabling JavaScript rendering or providing authentication to improve coverage."
            )
        else:
            data["crawl_note"] = (
                "WARNING: No links found during crawling even after fallbacks. "
                "Site may require login, heavy JavaScript rendering, or blocks automated agents."
            )
    else:
        links = data.get("links_discovered", [])
        data["crawl_note"] = f"Crawled {data.get('crawled_links', 0)} links successfully."
        if links:
            data["crawl_note"] += "<br><small>Discovered links:<br>" + "<br>".join(links) + "</small>"

    for test in data["tests"]:
        advice = TEST_GUIDE.get(test["type"], "General best practices")
        for r in test["results"]:
            r["mitigation"] = advice

    summary = {
        "total_tests": len(data["tests"]),
        "total_findings": sum(len(t["results"]) for t in data["tests"]),
        "vulnerable": sum(
            1 for t in data["tests"] for r in t["results"] if r.get("status") == "Vulnerable"
        ),
    }
    data["summary"] = summary

    template_path = Path(__file__).parent / "templates" / "report.html"
    template = template_path.read_text(encoding="utf-8")
    full_html = Template(template).render(data=data)
    out_file = json_file.replace(".json", ".html")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(full_html)

    exploited = {
        "site": data["site"],
        "timestamp": data["timestamp"],
        "crawled_links": data["crawled_links"],
        "crawl_note": f"Crawled {data.get('crawled_links', 0)} links successfully.",
        "tests": [],
    }
    for test in data["tests"]:
        only_vulns = [r for r in test["results"] if r.get("status") == "Vulnerable"]
        if only_vulns:
            exploited["tests"].append({"type": test["type"], "results": only_vulns})
    exploited["summary"] = {
        "total_tests": len(exploited["tests"]),
        "vulnerable": sum(len(t["results"]) for t in exploited["tests"]),
    }

    exploited_html = json_file.replace(".json", "_exploited.html")
    html_exploited = Template(template).render(data=exploited)
    with open(exploited_html, "w", encoding="utf-8") as f:
        f.write(html_exploited)

    audit_entry = {
        "site": data["site"],
        "timestamp": data["timestamp"],
        "findings": summary["total_findings"],
        "vulnerabilities": summary["vulnerable"],
    }
    audit_log = Path(__file__).parent / "reports" / "audit_log.jsonl"
    audit_log.parent.mkdir(exist_ok=True)
    with open(audit_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(audit_entry) + "\n")

    return out_file, exploited_html
