#!/usr/bin/env python3
import argparse, json
from urllib.parse import urlparse
from csrf_suite_cli import run_suite

def parse_cookies(s,base):
    if not s: return []
    host=urlparse(base).hostname; out=[]
    for part in [p.strip() for p in s.split(";") if p.strip()]:
        if "=" in part: n,v=part.split("=",1); out.append({"name":n.strip(),"value":v.strip(),"domain":host,"path":"/"})
    return out

def parse_add_posts(lst):
    acts=[]; idx=1
    for item in lst or []:
        if " " not in item: continue
        u,kv=item.split(" ",1); params={}
        for pair in kv.split("&"):
            if "=" in pair: k,v=pair.split("=",1); params[k]=v
        acts.append({"name":f"POST_{idx}","method":"POST","url":u,"params":params}); idx+=1
    return acts

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--base",required=True)
    ap.add_argument("--cookie",help="Single cookie, e.g. PHPSESSID=abcd")
    ap.add_argument("--cookies",help="Extra cookies separated by ;")
    ap.add_argument("--auth-header",help="JWT header, e.g. Authorization: Bearer <token>")
    ap.add_argument("--add-post",action="append",help="Target endpoint + params, e.g. 'http://... password_new=123&password_conf=123'")
    ap.add_argument("--body-format",choices=["form","json"],default="form")
    ap.add_argument("--out",default="reports")
    ap.add_argument("--exploits-only",action="store_true")
    args=ap.parse_args()

    cfg={"base_url":args.base,"actions":[],"optional":{}}
    host=urlparse(args.base).hostname

    # Cookies
    if args.cookie:
        n,v=args.cookie.split("=",1)
        cfg["session_cookie"]={"name":n,"value":v,"domain":host,"path":"/"}
    extra=parse_cookies(args.cookies,args.base)
    if extra: cfg["optional"]["extra_cookies"]=extra

    # JWT / Auth header
    if args.auth_header: cfg["optional"]["auth_header"]=args.auth_header

    # Actions
    posts=parse_add_posts(args.add_post)
    for p in posts: 
        p["body_format"]=args.body_format
        cfg["actions"].append(p)

    if not cfg["actions"]:
        print("[!] Need at least one --add-post (form endpoint + params)")
        exit(1)

    run_suite(cfg,args.out,args.exploits_only)
