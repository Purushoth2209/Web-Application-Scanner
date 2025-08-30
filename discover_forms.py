#!/usr/bin/env python3
import requests,argparse,json
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def discover_forms(base,out_file="actions_autogen.json"):
    r=requests.get(base,timeout=10,verify=False)
    soup=BeautifulSoup(r.text,"html.parser")
    forms=[]; idx=1
    for form in soup.find_all("form"):
        method=form.get("method","get").upper()
        action=form.get("action") or base
        url=urljoin(base,action)
        inputs={i.get("name"):"test" for i in form.find_all("input") if i.get("name")}
        forms.append({"name":f"FORM_{idx}","method":method,"url":url,"params":inputs,"body_format":"form"}); idx+=1
    doc={"base_url":base,"actions":forms,"optional":{}}
    with open(out_file,"w") as f: json.dump(doc,f,indent=2)
    print(f"[+] Discovered {len(forms)} forms → {out_file}")

if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--base",required=True); ap.add_argument("--out",default="actions_autogen.json")
    args=ap.parse_args(); discover_forms(args.base,args.out)
