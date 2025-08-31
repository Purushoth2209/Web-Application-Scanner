#!/usr/bin/env python3
import argparse, json, os, time
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from csrf_suite_cli import run_suite

# ------------------- token extractor -------------------
def get_tokens(base, login_path, username, password, user_field, pass_field, login_button):
    jwt=None; cookies=[]
    chrome_options=Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--ignore-certificate-errors")
    driver=webdriver.Chrome(options=chrome_options)

    try:
        url=base if not login_path else urljoin(base, login_path.lstrip("/"))
        driver.get(url); time.sleep(2)

        if username and password:
            try:
                driver.find_element(By.CSS_SELECTOR, user_field).send_keys(username)
                driver.find_element(By.CSS_SELECTOR, pass_field).send_keys(password)
                if login_button:
                    try:
                        driver.find_element(By.CSS_SELECTOR, login_button).click()
                    except:
                        driver.find_element(By.CSS_SELECTOR, pass_field).send_keys(Keys.RETURN)
                time.sleep(3)
            except Exception as e:
                print(f"[!] Login failed: {e}")

        cookies=[c["name"] for c in driver.get_cookies()]
        try:
            jwt=driver.execute_script(
                "return window.localStorage.getItem('token')||window.sessionStorage.getItem('token');"
            )
        except: pass
    finally:
        driver.quit()
    return cookies,jwt

# ------------------- dynamic crawler -------------------
def crawl(base, depth=2):
    visited=set(); forms=[]; all_links=[]
    opts=Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--ignore-certificate-errors")
    driver=webdriver.Chrome(options=opts)

    def _crawl(url,d):
        if d<0 or url in visited: return
        visited.add(url); all_links.append(url)
        print(f"[+] Visiting {url}")
        try:
            driver.get(url); time.sleep(2)

            # extract forms dynamically
            form_elems=driver.find_elements(By.TAG_NAME,"form")
            for f in form_elems:
                action=f.get_attribute("action") or url
                method=f.get_attribute("method") or "GET"
                inputs=f.find_elements(By.TAG_NAME,"input")
                params={i.get_attribute("name") or f"field_{idx}": i.get_attribute("value") or "" 
                        for idx,i in enumerate(inputs) if i.get_attribute("name")}
                forms.append({
                    "name":f"form_{len(forms)+1}",
                    "method":method.upper(),
                    "url":urljoin(url,action),
                    "params":params
                })
                print(f"    ↳ Found form at {url} (method={method}, action={action})")

            # collect all links (normal + hash routes)
            links=[]
            for a in driver.find_elements(By.TAG_NAME,"a"):
                href=a.get_attribute("href")
                if href: links.append(href)
            # also include hash routes found in Angular/React
            hrefs=driver.execute_script("return Array.from(document.querySelectorAll('[href]')).map(a=>a.getAttribute('href'));")
            for h in hrefs:
                if h and (h.startswith("#/") or h.startswith("/")):
                    links.append(urljoin(base,h))

            # crawl deeper
            for link in set(links):
                if urlparse(link).netloc==urlparse(base).netloc and link not in visited:
                    _crawl(link,d-1)
        except Exception as e:
            print(f"[!] Crawl error at {url}: {e}")

    _crawl(base,depth)
    driver.quit()
    return forms,visited,all_links

# ------------------- orchestrator -------------------
if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--base",required=True)
    ap.add_argument("--login-path")
    ap.add_argument("--username")
    ap.add_argument("--password")
    ap.add_argument("--username-field")
    ap.add_argument("--password-field")
    ap.add_argument("--login-button")
    ap.add_argument("--depth",type=int,default=2)
    ap.add_argument("--out",default="reports")
    args=ap.parse_args()

    print(f"[+] Crawling {args.base} (depth={args.depth}) ...")
    forms,links,all_links=crawl(args.base,args.depth)
    print(f"[+] Found {len(forms)} forms. Crawled {len(links)} links total.")

    print("[+] Extracting session tokens...")
    cookies,jwt=get_tokens(args.base,args.login_path,args.username,
                           args.password,args.username_field,
                           args.password_field,args.login_button)
    print(f"[+] Cookies: {cookies} , JWT: {jwt}")

    cfg={"base_url":args.base,"actions":forms,"optional":{"jwt":bool(jwt),"visited_links":all_links}}
    if cookies:
        cfg["session_cookie"]={
            "name":cookies[0],
            "value":"dummy",
            "domain":urlparse(args.base).hostname,
            "path":"/"
        }

    reports=run_suite(cfg,args.out)
    print("[+] Reports written:",reports)
    print("[+] Done.")
