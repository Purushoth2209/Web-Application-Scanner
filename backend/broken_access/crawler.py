import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import time
import logging
import warnings

# Suppress all unnecessary logging
logging.getLogger('selenium').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('webdriver_manager').setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore")

# Suppress TensorFlow logging if it's imported elsewhere
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'


def normalize_url(url):
    return url.rstrip("/")


def get_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-software-rasterizer")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--disable-features=VizDisplayCompositor")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-plugins")
    chrome_options.add_argument("--disable-images")
    chrome_options.add_argument("--disable-javascript")
    chrome_options.add_argument("--remote-debugging-port=9222")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebDriver/537.36")
    
    # Suppress all Chrome logging and noise
    chrome_options.add_argument("--log-level=3")  # Only fatal errors
    chrome_options.add_argument("--silent")
    chrome_options.add_argument("--disable-logging")
    chrome_options.add_argument("--disable-gpu-logging")
    chrome_options.add_argument("--disable-background-timer-throttling")
    chrome_options.add_argument("--disable-backgrounding-occluded-windows")
    chrome_options.add_argument("--disable-renderer-backgrounding")
    chrome_options.add_argument("--disable-component-cloud-policy")
    chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    attempt_errors = []
    for attempt in range(1, 3):  # two attempts max
        try:
            print(f"[+] Setting up Chrome driver using WebDriverManager (attempt {attempt})...")
            service = Service(ChromeDriverManager().install())
            service.creationflags = 0x08000000  # CREATE_NO_WINDOW (Windows)
            driver = webdriver.Chrome(service=service, options=chrome_options)
            # Keep page load tight to avoid renderer hangs but allow short bump on retry
            driver.set_page_load_timeout(12 if attempt == 2 else 8)
            driver.implicitly_wait(2)
            print("[+] Chrome driver successfully initialized")
            return driver
        except Exception as e:
            attempt_errors.append(str(e))
            # Small backoff
            time.sleep(1.2 * attempt)
    print(f"[!] Chrome driver setup failed after retries: {' | '.join(attempt_errors)}")
    raise RuntimeError("webdriver_init_failed")


def crawl_site(base_url, session, max_depth=3):
    visited = set()
    to_visit = [(base_url, 0)]
    all_links = []

    print(f"[+] Crawling {base_url} (depth={max_depth}) ...")

    while to_visit:
        url, depth = to_visit.pop()
        norm_url = normalize_url(url)
        if norm_url in visited or depth > max_depth:
            continue
        visited.add(norm_url)
        print(f"[+] Visiting {norm_url}")

        try:
            # Supply a consistent header to avoid some WAF blocks
            hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecScanner/1.0"}
            res = session.get(norm_url, timeout=5, headers=hdrs)
            soup = BeautifulSoup(res.text, "lxml")

            for tag in soup.find_all(["a", "form", "script"]):
                href = tag.get("href") or tag.get("action") or tag.get("src")
                if not href:
                    continue
                full_url = normalize_url(urljoin(base_url, href))
                if base_url.split("#")[0] in full_url and full_url not in visited:
                    to_visit.append((full_url, depth + 1))
                    all_links.append(full_url)
        except Exception:
            continue

    # If we still have zero links, attempt regex-based extraction as a last resort
    if not all_links:
        try:
            base_res = requests.get(base_url, timeout=6)
            # crude href/src/action extraction
            candidates = set(re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', base_res.text, re.I))
            for href in list(candidates)[:40]:
                full_url = normalize_url(urljoin(base_url, href))
                if base_url.split('#')[0] in full_url and full_url not in visited:
                    all_links.append(full_url)
        except Exception:
            pass

    if len(all_links) < 15 and not os.getenv("BAC_DISABLE_SELENIUM"):
        print("[!] Few links found with requests. Trying alternative discovery (selenium)...")
        start_selenium = time.time()
        driver = None
        try:
            driver = get_driver()
            # Harden: fail fast if renderer becomes unresponsive
            try:
                driver.get(base_url)
            except Exception as nav_err:
                print(f"[!] Initial navigation error: {nav_err}")
            # Minimal wait – JS heavy apps sometimes need a brief settle
            time.sleep(1.2)
            safe_scripts = [
                "try{window.scrollTo(0, document.body.scrollHeight);}catch(e){}",
                "return Array.from(document.querySelectorAll('a,form,script')).map(e=>e.href||e.action||e.src||e.getAttribute('routerlink')||'').filter(Boolean);"
            ]
            harvested = []
            for sc in safe_scripts:
                try:
                    r = driver.execute_script(sc)
                    if isinstance(r, list):
                        harvested.extend(r)
                except Exception:
                    continue
            # Deduplicate & normalize
            for href in set(harvested):
                full_url = normalize_url(urljoin(base_url, href))
                if base_url.split('#')[0] in full_url and full_url not in visited:
                    all_links.append(full_url)
            # Light router probing
            try:
                nav_items = driver.find_elements(By.XPATH, "//a[@routerlink]")[:3]
                for item in nav_items:
                    try:
                        driver.execute_script("arguments[0].click();", item)
                        time.sleep(0.4)
                        inner_links = driver.execute_script(safe_scripts[1]) or []
                        for href in set(inner_links):
                            full_url = normalize_url(urljoin(base_url, href))
                            if base_url.split('#')[0] in full_url and full_url not in visited:
                                all_links.append(full_url)
                    except Exception:
                        continue
            except Exception:
                pass
            print(f"[+] Selenium enrichment added ~{len(all_links)} total so far (elapsed {(time.time()-start_selenium):.1f}s)")
        except Exception as e:
            print(f"[!] Selenium crawl error: {e}")
        finally:
            if driver:
                try: driver.quit()
                except Exception: pass
    if len(all_links) < 10:
            print("[!] Using enhanced static path dictionary fallback...")
            # Enhanced fallback: use more comprehensive paths
            common_paths = [
                "/", "/home", "/index", "/main", "/dashboard", "/admin", "/login", "/logout",
                "/profile", "/account", "/settings", "/config", "/users", "/user", "/api",
                "/api/users", "/api/admin", "/api/v1", "/management", "/panel", "/control",
                "/search", "/help", "/about", "/contact", "/register", "/signup", "/signin",
                "/forgot", "/reset", "/change-password", "/edit-profile", "/preferences",
                "/notifications", "/messages", "/inbox", "/reports", "/analytics", "/logs",
                "/admin/users", "/admin/settings", "/admin/reports", "/admin/logs",
                "/user/profile", "/user/settings", "/user/dashboard", "/user/account"
            ]
            for path in common_paths:
                full_url = normalize_url(urljoin(base_url, path))
                if full_url not in visited:
                    all_links.append(full_url)
            
            # Also try to extract links from robots.txt and sitemap.xml
            try:
                robots_url = urljoin(base_url, "/robots.txt")
                robots_res = session.get(robots_url, timeout=5)
                if robots_res.status_code == 200:
                    for line in robots_res.text.split('\n'):
                        if line.strip().startswith('Disallow:') or line.strip().startswith('Allow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                full_url = normalize_url(urljoin(base_url, path))
                                if full_url not in visited:
                                    all_links.append(full_url)
            except:
                pass

    # If still empty after all strategies, enforce dictionary fallback to provide baseline endpoints
    if not all_links:
        print("[!] No links discovered; injecting core dictionary paths for baseline testing.")
        core_paths = ["/", "/login", "/admin", "/config", "/dashboard", "/profile", "/user", "/account"]
        for p in core_paths:
            full_url = normalize_url(urljoin(base_url, p))
            all_links.append(full_url)

    final_links = list(dict.fromkeys(all_links))  # preserve insertion order, de-dupe
    print(f"[+] Found {len(final_links)} links total (unique).")
    return final_links
