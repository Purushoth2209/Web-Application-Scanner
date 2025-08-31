import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def normalize_url(url):
    """Normalize URLs but keep Angular/React hash routes (#/login)."""
    return url.rstrip("/")

def get_driver():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.binary_location = "/usr/bin/chromium-browser"
    return webdriver.Chrome(options=chrome_options)

def crawl_site(base_url, session, max_depth=3):
    visited = set()
    to_visit = [(base_url, 0)]
    all_links = []

    print(f"[+] Crawling {base_url} (depth={max_depth}) ...")

    # --- Requests-based crawl
    while to_visit:
        url, depth = to_visit.pop()
        norm_url = normalize_url(url)
        if norm_url in visited or depth > max_depth:
            continue
        visited.add(norm_url)
        print(f"[+] Visiting {norm_url}")

        try:
            res = session.get(norm_url, timeout=5)
            soup = BeautifulSoup(res.text, "lxml")

            for tag in soup.find_all(["a", "form", "script"]):
                href = tag.get("href") or tag.get("action") or tag.get("src")
                if not href:
                    continue
                full_url = normalize_url(urljoin(base_url, href))
                if base_url.split("#")[0] in full_url and full_url not in visited:
                    to_visit.append((full_url, depth + 1))
                    all_links.append(full_url)
        except:
            continue

    # --- Selenium fallback for Angular/React SPAs
    if len(all_links) < 15:  # aim for richer crawl
        print("[!] Few links found with requests. Falling back to Selenium...")
        driver = get_driver()
        try:
            driver.get(base_url)

            # ✅ Wait for Angular app root
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "app-root, router-outlet"))
            )
            time.sleep(3)

            # ✅ Scroll to trigger lazy load
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)

            # ✅ Capture normal hrefs, forms, scripts
            elems = driver.find_elements(By.XPATH, "//a[@href] | //form[@action] | //script[@src]")

            # ✅ Capture Angular routerlinks
            router_links = driver.find_elements(By.XPATH, "//*[@routerlink]")

            for e in elems + router_links:
                href = (
                    e.get_attribute("href")
                    or e.get_attribute("action")
                    or e.get_attribute("src")
                    or e.get_attribute("routerlink")
                )
                if href:
                    full_url = normalize_url(urljoin(base_url, href))
                    if base_url.split("#")[0] in full_url and full_url not in visited:
                        all_links.append(full_url)

            # ✅ Try clicking nav menu items (for hidden Angular routes)
            nav_items = driver.find_elements(By.XPATH, "//a[@routerlink]")
            for item in nav_items:
                try:
                    driver.execute_script("arguments[0].click();", item)
                    time.sleep(1)
                    page_html = driver.page_source
                    soup = BeautifulSoup(page_html, "lxml")
                    for tag in soup.find_all("a", href=True):
                        full_url = normalize_url(urljoin(base_url, tag["href"]))
                        if base_url.split("#")[0] in full_url and full_url not in visited:
                            all_links.append(full_url)
                except:
                    continue

        except Exception as e:
            print(f"[!] Selenium crawl error: {e}")
        finally:
            driver.quit()

    # Deduplicate
    final_links = list(set(all_links))
    print(f"[+] Found {len(final_links)} links total.")
    return final_links
