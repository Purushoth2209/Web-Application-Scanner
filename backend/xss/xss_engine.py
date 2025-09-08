# Minimal XSS engine placeholder (replace with your full engine as needed)
import os
import logging
import warnings
import time
import requests
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from common.param_discovery import discover_parameters

# Suppress all unnecessary logging
logging.getLogger('selenium').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('webdriver_manager').setLevel(logging.CRITICAL)
warnings.filterwarnings("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


class XSSScannerEngine:
    BASIC_PAYLOADS = [
        "<script>alert('x1')</script>",
        "\"'><svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<svg><script>confirm(1)</script>",
    ]

    def __init__(self, driver_path=None, headless=True, output_dir="screenshots"):
        opts = Options()
        if headless:
            opts.add_argument("--headless=new")
            
        # Enhanced Chrome options for better stability and suppressed logging
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--disable-software-rasterizer")
        opts.add_argument("--disable-web-security")
        opts.add_argument("--disable-features=VizDisplayCompositor")
        opts.add_argument("--disable-extensions")
        opts.add_argument("--disable-plugins")
        opts.add_argument("--disable-images")
        opts.add_argument("--remote-debugging-port=9223")  # Different port from crawler
        opts.add_argument("--window-size=1920,1080")
        opts.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebDriver/537.36")
        
        # Suppress all Chrome logging and noise
        opts.add_argument("--log-level=3")
        opts.add_argument("--silent")
        opts.add_argument("--disable-logging")
        opts.add_argument("--disable-gpu-logging")
        opts.add_argument("--disable-background-timer-throttling")
        opts.add_argument("--disable-backgrounding-occluded-windows")
        opts.add_argument("--disable-renderer-backgrounding")
        opts.add_argument("--disable-component-cloud-policy")
        opts.add_experimental_option('excludeSwitches', ['enable-logging'])
        opts.add_experimental_option('useAutomationExtension', False)
        
        # Allow overriding Chrome binary (for portable Chromium)
        chrome_bin = os.environ.get("CHROME_BIN")
        if chrome_bin:
            opts.binary_location = chrome_bin
            
        # Always use WebDriverManager for automatic version compatibility
        self.driver = None
        try:
            auto_path = ChromeDriverManager().install()
            service = Service(auto_path)
            service.creationflags = 0x08000000  # CREATE_NO_WINDOW flag for Windows
            self.driver = webdriver.Chrome(service=service, options=opts)
            self.driver.set_page_load_timeout(10)
            self.driver.implicitly_wait(3)
        except Exception as e:
            # Fallback: continue without selenium
            print(f"[XSS] ChromeDriver setup failed (continuing with requests-only mode): {e}")
            self.driver = None

    def _reflect_test(self, base_url: str):
        vulns = []
        session = requests.Session()
        parsed = urlparse(base_url)
        base_no_query = base_url.split('?')[0]
        existing_params = parse_qs(parsed.query)
        candidates = [{"url": base_no_query, "params": existing_params}]
        # Discover additional endpoints with params
        try:
            discovered = discover_parameters(base_url, max_pages=5, max_endpoints=12)
            candidates.extend(discovered)
        except Exception:
            pass
        for ep in candidates:
            param_space = ep.get("params") or {"xss": "test"}
            for param_name in list(param_space.keys())[:3]:  # limit breadth
                for payload in self.BASIC_PAYLOADS:
                    try:
                        params = {**param_space, param_name: payload}
                        # Build URL
                        test_url = ep["url"].split('?')[0] + "?" + urlencode(params, doseq=True)
                        r = session.get(test_url, timeout=6)
                        if payload in r.text:
                            vulns.append({
                                "url": test_url,
                                "field": param_name,
                                "payload": payload,
                                "detection_method": "reflection",
                                "evidence_length": len(payload),
                            })
                            # Stop early per endpoint to save time
                            break
                    except Exception:
                        continue
                # If we already found one for this param, move to next endpoint
                if any(v.get("field") == param_name and v.get("url", "").startswith(ep["url"]) for v in vulns):
                    break
            if len(vulns) >= 5:  # global cap
                break
        return vulns

    def scan(self, url: str):
        start = time.time()
        visited = [url]
        vulns = []
        # Requests-based quick reflection tests
        vulns.extend(self._reflect_test(url))
        # Limited selenium DOM interaction (optional)
        if self.driver:
            try:
                self.driver.get(url)
                visited.append(self.driver.current_url)
            except Exception:
                pass

        class Report:
            target_url = url
            start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start))
            end_time = time.strftime("%Y-%m-%d %H:%M:%S")
            visited_urls = list(dict.fromkeys(visited))
            potential_vulnerabilities = vulns
            summary = {
                "Total Pages Visited": len(visited),
                "Total Potential Vulnerabilities Found": len(vulns),
                "Scan Duration": f"{time.time()-start:.2f}s"
            }
        return Report()

    def close(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
