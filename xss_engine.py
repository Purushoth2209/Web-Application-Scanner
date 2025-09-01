# xss_engine.py

import os
import time
import datetime
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from payloads import XSS_PAYLOADS
from models import Vulnerability, ScanReport

class XSSScannerEngine:
    def __init__(self, driver_path, headless=True, page_load_timeout=30, output_dir="screenshots"):
        self.visited_urls = set()
        self.potential_vulnerabilities = []
        self.base_domain = None # To store the base domain for in-scope checks
        self.start_scan_time = None
        self.end_scan_time = None
        
        self.screenshot_dir = os.path.join(output_dir, "screenshots")
        os.makedirs(self.screenshot_dir, exist_ok=True)

        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
        chrome_options.add_argument("--window-size=1920,1080") # Set window size for consistent screenshots

        service = Service(driver_path)
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.driver.set_page_load_timeout(page_load_timeout)
        self.driver.implicitly_wait(5) # Implicit wait for elements

        self.xss_payloads = XSS_PAYLOADS # Use payloads from the payloads.py file

    def _take_screenshot(self, vulnerability: Vulnerability) -> str:
        """Takes a screenshot of the current page and saves it."""
        filename = f"xss_vuln_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{len(self.potential_vulnerabilities)}.png"
        filepath = os.path.join(self.screenshot_dir, filename)
        try:
            self.driver.save_screenshot(filepath)
            vulnerability.screenshot_path = filepath
            print(f"    Screenshot saved: {filepath}")
            return filepath
        except Exception as e:
            print(f"    Failed to take screenshot: {e}")
            return ""

    def _is_same_domain(self, url, base_domain_url):
        """Checks if a URL belongs to the same exact domain as the base URL."""
        return urlparse(url).netloc == urlparse(base_domain_url).netloc

    def _get_absolute_url(self, base_url, href):
        """Converts a relative URL to an absolute URL."""
        return urljoin(base_url, href)

    def _extract_links_from_page(self, current_url: str, base_domain_url: str) -> list[str]:
        """Extracts all same-domain, absolute links from the current page."""
        found_links = set()
        try:
            self.driver.get(current_url)
            time.sleep(1) # Give page some time to load JS
            
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href:
                        absolute_url = self._get_absolute_url(current_url, href)
                        
                        if (absolute_url.startswith('http://') or absolute_url.startswith('https://')) \
                           and self._is_same_domain(absolute_url, base_domain_url):
                            
                            parsed_absolute_url = urlparse(absolute_url)
                            if parsed_absolute_url.path.startswith('/redirect') and 'to=' in absolute_url:
                                query_params = urlparse(absolute_url).query
                                to_param = next((param.split('=')[1] for param in query_params.split('&') if param.startswith('to=')), None)
                                
                                if to_param and not self._is_same_domain(to_param, base_domain_url):
                                    continue 
                            
                            if absolute_url not in self.visited_urls: 
                                found_links.add(absolute_url)
                except StaleElementReferenceException:
                    pass # Element might have become stale during iteration
                except Exception as e:
                    # print(f"  Error processing link on {current_url}: {e}")
                    pass
        except TimeoutException:
            print(f"  Timeout accessing {current_url} during link extraction.")
        except WebDriverException as e:
            print(f"  WebDriver error accessing {current_url} during link extraction: {e}")
        except Exception as e:
            print(f"  General error accessing {current_url} during link extraction: {e}")
        return list(found_links)

    def crawl_all_pages(self, start_url: str, max_pages_to_crawl: int = 50):
        """Crawls the entire website from the start_url."""
        self.base_domain = urlparse(start_url).netloc
        self.visited_urls.add(start_url)
        urls_to_visit = [start_url]
        
        print(f"Starting crawl from: {start_url} (Max pages: {max_pages_to_crawl})")

        pages_crawled_count = 0
        while urls_to_visit and pages_crawled_count < max_pages_to_crawl:
            current_url = urls_to_visit.pop(0)
            print(f"Crawling ({pages_crawled_count + 1}/{max_pages_to_crawl}): {current_url}")

            new_links = self._extract_links_from_page(current_url, start_url) # Use start_url for base domain check
            for link in new_links:
                if link not in self.visited_urls:
                    self.visited_urls.add(link)
                    urls_to_visit.append(link)
            pages_crawled_count += 1
        print(f"Crawl completed. Visited {len(self.visited_urls)} unique pages.")


    def check_xss_on_page(self, url: str):
        print(f"\n--- Checking XSS on page: {url} ---")
        try:
            self.driver.get(url)
            time.sleep(1) # Initial wait for page to settle
        except TimeoutException:
            print(f"  Timeout accessing {url} for XSS check. Skipping.")
            return
        except WebDriverException as e:
            print(f"  WebDriver error accessing {url} for XSS check: {e}. Skipping.")
            return
        except Exception as e:
            print(f"  Error accessing {url} for XSS check: {e}. Skipping.")
            return

        initial_input_elements = self.driver.find_elements(
            By.CSS_SELECTOR, 'input[type="text"], input[type="search"], textarea'
        )
        
        input_field_identifiers = []
        for i, field in enumerate(initial_input_elements):
            identifier = {
                "tag": field.tag_name,
                "name": field.get_attribute("name"),
                "id": field.get_attribute("id"),
                "index": i # Fallback index
            }
            input_field_identifiers.append(identifier)


        if not input_field_identifiers:
            print("  No input fields found on this page to test.")
            return

        for field_index, field_identifier in enumerate(input_field_identifiers):
            field_name_for_output = field_identifier.get('name') or field_identifier.get('id') or f'unnamed_field_{field_identifier.get("index", field_index)}'
            print(f"  Testing field: '{field_name_for_output}'")

            original_window = self.driver.current_window_handle

            for payload in self.xss_payloads:
                try:
                    self.driver.get(url) # Re-navigate to clear state
                    time.sleep(1) 

                    current_field = None
                    try: # Try to find by name, then id, then tag+index
                        if field_identifier.get("name"):
                            current_field = self.driver.find_element(By.NAME, field_identifier["name"])
                        elif field_identifier.get("id"):
                            current_field = self.driver.find_element(By.ID, field_identifier["id"])
                        else: # Fallback to finding all relevant inputs and selecting by index
                            all_inputs_on_page = self.driver.find_elements(By.CSS_SELECTOR, 'input[type="text"], input[type="search"], textarea')
                            if field_identifier["index"] < len(all_inputs_on_page):
                                current_field = all_inputs_on_page[field_identifier["index"]]
                    except Exception:
                         print(f"    Could not re-find field '{field_name_for_output}'. Skipping payload '{payload}'.")
                         continue # Field might be dynamic or disappear

                    if not current_field or not current_field.is_displayed() or not current_field.is_enabled():
                        # print(f"    Field '{field_name_for_output}' not visible or enabled. Skipping payload '{payload}'.")
                        continue

                    current_field.clear()
                    current_field.send_keys(payload)

                    # Attempt to submit form or press ENTER
                    try:
                        form = current_field.find_element(By.XPATH, "./ancestor::form")
                        form.submit()
                        time.sleep(2) # Give time for submission and potential redirect/alert
                    except Exception:
                        if current_field.tag_name == 'input':
                            try:
                                current_field.send_keys(Keys.ENTER)
                                time.sleep(2) 
                            except Exception:
                                pass # No form or enter key didn't work


                    # Check for new window/tab (e.g., alert() payload)
                    if len(self.driver.window_handles) > 1:
                        vuln = Vulnerability(
                            url=self.driver.current_url,
                            field=field_name_for_output,
                            payload=payload,
                            detection_method="New Window/Tab (Potential JS Alert/XSS)",
                        )
                        self.potential_vulnerabilities.append(vuln)
                        print(f"    [!!! POTENTIAL XSS - New Window Opened !!!] Payload '{payload}' in field '{field_name_for_output}' at {self.driver.current_url}")
                        self._take_screenshot(vuln)
                        
                        # Close new windows
                        for window_handle in self.driver.window_handles:
                            if window_handle != original_window:
                                self.driver.switch_to.window(window_handle)
                                self.driver.close()
                        self.driver.switch_to.window(original_window)
                        continue # Found XSS, move to next field/page


                    # Check for reflection of payload in page source
                    # (Simple check, doesn't confirm execution, just reflection)
                    if payload in self.driver.page_source:
                        vuln = Vulnerability(
                            url=self.driver.current_url,
                            field=field_name_for_output,
                            payload=payload,
                            detection_method="String Reflection (Potential XSS)",
                        )
                        self.potential_vulnerabilities.append(vuln)
                        print(f"    [!!! POTENTIAL XSS !!!] Payload '{payload}' reflected in field '{field_name_for_output}' at {self.driver.current_url}")
                        self._take_screenshot(vuln)
                        continue # Found XSS, move to next field/page

                except StaleElementReferenceException:
                    print(f"    StaleElementReferenceException for field '{field_name_for_output}' with payload '{payload}'. Element might have reloaded or disappeared.")
                except TimeoutException:
                    print(f"    Timeout during payload submission for field '{field_name_for_output}' with payload '{payload}'.")
                except WebDriverException as e:
                    # print(f"    WebDriver error for field '{field_name_for_output}' with payload '{payload}': {e}")
                    pass # Continue to next payload/field
                except Exception as e:
                    # print(f"    General error for field '{field_name_for_output}' with payload '{payload}': {e}")
                    pass # Continue to next payload/field


    def scan(self, target_url: str) -> ScanReport:
        """Executes the full XSS scan and returns a ScanReport object."""
        self.start_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"Starting XSS scan for: {target_url} at {self.start_scan_time}")
        print("Initializing browser and crawling website...\n")

        self.crawl_all_pages(target_url)

        print("\n--- Starting XSS vulnerability checks on visited pages ---\n")
        for url in sorted(list(self.visited_urls)):
            self.check_xss_on_page(url)

        self.end_scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n--- XSS Scan Finished at {self.end_scan_time} ---")
        
        summary = {
            "Total Pages Visited": len(self.visited_urls),
            "Total Potential Vulnerabilities Found": len(self.potential_vulnerabilities),
            "Scan Duration": str(datetime.datetime.strptime(self.end_scan_time, "%Y-%m-%d %H:%M:%S") - datetime.datetime.strptime(self.start_scan_time, "%Y-%m-%d %H:%M:%S"))
        }

        report = ScanReport(
            target_url=target_url,
            start_time=self.start_scan_time,
            end_time=self.end_scan_time,
            visited_urls=list(self.visited_urls),
            potential_vulnerabilities=self.potential_vulnerabilities,
            summary=summary
        )
        return report

    def close(self):
        """Closes the WebDriver."""
        if self.driver:
            self.driver.quit()
            print("WebDriver closed.")