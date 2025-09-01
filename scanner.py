import os
import time
from urllib.parse import urljoin, urlparse

from selenium import webdriver
from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys # Added for Keys.ENTER

class XSSScanner:
    def __init__(self, driver_path):
        self.visited_urls = set()
        self.potential_vulnerabilities = []

        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode (no GUI)
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])  # Suppress console logs

        service = Service(driver_path)
        self.driver = webdriver.Chrome(service=service, options=chrome_options)
        self.driver.set_page_load_timeout(30)  # Set a timeout for page loads

        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>Hover here!</div>",
            # Add more payloads for better coverage
            # E.g., HTML entity encoded, URL encoded, different tags, etc.
        ]

    def _is_same_domain(self, url, base_domain_url):
        """Checks if a URL belongs to the same exact domain as the base URL."""
        return urlparse(url).netloc == urlparse(base_domain_url).netloc

    def _get_absolute_url(self, base_url, href):
        """Converts a relative URL to an absolute URL."""
        return urljoin(base_url, href)

    def _extract_links_from_page(self, current_url, base_domain_url):
        """Extracts all same-domain, absolute links from the current page."""
        found_links = set()
        try:
            self.driver.get(current_url)
            # Reduced sleep for faster crawling
            time.sleep(0.5) 
            
            links = self.driver.find_elements(By.TAG_NAME, 'a')
            for link in links:
                try:
                    href = link.get_attribute('href')
                    if href:
                        absolute_url = self._get_absolute_url(current_url, href)
                        
                        # Only follow http/https links within the exact same domain
                        if (absolute_url.startswith('http://') or absolute_url.startswith('https://')) \
                           and self._is_same_domain(absolute_url, base_domain_url):
                           
                            # Explicitly exclude known external redirect patterns if they still pass the domain check
                            # This targets URLs like https://juice-shop.herokuapp.com/redirect?to=https://github.com/...
                            parsed_absolute_url = urlparse(absolute_url)
                            if parsed_absolute_url.path.startswith('/redirect') and 'to=' in absolute_url:
                                # Extract the 'to' parameter from the query string
                                query_params = urlparse(absolute_url).query
                                to_param = next((param.split('=')[1] for param in query_params.split('&') if param.startswith('to=')), None)
                                
                                if to_param:
                                    # Ensure the redirect target is not within the same domain
                                    if not self._is_same_domain(to_param, base_domain_url):
                                        # print(f"  Skipping external redirect target: {absolute_url} pointing to {to_param}")
                                        continue # Skip this link as it points externally
                            
                            if absolute_url not in self.visited_urls: 
                                found_links.add(absolute_url)
                except Exception as e:
                    pass
        except Exception as e:
            print(f"  Error accessing {current_url} during link extraction: {e}")
        return list(found_links)

    def crawl_all_pages(self, start_url):
        """Crawls the entire website from the start_url."""
        self.base_url = start_url
        self.visited_urls.add(start_url)
        urls_to_visit = [start_url]
        base_domain_url = start_url  # Keep the original base URL for domain checks

        i = 0
        while urls_to_visit and i < 50:  # Limit crawl depth/number of pages for practical reasons
            current_url = urls_to_visit.pop(0)  # BFS-like approach
            print(f"Crawling: {current_url}")

            new_links = self._extract_links_from_page(current_url, base_domain_url)
            for link in new_links:
                if link not in self.visited_urls:
                    self.visited_urls.add(link)
                    urls_to_visit.append(link)
            i += 1

    def check_xss_on_page(self, url):
        print(f"\n--- Checking XSS on page: {url} ---")
        try:
            self.driver.get(url)
            # Reduced initial sleep
            time.sleep(0.5) 
        except Exception as e:
            print(f"  Error accessing {url} for XSS check: {e}")
            return

        initial_input_elements = self.driver.find_elements(
            By.CSS_SELECTOR, 'input[type="text"], input[type="search"], textarea'
        )
        
        input_field_identifiers = []
        for i, field in enumerate(initial_input_elements):
            identifier = {}
            if field.get_attribute("name"):
                identifier["name"] = field.get_attribute("name")
            if field.get_attribute("id"):
                identifier["id"] = field.get_attribute("id")
            if not identifier: # If no name or id, use index as a fallback (less reliable)
                identifier["index"] = i
            identifier["tag"] = field.tag_name # Store tag name to refine CSS selector
            input_field_identifiers.append(identifier)


        if not input_field_identifiers:
            print("  No input fields found on this page.")
            return

        for field_index, field_identifier in enumerate(input_field_identifiers):
            field_name_for_output = field_identifier.get('name') or field_identifier.get('id') or f'unnamed_field_{field_identifier.get("index", field_index)}'
            print(f"  Testing field: '{field_name_for_output}'")

            original_window = self.driver.current_window_handle

            for payload in self.xss_payloads:
                try:
                    self.driver.get(url)
                    # Reduced sleep after navigating back for each payload
                    time.sleep(0.5) 

                    current_field = None
                    if "name" in field_identifier:
                        current_field = self.driver.find_element(
                            By.NAME, field_identifier["name"]
                        )
                    elif "id" in field_identifier:
                        current_field = self.driver.find_element(
                            By.ID, field_identifier["id"]
                        )
                    else:  # Fallback: re-find all input fields and pick by index
                        all_inputs_on_page = self.driver.find_elements(
                            By.CSS_SELECTOR,
                            'input[type="text"], input[type="search"], textarea',
                        )
                        if field_identifier["index"] < len(all_inputs_on_page):
                            current_field = all_inputs_on_page[field_identifier["index"]]

                    if not current_field:
                        print(f"    Could not re-find field '{field_name_for_output}'. Skipping.")
                        continue

                    current_field.clear()
                    current_field.send_keys(payload)

                    form = None
                    try:
                        form = current_field.find_element(By.XPATH, "./ancestor::form")
                        form.submit()
                        # Reduced sleep after form submission
                        time.sleep(1) 
                    except Exception:
                        if current_field.tag_name == 'input':
                            try:
                                current_field.send_keys(Keys.ENTER)
                                # Reduced sleep after pressing ENTER
                                time.sleep(1) 
                            except Exception as e:
                                pass

                    if len(self.driver.window_handles) > 1:
                        print(
                            f"    [!!! POTENTIAL XSS - New Window Opened !!!] Payload '{payload}' in field '{field_name_for_output}' at {self.driver.current_url}"
                        )
                        self.potential_vulnerabilities.append(
                            {
                                "url": self.driver.current_url,
                                "field": field_name_for_output,
                                "payload": payload,
                                "detection_method": "New Window/Tab Opened",
                            }
                        )
                        for window_handle in self.driver.window_handles:
                            if window_handle != original_window:
                                self.driver.switch_to.window(window_handle)
                                self.driver.close()
                        self.driver.switch_to.window(original_window)
                        break

                    if payload in self.driver.page_source:
                        print(
                            f"    [!!! POTENTIAL XSS !!!] Payload '{payload}' reflected in field '{field_name_for_output}' at {self.driver.current_url}"
                        )
                        self.potential_vulnerabilities.append(
                            {
                                "url": self.driver.current_url,
                                "field": field_name_for_output,
                                "payload": payload,
                                "detection_method": "String Reflection",
                            }
                        )
                        break

                except StaleElementReferenceException:
                    print(f"    StaleElementReferenceException for field '{field_name_for_output}' with payload '{payload}'. Re-trying might be needed or element disappeared.")
                    continue
                except Exception as e:
                    pass

    def scan(self, target_url):
        print(f"Starting XSS scan for: {target_url}")
        print("Initializing browser and crawling website...\n")

        self.crawl_all_pages(target_url)

        print("\nCrawl complete. Visited the following pages:")
        self.base_url = target_url 
        for url in sorted(list(self.visited_urls)):
            print(f"- {url}")

        print("\n--- Starting XSS vulnerability checks on visited pages ---\n")
        for url in sorted(list(self.visited_urls)):
            self.check_xss_on_page(url)

        print("\n--- XSS Scan Finished ---")
        if self.potential_vulnerabilities:
            print("\n!!! POTENTIAL XSS VULNERABILITIES FOUND !!!")
            for i, vul in enumerate(self.potential_vulnerabilities):
                print(f"\nVulnerability {i+1}:")
                print(f"  URL: {vul['url']}")
                print(f"  Field: {vul['field']}")
                print(f"  Payload: {vul['payload']}")
                print(f"  Detection: {vul.get('detection_method', 'Unknown')}")
                print("-" * 40)
        else:
            print("\nNo reflected XSS vulnerabilities detected with the given payloads (basic check).")
            print("Remember, this is a basic scanner and may miss complex XSS.")

    def close(self):
        self.driver.quit()

if __name__ == "__main__":
    CHROMEDRIVER_PATH = "/usr/local/bin/chromedriver"

    if not os.path.exists(CHROMEDRIVER_PATH):
        print(f"Error: Chromedriver not found at '{CHROMEDRIVER_PATH}'.")
        print("Please download the correct version for your Chrome browser and OS from:")
        print("https://chromedriver.chromium.org/downloads")
        print("And place it in the specified path.")
        exit()

    target_website = input(
        "Enter the target website URL (e.g., http://example.com): "
    ).strip()
    if not target_website.startswith("http://") and not target_website.startswith(
        "https://"
    ):
        print("Error: URL must start with http:// or https://")
        exit()

    scanner = XSSScanner(CHROMEDRIVER_PATH)
    try:
        scanner.scan(target_website)
    finally:
        scanner.close()