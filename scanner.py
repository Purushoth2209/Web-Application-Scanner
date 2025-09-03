import asyncio
import concurrent.futures
import json
import time
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote
import threading
from queue import Queue
import logging
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.keys import Keys
import requests
from bs4 import BeautifulSoup
import re

class XSSScanner:
    def __init__(self, target_url: str, max_threads: int = 10, depth: int = 3, payloads_file: str = "payloads.json"):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_threads = max_threads
        self.depth = depth
        self.crawled_urls = set()
        self.vulnerable_urls = []
        self.forms_found = []
        self.ajax_endpoints = set()
        self.scan_results = {
            'reflected_xss': [],
            'dom_based_xss': [],
            'stored_xss': [],
            'summary': {}
        }
        self.url_queue = Queue()
        self.lock = threading.Lock()
        
        # Load payloads from external file
        self.xss_payloads = self.load_payloads(payloads_file)
        
        # Common parameter names for XSS testing
        self.common_params = [
            'search', 'q', 'query', 'term', 'keyword', 'input', 'data',
            'text', 'message', 'comment', 'content', 'name', 'value',
            'id', 'page', 'url', 'redirect', 'return', 'callback', 'filter',
            'sort', 'order', 'category', 'tag', 'type', 'action', 'cmd'
        ]
        
        # DOM XSS sources and sinks
        self.dom_sources = [
            'document.URL', 'document.location', 'window.location',
            'location.href', 'location.search', 'location.hash',
            'document.referrer', 'window.name', 'document.cookie',
            'localStorage', 'sessionStorage', 'history.pushState',
            'history.replaceState', 'postMessage'
        ]
        
        self.dom_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function', 'execScript',
            'msSetImmediate', 'setImmediate', 'execCommand'
        ]
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, 
                          format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def load_payloads(self, payloads_file: str) -> Dict:
        """Load payloads from external JSON file"""
        try:
            if os.path.exists(payloads_file):
                with open(payloads_file, 'r', encoding='utf-8') as f:
                    payloads = json.load(f)
                self.logger.info(f"Loaded payloads from {payloads_file}")
                return payloads
            else:
                self.logger.warning(f"Payloads file {payloads_file} not found, using default payloads")
                return self.get_default_payloads()
        except Exception as e:
            self.logger.error(f"Error loading payloads: {str(e)}")
            return self.get_default_payloads()

    def get_default_payloads(self) -> Dict:
        """Fallback default payloads if file not found"""
        return {
            'reflected_xss': {
                'basic': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')></iframe>"
                ]
            },
            'dom_xss': {
                'basic': [
                    "<script>alert('DOM-XSS')</script>",
                    "<img src=x onerror=alert('DOM-XSS')>",
                    "<svg onload=alert('DOM-XSS')>"
                ]
            },
            'stored_xss': {
                'basic': [
                    "<script>alert('Stored-XSS')</script>",
                    "<img src=x onerror=alert('Stored-XSS')>",
                    "<svg onload=alert('Stored-XSS')>"
                ]
            }
        }

    def create_driver(self) -> webdriver.Chrome:
        """Create a Chrome WebDriver instance"""
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-web-security')
        options.add_argument('--allow-running-insecure-content')
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(5)
        return driver

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for testing"""
        try:
            parsed = urlparse(url)
            return (parsed.scheme in ['http', 'https'] and 
                    parsed.netloc and 
                    not url.startswith('mailto:') and
                    not url.startswith('javascript:') and
                    not url.startswith('tel:') and
                    not url.startswith('ftp:'))
        except:
            return False

    def ajax_spider(self, url: str, current_depth: int = 0) -> Set[str]:
        """Advanced AJAX spidering to discover dynamic content"""
        if current_depth >= self.depth or not self.is_valid_url(url):
            return set()
            
        found_urls = set()
        driver = self.create_driver()
        
        try:
            self.logger.info(f"AJAX Spidering (Depth {current_depth + 1}/{self.depth}): {url}")
            driver.get(url)
            
            # Wait for initial page load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Test search functionality if present
            self.test_search_forms(driver, url, found_urls)
            
            # Find all interactive elements
            interactive_selectors = [
                "a[href]", "button", "input[type='submit']", "input[type='button']", 
                "[onclick]", "[onchange]", "[onsubmit]", "form", 
                "input[type='text']", "input[type='search']", "textarea"
            ]
            
            for selector in interactive_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements[:5]:  # Limit per selector
                        try:
                            if element.is_displayed() and element.is_enabled():
                                if selector.startswith("a[href]"):
                                    href = element.get_attribute("href")
                                    if href and self.is_valid_url(href) and self.is_same_domain(href):
                                        found_urls.add(href)
                                        self.add_parameter_variations(href, found_urls)
                                else:
                                    driver.execute_script("arguments[0].click();", element)
                                    time.sleep(1)
                        except:
                            continue
                except:
                    continue
            
            # Find forms
            forms = driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                form_data = self.extract_form_data(form, url)
                if form_data:
                    self.forms_found.append(form_data)
                    found_urls.add(form_data['action'])
            
        except Exception as e:
            self.logger.error(f"Error in AJAX spidering {url}: {str(e)}")
        finally:
            driver.quit()
            
        return found_urls

    def test_search_forms(self, driver, base_url: str, found_urls: Set[str]):
        """Test search forms on the page"""
        try:
            search_selectors = [
                "input[type='text']", "input[type='search']", 
                "input[name*='search']", "input[placeholder*='search']",
                "input[name*='query']", "input[name*='q']"
            ]
            
            for selector in search_selectors:
                try:
                    search_inputs = driver.find_elements(By.CSS_SELECTOR, selector)
                    for search_input in search_inputs:
                        try:
                            # Get the form this input belongs to
                            form = search_input.find_element(By.XPATH, "./ancestor::form[1]")
                            action = form.get_attribute("action") or base_url
                            method = form.get_attribute("method") or "GET"
                            
                            if method.upper() == "GET":
                                param_name = search_input.get_attribute("name") or "search"
                                action_url = urljoin(base_url, action)
                                test_url = f"{action_url}?{param_name}=test"
                                found_urls.add(test_url)
                                
                        except Exception:
                            # If no form, try to construct URL manually
                            param_name = search_input.get_attribute("name") or "search"
                            test_url = f"{base_url}?{param_name}=test"
                            found_urls.add(test_url)
                except:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Error testing search forms: {str(e)}")

    def add_parameter_variations(self, base_url: str, found_urls: Set[str]):
        """Add common parameter variations to test"""
        parsed_url = urlparse(base_url)
        
        # Add common parameters for testing
        for param in self.common_params[:5]:
            if '?' in base_url:
                test_url = f"{base_url}&{param}=test"
            else:
                test_url = f"{base_url}?{param}=test"
            found_urls.add(test_url)

    def extract_form_data(self, form_element, base_url: str) -> Optional[Dict]:
        """Extract form data for testing"""
        try:
            action = form_element.get_attribute("action") or ""
            method = form_element.get_attribute("method") or "GET"
            action_url = urljoin(base_url, action)
            
            inputs = form_element.find_elements(By.TAG_NAME, "input")
            textareas = form_element.find_elements(By.TAG_NAME, "textarea")
            
            form_data = {
                'action': action_url,
                'method': method.upper(),
                'inputs': []
            }
            
            for input_elem in inputs:
                input_type = input_elem.get_attribute("type") or "text"
                name = input_elem.get_attribute("name")
                if name and input_type not in ['submit', 'button', 'reset', 'image']:
                    form_data['inputs'].append({
                        'name': name,
                        'type': input_type,
                        'value': input_elem.get_attribute("value") or ""
                    })
            
            for textarea in textareas:
                name = textarea.get_attribute("name")
                if name:
                    form_data['inputs'].append({
                        'name': name,
                        'type': 'textarea',
                        'value': textarea.get_attribute("value") or ""
                    })
            
            return form_data if form_data['inputs'] else None
            
        except Exception as e:
            self.logger.error(f"Error extracting form data: {str(e)}")
            return None

    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc == ""
        except:
            return False

    def test_reflected_xss(self, url: str) -> List[Dict]:
        """Test for reflected XSS vulnerabilities"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Skip invalid URLs
        if not self.is_valid_url(url):
            return vulnerabilities
        
        # Test URL with existing parameters
        if parsed_url.query:
            params = parse_qs(parsed_url.query, keep_blank_values=True)
            vulnerabilities.extend(self.test_url_parameters(url, params))
        
        # Test URL with common parameters if no existing parameters
        else:
            for param_name in self.common_params[:3]:
                test_params = {param_name: ['test']}
                test_url = f"{url}?{param_name}=test"
                vulnerabilities.extend(self.test_url_parameters(test_url, test_params))
        
        return vulnerabilities

    def test_url_parameters(self, base_url: str, params: Dict) -> List[Dict]:
        """Test URL parameters for XSS"""
        vulnerabilities = []
        parsed_url = urlparse(base_url)
        
        # Get reflected XSS payloads
        reflected_payloads = self.xss_payloads.get('reflected_xss', {})
        
        for payload_category, payloads in reflected_payloads.items():
            for param_name in params.keys():
                for payload in payloads[:3]:  # Limit payloads per parameter
                    try:
                        # Modify the parameter with XSS payload
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        new_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse((
                            parsed_url.scheme, parsed_url.netloc,
                            parsed_url.path, parsed_url.params,
                            new_query, parsed_url.fragment
                        ))
                        
                        # Make request with timeout and user agent
                        headers = {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                        }
                        
                        response = requests.get(test_url, timeout=15, 
                                              allow_redirects=True, headers=headers)
                        
                        # Check if payload is reflected in response
                        if (payload in response.text and 
                            response.status_code == 200 and 
                            'text/html' in response.headers.get('content-type', '')):
                            
                            vulnerability = {
                                'type': 'Reflected XSS',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'payload_category': payload_category,
                                'method': 'GET',
                                'evidence': self.extract_evidence(response.text, payload),
                                'response_length': len(response.text)
                            }
                            vulnerabilities.append(vulnerability)
                            self.logger.info(f"🚨 Reflected XSS found: {param_name} in {base_url}")
                            return vulnerabilities  # Return immediately on first finding
                        
                    except Exception as e:
                        self.logger.debug(f"Error testing reflected XSS: {str(e)}")
                        continue
        
        return vulnerabilities

    def test_stored_xss(self, form_data: Dict) -> List[Dict]:
        """Test for stored XSS vulnerabilities"""
        vulnerabilities = []
        
        if not form_data or not self.is_valid_url(form_data['action']):
            return vulnerabilities
            
        stored_payloads = self.xss_payloads.get('stored_xss', {})
        
        for payload_category, payloads in stored_payloads.items():
            for input_field in form_data['inputs']:
                if input_field['type'] in ['text', 'textarea', 'email', 'search', 'url']:
                    for payload in payloads[:2]:  # Limit payloads for stored XSS
                        try:
                            # Prepare form data
                            post_data = {}
                            for field in form_data['inputs']:
                                if field['name'] == input_field['name']:
                                    post_data[field['name']] = payload
                                else:
                                    post_data[field['name']] = field['value'] or 'test'
                            
                            headers = {
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                                'Content-Type': 'application/x-www-form-urlencoded'
                            }
                            
                            if form_data['method'] == 'POST':
                                response = requests.post(form_data['action'], 
                                                       data=post_data, timeout=15, headers=headers)
                            else:
                                response = requests.get(form_data['action'], 
                                                      params=post_data, timeout=15, headers=headers)
                            
                            if response.status_code == 200:
                                time.sleep(2)  # Wait for storage processing
                                # Check if payload is stored and reflected
                                check_response = requests.get(form_data['action'], timeout=15, headers=headers)
                                if payload in check_response.text:
                                    vulnerability = {
                                        'type': 'Stored XSS',
                                        'url': form_data['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'payload_category': payload_category,
                                        'method': form_data['method'],
                                        'evidence': self.extract_evidence(check_response.text, payload)
                                    }
                                    vulnerabilities.append(vulnerability)
                                    self.logger.info(f"🚨 Stored XSS found: {input_field['name']} in {form_data['action']}")
                                    return vulnerabilities
                                    
                        except Exception as e:
                            self.logger.debug(f"Error testing stored XSS: {str(e)}")
                            continue
        
        return vulnerabilities

    def test_dom_xss(self, url: str) -> List[Dict]:
        """Enhanced DOM-based XSS testing"""
        vulnerabilities = []
        
        if not self.is_valid_url(url):
            return vulnerabilities
            
        driver = self.create_driver()
        dom_payloads = self.xss_payloads.get('dom_xss', {})
        
        try:
            # Test 1: Fragment-based DOM XSS
            for payload_category, payloads in dom_payloads.items():
                for payload in payloads[:3]:  # Limit payloads
                    test_urls = [
                        f"{url}#{payload}",
                        f"{url}#section={payload}",
                        f"{url}#data={payload}",
                        f"{url}?fragment={payload}"
                    ]
                    
                    for test_url in test_urls:
                        try:
                            driver.get(test_url)
                            time.sleep(3)  # Wait for DOM processing
                            
                            # Check for JavaScript execution indicators
                            execution_indicators = [
                                # Check if our payload executed
                                f"alert('DOM-XSS')",
                                f"alert(\"DOM-XSS\")",
                                # Check if payload is in DOM
                                payload
                            ]
                            
                            page_source = driver.page_source
                            current_url = driver.current_url
                            
                            # Method 1: Check if payload appears in DOM unescaped
                            if payload in page_source and not self.is_payload_escaped(page_source, payload):
                                # Method 2: Check for DOM manipulation via JavaScript
                                dom_check_script = f"""
                                var found = false;
                                var sources = {json.dumps(self.dom_sources)};
                                var sinks = {json.dumps(self.dom_sinks)};
                                
                                // Check if URL hash/search is being used unsafely
                                if (location.hash.indexOf('{payload.replace("'", "\\'")}') !== -1 ||
                                    location.search.indexOf('{payload.replace("'", "\\'")}') !== -1) {{
                                    
                                    // Check if any dangerous sinks are present in the page
                                    var scripts = document.getElementsByTagName('script');
                                    for (var i = 0; i < scripts.length; i++) {{
                                        var scriptContent = scripts[i].innerHTML;
                                        for (var j = 0; j < sinks.length; j++) {{
                                            if (scriptContent.indexOf(sinks[j]) !== -1) {{
                                                found = true;
                                                break;
                                            }}
                                        }}
                                        if (found) break;
                                    }}
                                }}
                                
                                return {{
                                    found: found,
                                    hash: location.hash,
                                    search: location.search,
                                    payloadInUrl: location.href.indexOf('{payload.replace("'", "\\'")}') !== -1
                                }};
                                """
                                
                                try:
                                    dom_result = driver.execute_script(dom_check_script)
                                    
                                    if (dom_result.get('found') or 
                                        dom_result.get('payloadInUrl') or 
                                        self.detect_dom_manipulation(driver, payload)):
                                        
                                        vulnerability = {
                                            'type': 'DOM-based XSS',
                                            'url': test_url,
                                            'parameter': 'fragment/url',
                                            'payload': payload,
                                            'payload_category': payload_category,
                                            'method': 'GET',
                                            'evidence': f"Payload found in DOM context, potential execution vector detected",
                                            'dom_result': dom_result
                                        }
                                        vulnerabilities.append(vulnerability)
                                        self.logger.info(f"🚨 DOM XSS found: {test_url}")
                                        return vulnerabilities
                                        
                                except Exception as e:
                                    self.logger.debug(f"DOM check script error: {str(e)}")
                                    
                        except Exception as e:
                            self.logger.debug(f"Error testing DOM XSS: {str(e)}")
                            continue
                            
        except Exception as e:
            self.logger.error(f"Error in DOM XSS testing: {str(e)}")
        finally:
            driver.quit()
            
        return vulnerabilities

    def is_payload_escaped(self, html_content: str, payload: str) -> bool:
        """Check if payload is properly escaped in HTML"""
        # Check for common HTML escaping
        escaped_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;'
        }
        
        for char, escaped in escaped_chars.items():
            if char in payload and escaped in html_content:
                return True
        
        return False

    def detect_dom_manipulation(self, driver, payload: str) -> bool:
        """Detect if DOM is being manipulated unsafely"""
        try:
            # Check for common DOM manipulation patterns
            detection_script = """
            var dangerous = false;
            
            // Check for innerHTML usage with location data
            if (document.body.innerHTML.indexOf('innerHTML') !== -1 &&
                (window.location.hash || window.location.search)) {
                dangerous = true;
            }
            
            // Check for document.write with location data
            if (document.documentElement.outerHTML.indexOf('document.write') !== -1 &&
                (window.location.hash || window.location.search)) {
                dangerous = true;
            }
            
            // Check for eval with location data
            if (document.documentElement.outerHTML.indexOf('eval') !== -1 &&
                (window.location.hash || window.location.search)) {
                dangerous = true;
            }
            
            return dangerous;
            """
            
            return driver.execute_script(detection_script)
        except:
            return False

    def extract_evidence(self, response_text: str, payload: str) -> str:
        """Extract evidence of XSS vulnerability"""
        try:
            if payload in response_text:
                # Find surrounding context
                index = response_text.find(payload)
                start = max(0, index - 100)
                end = min(len(response_text), index + len(payload) + 100)
                context = response_text[start:end].strip()
                
                # Clean up context for readability
                context = re.sub(r'\s+', ' ', context)
                return f"Payload found in context: ...{context[:200]}..."
            
            return "Payload reflected in response"
        except:
            return "Payload reflected in response"

    def scan_url_worker(self, url: str):
        """Worker function for scanning individual URLs"""
        with self.lock:
            if url in self.crawled_urls or not self.is_valid_url(url):
                return
            self.crawled_urls.add(url)
        
        self.logger.info(f"🔍 Scanning: {url}")
        
        # Test for reflected XSS
        reflected_vulns = self.test_reflected_xss(url)
        with self.lock:
            self.scan_results['reflected_xss'].extend(reflected_vulns)
        
        # Test for DOM XSS
        dom_vulns = self.test_dom_xss(url)
        with self.lock:
            self.scan_results['dom_based_xss'].extend(dom_vulns)

    def scan_forms_worker(self, form_data: Dict):
        """Worker function for scanning forms"""
        stored_vulns = self.test_stored_xss(form_data)
        with self.lock:
            self.scan_results['stored_xss'].extend(stored_vulns)

    def run_scan(self):
        """Main scanning function with multi-threading"""
        start_time = time.time()
        self.logger.info(f"🚀 Starting XSS scan for: {self.target_url}")
        self.logger.info(f"📊 Crawl depth: {self.depth} levels")
        
        # Display payload statistics
        total_payloads = sum(len(payloads) for category in self.xss_payloads.values() 
                           for payloads in category.values())
        self.logger.info(f"🎯 Loaded {total_payloads} XSS payloads")
        
        # Phase 1: AJAX Spidering
        self.logger.info("📡 Phase 1: AJAX Spidering and URL Discovery")
        discovered_urls = self.ajax_spider(self.target_url)
        
        # Add discovered URLs to queue (filter out invalid URLs)
        all_urls = {self.target_url}
        for url in discovered_urls | self.ajax_endpoints:
            if self.is_valid_url(url):
                all_urls.add(url)
        
        for url in all_urls:
            self.url_queue.put(url)
        
        self.logger.info(f"🕸️  Discovered {len(all_urls)} URLs and {len(self.forms_found)} forms")
        
        # Phase 2: Active Scanning with Multi-threading
        self.logger.info("🎯 Phase 2: Active XSS Scanning")
        
        # Scan URLs for reflected and DOM XSS
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            url_futures = []
            while not self.url_queue.empty():
                url = self.url_queue.get()
                future = executor.submit(self.scan_url_worker, url)
                url_futures.append(future)
            
            # Wait for URL scanning to complete
            concurrent.futures.wait(url_futures, timeout=300)  # 5 min timeout
        
        # Scan forms for stored XSS
        if self.forms_found:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_threads, len(self.forms_found))) as executor:
                form_futures = []
                for form_data in self.forms_found:
                    future = executor.submit(self.scan_forms_worker, form_data)
                    form_futures.append(future)
                
                # Wait for form scanning to complete
                concurrent.futures.wait(form_futures, timeout=180)  # 3 min timeout
        
        # Calculate summary
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.scan_results['summary'] = {
            'target_url': self.target_url,
            'scan_duration': f"{scan_duration:.2f} seconds",
            'urls_crawled': len(self.crawled_urls),
            'forms_found': len(self.forms_found),
            'ajax_endpoints': len(self.ajax_endpoints),
            'crawl_depth': self.depth,
            'payloads_used': total_payloads,
            'total_vulnerabilities': (
                len(self.scan_results['reflected_xss']) +
                len(self.scan_results['dom_based_xss']) +
                len(self.scan_results['stored_xss'])
            ),
            'reflected_xss_count': len(self.scan_results['reflected_xss']),
            'dom_xss_count': len(self.scan_results['dom_based_xss']),
            'stored_xss_count': len(self.scan_results['stored_xss']),
            'scan_timestamp': datetime.now().isoformat()
        }
        
        self.logger.info(f"✅ Scan completed in {scan_duration:.2f} seconds")
        self.logger.info(f"🚨 Found {self.scan_results['summary']['total_vulnerabilities']} vulnerabilities")

    def generate_report(self, output_file: str = "xss_scan_report.json"):
        """Generate detailed scan report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            
            # Also generate HTML report
            html_file = output_file.replace('.json', '.html')
            self.generate_html_report(html_file)
            
            self.logger.info(f"📄 Reports generated: {output_file} and {html_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Error generating report: {str(e)}")

    def generate_html_report(self, output_file: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Scanner Report</title>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
                .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .vulnerability {{ background-color: #e74c3c; color: white; padding: 15px; margin: 15px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }}
                .vulnerability.medium {{ background-color: #f39c12; }}
                .vulnerability.low {{ background-color: #27ae60; }}
                .details {{ background-color: rgba(255,255,255,0.1); padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #fff; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
                .payload {{ font-family: monospace; background-color: #2c3e50; color: #ecf0f1; padding: 5px; border-radius: 3px; word-break: break-all; }}
                .no-vulns {{ text-align: center; padding: 50px; color: #27ae60; font-size: 18px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; min-width: 150px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ XSS Vulnerability Scanner Report</h1>
                <p>Target: {target_url}</p>
                <p>Scan Date: {scan_date}</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{total_vulnerabilities}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-box">
                    <h3>{urls_crawled}</h3>
                    <p>URLs Scanned</p>
                </div>
                <div class="stat-box">
                    <h3>{payloads_used}</h3>
                    <p>Payloads Used</p>
                </div>
                <div class="stat-box">
                    <h3>{duration}</h3>
                    <p>Scan Duration</p>
                </div>
            </div>
            
            <div class="summary">
                <h2>📊 Scan Summary</h2>
                <table>
                    <tr><td><strong>Scan Duration</strong></td><td>{duration}</td></tr>
                    <tr><td><strong>Crawl Depth</strong></td><td>{crawl_depth} levels</td></tr>
                    <tr><td><strong>URLs Crawled</strong></td><td>{urls_crawled}</td></tr>
                    <tr><td><strong>Forms Found</strong></td><td>{forms_found}</td></tr>
                    <tr><td><strong>AJAX Endpoints</strong></td><td>{ajax_endpoints}</td></tr>
                    <tr><td><strong>Payloads Used</strong></td><td>{payloads_used}</td></tr>
                    <tr><td><strong>Total Vulnerabilities</strong></td><td><strong>{total_vulnerabilities}</strong></td></tr>
                    <tr><td><strong>Reflected XSS</strong></td><td>{reflected_count}</td></tr>
                    <tr><td><strong>DOM-based XSS</strong></td><td>{dom_count}</td></tr>
                    <tr><td><strong>Stored XSS</strong></td><td>{stored_count}</td></tr>
                </table>
            </div>
            
            {vulnerabilities_section}
        </body>
        </html>
        """
        
        # Build vulnerabilities section
        vuln_section = ""
        
        vuln_types = {
            'reflected_xss': '🔍 Reflected XSS Vulnerabilities',
            'dom_based_xss': '🌐 DOM-based XSS Vulnerabilities',
            'stored_xss': '💾 Stored XSS Vulnerabilities'
        }
        
        for vuln_type, title in vuln_types.items():
            if self.scan_results[vuln_type]:
                vuln_section += f"<div class='summary'><h2>{title}</h2>"
                for vuln in self.scan_results[vuln_type]:
                    vuln_section += f"""
                    <div class="vulnerability">
                        <h3>🚨 {vuln['type']} Found</h3>
                        <div class="details">
                            <p><strong>URL:</strong> {vuln['url']}</p>
                            <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                            <p><strong>Method:</strong> {vuln['method']}</p>
                            <p><strong>Payload Category:</strong> {vuln.get('payload_category', 'N/A')}</p>
                            <p><strong>Payload:</strong></p>
                            <div class="payload">{vuln['payload']}</div>
                            <p><strong>Evidence:</strong> {vuln['evidence']}</p>
                        </div>
                    </div>
                    """
                vuln_section += "</div>"
        
        if not vuln_section:
            vuln_section = """
            <div class="summary">
                <div class="no-vulns">
                    <h2>🛡️ No Vulnerabilities Found</h2>
                    <p>The scan did not identify any XSS vulnerabilities in the target application.</p>
                    <p>This could mean the application is secure, or the vulnerabilities require different attack vectors.</p>
                </div>
            </div>
            """
        
        # Fill template
        html_content = html_template.format(
            target_url=self.scan_results['summary']['target_url'],
            scan_date=self.scan_results['summary']['scan_timestamp'],
            duration=self.scan_results['summary']['scan_duration'],
            crawl_depth=self.scan_results['summary']['crawl_depth'],
            urls_crawled=self.scan_results['summary']['urls_crawled'],
            forms_found=self.scan_results['summary']['forms_found'],
            ajax_endpoints=self.scan_results['summary']['ajax_endpoints'],
            payloads_used=self.scan_results['summary'].get('payloads_used', 0),
            total_vulnerabilities=self.scan_results['summary']['total_vulnerabilities'],
            reflected_count=self.scan_results['summary']['reflected_xss_count'],
            dom_count=self.scan_results['summary']['dom_xss_count'],
            stored_count=self.scan_results['summary']['stored_xss_count'],
            vulnerabilities_section=vuln_section
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

def get_user_input():
    """Get user input for scanner configuration"""
    print("\n" + "="*60)
    print("    🛡️  ADVANCED XSS VULNERABILITY SCANNER")
    print("="*60)
    
    # Get target URL
    while True:
        target_url = input("\n🎯 Enter the target URL to scan: ").strip()
        if target_url:
            # Add protocol if missing
            if not target_url.startswith(('http://', 'https://')):
                target_url = 'https://' + target_url
            break
        print("❌ Please enter a valid URL.")
    
    # Get max threads
    while True:
        try:
            threads_input = input("\n⚡ Enter max threads (1-10, default: 5): ").strip()
            if not threads_input:
                max_threads = 5
                break
            max_threads = int(threads_input)
            if 1 <= max_threads <= 10:
                break
            print("❌ Please enter a number between 1 and 10.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    # Get crawl depth
    print("\n" + "-"*60)
    print("📊 CRAWL DEPTH EXPLANATION:")
    print("- Depth 1: Scan only the main page and direct links")
    print("- Depth 2: Scan main page + direct links + their links")  
    print("- Depth 3: Three levels deep (recommended for thorough scan)")
    print("-"*60)
    
    while True:
        try:
            depth_input = input("\n📡 Enter crawl depth (1-3, default: 2): ").strip()
            if not depth_input:
                crawl_depth = 2
                break
            crawl_depth = int(depth_input)
            if 1 <= crawl_depth <= 3:
                break
            print("❌ Please enter a number between 1 and 3.")
        except ValueError:
            print("❌ Please enter a valid number.")
    
    return target_url, max_threads, crawl_depth

# Usage Example with user input
if __name__ == "__main__":
    try:
        # Get user configuration
        target_url, max_threads, crawl_depth = get_user_input()
        
        print(f"\n" + "="*60)
        print("⚙️  SCANNER CONFIGURATION:")
        print(f"🎯 Target URL: {target_url}")
        print(f"⚡ Max Threads: {max_threads}")
        print(f"📡 Crawl Depth: {crawl_depth} levels")
        print(f"📄 Payloads File: payloads.json")
        print("="*60)
        
        confirm = input("\n🚀 Proceed with scan? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Scan cancelled.")
            exit(0)
        
        # Initialize scanner
        scanner = XSSScanner(
            target_url=target_url,
            max_threads=max_threads,
            depth=crawl_depth,
            payloads_file="payloads.json"
        )
        
        print(f"\n🚀 Starting advanced XSS scan...")
        print("⚠️  Make sure you have permission to scan the target website!")
        
        # Run the scan
        scanner.run_scan()
        
        # Generate reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"xss_scan_report_{timestamp}.json"
        scanner.generate_report(report_filename)
        
        print(f"\n" + "="*60)
        print("📊 SCAN RESULTS SUMMARY")
        print("="*60)
        print(f"🎯 Target: {scanner.scan_results['summary']['target_url']}")
        print(f"⏱️  Duration: {scanner.scan_results['summary']['scan_duration']}")
        print(f"📡 Crawl Depth: {scanner.scan_results['summary']['crawl_depth']} levels")
        print(f"🕸️  URLs Crawled: {scanner.scan_results['summary']['urls_crawled']}")
        print(f"📝 Forms Found: {scanner.scan_results['summary']['forms_found']}")
        print(f"⚡ AJAX Endpoints: {scanner.scan_results['summary']['ajax_endpoints']}")
        print(f"🎯 Payloads Used: {scanner.scan_results['summary'].get('payloads_used', 0)}")
        print(f"\n🚨 VULNERABILITIES FOUND:")
        print(f"  📊 Total: {scanner.scan_results['summary']['total_vulnerabilities']}")
        print(f"  🔍 Reflected XSS: {scanner.scan_results['summary']['reflected_xss_count']}")
        print(f"  🌐 DOM-based XSS: {scanner.scan_results['summary']['dom_xss_count']}")
        print(f"  💾 Stored XSS: {scanner.scan_results['summary']['stored_xss_count']}")
        print(f"\n📄 Reports generated:")
        print(f"  📋 JSON Report: {report_filename}")
        print(f"  🌐 HTML Report: {report_filename.replace('.json', '.html')}")
        print("="*60)
        
        if scanner.scan_results['summary']['total_vulnerabilities'] > 0:
            print("\n🚨 SECURITY ALERT: XSS vulnerabilities found!")
            print("🔧 Please review the detailed reports and fix the identified issues.")
        else:
            print("\n✅ No XSS vulnerabilities detected in this scan.")
            print("🔍 Consider manual testing for complex attack vectors.")
        
    except KeyboardInterrupt:
        print("\n\n⛔ Scan interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print("🔧 Please check your configuration and try again.")
