#!/usr/bin/env python3
"""
Multi-threaded Web Vulnerability Scanner - FIXED VERSION
Focuses on CORS, SSL/TLS, and Certificate vulnerabilities
"""

import os
import sys
import ssl
import json
import time
import socket
import asyncio
import threading
import requests
import urllib3
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# SSL/Certificate analysis
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class VulnerabilityResult:
    """Data class to store vulnerability findings"""
    url: str
    vulnerability_type: str
    severity: str
    description: str
    details: Dict
    timestamp: str

class WebScanner:
    """Main scanner class handling crawling and vulnerability detection"""
    
    def __init__(self, target_url: str, max_threads: int, crawl_depth: int):
        self.target_url = target_url.rstrip('/')
        self.max_threads = max_threads
        self.crawl_depth = crawl_depth
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.url_queue = deque([(target_url, 0)])  # (url, depth)
        self.vulnerabilities: List[VulnerabilityResult] = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        
        # Domain validation
        self.target_domain = urlparse(target_url).netloc
        
        print(f"🚀 Initializing scanner for: {target_url}")
        print(f"📊 Threads: {max_threads}, Depth: {crawl_depth}")

    def get_driver(self) -> webdriver.Chrome:
        """Create optimized Chrome WebDriver instance"""
        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--disable-images')
        options.add_argument('--disable-web-security')
        options.add_argument('--allow-running-insecure-content')
        options.add_argument('--ignore-certificate-errors')
        options.add_argument('--ignore-ssl-errors')
        options.add_argument('--page-load-strategy=eager')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-logging')
        options.add_argument('--log-level=3')
        options.add_argument('--silent')
        
        # Performance optimizations
        prefs = {
            "profile.default_content_setting_values": {
                "images": 2,
                "plugins": 2,
                "popups": 2,
                "geolocation": 2,
                "notifications": 2,
                "media_stream": 2,
            }
        }
        options.add_experimental_option("prefs", prefs)
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        options.add_experimental_option('useAutomationExtension', False)
        
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(10)
            return driver
        except Exception as e:
            print(f"❌ Failed to create WebDriver: {e}")
            return None

    def crawl_website(self) -> Set[str]:
        """FIXED: Crawl website to discover URLs based on specified depth"""
        print("🕷️  Starting website crawling...")
        
        # Process URLs level by level to ensure proper depth crawling
        current_depth = 0
        
        while current_depth <= self.crawl_depth and self.url_queue:
            # Get all URLs at current depth
            urls_at_depth = []
            temp_queue = deque()
            
            # Separate URLs by depth
            while self.url_queue:
                url, depth = self.url_queue.popleft()
                if depth == current_depth:
                    urls_at_depth.append(url)
                else:
                    temp_queue.append((url, depth))
            
            # Put remaining URLs back in queue
            self.url_queue = temp_queue
            
            if not urls_at_depth:
                current_depth += 1
                continue
                
            print(f"🔍 Processing {len(urls_at_depth)} URLs at depth {current_depth}")
            
            # Process URLs at current depth with threading
            with ThreadPoolExecutor(max_workers=min(self.max_threads, len(urls_at_depth))) as executor:
                future_to_url = {
                    executor.submit(self._crawl_single_page, url, current_depth): url 
                    for url in urls_at_depth if url not in self.visited_urls
                }
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        page_urls = future.result()
                        with self.lock:
                            self.discovered_urls.update(page_urls)
                            
                            # Add new URLs to queue for next depth level
                            for new_url in page_urls:
                                if (new_url not in self.visited_urls and 
                                    current_depth < self.crawl_depth and
                                    self._is_valid_url(new_url)):
                                    self.url_queue.append((new_url, current_depth + 1))
                                    
                    except Exception as e:
                        print(f"⚠️  Crawling error for {url}: {e}")
            
            current_depth += 1
        
        print(f"✅ Discovered {len(self.discovered_urls)} URLs across {self.crawl_depth + 1} depth levels")
        return self.discovered_urls

    def _crawl_single_page(self, url: str, depth: int) -> Set[str]:
        """FIXED: Crawl a single page and extract links"""
        page_urls = set()
        driver = None
        
        try:
            # Check if already visited (thread-safe)
            with self.lock:
                if url in self.visited_urls:
                    return page_urls
                self.visited_urls.add(url)
            
            # Skip fragment URLs for crawling but include in results
            if '#' in url and url.split('#')[0] in self.visited_urls:
                page_urls.add(url)
                return page_urls
            
            print(f"🔍 Crawling: {url} (depth: {depth})")
            
            # Create driver for this thread
            driver = self.get_driver()
            if not driver:
                print(f"❌ Failed to create driver for {url}")
                return page_urls
                
            # Load page
            driver.get(url)
            
            # Wait for page to load
            try:
                WebDriverWait(driver, 8).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except TimeoutException:
                print(f"⏰ Timeout loading {url}")
            
            # Extract all links
            links = driver.find_elements(By.TAG_NAME, "a")
            
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href and self._is_valid_url(href):
                        absolute_url = urljoin(url, href)
                        if self._is_same_domain(absolute_url):
                            page_urls.add(absolute_url)
                except Exception:
                    continue
            
            # Also check for form actions
            try:
                forms = driver.find_elements(By.TAG_NAME, "form")
                for form in forms:
                    action = form.get_attribute("action")
                    if action and self._is_valid_url(action):
                        absolute_url = urljoin(url, action)
                        if self._is_same_domain(absolute_url):
                            page_urls.add(absolute_url)
            except Exception:
                pass
            
            # Add current URL to results
            page_urls.add(url)
            
            print(f"✅ Found {len(page_urls)} URLs on {url}")
            
        except Exception as e:
            print(f"⚠️  Error crawling {url}: {e}")
            page_urls.add(url)  # At least include the original URL
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
                
        return page_urls

    def _is_valid_url(self, url: str) -> bool:
        """IMPROVED: Validate if URL should be crawled"""
        if not url or url.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            return False
            
        try:
            parsed = urlparse(url)
            
            # Skip common file extensions
            skip_extensions = {
                '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', 
                '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
                '.zip', '.rar', '.exe', '.dmg', '.mp4', '.avi', '.mov'
            }
            
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
        except:
            return False

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.target_domain or not parsed.netloc
        except:
            return False

    def scan_vulnerabilities(self, urls: Set[str]):
        """Scan discovered URLs for vulnerabilities"""
        print(f"🔐 Starting vulnerability scan on {len(urls)} URLs...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_single_url, url): url for url in urls}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                url = futures[future]
                
                try:
                    results = future.result()
                    with self.lock:
                        self.vulnerabilities.extend(results)
                    
                    if completed % 5 == 0 or completed == len(urls):
                        print(f"📈 Progress: {completed}/{len(urls)} URLs scanned")
                    
                except Exception as e:
                    print(f"❌ Error scanning {url}: {e}")

    def _scan_single_url(self, url: str) -> List[VulnerabilityResult]:
        """Scan a single URL for all vulnerability types"""
        results = []
        
        try:
            # CORS vulnerabilities
            cors_results = self._check_cors_vulnerabilities(url)
            results.extend(cors_results)
            
            # SSL/TLS vulnerabilities
            if url.startswith('https://'):
                ssl_results = self._check_ssl_tls_vulnerabilities(url)
                results.extend(ssl_results)
                
                # Certificate vulnerabilities
                cert_results = self._check_certificate_vulnerabilities(url)
                results.extend(cert_results)
            
        except Exception as e:
            print(f"⚠️  Scan error for {url}: {e}")
            
        return results

    def _check_cors_vulnerabilities(self, url: str) -> List[VulnerabilityResult]:
        """Check for CORS misconfigurations"""
        results = []
        
        try:
            # Test various CORS scenarios
            test_origins = [
                'https://evil.com',
                'null',
                'https://attacker.evil.com'
            ]
            
            for origin in test_origins:
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'Content-Type'
                }
                
                try:
                    # Send preflight request
                    response = self.session.options(url, headers=headers, timeout=5)
                    
                    # Check response headers
                    cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
                    cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Vulnerability detection
                    if cors_origin == '*' and cors_credentials.lower() == 'true':
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="CORS",
                            severity="HIGH",
                            description="CORS wildcard origin with credentials enabled",
                            details={
                                "origin_header": origin,
                                "cors_origin": cors_origin,
                                "cors_credentials": cors_credentials
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    elif cors_origin == '*':
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="CORS",
                            severity="MEDIUM",
                            description="CORS wildcard origin allowed",
                            details={
                                "cors_origin": cors_origin,
                                "test_origin": origin
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    elif cors_origin == origin and origin not in ['null']:
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="CORS",
                            severity="MEDIUM",
                            description="CORS arbitrary origin reflection",
                            details={
                                "reflected_origin": origin,
                                "cors_origin": cors_origin
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    elif cors_origin == 'null':
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="CORS",
                            severity="MEDIUM",
                            description="CORS null origin allowed",
                            details={
                                "cors_origin": cors_origin
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            pass
            
        return results

    def _check_ssl_tls_vulnerabilities(self, url: str) -> List[VulnerabilityResult]:
        """FIXED: Check for SSL/TLS vulnerabilities"""
        results = []
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Check for weak protocols using modern approach
            try:
                # Test TLS versions
                for protocol_name, min_version, max_version in [
                    ("TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
                    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
                ]:
                    try:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.minimum_version = min_version
                        context.maximum_version = max_version
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        with socket.create_connection((hostname, port), timeout=5) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                if ssock.version() in ['TLSv1', 'TLSv1.1']:
                                    results.append(VulnerabilityResult(
                                        url=url,
                                        vulnerability_type="SSL/TLS",
                                        severity="HIGH",
                                        description=f"Weak TLS protocol supported: {protocol_name}",
                                        details={
                                            "protocol_version": ssock.version()
                                        },
                                        timestamp=datetime.now().isoformat()
                                    ))
                                    break
                    except:
                        continue
            except:
                pass
            
            # Check HSTS header
            try:
                response = self.session.get(url, timeout=5)
                hsts_header = response.headers.get('Strict-Transport-Security')
                
                if not hsts_header:
                    results.append(VulnerabilityResult(
                        url=url,
                        vulnerability_type="SSL/TLS",
                        severity="LOW",
                        description="Missing HSTS header",
                        details={
                            "recommendation": "Implement HTTP Strict Transport Security"
                        },
                        timestamp=datetime.now().isoformat()
                    ))
            except:
                pass
                
        except Exception as e:
            pass
            
        return results

    def _check_certificate_vulnerabilities(self, url: str) -> List[VulnerabilityResult]:
        """FIXED: Check for certificate vulnerabilities"""
        results = []
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Get certificate using modern approach
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Check expiration
                    now = datetime.now()
                    if cert.not_valid_after < now:
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="Certificate",
                            severity="HIGH",
                            description="Certificate has expired",
                            details={
                                "expired_date": cert.not_valid_after.isoformat(),
                                "days_expired": (now - cert.not_valid_after).days
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    elif cert.not_valid_after < now + timedelta(days=30):
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="Certificate",
                            severity="MEDIUM",
                            description="Certificate expires within 30 days",
                            details={
                                "expiration_date": cert.not_valid_after.isoformat(),
                                "days_until_expiry": (cert.not_valid_after - now).days
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    # Check signature algorithm
                    signature_algorithm = cert.signature_algorithm_oid._name
                    if 'sha1' in signature_algorithm.lower() or 'md5' in signature_algorithm.lower():
                        results.append(VulnerabilityResult(
                            url=url,
                            vulnerability_type="Certificate",
                            severity="MEDIUM",
                            description="Weak certificate signature algorithm",
                            details={
                                "signature_algorithm": signature_algorithm
                            },
                            timestamp=datetime.now().isoformat()
                        ))
                    
                    # Check key size
                    public_key = cert.public_key()
                    if hasattr(public_key, 'key_size'):
                        key_size = public_key.key_size
                        if key_size < 2048:
                            results.append(VulnerabilityResult(
                                url=url,
                                vulnerability_type="Certificate",
                                severity="HIGH",
                                description="Weak certificate key size",
                                details={
                                    "key_size": key_size,
                                    "recommended_minimum": 2048
                                },
                                timestamp=datetime.now().isoformat()
                            ))
                
        except Exception as e:
            pass
            
        return results

    def generate_report(self) -> Dict:
        """Generate comprehensive vulnerability report"""
        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_time": datetime.now().isoformat(),
                "total_urls_discovered": len(self.discovered_urls),
                "total_urls_scanned": len(self.visited_urls),
                "total_vulnerabilities": len(self.vulnerabilities),
                "threads_used": self.max_threads,
                "crawl_depth": self.crawl_depth
            },
            "vulnerabilities": [],
            "summary": defaultdict(int)
        }
        
        # Process vulnerabilities
        for vuln in self.vulnerabilities:
            report["vulnerabilities"].append(asdict(vuln))
            report["summary"][f"{vuln.vulnerability_type}_{vuln.severity}"] += 1
            report["summary"]["total_vulnerabilities"] += 1
        
        return report

def main():
    """Main function to run the scanner"""
    print("=" * 60)
    print("🔒 Multi-threaded Web Vulnerability Scanner")
    print("   Focuses on CORS, SSL/TLS, and Certificate Issues")
    print("=" * 60)
    
    try:
        # Get user inputs
        target_url = input("\n🌐 Enter target URL (e.g., https://example.com): ").strip()
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        print("\n🧵 Thread Configuration:")
        print("   - Light scanning: 2-4 threads")
        print("   - Normal scanning: 4-8 threads") 
        print("   - Intensive scanning: 8-16 threads")
        max_threads = int(input("Enter number of threads (recommended: 4-8): "))
        
        print("\n🕳️ Crawl Depth Options:")
        print("   1. Shallow (homepage + direct links)")
        print("   2. Medium (2-3 levels deep)")
        print("   3. Deep (comprehensive scan)")
        depth_choice = int(input("Select crawl depth (1-3): "))
        
        depth_mapping = {1: 1, 2: 3, 3: 5}
        crawl_depth = depth_mapping.get(depth_choice, 3)
        
        # Initialize and run scanner
        scanner = WebScanner(target_url, max_threads, crawl_depth)
        
        # Start scanning process
        start_time = time.time()
        
        # Step 1: Crawl website
        discovered_urls = scanner.crawl_website()
        
        # Step 2: Scan for vulnerabilities
        scanner.scan_vulnerabilities(discovered_urls)
        
        # Step 3: Generate report
        report = scanner.generate_report()
        
        # Display results
        end_time = time.time()
        print(f"\n✅ Scan completed in {end_time - start_time:.2f} seconds")
        print(f"📊 Total vulnerabilities found: {len(scanner.vulnerabilities)}")
        
        # Save report
        report_filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report saved to: {report_filename}")
        
        # Display summary
        print("\n📈 Vulnerability Summary:")
        for vuln in scanner.vulnerabilities:
            print(f"   🚨 {vuln.severity} - {vuln.vulnerability_type}: {vuln.description}")
            print(f"      URL: {vuln.url}")
            if len(str(vuln.details)) < 100:
                print(f"      Details: {vuln.details}")
            print()
        
    except KeyboardInterrupt:
        print("\n⚠️  Scanner interrupted by user")
    except Exception as e:
        print(f"\n❌ Scanner error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
