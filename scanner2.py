#!/usr/bin/env python3
"""
Multi-threaded Web Vulnerability Scanner
Focuses on CORS, SSL/TLS, and Certificate vulnerabilities
Uses Selenium for web crawling with configurable depth and threading
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
import OpenSSL
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
        
        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.set_page_load_timeout(15)
            return driver
        except Exception as e:
            print(f"❌ Failed to create WebDriver: {e}")
            return None

    def crawl_website(self) -> Set[str]:
        """Crawl website to discover URLs based on specified depth"""
        print("🕷️  Starting website crawling...")
        discovered_urls = set()
        
        with ThreadPoolExecutor(max_workers=min(self.max_threads, 4)) as executor:
            futures = []
            
            while self.url_queue and len(futures) < self.max_threads:
                if not self.url_queue:
                    break
                    
                url, depth = self.url_queue.popleft()
                
                if url in self.visited_urls or depth > self.crawl_depth:
                    continue
                    
                future = executor.submit(self._crawl_single_page, url, depth)
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    page_urls = future.result()
                    discovered_urls.update(page_urls)
                except Exception as e:
                    print(f"⚠️  Crawling error: {e}")
        
        print(f"✅ Discovered {len(discovered_urls)} URLs")
        return discovered_urls

    def _crawl_single_page(self, url: str, depth: int) -> Set[str]:
        """Crawl a single page and extract links"""
        page_urls = set()
        driver = None
        
        try:
            with self.lock:
                if url in self.visited_urls:
                    return page_urls
                self.visited_urls.add(url)
            
            driver = self.get_driver()
            if not driver:
                return page_urls
                
            print(f"🔍 Crawling: {url} (depth: {depth})")
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Extract links
            links = driver.find_elements(By.TAG_NAME, "a")
            
            for link in links:
                try:
                    href = link.get_attribute("href")
                    if href and self._is_valid_url(href):
                        absolute_url = urljoin(url, href)
                        page_urls.add(absolute_url)
                        
                        # Add to queue for further crawling if within depth limit
                        if depth < self.crawl_depth:
                            with self.lock:
                                if absolute_url not in self.visited_urls:
                                    self.url_queue.append((absolute_url, depth + 1))
                                    
                except Exception as e:
                    continue
            
            # Add current URL to results
            page_urls.add(url)
            
        except Exception as e:
            print(f"⚠️  Error crawling {url}: {e}")
        finally:
            if driver:
                driver.quit()
                
        return page_urls

    def _is_valid_url(self, url: str) -> bool:
        """Validate if URL should be crawled"""
        if not url or url.startswith(('#', 'javascript:', 'mailto:')):
            return False
            
        try:
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != self.target_domain:
                return False
                
            # Skip common file extensions
            skip_extensions = {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico'}
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return False
                
            return True
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
                'https://attacker.evil.com',
                '*'
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
                    
                    elif cors_origin == origin and origin != url:
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
            print(f"CORS check error for {url}: {e}")
            
        return results

    def _check_ssl_tls_vulnerabilities(self, url: str) -> List[VulnerabilityResult]:
        """Check for SSL/TLS vulnerabilities"""
        results = []
        
        if not url.startswith('https://'):
            return results
            
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Test SSL/TLS protocols
            vulnerable_protocols = []
            
            for protocol in [ssl.PROTOCOL_SSLv23, ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1]:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            protocol_version = ssock.version()
                            if protocol_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                                vulnerable_protocols.append(protocol_version)
                except:
                    continue
            
            if vulnerable_protocols:
                results.append(VulnerabilityResult(
                    url=url,
                    vulnerability_type="SSL/TLS",
                    severity="HIGH",
                    description="Weak SSL/TLS protocols supported",
                    details={
                        "vulnerable_protocols": vulnerable_protocols
                    },
                    timestamp=datetime.now().isoformat()
                ))
            
            # Check for weak ciphers
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            
                            # Check for weak ciphers
                            weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
                            if any(weak in cipher_name for weak in weak_ciphers):
                                results.append(VulnerabilityResult(
                                    url=url,
                                    vulnerability_type="SSL/TLS",
                                    severity="MEDIUM",
                                    description="Weak cipher suite detected",
                                    details={
                                        "cipher_suite": cipher_name
                                    },
                                    timestamp=datetime.now().isoformat()
                                ))
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
            print(f"SSL/TLS check error for {url}: {e}")
            
        return results

    def _check_certificate_vulnerabilities(self, url: str) -> List[VulnerabilityResult]:
        """Check for certificate vulnerabilities"""
        results = []
        
        if not url.startswith('https://'):
            return results
            
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Get certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                    
                    # Parse certificate
                    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                    
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
            print(f"Certificate check error for {url}: {e}")
            
        return results

    def generate_report(self) -> Dict:
        """Generate comprehensive vulnerability report"""
        report = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_time": datetime.now().isoformat(),
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
            print(f"      Details: {vuln.details}")
            print()
        
    except KeyboardInterrupt:
        print("\n⚠️  Scanner interrupted by user")
    except Exception as e:
        print(f"\n❌ Scanner error: {e}")

if __name__ == "__main__":
    main()
