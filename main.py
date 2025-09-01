# main.py

import os
from xss_engine import XSSScannerEngine
from reporter import ReportGenerator

def main():
    CHROMEDRIVER_PATH = "/usr/local/bin/chromedriver" # Adjust this path as needed

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

    scanner = None
    try:
        # Initialize the scanner engine
        # You can pass headless=False here to see the browser actions
        scanner = XSSScannerEngine(CHROMEDRIVER_PATH, headless=True) 
        
        # Run the scan
        scan_report = scanner.scan(target_website)
        
        # Generate and save the report
        reporter = ReportGenerator()
        reporter.save_report(scan_report)

        if scan_report.potential_vulnerabilities:
            print("\nScan completed. Potential XSS vulnerabilities found. Check the report files.")
        else:
            print("\nScan completed. No reflected XSS vulnerabilities detected (basic check).")

    except Exception as e:
        print(f"An unexpected error occurred during the scan: {e}")
    finally:
        if scanner:
            scanner.close()

if __name__ == "__main__":
    main()