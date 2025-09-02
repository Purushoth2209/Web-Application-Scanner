import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys

visited = set()
errors = []
redirects = []
open_redirects = []
to_visit = []


def is_valid(url, domain):
    """
    Check if the URL belongs to the same domain and is valid.
    """
    parsed = urlparse(url)
    return parsed.netloc == "" or parsed.netloc == domain


def crawl(domain, max_depth=3):
    """
    Iterative crawl with console logs.
    """
    while to_visit:
        url, depth = to_visit.pop(0)

        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        print(f"[+] Crawling ({len(visited)}): {url}")

        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            status = response.status_code

            if status >= 400:
                print(f"   [ERROR] {url} -> {status}")
                errors.append((url, status))
            elif 300 <= status < 400:
                location = response.headers.get("Location")
                print(f"   [REDIRECT] {url} -> {status} to {location}")
                redirects.append((url, status, location))

                # Detect open redirects (pointing outside the domain)
                if location:
                    parsed_location = urlparse(urljoin(url, location))
                    if parsed_location.netloc and parsed_location.netloc != domain:
                        print(f"   [!!] Potential Open Redirect: {url} -> {location}")
                        open_redirects.append((url, status, location))

            # Only parse HTML pages
            if "text/html" in response.headers.get("Content-Type", ""):
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    next_url = urljoin(url, link["href"])
                    if is_valid(next_url, domain) and next_url not in visited:
                        to_visit.append((next_url, depth + 1))

        except requests.RequestException as e:
            print(f"   [EXCEPTION] {url} -> {str(e)}")
            errors.append((url, str(e)))


def save_results(filename):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("--- Scan Results ---\n")
        f.write(f"Total unique endpoints scanned: {len(visited)}\n\n")

        if errors:
            f.write("[!] Errors Found:\n")
            for url, status in errors:
                f.write(f"  {url} -> {status}\n")
        else:
            f.write("[+] No errors found.\n")

        f.write("\n")

        if redirects:
            f.write("[!] Redirects Found:\n")
            for url, status, location in redirects:
                f.write(f"  {url} -> {status} (redirects to {location})\n")
        else:
            f.write("[+] No redirects found.\n")

        f.write("\n")

        if open_redirects:
            f.write("[!!] Potential Open Redirects Detected:\n")
            for url, status, location in open_redirects:
                f.write(f"  {url} -> {status} (redirects to external: {location})\n")
        else:
            f.write("[+] No open redirects detected.\n")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <url>")
        sys.exit(1)

    start_url = sys.argv[1]
    parsed = urlparse(start_url)
    domain = parsed.netloc

    print(f"[+] Starting crawl at {start_url}")

    # Add start URL to the queue
    to_visit.append((start_url, 0))

    # Start crawling
    crawl(domain)

    # Save results
    filename = "scan_results.txt"
    save_results(filename)

    print("\n--- Scan Complete ---")
    print(f"Total unique endpoints scanned: {len(visited)}")
    print(f"Results saved to {filename}")


if __name__ == "__main__":
    main()
