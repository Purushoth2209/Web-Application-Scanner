import argparse, time, json
from bac_scanner import run_bac_scan
from report_generator import generate_reports

def main():
    parser = argparse.ArgumentParser(description="Automated BAC Scanner")
    parser.add_argument("--base", required=True, help="Target site URL")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth (default=3)")
    args = parser.parse_args()

    base_url, depth = args.base, args.depth
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    print(f"[+] Starting BAC scan on {base_url} at {timestamp}...")

    json_report = run_bac_scan(base_url, user_creds={"username": "dummy", "password": "dummy"}, max_depth=depth)
    if not json_report:
        print("[-] Scan failed. No report generated.")
        return

    full_report, exploited_report = generate_reports(json_report)

    with open(json_report) as f:
        data = json.load(f)

    total_tests = len(data["tests"])
    total_findings = sum(len(t["results"]) for t in data["tests"])
    vulnerable = sum(1 for t in data["tests"] for r in t["results"] if r.get("status") == "Vulnerable")
    risk_breakdown = {"High": 0, "Medium": 0, "Low": 0}
    for t in data["tests"]:
        for r in t["results"]:
            if r.get("status") == "Vulnerable":
                risk_breakdown[r.get("risk", "Low")] += 1

    print("\n[+] Scan Complete")
    print(f"    Site: {base_url}")
    print(f"    Total Tests: {total_tests}")
    print(f"    Total Findings: {total_findings}")
    print(f"    Vulnerabilities: {vulnerable}")
    print(f"    Risk Breakdown → High: {risk_breakdown['High']} | Medium: {risk_breakdown['Medium']} | Low: {risk_breakdown['Low']}")
    print(f"\n    Full Report: {full_report}")
    print(f"    Exploited-Only Report: {exploited_report}")
    print("\n[+] Done. View reports by running:")
    print("    python3 -m http.server 8001 --directory reports")
    print("    Open http://localhost:8001 in your browser.")

if __name__ == "__main__":
    main()
