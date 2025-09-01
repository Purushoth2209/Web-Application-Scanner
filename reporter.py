# reporter.py

import os
import json
import datetime
from typing import List, Dict, Any
from models import ScanReport, Vulnerability

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _generate_json_report(self, report_data: ScanReport) -> Dict[str, Any]:
        """Converts the ScanReport object to a dictionary for JSON serialization."""
        vulnerabilities_json = [vul.__dict__ for vul in report_data.potential_vulnerabilities]
        
        report_dict = {
            "target_url": report_data.target_url,
            "scan_start_time": report_data.start_time,
            "scan_end_time": report_data.end_time,
            "visited_urls": sorted(report_data.visited_urls),
            "vulnerabilities_found": len(report_data.potential_vulnerabilities),
            "vulnerabilities": vulnerabilities_json,
            "summary": report_data.summary
        }
        return report_dict

    def _generate_markdown_report(self, report_data: ScanReport) -> str:
        """Generates a human-readable Markdown report."""
        md_report = f"# XSS Scan Report for {report_data.target_url}\n\n"
        md_report += f"**Scan Start Time:** {report_data.start_time}\n"
        md_report += f"**Scan End Time:** {report_data.end_time}\n"
        md_report += f"**Total URLs Visited:** {len(report_data.visited_urls)}\n"
        md_report += f"**Potential XSS Vulnerabilities Found:** {len(report_data.potential_vulnerabilities)}\n\n"

        md_report += "## Visited URLs\n"
        if report_data.visited_urls:
            for url in sorted(report_data.visited_urls):
                md_report += f"- {url}\n"
        else:
            md_report += "No URLs were visited during the scan.\n"
        md_report += "\n"

        md_report += "## Potential XSS Vulnerabilities\n"
        if report_data.potential_vulnerabilities:
            for i, vul in enumerate(report_data.potential_vulnerabilities):
                md_report += f"### Vulnerability {i+1}\n"
                md_report += f"- **URL:** `{vul.url}`\n"
                md_report += f"- **Affected Field:** `{vul.field}`\n"
                md_report += f"- **Payload Used:** `{vul.payload}`\n"
                md_report += f"- **Detection Method:** {vul.detection_method}\n"
                if vul.screenshot_path:
                    md_report += f"- **Screenshot:** [Link to Screenshot]({os.path.basename(vul.screenshot_path)})\n"
                md_report += "\n"
        else:
            md_report += "No reflected XSS vulnerabilities detected with the given payloads.\n"
            md_report += "*(Note: This is a basic scanner and may miss complex XSS or other vulnerability types.)*\n"
        md_report += "\n"

        if report_data.summary:
            md_report += "## Scan Summary\n"
            for key, value in report_data.summary.items():
                md_report += f"- **{key.replace('_', ' ').title()}:** {value}\n"
        
        return md_report

    def save_report(self, report_data: ScanReport):
        """Saves the scan report in both JSON and Markdown formats."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Sanitize target_url for filename
        sanitized_url = report_data.target_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_").replace(".", "_")
        report_filename_base = f"xss_scan_{sanitized_url}_{timestamp}"

        # Save JSON report
        json_report_path = os.path.join(self.output_dir, f"{report_filename_base}.json")
        with open(json_report_path, "w", encoding="utf-8") as f:
            json.dump(self._generate_json_report(report_data), f, indent=4)
        print(f"JSON report saved to: {json_report_path}")

        # Save Markdown report
        md_report_path = os.path.join(self.output_dir, f"{report_filename_base}.md")
        with open(md_report_path, "w", encoding="utf-8") as f:
            f.write(self._generate_markdown_report(report_data))
        print(f"Markdown report saved to: {md_report_path}")