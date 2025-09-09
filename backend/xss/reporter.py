import os, json, datetime

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def save_report(self, report_data):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = (report_data.target_url
                .replace("http://", "")
                .replace("https://", "")
                .replace(":", "_")
                .replace("/", "_"))
        json_path = os.path.join(self.output_dir, f"xss_{name}_{ts}.json")
        # Include potential vulnerabilities if present on the report object
        vulns = []
        try:
            vulns_attr = getattr(report_data, "potential_vulnerabilities", [])
            for v in vulns_attr:
                # Support both simple dict-like and object models
                if isinstance(v, dict):
                    vulns.append(v)
                else:
                    vulns.append({k: getattr(v, k, None) for k in ["url", "field", "payload", "detection_method", "screenshot_path"]})
        except Exception:
            vulns = []
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "target_url": report_data.target_url,
                "visited_urls": report_data.visited_urls,
                "summary": report_data.summary,
                "vulnerabilities": vulns,
            }, f, indent=2)
        return json_path
