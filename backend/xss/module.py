from pathlib import Path
import os
from reports.unified import render_report
from .xss_engine import XSSScannerEngine
from .reporter import ReportGenerator


def run(url: str, out_dir: Path | None = None, chromedriver: str | None = None):
    # chromedriver parameter is ignored - XSSScannerEngine handles WebDriverManager internally
    eng = XSSScannerEngine(headless=True, output_dir=str(out_dir or (Path(__file__).parent / "screenshots")))
    try:
        out_base = Path(out_dir or (Path(__file__).parent / "reports"))
        out_base.mkdir(parents=True, exist_ok=True)
        report = eng.scan(url)
        json_path = ReportGenerator(output_dir=str(out_base)).save_report(report)
        # Render HTML
        html_path = out_base / (Path(json_path).stem + ".html")
        findings = []
        try:
            for v in getattr(report, "potential_vulnerabilities", []):
                if isinstance(v, dict):
                    findings.append(v)
                else:
                    findings.append({k: getattr(v, k, None) for k in ["url", "field", "payload", "detection_method"]})
        except Exception:
            pass
        render_report(
            category="XSS",
            target=report.target_url,
            findings=findings,
            out_html=html_path,
            summary={"total_findings": len(findings), "vulnerabilities": len(findings)},
            extras={"visited_urls": report.visited_urls},
        )
        return {"json": str(json_path), "html": str(html_path)}
    finally:
        eng.close()
