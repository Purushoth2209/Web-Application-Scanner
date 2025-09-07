from pathlib import Path
import os
from jinja2 import Template
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
        tpl = (Path(__file__).parent / "templates" / "report.html").read_text(encoding="utf-8")
        html_path = out_base / (Path(json_path).stem + ".html")
        html = Template(tpl).render(target_url=report.target_url, visited_urls=report.visited_urls, summary=report.summary)
        html_path.write_text(html, encoding="utf-8")
        return {"json": str(json_path), "html": str(html_path)}
    finally:
        eng.close()
