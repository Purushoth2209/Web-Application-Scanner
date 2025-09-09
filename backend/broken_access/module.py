from pathlib import Path
from .scanner import run as run_scan
from .report_generator import generate_reports


def run(url: str, out_dir: Path, depth: int = 3):
    res = run_scan(url, out_dir=Path(out_dir), max_depth=depth)
    if res and res.get("json"):
        full_html, exploited_html = generate_reports(res["json"])
        return {"json": res["json"], "html": full_html, "html_exploited": exploited_html}
    return res
