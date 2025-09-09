from __future__ import annotations

"""Build a single, complete HTML report by inlining all per-scanner reports.

Optionally generates an executive summary using Gemini (if configured), then
converts this single HTML into a PDF using the existing html_to_pdf utility.

Outputs:
- index_full.html in the combined report folder (same folder passed as root)

This module is intentionally self-contained and resilient to missing pieces:
it skips scanners without HTML outputs and continues on errors.
"""

from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from .pdf import html_to_pdf

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore

# Optional AI summary
def _try_ai_summary(results: dict) -> str | None:
    try:
        from .ai_enhance import generate_ai_summary  # lazy import
    except Exception:
        return None
    try:
        analysis = generate_ai_summary(results)  # type: ignore[arg-type]
        if not isinstance(analysis, dict):
            return None
        parts: List[str] = []
        summary = analysis.get("summary")
        if summary:
            parts.append(f"<p>{summary}</p>")
        recs = analysis.get("recommendations")
        if isinstance(recs, list) and recs:
            parts.append("<ul>")
            for r in recs[:8]:
                parts.append(f"<li>{r}</li>")
            parts.append("</ul>")
        return "\n".join(parts) if parts else None
    except Exception:
        return None


def _read_body(html_path: Path) -> str:
    if not html_path.exists():
        return ""
    try:
        raw = html_path.read_text(encoding="utf-8", errors="ignore")
        if BeautifulSoup is None:
            # Best-effort: strip outer html/head crudely
            return raw.split("<body", 1)[-1].split(">", 1)[-1].rsplit("</body>", 1)[0]
        soup = BeautifulSoup(raw, "html.parser")
        body = soup.body or soup
        # Remove script tags to avoid client-only behaviors in PDF
        for s in body.find_all("script"):
            s.decompose()
        return body.decode()
    except Exception:
        return ""


def generate_full_combined(root: Path, results: Dict[str, Any]) -> Dict[str, str]:
    """Create a complete combined HTML by inlining all scanner HTMLs.

    Returns a dict with keys: html_full (path to HTML) and optionally pdf_full.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    target_url = results.get("url", "Unknown")
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Collect blocks per scanner
    sections: List[str] = []
    order = ["broken_access", "csrf", "sqli", "xss", "cors", "ssl_tls"]
    outputs: Dict[str, Any] = results.get("outputs", {}) if isinstance(results.get("outputs"), dict) else {}

    # Optional executive summary using AI
    ai_summary_html = _try_ai_summary(results) or ""

    for key in order:
        out = outputs.get(key)
        if not (out and isinstance(out, dict) and out.get("html")):
            continue
        html_path = Path(out["html"])  # may be relative
        try:
            body = _read_body(html_path)
            if not body:
                continue
            title = key.replace("_", " ").title()
            sections.append(
                f"""
                <section id="sect-{key}" class="scanner-section">
                  <h2>{title}</h2>
                  <div class="inlined-report">
                    {body}
                  </div>
                </section>
                """
            )
        except Exception:
            continue

    # Build a minimal, printable wrapper
    style = """
    body { font-family: Segoe UI, Tahoma, Arial, sans-serif; color:#333; }
    header { padding: 12px 0 18px; border-bottom: 2px solid #ddd; margin-bottom: 18px; }
    h1 { margin: 0 0 6px; }
    .meta { color:#666; font-size: 12px; }
    nav.toc { background:#f7f7f9; border:1px solid #eee; padding:10px; margin: 10px 0 20px; }
    nav.toc a { text-decoration:none; color:#0366d6; }
    section.scanner-section { page-break-before: always; margin-top: 20px; }
    section.scanner-section h2 { border-left: 4px solid #667eea; padding-left: 8px; }
    .inlined-report { margin-top: 8px; }
    .exec-summary { background:#f0f7ff; border:1px solid #d8e8ff; padding:12px; margin:12px 0; }
    """

    # Table of contents
    toc_items = []
    for key in order:
        out = outputs.get(key)
        if out and isinstance(out, dict) and out.get("html"):
            title = key.replace("_", " ").title()
            toc_items.append(f"<li><a href=\"#sect-{key}\">{title}</a></li>")

    html = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <title>Complete Security Report</title>
    <style>{style}</style>
  </head>
  <body>
    <header>
      <h1>Complete Security Report</h1>
      <div class=\"meta\">
        Target: {target_url} • Generated: {ts}
      </div>
      {f'<div class="exec-summary"><h3>Executive Summary</h3>{ai_summary_html}</div>' if ai_summary_html else ''}
    </header>
    <nav class=\"toc\">
      <strong>Contents</strong>
      <ol>
        {''.join(toc_items)}
      </ol>
    </nav>
    {''.join(sections) if sections else '<p>No detailed scanner reports available.</p>'}
  </body>
</html>
    """

    out_html = root / "index_full.html"
    out_html.write_text(html, encoding="utf-8")

    # Try to generate PDF immediately; caller may also call html_to_pdf again.
    out_pdf = out_html.with_suffix(".pdf")
    pdf_ok = html_to_pdf(out_html, out_pdf)

    result: Dict[str, str] = {"html_full": str(out_html)}
    if pdf_ok:
        result["pdf_full"] = str(out_pdf)
    return result


__all__ = ["generate_full_combined"]
