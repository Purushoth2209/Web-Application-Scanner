from __future__ import annotations

"""Lightweight HTML -> PDF conversion utility.

Uses reportlab (already in requirements) + BeautifulSoup to extract
readable text content from the generated HTML reports. This is not a
full-fidelity renderer (no CSS layout) but preserves headings, lists,
tables (as text), and paragraphs to provide an exportable PDF version
of the combined or individual vulnerability reports.

If reportlab is unavailable, the function returns False so callers can
gracefully skip PDF generation.
"""

from pathlib import Path
import re
from typing import List, Tuple

try:  # core light parsing + basic PDF
    from bs4 import BeautifulSoup  # type: ignore
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    from reportlab.lib import colors
except Exception:  # pragma: no cover - dependency issues
    BeautifulSoup = None  # type: ignore
    canvas = None  # type: ignore

# Optional higher-fidelity engines (best-effort)
_FULL_ENGINES = []
try:  # WeasyPrint (preferred)
    from weasyprint import HTML  # type: ignore
    _FULL_ENGINES.append("weasyprint")
except Exception:  # pragma: no cover
    pass
try:  # xhtml2pdf fallback
    from xhtml2pdf import pisa  # type: ignore
    _FULL_ENGINES.append("xhtml2pdf")
except Exception:  # pragma: no cover
    pass


def _wrap_text(text: str, max_chars: int = 105):
    lines: list[str] = []
    for raw in text.splitlines():
        raw = raw.rstrip()
        if not raw:
            lines.append("")
            continue
        while len(raw) > max_chars:
            # break at last space before max_chars, else hard wrap
            cut = raw.rfind(" ", 0, max_chars)
            if cut == -1 or cut < max_chars * 0.4:
                cut = max_chars
            lines.append(raw[:cut].rstrip())
            raw = raw[cut:].lstrip()
        lines.append(raw)
    return lines


def _try_full_engine(html_p: Path, pdf_p: Path) -> bool:
    """Attempt high-fidelity conversion with optional engines."""
    if not _FULL_ENGINES:
        return False
    html_str = html_p.read_text(encoding="utf-8", errors="ignore")
    for engine in _FULL_ENGINES:
        try:
            if engine == "weasyprint":
                HTML(string=html_str, base_url=str(html_p.parent)).write_pdf(str(pdf_p))  # type: ignore
                return True
            if engine == "xhtml2pdf":
                with open(str(pdf_p), "wb") as outf:  # type: ignore
                    pisa.CreatePDF(html_str, dest=outf)  # type: ignore
                return pdf_p.exists() and pdf_p.stat().st_size > 100
        except Exception:
            continue
    return False


def _collect_blocks(soup) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    # Track table rows accumulation
    current_table: List[str] = []
    def flush_table():
        nonlocal current_table
        if current_table:
            blocks.append(("table", " | ".join(current_table)))
            current_table = []
    for el in soup.find_all(["h1", "h2", "h3", "p", "li", "tr", "th", "td", "code"]):
        name = el.name.lower()
        if name in {"tr"}:
            # accumulate row text
            cells = [re.sub(r"\s+", " ", c.get_text(strip=True)) for c in el.find_all(["th","td"]) if c.get_text(strip=True)]
            if cells:
                current_table.append(" || ".join(cells))
            continue
        if name in {"th", "td"}:
            # should be handled via tr; ignore direct stray cells
            continue
        flush_table()
        txt = re.sub(r"\s+", " ", el.get_text(strip=True))
        if not txt:
            continue
        # Remove decorative leading bullets (■, ▪, ●) duplicates
        txt = re.sub(r"^(?:[■▪●]+\s*)+", "", txt).strip()
        if name in {"h1","h2","h3"}:
            blocks.append(("heading", txt))
        elif name == "li":
            blocks.append(("bullet", f"• {txt}"))
        elif name == "code":
            blocks.append(("code", txt))
        else:
            blocks.append(("para", txt))
    flush_table()
    # De-duplicate consecutive identical headings
    cleaned: List[Tuple[str,str]] = []
    for kind, text in blocks:
        if cleaned and kind == "heading" and cleaned[-1][0] == "heading" and cleaned[-1][1].lower() == text.lower():
            continue
        cleaned.append((kind, text))
    return cleaned


def html_to_pdf(html_path, pdf_path) -> bool:  # type: ignore
    html_p = Path(html_path)
    pdf_p = Path(pdf_path)
    if not html_p.exists():
        return False
    # Try high fidelity first
    if _try_full_engine(html_p, pdf_p):
        return True
    # Fallback lightweight renderer
    if BeautifulSoup is None or canvas is None:
        return False
    try:
        soup = BeautifulSoup(html_p.read_text(encoding="utf-8", errors="ignore"), "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else html_p.stem
        blocks = _collect_blocks(soup)
        # Inject vulnerability summary (if JSON present) at start
        summary_blocks: List[Tuple[str,str]] = []
        risk_map = {"high": 8.8, "medium": 5.3, "low": 3.1, "info": 2.0}
        try:
            json_candidates = list(html_p.parent.glob("*.json"))
            vulns: List[dict] = []
            for jc in json_candidates:
                if jc.stat().st_size > 2_000_000:  # skip huge
                    continue
                try:
                    import json as _json
                    data = _json.loads(jc.read_text(encoding="utf-8", errors="ignore"))
                except Exception:
                    continue
                if isinstance(data, dict):
                    if isinstance(data.get("vulnerabilities"), list):
                        for v in data["vulnerabilities"]:
                            if isinstance(v, dict):
                                vulns.append(v)
                    if isinstance(data.get("results"), list):
                        for r in data["results"]:
                            if isinstance(r, dict):
                                vulns.append(r)
                    if isinstance(data.get("tests"), list):
                        for tb in data["tests"]:
                            if isinstance(tb, dict):
                                for r in tb.get("results", []):
                                    if isinstance(r, dict):
                                        vulns.append(r)
            # deduplicate by (issue/type + url/payload)
            seen_keys = set()
            summarized = []
            for v in vulns:
                issue = v.get("issue") or v.get("type") or v.get("name") or "Vulnerability"
                risk = (v.get("risk") or v.get("severity") or ("High" if v.get("vulnerable") else "Info")).title()
                loc = v.get("url") or v.get("endpoint") or v.get("action") or v.get("path") or v.get("parameter")
                key = (issue, loc, risk)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                cvss = v.get("cvss")
                if cvss is None:
                    r_lower = risk.lower()
                    cvss = risk_map.get(r_lower, 5.0 if v.get("vulnerable") else 0.0)
                summarized.append((issue, risk, cvss, loc))
                if len(summarized) >= 60:
                    break
            if summarized:
                summary_blocks.append(("heading", "Vulnerability Summary"))
                for issue, risk, cvss, loc in summarized:
                    line = f"[CVSS {cvss:.1f}] {risk.upper()} - {issue}" + (f" (@ {loc})" if loc else "")
                    summary_blocks.append(("bullet", line))
        except Exception:
            pass
        if summary_blocks:
            blocks = summary_blocks + [("heading","Details")] + blocks
        c = canvas.Canvas(str(pdf_p), pagesize=A4)
        width, height = A4
        margin = 18 * mm
        y = height - margin
        line_height = 11

        def new_page():
            nonlocal y
            # footer page number
            c.setFont("Helvetica-Oblique", 8)
            c.setFillColor(colors.grey)
            c.drawString(margin, 10 * mm, f"Page {c.getPageNumber()}")
            c.setFillColor(colors.black)
            c.showPage()
            y = height - margin

        # Title block
        c.setFont("Helvetica-Bold", 18)
        c.drawString(margin, y, title[:120])
        y -= 26
        c.setStrokeColor(colors.darkgray)
        c.setLineWidth(0.8)
        c.line(margin, y, width - margin, y)
        y -= 14
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.grey)
        c.drawString(margin, y, f"Generated from {html_p.name}")
        c.setFillColor(colors.black)
        y -= 18

        for kind, text in blocks:
            if kind == "heading":
                c.setFont("Helvetica-Bold", 13)
                # section divider
                needed = line_height + 10
                if y - needed < margin:
                    new_page()
                c.drawString(margin, y, text[:150])
                y -= line_height + 2
                c.setStrokeColor(colors.lightgrey)
                c.setLineWidth(0.5)
                c.line(margin, y, width - margin, y)
                y -= 8
                continue
            if kind == "bullet":
                c.setFont("Helvetica", 10)
                gap = 4
            elif kind == "code":
                c.setFont("Courier", 8)
                gap = 4
            elif kind == "table":
                c.setFont("Helvetica", 8)
                gap = 6
            else:
                c.setFont("Helvetica", 9)
                gap = 7
            wrap_width = 100 if kind == "code" else 105
            lines = _wrap_text(text, wrap_width)
            needed = (len(lines) * line_height) + gap
            if y - needed < margin:
                new_page()
            for ln in lines:
                c.drawString(margin, y, ln)
                y -= line_height
                if y < margin + line_height:
                    new_page()
            y -= gap

        # Final footer on last page
        c.setFont("Helvetica-Oblique", 8)
        c.setFillColor(colors.grey)
        c.drawRightString(width - margin, 10 * mm, "Generated by B-Secure Scanner")
        c.save()
        return True
    except Exception:
        return False

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Convert HTML security report to PDF")
    ap.add_argument("html", help="Path to HTML report (index.html)")
    ap.add_argument("-o", "--output", help="Output PDF path (default: same name .pdf)")
    args = ap.parse_args()
    src = Path(args.html)
    dst = Path(args.output) if args.output else src.with_suffix(".pdf")
    ok = html_to_pdf(src, dst)
    print("SUCCESS" if ok else "FAILED", "->", dst)

__all__ = ["html_to_pdf"]
