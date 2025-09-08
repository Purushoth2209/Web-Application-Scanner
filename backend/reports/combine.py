from pathlib import Path
from jinja2 import Template
from typing import Dict, Any
from datetime import datetime
from .ai_enhance import generate_ai_enhanced_index


def combine_reports(root: Path, results: dict):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    try:
        # Try AI-enhanced report generation
        target_url = results.get('url', 'Unknown')
        html_content = generate_ai_enhanced_index(root, results, target_url)
        
        idx = root / "index.html"
        idx.write_text(html_content, encoding="utf-8")
        
        return {
            "html": str(idx),
            "web_html": f"/reports/{root.name}/index.html"
        }
    except Exception:
        # Fallback to original implementation
        return combine_reports_fallback(root, results)


def combine_reports_fallback(root: Path, results: dict):
    """Original combine_reports implementation as fallback"""
    # Build normalized relative links per scanner
    links = {}
    for name, out in (results.get("outputs") or {}).items():
        href = None
        if out and isinstance(out, dict) and out.get("html"):
            p = Path(out["html"])  # may be relative
            try:
                rel = p.resolve().relative_to(root.resolve())
            except Exception:
                # fallback: strip root prefix from string
                pstr = str(p).replace("\\", "/")
                rstr = str(root).replace("\\", "/")
                if pstr.startswith(rstr):
                    rel = pstr[len(rstr):].lstrip("/")
                else:
                    rel = p.name
            href = str(rel).replace("\\", "/")
        links[name] = href

    template = """
    <html><head><title>Combined Report</title></head><body>
    <h1>Combined Report for {{url}}</h1>
    <ul>
      {% for name, href in links.items() %}
        <li>{{name}}: 
          {% if href %}
            <a href="{{ href }}">HTML</a>
          {% else %}
            failed
          {% endif %}
        </li>
      {% endfor %}
    </ul>
    </body></html>
    """
    html = Template(template).render(url=results.get("url"), links=links)
    idx = root / "index.html"
    idx.write_text(html, encoding="utf-8")
    return {"html": str(idx)}
