import time
import json
from pathlib import Path
from jinja2 import Template
from .utils import parse_domain
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

# Lightweight adapters to reuse original engine if available
def _import_csrf_suite_cli():
    try:
        from csrf import runner as _runner
        root = Path(__file__).resolve().parents[2] / "Web-Application-Scanner-csrf"
        if root.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("csrf_suite_cli", root / "csrf_suite_cli.py")
            mod = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(mod)  # type: ignore
            return mod
    except Exception:
        pass
    return None

def _import_auto_full():
    try:
        root = Path(__file__).resolve().parents[2] / "Web-Application-Scanner-csrf"
        if root.exists():
            import importlib.util
            spec = importlib.util.spec_from_file_location("auto_full", root / "auto_full.py")
            mod = importlib.util.module_from_spec(spec)
            assert spec and spec.loader
            spec.loader.exec_module(mod)  # type: ignore
            return mod
    except Exception:
        pass
    return None


def run(url: str, out_dir: Path, depth: int = 2):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    domain = parse_domain(url)

    suite = _import_csrf_suite_cli()
    auto = _import_auto_full()

    if suite and auto:
        # Use original dynamic crawler + suite for richer output
        forms, _, all_links = auto.crawl(url, depth)
        cfg = {"base_url": url, "actions": forms, "optional": {"visited_links": all_links}}
        html, jsonp, html_exp, json_exp, curl = suite.run_suite(cfg, str(out_dir))
        # Return paths expected by the API/frontend
        return {"json": str(jsonp), "html": str(html), "html_exploited": str(html_exp)}

    # Fallback simple heuristic scan: enumerate forms & flag missing CSRF token indicators
    results = []
    try:
        session = requests.Session()
        r = session.get(url, timeout=8)
        soup = BeautifulSoup(r.text, "lxml")
        forms = soup.find_all("form")
        for idx, form in enumerate(forms, start=1):
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            hidden_names = [i.get("name", "").lower() for i in inputs if i.get("type") == "hidden"]
            has_token = any("csrf" in n or "token" in n for n in hidden_names)
            action = form.get("action") or url
            full_action = action if action.startswith("http") else url.rstrip('/') + '/' + action.lstrip('/')
            results.append({
                "action": full_action,
                "method": method,
                "vector": "form_post" if method == "post" else "form_get",
                "missing_csrf": (method == "post" and not has_token),
                "status": 200,
                "exploited": False,
                "note": "Missing CSRF token" if (method == "post" and not has_token) else "Token present or not required"
            })
    except Exception as e:
        results.append({
            "action": url,
            "method": "get",
            "vector": "page",
            "status": 0,
            "exploited": False,
            "note": f"Enumeration error: {e}",
        })
    json_out = out_dir / f"{domain}_csrf_{ts}.json"
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "base_url": url, "results": results, "exploited": []}, f, indent=2)

    template = (Path(__file__).parent / "templates" / "csrf_report.html").read_text(encoding="utf-8")
    html_out = out_dir / f"{domain}_csrf_{ts}.html"
    with open(html_out, "w", encoding="utf-8") as f:
        f.write(Template(template).render(
            generated=time.strftime("%Y-%m-%d %H:%M:%S"),
            base_url=url, actions_count=1, total_vectors=len(results), results=results, exploited=[]
        ))
    return {"json": str(json_out), "html": str(html_out)}
