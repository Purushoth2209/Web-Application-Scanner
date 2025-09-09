#!/usr/bin/env python3
"""
backend/app.py

Compatibility-safe FastAPI entrypoint for the Unified Security Scanner backend.

Notes:
 - Robustly imports the various scanner modules (BAC, CSRF, SQLi, XSS, CORS, SSL/TLS).
 - If the CSRF module is absent or missing the expected API, creates a safe
   placeholder that still writes minimal JSON/HTML reports so frontend links work.
 - Does not modify any other modules; it only adapts how CSRF is invoked.
"""

import os
import time
import json
import logging
import warnings
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# suppress noisy TLS verification warnings in the backend UI logs
warnings.filterwarnings("ignore", category=UserWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend.app")
logger.info("=== Starting Unified Security Scanner Backend (app.py) ===")

# ---- Import scanner modules (fail-safe) ----
# Broken Access Control (BAC)
try:
    from backend.broken_access.module import run as run_bac
    from backend.broken_access.quick_scan import quick_fallback_scan
    from backend.broken_access.report_generator import generate_reports as bac_generate_reports
    logger.info("Loaded Broken Access Control scanner.")
except Exception as e:
    logger.warning(f"Broken Access Control scanner not available: {e}")
    run_bac = None
    quick_fallback_scan = None
    bac_generate_reports = None

# SQLi, XSS, CORS
def _safe_import(path, name):
    try:
        mod = __import__(path, fromlist=[name])
        fn = getattr(mod, name)
        logger.info(f"Loaded {path}.{name}.")
        return fn
    except Exception as ee:
        logger.warning(f"Could not import {path}.{name}: {ee}")
        return None

run_sqli = _safe_import("backend.sqli.module", "run")
run_xss = _safe_import("backend.xss.module", "run")
run_cors = _safe_import("backend.cors.module", "run")

# Reports helpers
combine_reports = _safe_import("backend.reports.enhanced_combine", "combine_reports")
html_to_pdf = _safe_import("backend.reports.pdf", "html_to_pdf")
generate_ai_summary = _safe_import("backend.reports.ai_enhance", "generate_ai_summary")
generate_detailed_recommendations = _safe_import("backend.reports.ai_enhance", "generate_detailed_recommendations")

# SSL/TLS module (optional)
ssl_tls_module = None
try:
    from backend.ssl_tls import module as ssl_tls_module  # type: ignore
    logger.info("Loaded SSL/TLS module.")
except Exception as e:
    logger.warning(f"SSL/TLS module not available: {e}")
    ssl_tls_module = None

# ----- CSRF compatibility shim -----
# Try to import a canonical 'run' function (old behavior), or detect individual helpers.
csrf_wrapper = None
try:
    # first attempt: module exports run (expected signature run(url, out_dir, depth=...))
    from backend.csrf.module import run as run_csrf  # type: ignore
    csrf_wrapper = run_csrf
    logger.info("CSRF scanner 'run' found and will be used.")
except Exception as e_run:
    try:
        # import module and try to find helpers
        from backend.csrf import module as csrf_module  # type: ignore
        logger.info("Imported backend.csrf.module; creating compatibility wrapper.")
        # see what the module provides
        has_run_suite = hasattr(csrf_module, "run_suite")
        has_build_cfg = hasattr(csrf_module, "build_csrf_cfg_from_forms")
        has_extract = hasattr(csrf_module, "extract_forms")
        has_crawl = hasattr(csrf_module, "crawl_site_multithread")

        def _write_minimal_csrf_report(base_url: str, out_dir: Path, forms_count: int, actions: list):
            """
            Writes a minimal csrf JSON + HTML so frontend can link to it
            if the full run_suite isn't available.
            """
            out_dir = Path(out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H-%M-%S")
            domain = (urlparse(base_url).hostname or "target").replace(".", "_")
            prefix = out_dir / f"{domain}_csrf_{ts}"
            data = {
                "base": base_url,
                "generated": time.ctime(),
                "actions": len(actions),
                "results": [],
                "exploited": []
            }
            json_path = prefix.with_suffix(".json")
            html_path = prefix.with_suffix(".html")
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                # Minimal HTML
                html = f"""<!doctype html><html><head><meta charset="utf-8"><title>CSRF Report</title></head>
                <body><h1>CSRF Report - {base_url}</h1><p>Generated {data['generated']}</p>
                <p>Actions: {len(actions)}</p>
                <p>This is a minimal placeholder CSRF report (full scanner not available).</p></body></html>"""
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html)
                return str(html_path), str(json_path)
            except Exception as e:
                logger.warning(f"Failed to write minimal CSRF report: {e}")
                return None, None

        # build compatibility wrapper
        def csrf_wrapper(url, out_dir, depth=2, **kwargs):
            """
            Compatibility wrapper that attempts to:
              - Use run_suite if present
              - Otherwise: crawl -> extract_forms -> build_cfg -> run_suite (if available)
              - If run_suite still missing: create minimal JSON/HTML placeholder
            """
            try:
                session = __import__("requests").Session()
                session.headers.update({"User-Agent": "UnifiedBACCSRF/1.0"})
            except Exception:
                session = None

            # If module provides a direct run_suite function with expected semantics, prefer that.
            if has_run_suite:
                try:
                    # Some variants might expect different parameter names; try common ones:
                    try:
                        return csrf_module.run_suite({"base_url": url, "actions": []}, out_dir=str(out_dir))
                    except TypeError:
                        # try calling run_suite with signature (cfg, out_dir, ...)
                        pass
                except Exception:
                    # ignore and fall back to building cfg
                    pass

            links = [url]
            if has_crawl and session:
                try:
                    links = csrf_module.crawl_site_multithread(url, session, max_depth=depth)
                except Exception as e:
                    logger.warning(f"CSRF crawl failed: {e}; proceeding with base url only")

            forms = []
            if has_extract and session:
                for l in links:
                    try:
                        forms.extend(csrf_module.extract_forms(l, session))
                    except Exception:
                        continue

            # if module can build cfg and run_suite exists, try that
            if has_build_cfg and hasattr(csrf_module, "run_suite"):
                try:
                    cfg = csrf_module.build_csrf_cfg_from_forms(url, session, forms)
                    return csrf_module.run_suite(cfg, out_dir=str(out_dir))
                except Exception as e:
                    logger.warning(f"CSRF run_suite via build_cfg failed: {e}")

            # final fallback: create minimal report files (JSON + HTML) so UI links work
            actions = [{"name": f.get("name", "form"), "url": f.get("url"), "params": f.get("params", {})} for f in forms]
            html_path, json_path = _write_minimal_csrf_report(url, Path(out_dir), len(forms), actions)
            return {"html": html_path, "json": json_path, "vulnerabilities_found": 0, "links_crawled": len(links), "forms_found": len(forms)}

        logger.info("CSRF compatibility wrapper installed.")
    except Exception as ee:
        # No CSRF module available at all — provide a safe shim that writes minimal report
        logger.warning(f"CSRF module import failed; using safe placeholder: {ee}")

        def _write_minimal_csrf_report(base_url: str, out_dir: Path, forms_count: int, actions: list):
            out_dir = Path(out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H-%M-%S")
            domain = (urlparse(base_url).hostname or "target").replace(".", "_")
            prefix = out_dir / f"{domain}_csrf_{ts}"
            data = {
                "base": base_url,
                "generated": time.ctime(),
                "actions": len(actions),
                "results": [],
                "exploited": []
            }
            json_path = prefix.with_suffix(".json")
            html_path = prefix.with_suffix(".html")
            try:
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                html = f"""<!doctype html><html><head><meta charset="utf-8"><title>CSRF Report</title></head>
                <body><h1>CSRF Report - {base_url}</h1><p>Generated {data['generated']}</p>
                <p>Actions: {len(actions)}</p>
                <p>This is a minimal placeholder CSRF report (scanner not available).</p></body></html>"""
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html)
                return str(html_path), str(json_path)
            except Exception as e:
                logger.warning(f"Failed to write minimal CSRF report: {e}")
                return None, None

        def csrf_wrapper(url, out_dir, depth=2, **kwargs):
            # minimal placeholder
            html_path, json_path = _write_minimal_csrf_report(url, Path(out_dir), 0, [])
            return {"html": html_path, "json": json_path, "vulnerabilities_found": 0, "links_crawled": 0, "forms_found": 0}

# ---- end CSRF shim ----

# ---- FastAPI app ----
class ScanRequest(BaseModel):
    url: str
    depth: int | None = 2


class AIAnalysisRequest(BaseModel):
    scan_results: dict
    analysis_type: str = "summary"  # summary, recommendations, compliance


app = FastAPI(title="AI-Enhanced Web Scanner Backend", version="2.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

reports_root = Path("backend_reports")
reports_root.mkdir(exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(reports_root)), name="reports")


# small helper to wrap long-running scans with timeouts
def run_with_timeout(fn, timeout: int, scanner_name: str, **kwargs):
    logger.info(f"Starting {scanner_name} scan")
    start = time.time()
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn, **kwargs)
        try:
            result = fut.result(timeout=timeout)
            elapsed = time.time() - start
            logger.info(f"{scanner_name} scan completed in {elapsed:.2f}s")
            return result
        except TimeoutError:
            logger.warning(f"{scanner_name} scan timed out after {timeout}s")
            return TimeoutError()
        except Exception as e:
            logger.error(f"{scanner_name} scan failed: {e}")
            return e


@app.post("/scan")
def scan(req: ScanRequest):
    start_time = time.time()
    target = req.url.rstrip("/")
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    reports_dir = reports_root / (target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_") + f"_{ts}")
    reports_dir.mkdir(parents=True, exist_ok=True)

    results = {"url": target, "outputs": {}, "errors": {}, "scan_metadata": {}}
    results["scan_metadata"] = {
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_url": target,
        "scan_depth": req.depth or 2,
        "scan_id": ts
    }

    # 1) Broken Access Control
    if run_bac:
        try:
            res = run_with_timeout(run_bac, timeout=int(os.getenv("BAC_SCAN_TIMEOUT", "10")),
                                   scanner_name="Broken Access Control", url=target, out_dir=str(reports_dir / "broken_access"),
                                   depth=req.depth or 2)
            if isinstance(res, TimeoutError):
                if quick_fallback_scan:
                    fb = quick_fallback_scan(target, reports_dir / "broken_access" / "fallback")
                    if fb.get("json") and bac_generate_reports:
                        try:
                            html_full, html_ex = bac_generate_reports(fb["json"])
                            fb["html"] = html_full
                            fb["html_exploited"] = html_ex
                        except Exception:
                            pass
                    fb["timeout"] = True
                    results["outputs"]["broken_access"] = fb
                else:
                    results["errors"]["broken_access"] = "Timeout and no fallback available"
            elif isinstance(res, Exception):
                results["errors"]["broken_access"] = str(res)
            else:
                results["outputs"]["broken_access"] = res
        except Exception as e:
            results["errors"]["broken_access"] = str(e)
    else:
        logger.warning("Broken Access Control scanner not configured; skipping")

    # 2) CSRF Protection — use csrf_wrapper (defined above) — always return consistent dict
    try:
        csrf_res = run_with_timeout(csrf_wrapper, timeout=60, scanner_name="CSRF Protection",
                                    url=target, out_dir=str(reports_dir / "csrf"), depth=req.depth or 2)
        if isinstance(csrf_res, TimeoutError):
            results["errors"]["csrf"] = "Timeout - CSRF analysis could not complete"
        elif isinstance(csrf_res, Exception):
            results["errors"]["csrf"] = f"CSRF scan error: {csrf_res}"
        else:
            results["outputs"]["csrf"] = csrf_res
    except Exception as e:
        results["errors"]["csrf"] = str(e)

    # 3) SQLi
    if run_sqli:
        res = run_with_timeout(run_sqli, timeout=60, scanner_name="SQL Injection", url=target, out_dir=str(reports_dir / "sqli"))
        if isinstance(res, TimeoutError):
            results["errors"]["sqli"] = "Timeout - SQLi analysis could not complete"
        elif isinstance(res, Exception):
            results["errors"]["sqli"] = f"SQLi scan error: {res}"
        else:
            results["outputs"]["sqli"] = res
    else:
        logger.warning("SQLi scanner not available; skipping")

    # 4) XSS
    if run_xss:
        res = run_with_timeout(run_xss, timeout=60, scanner_name="XSS Protection", url=target, out_dir=str(reports_dir / "xss"))
        if isinstance(res, TimeoutError):
            results["errors"]["xss"] = "Timeout - XSS analysis could not complete"
        elif isinstance(res, Exception):
            results["errors"]["xss"] = f"XSS scan error: {res}"
        else:
            results["outputs"]["xss"] = res
    else:
        logger.warning("XSS scanner not available; skipping")

    # 5) CORS
    if run_cors:
        res = run_with_timeout(run_cors, timeout=10, scanner_name="CORS Configuration", url=target, out_dir=str(reports_dir / "cors"))
        if isinstance(res, TimeoutError):
            results["errors"]["cors"] = "Timeout - CORS analysis could not complete"
        elif isinstance(res, Exception):
            results["errors"]["cors"] = f"CORS scan error: {res}"
        else:
            results["outputs"]["cors"] = res
    else:
        logger.warning("CORS scanner not available; skipping")

    # 6) SSL/TLS — always attempt if ssl_tls_module present. The ssl module will
    # decide the right host/port to probe even if the target URL is http://.
    if ssl_tls_module:
        try:
            # Use run_with_timeout wrapper — pass the original target and the reports dir
            res = run_with_timeout(lambda target=target, reports_dir=str(reports_dir / "ssl_tls"): ssl_tls_module.run(target, reports_dir),
                                   timeout=int(os.getenv("SSL_TLS_TIMEOUT", "30")), scanner_name="SSL/TLS", target=target, reports_dir=str(reports_dir / "ssl_tls"))
            if isinstance(res, TimeoutError):
                results["errors"]["ssl_tls"] = "Timeout - SSL/TLS analysis could not complete"
            elif isinstance(res, Exception):
                results["errors"]["ssl_tls"] = f"SSL/TLS scan error: {res}"
            else:
                results["outputs"]["ssl_tls"] = res
        except Exception as e:
            results["errors"]["ssl_tls"] = str(e)
    else:
        logger.info("Skipping SSL/TLS (module missing).")

    # Combine/generate reports if available
    try:
        if combine_reports:
            combined = combine_reports(reports_dir, results)
            results["outputs"]["combined"] = combined
    except Exception as e:
        results["errors"]["combined"] = f"Combine reports failed: {e}"

    # Try to convert available HTMLs to PDF (best-effort)
    if html_to_pdf:
        for name, out in list(results["outputs"].items()):
            if isinstance(out, dict) and out.get("html"):
                try:
                    html_path = Path(out["html"]).resolve()
                    pdf_path = html_path.with_suffix(".pdf")
                    if html_to_pdf(html_path, pdf_path):
                        out["pdf"] = str(pdf_path)
                except Exception as e:
                    logger.warning(f"PDF generation failed for {name}: {e}")

    # Add web-accessible URLs
    def to_web(p: str) -> str | None:
        try:
            rel = Path(p).resolve().relative_to(reports_root.resolve()).as_posix()
            return f"/reports/{rel}"
        except Exception:
            return None

    for name, out in list(results["outputs"].items()):
        if isinstance(out, dict):
            for key in ["html", "pdf", "json"]:
                if out.get(key):
                    web = to_web(out[key])
                    if web:
                        out[f"web_{key}"] = web

    total_duration = time.time() - start_time
    results["scan_metadata"]["total_duration"] = round(total_duration, 2)
    results["scan_metadata"]["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # produce a compact response for the frontend
    return {
        "status": "ok",
        "reportsBase": f"/reports/{reports_dir.name}",
        "outputs": results["outputs"],
        "errors": results["errors"],
        "metadata": results["scan_metadata"]
    }


@app.post("/ai_analysis")
def ai_analysis(req: AIAnalysisRequest):
    try:
        if req.analysis_type == "summary":
            if generate_ai_summary:
                analysis = generate_ai_summary(req.scan_results)
            else:
                analysis = {"note": "AI summary not available (module missing)."}
        elif req.analysis_type == "recommendations":
            # collect vulnerabilities and forward to recommendation generator
            vulns = []
            for scanner, out in req.scan_results.get("outputs", {}).items():
                if isinstance(out, dict):
                    vulns.extend(out.get("vulnerabilities", []))
            if generate_detailed_recommendations:
                analysis = generate_detailed_recommendations(vulns)
            else:
                analysis = {"note": "AI recommendations not available (module missing)."}
        else:
            raise HTTPException(status_code=400, detail="Invalid analysis_type")
        return {"status": "ok", "analysis": analysis, "type": req.analysis_type}
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "2.1",
        "ai_enabled": generate_ai_summary is not None,
        "features": ["real_time_scanning", "enhanced_reporting", "vulnerability_analysis", "crawler_integration"]
    }
