#!/usr/bin/env python3
"""
backend/app.py

Unified Security Scanner Backend with:
 - Robust CSRF compatibility shim
 - Stable imports & logging ordering
 - Consistent run_with_timeout wrapper
 - CVSS/statistics augmentation (reads scanner JSON outputs and injects cvss fields)
 - Produces web paths for frontend (/reports/...)
"""

from __future__ import annotations

import os
import sys
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

# load dotenv if present (best-effort)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# suppress noisy TLS verification warnings in backend UI logs
warnings.filterwarnings("ignore", category=UserWarning)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", os.getenv("TF_CPP_MIN_LOG_LEVEL", "3"))

# Configure logging
log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("backend.app")
logger.info("=== Starting Unified Security Scanner Backend (app.py) ===")

# ---- Import scanner modules (fail-safe) ----
# Broken Access Control (BAC)
try:
    from backend.broken_access.module import run as run_bac  # type: ignore
    from backend.broken_access.quick_scan import quick_fallback_scan  # type: ignore
    from backend.broken_access.report_generator import generate_reports as bac_generate_reports  # type: ignore
    logger.info("Loaded Broken Access Control scanner.")
except Exception as e:
    logger.warning(f"Broken Access Control scanner not available: {e}")
    run_bac = None
    quick_fallback_scan = None
    bac_generate_reports = None

def _safe_import(path: str, name: str):
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
csrf_wrapper = None
try:
    # Preferred: canonical run(url, out_dir, depth=...)
    from backend.csrf.module import run as run_csrf  # type: ignore
    csrf_wrapper = run_csrf
    logger.info("CSRF scanner 'run' found and will be used.")
except Exception as e_run:
    logger.info("CSRF module.run not found directly, attempting to build compatibility wrapper.")
    try:
        from backend.csrf import module as csrf_module  # type: ignore
        logger.info("Imported backend.csrf.module; building compatibility wrapper.")

        def _write_minimal_csrf_report(base_url: str, out_dir: Path, forms_count: int, actions: list):
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H-%M-%S")
            domain = (urlparse(base_url).hostname or "target").replace(".", "_")
            prefix = out_dir / f"{domain}_csrf_{ts}"
            data = {"base": base_url, "generated": time.ctime(), "actions": len(actions), "results": [], "exploited": []}
            try:
                with open(prefix.with_suffix(".json"), "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                html = f"<!doctype html><html><body><h1>CSRF Report - {base_url}</h1><p>Generated {data['generated']}</p><p>Actions: {len(actions)}</p></body></html>"
                with open(prefix.with_suffix(".html"), "w", encoding="utf-8") as f:
                    f.write(html)
                return str(prefix.with_suffix(".html")), str(prefix.with_suffix(".json"))
            except Exception as e:
                logger.warning(f"Failed to write minimal CSRF report: {e}")
                return None, None

        def csrf_wrapper(url, out_dir, depth=2, **kwargs):
            """
            Compatibility wrapper:
             - prefer to call run_suite(cfg, out_dir) when csrf_module exposes helpers
             - otherwise fallback to minimal placeholder report
            """
            session = None
            try:
                import requests
                session = requests.Session()
                session.headers.update({"User-Agent": "UnifiedBACCSRF/1.0"})
            except Exception:
                session = None

            links = [url]
            if hasattr(csrf_module, "crawl_site_multithread") and session:
                try:
                    links = csrf_module.crawl_site_multithread(url, session, max_depth=depth)
                except Exception as e:
                    logger.debug(f"CSRF crawl failed: {e}; falling back to base url")

            forms = []
            if hasattr(csrf_module, "extract_forms") and session:
                for l in links:
                    try:
                        forms.extend(csrf_module.extract_forms(l, session))
                    except Exception:
                        continue

            # if module offers build_csrf_cfg_from_forms & run_suite, use them
            if hasattr(csrf_module, "build_csrf_cfg_from_forms") and hasattr(csrf_module, "run_suite"):
                try:
                    cfg = csrf_module.build_csrf_cfg_from_forms(url, session, forms)
                    cfg["optional"] = cfg.get("optional", {})
                    cfg["optional"]["visited_links"] = links
                    return csrf_module.run_suite(cfg, out_dir=str(out_dir))
                except Exception as e:
                    logger.warning(f"CSRF run_suite via build_cfg failed: {e}")

            # fallback: minimal report so UI links work
            actions = [{"name": f.get("name", "form"), "url": f.get("url"), "params": f.get("params", {})} for f in forms]
            html_path, json_path = _write_minimal_csrf_report(url, Path(out_dir), len(forms), actions)
            return {"html": html_path, "json": json_path, "vulnerabilities_found": 0, "links_crawled": len(links), "forms_found": len(forms)}

        logger.info("CSRF compatibility wrapper installed.")
    except Exception as ee:
        logger.warning(f"CSRF module import failed entirely; using safe placeholder: {ee}")

        def _write_minimal_csrf_report(base_url: str, out_dir: Path):
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%Y-%m-%d_%H-%M-%S")
            domain = (urlparse(base_url).hostname or "target").replace(".", "_")
            prefix = out_dir / f"{domain}_csrf_{ts}"
            data = {"base": base_url, "generated": time.ctime(), "actions": 0, "results": [], "exploited": []}
            try:
                with open(prefix.with_suffix(".json"), "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                with open(prefix.with_suffix(".html"), "w", encoding="utf-8") as f:
                    f.write(f"<!doctype html><html><body><h1>CSRF Report - {base_url}</h1><p>Generated {data['generated']}</p></body></html>")
                return str(prefix.with_suffix(".html")), str(prefix.with_suffix(".json"))
            except Exception:
                return None, None

        def csrf_wrapper(url, out_dir, depth=2, **kwargs):
            html, js = _write_minimal_csrf_report(url, Path(out_dir))
            return {"html": html, "json": js, "vulnerabilities_found": 0, "links_crawled": 0, "forms_found": 0}

# ---- FastAPI app ----
class ScanRequest(BaseModel):
    url: str
    depth: int | None = None

class AIAnalysisRequest(BaseModel):
    scan_results: dict
    analysis_type: str = "summary"

app = FastAPI(title="AI-Enhanced Web Scanner Backend", version="2.1")

# CORS config
origins = os.getenv("ALLOWED_ORIGINS", "*")
if origins == "*":
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in origins.split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allow_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Reports directory
reports_root = Path(os.getenv("REPORTS_BASE_DIR", "reports"))
reports_root.mkdir(exist_ok=True)
app.mount("/reports", StaticFiles(directory=str(reports_root)), name="reports")
logger.info(f"Reports directory: {reports_root.resolve()}")

# ---- Helpers: CVSS & stats augmentation ----
def enhance_output_with_stats(output: dict, scanner_type: str):
    """
    Read the scanner's JSON (if present), add cvss per finding and summary stats.
    Modifies output in-place and returns it.
    """
    if not output or not isinstance(output, dict):
        return output

    stats = {"vulnerabilities_found": 0, "links_crawled": 0, "forms_found": 0, "scan_duration": output.get("scan_duration", 0)}
    cvss_scores = []
    per_finding = []
    risk_map = {"high": 8.8, "medium": 5.3, "low": 3.1, "info": 2.0, "error": 0.0}

    def assign_cvss(f: dict, default: float | None = None):
        r = (f.get("risk") or f.get("severity") or "").lower()
        score = None
        if r in risk_map:
            score = risk_map[r]
        elif default is not None:
            score = default
        t = (f.get("type") or f.get("issue") or "").lower()
        if score is None:
            if "sql" in t or t.startswith("error_based") or t.startswith("union") or t.startswith("time_based"):
                score = 9.0
            elif "xss" in t:
                score = 6.4
            elif "csrf" in t:
                score = 5.0
        if score is None:
            score = 0.0
        f["cvss"] = round(float(score), 1)
        cvss_scores.append(f["cvss"])
        per_finding.append({"issue": f.get("issue") or f.get("type"), "risk": f.get("risk"), "cvss": f["cvss"]})

    # Try to read JSON file path reported by scanner
    try:
        if output.get("json"):
            json_path = Path(output["json"])
            if json_path.exists():
                with open(json_path, "r", encoding="utf-8") as rf:
                    data = json.load(rf)
                # heuristics for counts and assignments
                if isinstance(data, dict):
                    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                        stats["vulnerabilities_found"] = len(data["vulnerabilities"])
                        for v in data["vulnerabilities"]:
                            if "cvss" not in v:
                                assign_cvss(v)
                    if "results" in data and isinstance(data["results"], list):
                        # some scanners put vulnerability info in results
                        stats["vulnerabilities_found"] = max(stats["vulnerabilities_found"], len([r for r in data["results"] if r.get("exploited") or r.get("vulnerable")]))
                        for r in data["results"]:
                            if "cvss" not in r:
                                assign_cvss(r)
                    if "links" in data and isinstance(data["links"], list):
                        stats["links_crawled"] = len(data["links"])
                    if "crawled_links" in data:
                        stats["links_crawled"] = int(data.get("crawled_links") or stats["links_crawled"] or 0)
                    if "forms" in data and isinstance(data.get("forms"), list):
                        stats["forms_found"] = len(data["forms"])
                    if "forms_found" in data:
                        stats["forms_found"] = int(data.get("forms_found") or stats["forms_found"] or 0)

                # write augmented file back (best-effort)
                try:
                    with open(json_path, "w", encoding="utf-8") as wf:
                        json.dump(data, wf, indent=2)
                except Exception:
                    pass
    except Exception as e:
        logger.debug(f"Could not enhance stats from {output.get('json')}: {e}")

    stats.setdefault("links_crawled", 0)
    stats.setdefault("forms_found", 0)
    stats.setdefault("vulnerabilities_found", 0)

    output.update(stats)
    if cvss_scores:
        output["cvss_max"] = round(max(cvss_scores), 1)
        output["cvss_avg"] = round(sum(cvss_scores) / len(cvss_scores), 1)
        output["cvss_count"] = len(cvss_scores)
        # attach sample findings
        seen = set()
        trimmed = []
        for pf in per_finding:
            key = (pf.get("issue"), pf.get("risk"))
            if key in seen:
                continue
            seen.add(key)
            trimmed.append(pf)
            if len(trimmed) >= 50:
                break
        output["cvss_findings"] = trimmed
    else:
        output["cvss_max"] = 0.0
        output["cvss_avg"] = 0.0
        output["cvss_count"] = 0

    return output

# ---- Timeout runner ----
def run_with_timeout(fn, timeout: int, scanner_name: str, **kwargs):
    logger.info(f"Starting {scanner_name} scan")
    start = time.time()
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(fn, **kwargs)
        try:
            result = fut.result(timeout=timeout)
            elapsed = time.time() - start
            logger.info(f"{scanner_name} scan completed in {elapsed:.2f}s")
            if isinstance(result, dict):
                result = enhance_output_with_stats(result, scanner_name.lower().replace(" ", "_"))
            return result
        except TimeoutError:
            logger.warning(f"{scanner_name} scan timed out after {timeout}s")
            return TimeoutError()
        except Exception as e:
            logger.error(f"{scanner_name} scan failed: {e}")
            return e

# ---- API endpoints ----
@app.post("/scan")
def scan(req: ScanRequest):
    start_time = time.time()
    target = req.url.rstrip("/")
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    reports_dir = reports_root / f"{safe_name}_{ts}"
    reports_dir.mkdir(parents=True, exist_ok=True)

    scan_depth = req.depth if req.depth is not None else int(os.getenv("DEFAULT_SCAN_DEPTH", "2"))

    results = {"url": target, "outputs": {}, "errors": {}, "scan_metadata": {}}
    results["scan_metadata"] = {
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_url": target,
        "scan_depth": scan_depth,
        "scan_id": ts
    }

    # 1) Broken Access Control
    if run_bac:
        try:
            res = run_with_timeout(run_bac, timeout=int(os.getenv("BAC_SCAN_TIMEOUT", "10")),
                                   scanner_name="Broken Access Control", url=target,
                                   out_dir=str(reports_dir / "broken_access"), depth=scan_depth)
            if isinstance(res, TimeoutError):
                logger.info("BAC timed out - trying quick fallback if available")
                if quick_fallback_scan:
                    try:
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
                    except Exception as e:
                        results["errors"]["broken_access"] = f"Timeout and fallback failed: {e}"
                else:
                    results["errors"]["broken_access"] = "Timeout and no fallback available"
            elif isinstance(res, Exception):
                results["errors"]["broken_access"] = str(res)
            else:
                results["outputs"]["broken_access"] = res
        except Exception as exc:
            results["errors"]["broken_access"] = str(exc)
    else:
        logger.warning("Broken Access Control scanner not configured; skipping")

    # 2) CSRF Protection
    try:
        csrf_res = run_with_timeout(csrf_wrapper, timeout=int(os.getenv("DEFAULT_SCAN_TIMEOUT", "60")),
                                    scanner_name="CSRF Protection", url=target, out_dir=str(reports_dir / "csrf"), depth=scan_depth)
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
        res = run_with_timeout(run_sqli, timeout=int(os.getenv("DEFAULT_SCAN_TIMEOUT", "60")),
                               scanner_name="SQL Injection", url=target, out_dir=str(reports_dir / "sqli"))
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
        res = run_with_timeout(run_xss, timeout=int(os.getenv("DEFAULT_SCAN_TIMEOUT", "60")),
                               scanner_name="XSS Protection", url=target, out_dir=str(reports_dir / "xss"))
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
        res = run_with_timeout(run_cors, timeout=int(os.getenv("CORS_SCAN_TIMEOUT", "10")),
                               scanner_name="CORS Configuration", url=target, out_dir=str(reports_dir / "cors"))
        if isinstance(res, TimeoutError):
            results["errors"]["cors"] = "Timeout - CORS analysis could not complete"
        elif isinstance(res, Exception):
            results["errors"]["cors"] = f"CORS scan error: {res}"
        else:
            results["outputs"]["cors"] = res
    else:
        logger.warning("CORS scanner not available; skipping")

    # 6) SSL/TLS (if available)
    if ssl_tls_module:
        try:
            ssl_timeout = int(os.getenv("SSL_SCAN_TIMEOUT", "30"))
            res = run_with_timeout(lambda target=target, out_dir=str(reports_dir / "ssl_tls"): ssl_tls_module.run(target, out_dir),
                                   timeout=ssl_timeout, scanner_name="SSL/TLS")
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

    # Combine reports if available
    try:
        if combine_reports:
            combined = combine_reports(reports_dir, results)
            results["outputs"]["combined"] = combined
    except Exception as e:
        results["errors"]["combined"] = f"Combine reports failed: {e}"

    # Convert available HTML -> PDF (best-effort)
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

    # Add web-accessible URLs alongside returned outputs
    def to_web(p: str) -> str | None:
        try:
            rel = Path(p).resolve().relative_to(reports_root.resolve()).as_posix()
            return f"/reports/{rel}"
        except Exception:
            return None

    for name, out in list(results["outputs"].items()):
        if isinstance(out, dict):
            for key in ["html", "pdf", "json", "html_exploited"]:
                if out.get(key):
                    web = to_web(out[key])
                    if web:
                        out[f"web_{key}"] = web

    total_duration = time.time() - start_time
    results["scan_metadata"]["total_duration"] = round(total_duration, 2)
    results["scan_metadata"]["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # summary counts
    total_vulns = 0
    total_links = 0
    successful_scans = 0
    for out in results["outputs"].values():
        if isinstance(out, dict):
            successful_scans += 1
            total_vulns += int(out.get("vulnerabilities_found", 0))
            total_links += int(out.get("links_crawled", 0))
    results["scan_metadata"]["summary"] = {
        "total_vulnerabilities": total_vulns,
        "total_links_crawled": total_links,
        "successful_scans": successful_scans,
        "failed_scans": len(results["errors"])
    }

    logger.info(f"Security assessment completed in {total_duration:.2f}s - {total_vulns} vulns, {total_links} links")

    return {"status": "ok", "reportsBase": f"/reports/{reports_dir.name}", "outputs": results["outputs"], "errors": results["errors"], "metadata": results["scan_metadata"]}

# ---- AI analysis endpoint ----
@app.post("/ai_analysis")
def ai_analysis(req: AIAnalysisRequest):
    try:
        if req.analysis_type == "summary":
            if generate_ai_summary:
                analysis = generate_ai_summary(req.scan_results)
            else:
                analysis = {"note": "AI summary not available (module missing)."}
        elif req.analysis_type == "recommendations":
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
        "environment": {"reports_dir": str(reports_root), "log_level": os.getenv("LOG_LEVEL", "INFO")},
        "features": ["real_time_scanning", "enhanced_reporting", "vulnerability_analysis", "crawler_integration"]
    }

# CLI runner
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload_flag = os.getenv("RELOAD", "False").lower() == "true"
    logger.info(f"Starting server on {host}:{port} (reload={reload_flag})")
    uvicorn.run("app:app", host=host, port=port, reload=reload_flag, log_level=os.getenv("LOG_LEVEL", "info").lower())
