"""Unified HTML report rendering utilities.

Provides a single rendering function so that all individual
vulnerability scan modules output a consistent HTML layout.
JSON outputs remain module-specific; HTML now shares a common
structure & styling.

Normalized finding schema (fields optional):
  issue / type
  location (url / endpoint / action)
  param
  payload / vector
  status (Vulnerable / Not Vulnerable / Info / Error ...)
  risk (High/Medium/Low/Info)
  evidence / details / note
  mitigation
  vulnerable (bool)
  exploited (bool)

Extra sections (e.g. protocol support, certificate info, visited urls)
can be passed via the extras dictionary.
"""
from __future__ import annotations

from pathlib import Path
from jinja2 import Template
from datetime import datetime
from typing import Iterable, Dict, Any, List

_TEMPLATE_CACHE: str | None = None


def _load_template() -> str:
    global _TEMPLATE_CACHE
    if _TEMPLATE_CACHE is None:
        tpl_path = Path(__file__).parent / "templates" / "unified_report.html"
        _TEMPLATE_CACHE = tpl_path.read_text(encoding="utf-8")
    return _TEMPLATE_CACHE


def _coalesce(*vals):
    for v in vals:
        if v not in (None, ""):
            return v
    return "-"


def normalize_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    norm: List[Dict[str, Any]] = []
    for f in findings:
        item = dict(f) if isinstance(f, dict) else {k: getattr(f, k, None) for k in dir(f)}
        issue = _coalesce(item.get("issue"), item.get("type"))
        location = _coalesce(item.get("url"), item.get("endpoint"), item.get("action"))
        param = item.get("param") or item.get("field")
        payload = _coalesce(item.get("payload"), item.get("vector"))
        status = item.get("status") or ("Vulnerable" if item.get("vulnerable") else None)
        risk = item.get("risk") or ("High" if item.get("vulnerable") else None)
        evidence = _coalesce(item.get("evidence"), item.get("details"), item.get("note"))
        mitigation = item.get("mitigation")
        vulnerable_flag = bool(item.get("vulnerable") or status == "Vulnerable" or item.get("missing_csrf"))
        exploited = bool(item.get("exploited"))
        norm.append({
            "issue": issue,
            "location": location,
            "param": param,
            "payload": payload,
            "status": status or ("Vulnerable" if vulnerable_flag else "Not Vulnerable"),
            "risk": risk or ("High" if vulnerable_flag else "Low"),
            "evidence": evidence,
            "mitigation": mitigation,
            "vulnerable": vulnerable_flag,
            "exploited": exploited,
        })
    return norm


def render_report(category: str, target: str, findings: Iterable[Dict[str, Any]], out_html: Path,
                  summary: Dict[str, Any] | None = None, extras: Dict[str, Any] | None = None,
                  timestamp: str | None = None) -> Path:
    ts = timestamp or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    norm = normalize_findings(findings)
    if summary is None:
        summary = {
            "total_findings": len(norm),
            "vulnerabilities": sum(1 for n in norm if n["vulnerable"]),
        }
    template = _load_template()
    html = Template(template).render(
        category=category,
        target=target,
        generated=ts,
        summary=summary,
        findings=norm,
        extras=extras or {},
    )
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding="utf-8")
    return out_html


__all__ = ["render_report", "normalize_findings"]
