from __future__ import annotations

import os
from typing import Any, Dict, List

_AI_READY = False
_MODEL = None

def _init_ai():
    global _AI_READY, _MODEL
    if _AI_READY:
        return
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not api_key:
        _AI_READY = True
        return
    try:
        import google.generativeai as genai  # type: ignore
        genai.configure(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        # Fallback to 1.5-flash if requested model is unavailable at runtime
        try:
            _MODEL = genai.GenerativeModel(model_name)
        except Exception:
            _MODEL = genai.GenerativeModel("gemini-1.5-flash")
    except Exception:
        _MODEL = None
    finally:
        _AI_READY = True


def _summarize_text_with_ai(prompt: str) -> str | None:
    _init_ai()
    if _MODEL is None:
        return None
    try:
        resp = _MODEL.generate_content(prompt)
        # API SDK may return .text or .candidates[0].content.parts
        text = getattr(resp, "text", None)
        if not text and getattr(resp, "candidates", None):
            try:
                parts = resp.candidates[0].content.parts
                text = "".join(getattr(p, "text", "") for p in parts)
            except Exception:
                text = None
        return text or None
    except Exception:
        return None


def _build_summary_prompt(scan_results: Dict[str, Any]) -> str:
    url = scan_results.get("url", "Unknown")
    lines: List[str] = [
        "You are a security analyst. Produce a concise executive summary for a web application security scan.",
        f"Target: {url}",
        "Summarize key risks, affected areas, and high-level remediation guidance in bullet points.",
        "Avoid code blocks and overlong detail; keep under 200 words.",
        "\nFindings:" 
    ]
    outputs = scan_results.get("outputs", {}) if isinstance(scan_results.get("outputs"), dict) else {}
    for key, out in outputs.items():
        if not isinstance(out, dict):
            continue
        vulns = int(out.get("vulnerabilities_found") or 0)
        cvss_max = out.get("cvss_max")
        lines.append(f"- {key}: {vulns} findings; max CVSS: {cvss_max if cvss_max is not None else 'n/a'}")
    return "\n".join(lines)


def generate_ai_summary(scan_results: Dict[str, Any]):
    """Generate a short executive summary and simple recommendations with Gemini if available."""
    prompt = _build_summary_prompt(scan_results)
    text = _summarize_text_with_ai(prompt)
    if not text:
        return {
            "summary": "Automated scan completed. Review module reports for details.",
            "recommendations": [
                "Prioritize remediation of High and Medium risk findings.",
                "Implement input validation, output encoding, and least privilege.",
            ],
        }
    # Simple split of recommendations if present; else generic
    recs: List[str] = []
    for line in text.splitlines():
        s = line.strip("- •\t ")
        if not s:
            continue
        recs.append(s)
    # Keep first few lines as bullets, and one-liner summary as first sentence
    summary = recs[0] if recs else "Security assessment summary available."
    bullets = recs[:6] if recs else [
        "Review detailed reports per scanner module.",
        "Address high-risk items first and add tests to prevent regressions.",
    ]
    return {"summary": summary, "recommendations": bullets}


def generate_detailed_recommendations(vulnerabilities: List[Dict[str, Any]]):
    """Optionally produce actionable recommendations. Fallback to static tips."""
    if not vulnerabilities:
        return {"recommendations": ["No vulnerabilities provided."]}
    # Build a short prompt from vuln names
    cats = {}
    for v in vulnerabilities[:50]:
        t = (v.get("issue") or v.get("type") or "").lower()
        if not t:
            continue
        cats[t] = cats.get(t, 0) + 1
    top = ", ".join(f"{k}({n})" for k, n in list(cats.items())[:8]) or "general"
    prompt = (
        "Provide 4-6 concise, actionable security hardening recommendations tailored to: "
        + top + ". Use short bullet points."
    )
    text = _summarize_text_with_ai(prompt)
    if not text:
        return {
            "recommendations": [
                "Enable Content Security Policy (CSP) and secure headers.",
                "Use parameterized queries and input validation.",
                "Implement robust authentication and authorization checks.",
                "Add automated security tests to CI/CD.",
            ]
        }
    recs: List[str] = []
    for line in text.splitlines():
        s = line.strip("- •\t ")
        if s:
            recs.append(s)
    return {"recommendations": recs[:8] or [text.strip()[:250]]}
