from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup

# Lightweight heuristics & helpers added to expand BAC coverage without large time cost.

NUMERIC_MUTATIONS = [
    lambda v: str(int(v) + 1),
    lambda v: str(int(v) - 1) if int(v) > 0 else v,
    lambda v: '0',
    lambda v: str(int(v) + 10),
]


def _safe_int(val: str):
    try:
        return int(val)
    except Exception:
        return None


def extract_forms(url, session):
    forms = []
    try:
        res = session.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "lxml")
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            if action:
                full_url = urljoin(url, action)
                forms.append({"url": full_url, "method": method})
    except Exception:
        pass
    return forms


def test_idor(url, session):
    """Parameter-based IDOR checks with multiple numeric mutations."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings = []
    for param in params:
        base_val = params[param][0]
        base_int = _safe_int(base_val)
        if base_int is None:
            continue
        for mutate in NUMERIC_MUTATIONS:
            try:
                mutated = mutate(base_val)
                if mutated == base_val:
                    continue
                params[param] = mutated
                tampered_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
                res = session.get(tampered_url, timeout=4)
                body_l = res.text.lower()
                if res.status_code == 200 and 'unauthor' not in body_l and 'forbidden' not in body_l:
                    findings.append({
                        "url": tampered_url,
                        "status": "Vulnerable",
                        "risk": "High",
                        "parameter": param,
                        "details": f"Parameter {param} modified ({base_val} -> {mutated}) accepted",
                        "mitigation": "Validate object ownership server-side and use opaque identifiers."
                    })
                else:
                    findings.append({
                        "url": tampered_url,
                        "status": "Not Vulnerable",
                        "risk": "Medium",
                        "parameter": param,
                        "details": f"Modification blocked or unchanged ({base_val} -> {mutated}) (HTTP {res.status_code})",
                        "mitigation": "Validate object ownership server-side and use opaque identifiers."
                    })
            except Exception:
                continue
        # restore param for next loop
        params[param] = base_val
    if not findings:
        return [{
            "status": "No IDOR parameters found",
            "risk": "Low",
            "details": "No numeric query parameters discovered",
            "mitigation": "Use UUIDs or indirect references, enforce server-side access checks."
        }]
    return findings


def test_path_idor(url, session):
    """Attempt path segment numeric mutations ( /resource/123 -> 124 / 0 / 133 )."""
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split('/') if s]
    findings = []
    for idx, seg in enumerate(segments):
        val = _safe_int(seg)
        if val is None:
            continue
        for mutate in [val + 1, val - 1 if val > 0 else val, 0, val + 10]:
            if mutate == val:
                continue
            new_segments = segments.copy()
            new_segments[idx] = str(mutate)
            new_path = '/' + '/'.join(new_segments)
            mutated_url = urlunparse(parsed._replace(path=new_path))
            try:
                res = session.get(mutated_url, timeout=4)
                body_l = res.text.lower()
                if res.status_code == 200 and 'unauthor' not in body_l and 'forbidden' not in body_l:
                    findings.append({
                        "url": mutated_url,
                        "status": "Vulnerable",
                        "risk": "High",
                        "details": f"Path segment {seg} -> {mutate} accessible",
                        "mitigation": "Enforce authorization on object references and avoid predictable IDs."
                    })
                else:
                    findings.append({
                        "url": mutated_url,
                        "status": "Not Vulnerable",
                        "risk": "Medium",
                        "details": f"Path modification blocked ({seg}->{mutate}) (HTTP {res.status_code})",
                        "mitigation": "Enforce authorization on object references and avoid predictable IDs."
                    })
            except Exception:
                continue
    if not findings:
        return [{
            "status": "No numeric path segments",
            "risk": "Low",
            "details": "-",
            "mitigation": "Use opaque identifiers and enforce access checks."
        }]
    return findings


def test_unauthenticated_access(urls, user_session, anon_session, limit=20):
    """Check a subset of discovered URLs for accessibility without authentication."""
    results = []
    checked = 0
    for u in urls:
        if checked >= limit:
            break
        try:
            res_user = user_session.get(u, timeout=4, allow_redirects=False)
            res_anon = anon_session.get(u, timeout=4, allow_redirects=False)
            if res_user.status_code == 200:
                if res_anon.status_code == 200 and 'login' not in res_anon.text.lower():
                    results.append({
                        "url": u,
                        "status": "Vulnerable",
                        "risk": "High",
                        "details": "Accessible without authentication",
                        "mitigation": "Require authentication & enforce server-side session checks."
                    })
                elif res_anon.status_code in (401, 403):
                    results.append({
                        "url": u,
                        "status": "Not Vulnerable",
                        "risk": "Medium",
                        "details": f"Properly restricted (HTTP {res_anon.status_code})",
                        "mitigation": "Continue enforcing authentication."
                    })
                else:
                    results.append({
                        "url": u,
                        "status": "Info",
                        "risk": "Low",
                        "details": f"Ambiguous unauth response (HTTP {res_anon.status_code})",
                        "mitigation": "Verify access control for this endpoint."
                    })
            checked += 1
        except Exception:
            continue
    if not results:
        return [{
            "status": "No endpoints evaluated",
            "risk": "Low",
            "details": "No suitable URLs discovered or crawl empty",
            "mitigation": "Ensure application is reachable and provides protected paths."
        }]
    return results


def test_privilege(base_url, session, admin_creds):
    if not admin_creds:
        return [{
            "status": "Skipped", "risk": "High", "details": "No admin credentials provided",
            "mitigation": "Enforce role-based access control (RBAC) at server side."
        }]
    return [{
        "status": "Simulated", "risk": "High", "details": "Privilege escalation test placeholder",
        "mitigation": "Enforce role-based access control (RBAC) at server side."
    }]


def test_directory(base_url, session):
    payloads = ["../etc/passwd", "../../admin/config"]
    results = []
    for p in payloads:
        try:
            res = session.get(base_url + "/" + p, timeout=5)
            body = res.text.lower()

            if res.status_code == 200 and ("root:x:" in body or "bin/bash" in body or "administrator" in body):
                results.append({
                    "url": base_url + "/" + p, "status": "Vulnerable", "risk": "High",
                    "details": "Sensitive file content exposed",
                    "mitigation": "Sanitize user input, deny '../', enforce path whitelisting."
                })
            elif res.status_code in [403, 401]:
                results.append({
                    "url": base_url + "/" + p, "status": "Not Vulnerable", "risk": "High",
                    "details": f"Access blocked (HTTP {res.status_code})",
                    "mitigation": "Sanitize user input, deny '../', enforce path whitelisting."
                })
            else:
                results.append({
                    "url": base_url + "/" + p, "status": "Not Vulnerable", "risk": "High",
                    "details": f"No sensitive content detected (HTTP {res.status_code})",
                    "mitigation": "Sanitize user input, deny '../', enforce path whitelisting."
                })
        except Exception:
            results.append({
                "url": base_url + "/" + p, "status": "Error", "risk": "High",
                "details": "Request failed",
                "mitigation": "Sanitize user input, deny '../', enforce path whitelisting."
            })
    return results


def test_method_bypass(url, session):
    results = []
    try:
        res = session.post(url, timeout=5)
        body = res.text.lower()
        if res.status_code == 200 and not any(word in body for word in ["login", "signin", "error", "forbidden"]):
            results.append({
                "url": url,
                "method": "POST",
                "status": "Vulnerable",
                "risk": "Medium",
                "details": "Endpoint accepted POST (possible bypass)",
                "mitigation": "Restrict allowed HTTP methods, validate server-side.",
            })
        elif res.status_code == 405:
            results.append({
                "url": url,
                "method": "POST",
                "status": "Not Vulnerable",
                "risk": "Medium",
                "details": "Method Not Allowed (405)",
                "mitigation": "Restrict allowed HTTP methods, validate server-side.",
            })
        else:
            results.append({
                "url": url,
                "method": "POST",
                "status": "Not Vulnerable",
                "risk": "Medium",
                "details": f"Rejected (HTTP {res.status_code})",
                "mitigation": "Restrict allowed HTTP methods, validate server-side.",
            })
    except Exception:
        results.append({
            "url": url,
            "method": "POST",
            "status": "Error",
            "risk": "Medium",
            "details": "Request failed",
            "mitigation": "Restrict allowed HTTP methods, validate server-side.",
        })
    return results


def test_force_browse(base_url, session):
    endpoints = ["/admin", "/config", "/debug", "/private"]
    results = []
    for ep in endpoints:
        try:
            res = session.get(base_url + ep, timeout=5)
            body = res.text.lower()
            if res.status_code == 200 and ("login" not in body and "signin" not in body):
                results.append({
                    "url": base_url + ep, "status": "Vulnerable", "risk": "Medium",
                    "details": "Sensitive page accessible without login",
                    "mitigation": "Enforce authentication/authorization on all sensitive endpoints."
                })
            else:
                results.append({
                    "url": base_url + ep, "status": "Not Vulnerable", "risk": "Medium",
                    "details": f"Access blocked or redirected (HTTP {res.status_code})",
                    "mitigation": "Enforce authentication/authorization on all sensitive endpoints."
                })
        except Exception:
            results.append({
                "url": base_url + ep, "status": "Error", "risk": "Medium",
                "details": "Request failed",
                "mitigation": "Enforce authentication/authorization on all sensitive endpoints."
            })
    return results


def test_header_token(base_url, session):
    results = []
    endpoints = ["/admin", "/config", "/private"]
    for ep in endpoints:
        url = base_url + ep
        try:
            res1 = session.get(url, timeout=5)
            headers = {k: v for k, v in session.headers.items() if k.lower() != "authorization"}
            res2 = session.get(url, headers=headers, timeout=5)
            fake_headers = headers.copy()
            fake_headers["Authorization"] = "Bearer FAKE123"
            res3 = session.get(url, headers=fake_headers, timeout=5)

            if (res2.status_code == 200 and "login" not in res2.text.lower()) or \
               (res3.status_code == 200 and "login" not in res3.text.lower()):
                results.append({
                    "url": url,
                    "status": "Vulnerable",
                    "risk": "High",
                    "details": "Bypassed authorization using missing/forged token",
                    "mitigation": "Always validate tokens server-side, never trust client headers."
                })
            else:
                results.append({
                    "url": url,
                    "status": "Not Vulnerable",
                    "risk": "High",
                    "details": "Authorization header enforced",
                    "mitigation": "Always validate tokens server-side, never trust client headers."
                })
        except Exception:
            results.append({
                "url": url,
                "status": "Error",
                "risk": "High",
                "details": "Request failed",
                "mitigation": "Ensure proper error handling for auth headers."
            })
    return results


def test_cookie_manipulation(base_url, session):
    results = []
    endpoints = ["/admin", "/config"]
    for ep in endpoints:
        url = base_url + ep
        try:
            res1 = session.get(url, timeout=5)
            res2 = session.get(url, cookies={}, timeout=5)
            tampered = session.cookies.get_dict()
            for k, v in tampered.items():
                if "role" in k.lower():
                    tampered[k] = "admin"
            res3 = session.get(url, cookies=tampered, timeout=5)

            if (res2.status_code == 200 and "login" not in res2.text.lower()) or \
               (res3.status_code == 200 and "login" not in res3.text.lower()):
                results.append({
                    "url": url,
                    "status": "Vulnerable",
                    "risk": "High",
                    "details": "Cookie manipulation bypassed access",
                    "mitigation": "Do not store roles in cookies; enforce access server-side."
                })
            else:
                results.append({
                    "url": url,
                    "status": "Not Vulnerable",
                    "risk": "High",
                    "details": "Cookies required and validated",
                    "mitigation": "Do not store roles in cookies; enforce access server-side."
                })
        except Exception:
            results.append({
                "url": url,
                "status": "Error",
                "risk": "High",
                "details": "Request failed",
                "mitigation": "Ensure cookies are validated properly."
            })
    return results


def test_cors(base_url, session):
    results = []
    try:
        headers = {"Origin": "http://evil.com"}
        res = session.get(base_url, headers=headers, timeout=5)

        if (
            "access-control-allow-origin" in res.headers
            and res.headers.get("access-control-allow-origin") == "*"
        ):
            results.append({
                "url": base_url,
                "status": "Vulnerable",
                "risk": "Medium",
                "details": "CORS misconfiguration allows any origin (*)",
                "mitigation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
            })
        else:
            results.append({
                "url": base_url,
                "status": "Not Vulnerable",
                "risk": "Medium",
                "details": "CORS restricted properly",
                "mitigation": "Restrict Access-Control-Allow-Origin to trusted domains only.",
            })
    except Exception:
        results.append({
            "url": base_url,
            "status": "Error",
            "risk": "Medium",
            "details": "CORS test failed",
            "mitigation": "Ensure CORS headers are configured securely.",
        })
    return results
