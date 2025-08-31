from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup

# 🔹 Extract Forms
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
    except:
        pass
    return forms

# 🔹 IDOR
def test_idor(url, session):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings = []
    for param in params:
        try:
            original_val = params[param][0]
            new_val = str(int(original_val) + 1)
            params[param] = new_val
            tampered_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            res = session.get(tampered_url)

            if res.status_code == 200 and "unauthorized" not in res.text.lower():
                findings.append({
                    "url": tampered_url, "status": "Vulnerable", "risk": "High",
                    "details": f"Parameter {param} modified ({original_val} → {new_val})",
                    "mitigation": "Use UUIDs or indirect references, enforce server-side access checks."
                })
            else:
                findings.append({
                    "url": tampered_url, "status": "Not Vulnerable", "risk": "High",
                    "details": f"Access blocked for parameter {param}",
                    "mitigation": "Use UUIDs or indirect references, enforce server-side access checks."
                })
        except:
            continue
    return findings if findings else [{
        "status": "No IDOR parameters found", "risk": "Low", "details": "-",
        "mitigation": "Use UUIDs or indirect references, enforce server-side access checks."
    }]

# 🔹 Privilege Escalation
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

# 🔹 Directory Traversal
def test_directory(base_url, session):
    payloads = ["../etc/passwd", "../../admin/config"]
    results = []
    for p in payloads:
        try:
            res = session.get(base_url + "/" + p)
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
        except:
            results.append({
                "url": base_url + "/" + p, "status": "Error", "risk": "High",
                "details": "Request failed",
                "mitigation": "Sanitize user input, deny '../', enforce path whitelisting."
            })
    return results

# 🔹 Method Bypass
def test_method_bypass(url, session):
    results = []
    try:
        res = session.post(url)
        body = res.text.lower()
        if res.status_code == 200 and not any(word in body for word in ["login", "signin", "error", "forbidden"]):
            results.append({
                "url": url, "method": "POST", "status": "Vulnerable", "risk": "Medium",
                "details": "Endpoint accepted POST (possible bypass)",
                "mitigation": "Restrict allowed HTTP methods, validate server-side."
            })
        elif res.status_code == 405:
            results.append({
                "url": url, "method": "POST", "status": "Not Vulnerable", "risk": "Medium",
                "details": "Method Not Allowed (405)",
                "mitigation": "Restrict allowed HTTP methods, validate server-side."
            })
        else:
            results.append({
                "url": url, "method": "POST", "status": "Not Vulnerable", "risk": "Medium",
                "details": f"Rejected (HTTP {res.status_code})",
                "mitigation": "Restrict allowed HTTP methods, validate server-side."
            })
    except:
        results.append({
            "url": url, "method": "POST", "status": "Error", "risk": "Medium",
            "details": "Request failed",
            "mitigation": "Restrict allowed HTTP methods, validate server-side."
        })
    return results

# 🔹 Force Browsing
def test_force_browse(base_url, session):
    endpoints = ["/admin", "/config", "/debug", "/private"]
    results = []
    for ep in endpoints:
        try:
            res = session.get(base_url + ep)
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
        except:
            results.append({
                "url": base_url + ep, "status": "Error", "risk": "Medium",
                "details": "Request failed",
                "mitigation": "Enforce authentication/authorization on all sensitive endpoints."
            })
    return results
# 🔹 Header / Token Tampering
def test_header_token(base_url, session):
    results = []
    endpoints = ["/admin", "/config", "/private"]
    for ep in endpoints:
        url = base_url + ep
        try:
            # Normal request (baseline)
            res1 = session.get(url)

            # Without Authorization header
            headers = {k: v for k, v in session.headers.items() if k.lower() != "authorization"}
            res2 = session.get(url, headers=headers)

            # With fake token
            fake_headers = headers.copy()
            fake_headers["Authorization"] = "Bearer FAKE123"
            res3 = session.get(url, headers=fake_headers)

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
        except:
            results.append({
                "url": url,
                "status": "Error",
                "risk": "High",
                "details": "Request failed",
                "mitigation": "Ensure proper error handling for auth headers."
            })
    return results


# 🔹 Cookie Manipulation
def test_cookie_manipulation(base_url, session):
    results = []
    endpoints = ["/admin", "/config"]
    for ep in endpoints:
        url = base_url + ep
        try:
            # Normal request
            res1 = session.get(url)

            # Remove all cookies
            res2 = session.get(url, cookies={})

            # Tamper role=user → admin
            tampered = session.cookies.get_dict()
            for k, v in tampered.items():
                if "role" in k.lower():
                    tampered[k] = "admin"
            res3 = session.get(url, cookies=tampered)

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
        except:
            results.append({
                "url": url,
                "status": "Error",
                "risk": "High",
                "details": "Request failed",
                "mitigation": "Ensure cookies are validated properly."
            })
    return results


# 🔹 CORS Misconfiguration
def test_cors(base_url, session):
    results = []
    try:
        headers = {"Origin": "http://evil.com"}
        res = session.get(base_url, headers=headers)

        if "access-control-allow-origin" in res.headers and res.headers["access-control-allow-origin"] == "*":
            results.append({
                "url": base_url,
                "status": "Vulnerable",
                "risk": "Medium",
                "details": "CORS misconfiguration allows any origin (*)",
                "mitigation": "Restrict Access-Control-Allow-Origin to trusted domains only."
            })
        else:
            results.append({
                "url": base_url,
                "status": "Not Vulnerable",
                "risk": "Medium",
                "details": "CORS restricted properly",
                "mitigation": "Restrict Access-Control-Allow-Origin to trusted domains only."
            })
    except:
        results.append({
            "url": base_url,
            "status": "Error",
            "risk": "Medium",
            "details": "CORS test failed",
            "mitigation": "Ensure CORS headers are configured securely."
        })
    return results
