from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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
                findings.append({"url": tampered_url, "vulnerable": True})
        except:
            continue
    return findings
