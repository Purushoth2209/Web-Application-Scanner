def test_force_browse(base_url, session):
    endpoints = ["/admin", "/config", "/debug", "/private"]
    results = []
    for ep in endpoints:
        try:
            res = session.get(base_url + ep)
            if res.status_code == 200:
                results.append({"url": base_url+ep, "vulnerable": True})
        except:
            continue
    return results
