def test_method_bypass(url, session):
    results = []
    try:
        res = session.post(url)
        results.append({"url": url, "method": "POST", "status": res.status_code})
    except:
        pass
    return results
