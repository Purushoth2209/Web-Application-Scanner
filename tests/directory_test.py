def test_directory(base_url, session):
    payloads = ["../etc/passwd", "../../admin/config"]
    results = []
    for p in payloads:
        try:
            res = session.get(base_url + "/" + p)
            results.append({"path": p, "status": res.status_code})
        except:
            continue
    return results
