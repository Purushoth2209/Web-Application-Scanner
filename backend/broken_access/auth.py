import requests


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecScanner/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
}


def login(base_url, username, password, login_endpoint="/login"):
    session = requests.Session()
    # Provide stable headers to reduce chance of 403 or empty responses
    session.headers.update(DEFAULT_HEADERS)
    try:
        login_url = base_url + login_endpoint
        payload = {"username": username, "password": password}
        res = session.post(login_url, data=payload, timeout=5)
        if res.status_code == 200:
            return session
    except Exception:
        pass
    return session
