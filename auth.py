import requests

def login(base_url, username, password, login_endpoint="/login"):
    session = requests.Session()
    try:
        login_url = base_url + login_endpoint
        payload = {"username": username, "password": password}
        res = session.post(login_url, data=payload)
        if res.status_code == 200:
            return session
    except:
        pass
    return session  # return session anyway for non-login sites
