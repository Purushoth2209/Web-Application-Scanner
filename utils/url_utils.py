import re, urllib.parse

def parse_domain(url: str) -> str:
    u = urllib.parse.urlparse(url)
    host = u.hostname or "target"
    return re.sub(r"[^a-zA-Z0-9.\-]", "_", host)

def same_origin(url: str, origin: str) -> bool:
    u = urllib.parse.urlparse(url)
    return (u.scheme + "://" + u.hostname + (f":{u.port}" if u.port else "")) == origin

def build_query(url: str, params: dict) -> str:
    if not params: return url
    sep = "&" if urllib.parse.urlparse(url).query else "?"
    return url + sep + urllib.parse.urlencode(params)

def data_url(html: str) -> str:
    return "data:text/html;charset=utf-8," + urllib.parse.quote(html, safe=":/?&=,+-_.!~*'()#;")

def same_path(u1: str, u2: str) -> bool:
    return urllib.parse.urlparse(u1).path == urllib.parse.urlparse(u2).path
