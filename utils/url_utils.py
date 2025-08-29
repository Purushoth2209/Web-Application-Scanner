from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

def parse_domain(url: str) -> str:
    u = urlparse(url)
    return (u.hostname or "target")

def default_port(scheme: str):
    return 443 if scheme == "https" else 80

def same_origin(url: str, origin: str) -> bool:
    try:
        u = urlparse(url); o = urlparse(origin)
        up = u.port or default_port(u.scheme); op = o.port or default_port(o.scheme)
        return (u.scheme == o.scheme) and (u.hostname == o.hostname) and (up == op)
    except Exception:
        return False

def same_path(a: str, b: str) -> bool:
    try:
        ua, ub = urlparse(a), urlparse(b)
        return ua.path == ub.path
    except Exception:
        return False

def build_query(url: str, params: dict) -> str:
    if not params: return url
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q.update({k: str(v) for k, v in (params or {}).items()})
    new_query = urlencode(q)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))
