# backend/csrf/utils.py
from urllib.parse import urlparse

def parse_domain(url: str) -> str:
    """Return safe filename-friendly domain part for use in reports."""
    try:
        p = urlparse(url)
        host = p.hostname or p.path or "target"
        return host.replace(".", "_")
    except Exception:
        return "target"
