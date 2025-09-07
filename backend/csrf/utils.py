from urllib.parse import urlparse


def parse_domain(url: str) -> str:
    return urlparse(url).hostname or "target"
