import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs
from collections import deque

DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_ENDPOINTS = 30


def _same_origin(base, other):
    try:
        pb = urlparse(base)
        po = urlparse(other)
        return pb.netloc == po.netloc and po.scheme in ("http", "https")
    except Exception:
        return False


def _extract_params(url):
    try:
        qs = parse_qs(urlsplit(url).query)
        # Flatten param first value only for speed
        return {k: (v[0] if isinstance(v, list) and v else "") for k, v in qs.items()}
    except Exception:
        return {}


def discover_parameters(base_url: str, max_pages: int | None = None, max_endpoints: int | None = None):
    """Lightweight parameter endpoint discovery.
    Returns list of dicts: { 'url': full_url, 'params': {..}, 'method': 'get' }
    Only GET endpoints are collected for now (fast, low impact).
    """
    max_pages = max_pages or int(os.getenv("SCAN_MAX_PAGES", DEFAULT_MAX_PAGES))
    max_endpoints = max_endpoints or int(os.getenv("SCAN_MAX_PARAM_ENDPOINTS", DEFAULT_MAX_ENDPOINTS))

    session = requests.Session()
    queue: deque[str] = deque([base_url])
    visited: set[str] = set()
    endpoints: list[dict] = []

    while queue and len(visited) < max_pages and len(endpoints) < max_endpoints:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            r = session.get(url, timeout=6)
            soup = BeautifulSoup(r.text, "lxml")
            # Collect anchors with query params
            for a in soup.find_all('a'):
                href = a.get('href')
                if not href:
                    continue
                full = urljoin(url, href)
                if not _same_origin(base_url, full):
                    continue
                params = _extract_params(full)
                if params and len(endpoints) < max_endpoints:
                    endpoints.append({"url": full.split('#')[0], "params": params, "method": "get"})
                if full not in visited and len(visited) + len(queue) < max_pages:
                    queue.append(full)
            # Collect simple GET forms
            for form in soup.find_all('form'):
                method = form.get('method', 'get').lower()
                if method != 'get':
                    continue
                action = form.get('action') or url
                full = urljoin(url, action)
                if not _same_origin(base_url, full):
                    continue
                inputs = form.find_all('input')
                params = {i.get('name'): (i.get('value') or '') for i in inputs if i.get('name')}
                if params and len(endpoints) < max_endpoints:
                    endpoints.append({"url": full.split('#')[0], "params": params, "method": "get"})
        except Exception:
            continue

    return endpoints
