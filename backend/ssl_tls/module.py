from __future__ import annotations
import socket, ssl, datetime, json, os
from pathlib import Path
from jinja2 import Template
from urllib.parse import urlparse

HTML_TEMPLATE = """<!doctype html><html><head><meta charset='utf-8'>
<title>SSL/TLS Configuration Report</title>
<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px;line-height:1.45}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{border:1px solid #ddd;padding:6px;text-align:left}th{background:#f4f4f4}code{background:#f7f7f7;padding:2px 4px;border-radius:3px} .sev-High{color:#b30000;font-weight:bold} .sev-Medium{color:#b36b00;font-weight:bold} .sev-Low{color:#0a6e0a;font-weight:bold}</style>
</head><body>
<h1>SSL/TLS Configuration Report</h1>
<p><strong>Target:</strong> {{ host }}:{{ port }} | <strong>Generated:</strong> {{ ts }}</p>
<p>{{ summary_text }}</p>
<h2>Vulnerabilities / Findings</h2>
<table><tr><th>Issue</th><th>Status</th><th>Risk</th><th>Evidence</th><th>Mitigation</th></tr>
{% for v in vulnerabilities %}<tr><td>{{ v.issue }}</td><td>{{ v.status }}</td><td class='sev-{{v.risk}}'>{{ v.risk }}</td><td>{{ v.evidence }}</td><td>{{ v.mitigation }}</td></tr>{% endfor %}
</table>
<h2>Protocol Support</h2>
<table><tr><th>Protocol</th><th>Supported</th></tr>
{% for p,s in protocol_support.items() %}<tr><td>{{ p }}</td><td>{{ '✅' if s else '❌' }}</td></tr>{% endfor %}
</table>
<h2>Certificate Info</h2>
<table>
<tr><th>Subject</th><td>{{ cert.subject }}</td></tr>
<tr><th>Issuer</th><td>{{ cert.issuer }}</td></tr>
<tr><th>Valid From</th><td>{{ cert.not_before }}</td></tr>
<tr><th>Valid To</th><td>{{ cert.not_after }}</td></tr>
<tr><th>Days Until Expiry</th><td>{{ cert.days_until_expiry }}</td></tr>
<tr><th>Wildcard</th><td>{{ 'Yes' if cert.wildcard else 'No' }}</td></tr>
<tr><th>Self-Signed</th><td>{{ 'Yes' if cert.self_signed else 'No' }}</td></tr>
<tr><th>Host Match</th><td>{{ 'Yes' if cert.host_match else 'No' }}</td></tr>
</table>
</body></html>"""

MITIGATIONS = {
    "expired_cert": "Renew the TLS certificate immediately.",
    "expiring_soon": "Plan certificate renewal before expiration (ideally automate).",
    "self_signed": "Use a publicly trusted CA-signed certificate (Let's Encrypt or commercial CA).",
    "wildcard_broad": "Limit wildcard certificates; prefer SAN certificates scoped to required hosts only.",
    "tls1_0": "Disable TLS 1.0 on the server; support only TLS 1.2+.",
    "tls1_1": "Disable TLS 1.1 on the server; support only TLS 1.2+.",
    "no_tls1_2": "Ensure TLS 1.2 is enabled (modern clients require it).",
    "no_tls1_3": "(Info) Enable TLS 1.3 for better security & performance if platform supports it.",
    "hostname_mismatch": "Serve a certificate whose SAN/CN matches the requested hostname.",
}

# Helper to attempt protocol handshake

def _supports_protocol(host: str, port: int, protocol: ssl._SSLMethod, timeout_sec: float) -> bool:
    ctx = ssl.SSLContext(protocol)
    # We don't verify here: only probing capability
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _fetch_cert(host: str, port: int, timeout_sec: float):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return cert


def _parse_cert(cert: dict) -> dict:
    subject = dict(x[0] for x in cert.get('subject', []))
    issuer = dict(x[0] for x in cert.get('issuer', []))
    not_before = cert.get('notBefore')
    not_after = cert.get('notAfter')
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb_dt = datetime.datetime.strptime(not_before, fmt) if not_before else None
    na_dt = datetime.datetime.strptime(not_after, fmt) if not_after else None
    now = datetime.datetime.utcnow()
    days_until = (na_dt - now).days if na_dt else None
    cn = subject.get('commonName', '')
    wildcard = cn.startswith('*.')
    self_signed = subject == issuer
    sans = []
    for ext in cert.get('subjectAltName', []):
        if ext[0].lower() == 'dns':
            sans.append(ext[1])
    return {
        'subject': cn or subject,
        'issuer': issuer.get('commonName') or issuer,
        'not_before': not_before,
        'not_after': not_after,
        'days_until_expiry': days_until,
        'wildcard': wildcard,
        'self_signed': self_signed,
        'sans': sans,
    }


def _host_matches(cert_info: dict, host: str) -> bool:
    h = host.lower()
    sans = cert_info.get('sans') or []
    for name in sans:
        name = name.lower()
        if name.startswith('*.'):
            # wildcard covers one label only
            if h.split('.', 1)[-1] == name[2:]:
                return True
        elif name == h:
            return True
    cn = cert_info.get('subject')
    if isinstance(cn, str):
        if cn.startswith('*.') and h.split('.', 1)[-1] == cn[2:]:
            return True
        if cn == h:
            return True
    return False


def run(url: str, out_dir: Path):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    parsed = urlparse(url)
    host = parsed.hostname or url.split('//')[-1].split('/')[0]
    scheme = parsed.scheme or 'https'
    port = parsed.port or (443 if scheme == 'https' else 443)

    timeout_conn = float(os.getenv('SSL_TLS_TIMEOUT', '6'))
    vulnerabilities = []
    protocol_support = {}

    cert_raw = None
    cert_info = {}
    try:
        cert_raw = _fetch_cert(host, port, timeout_conn)
        cert_info = _parse_cert(cert_raw)
        cert_info['host_match'] = _host_matches(cert_info, host)
    except Exception as e:
        vulnerabilities.append({
            'issue': 'Certificate Retrieval Failed',
            'status': 'Error',
            'risk': 'Low',
            'evidence': str(e),
            'mitigation': 'Ensure port 443 reachable and proper TLS handshake possible.'
        })

    # Certificate based findings
    if cert_info:
        days = cert_info.get('days_until_expiry')
        if days is not None:
            if days < 0:
                vulnerabilities.append({
                    'issue': 'Expired Certificate', 'status': 'Vulnerable', 'risk': 'High',
                    'evidence': f"Expired {abs(days)} days ago", 'mitigation': MITIGATIONS['expired_cert']
                })
            elif days < 30:
                vulnerabilities.append({
                    'issue': 'Certificate Expiring Soon', 'status': 'Vulnerable', 'risk': 'Medium',
                    'evidence': f"Expires in {days} days", 'mitigation': MITIGATIONS['expiring_soon']
                })
        if cert_info.get('self_signed'):
            vulnerabilities.append({
                'issue': 'Self-Signed Certificate', 'status': 'Vulnerable', 'risk': 'High',
                'evidence': 'Issuer matches subject', 'mitigation': MITIGATIONS['self_signed']
            })
        if cert_info.get('wildcard') and len(cert_info.get('sans') or []) <= 1:
            vulnerabilities.append({
                'issue': 'Broad Wildcard Certificate', 'status': 'Info', 'risk': 'Low',
                'evidence': 'Wildcard used with minimal SAN entries', 'mitigation': MITIGATIONS['wildcard_broad']
            })
        if not cert_info.get('host_match'):
            vulnerabilities.append({
                'issue': 'Hostname Mismatch', 'status': 'Vulnerable', 'risk': 'High',
                'evidence': f"Host {host} not in SAN/CN", 'mitigation': MITIGATIONS['hostname_mismatch']
            })

    # Protocol support probing (fast: attempt limited set)
    # Some Python builds may disable old protocols; guard with getattr
    proto_map = [
        ('TLSv1.0', 'PROTOCOL_TLSv1'),
        ('TLSv1.1', 'PROTOCOL_TLSv1_1'),
        ('TLSv1.2', 'PROTOCOL_TLSv1_2'),
        ('TLSv1.3', 'PROTOCOL_TLS_CLIENT'),  # rely on modern negotiation
    ]
    for label, attr in proto_map:
        supports = False
        method = getattr(ssl, attr, None)
        if method is not None:
            supports = _supports_protocol(host, port, method, timeout_conn/2)
        protocol_support[label] = supports

    if protocol_support.get('TLSv1.0'):
        vulnerabilities.append({'issue': 'Deprecated TLS 1.0 Supported', 'status': 'Vulnerable', 'risk': 'Medium', 'evidence': 'Successful TLS 1.0 handshake', 'mitigation': MITIGATIONS['tls1_0']})
    if protocol_support.get('TLSv1.1'):
        vulnerabilities.append({'issue': 'Deprecated TLS 1.1 Supported', 'status': 'Vulnerable', 'risk': 'Medium', 'evidence': 'Successful TLS 1.1 handshake', 'mitigation': MITIGATIONS['tls1_1']})
    if not protocol_support.get('TLSv1.2'):
        vulnerabilities.append({'issue': 'Missing TLS 1.2 Support', 'status': 'Vulnerable', 'risk': 'High', 'evidence': 'TLS 1.2 handshake failed', 'mitigation': MITIGATIONS['no_tls1_2']})
    if not protocol_support.get('TLSv1.3'):
        vulnerabilities.append({'issue': 'No TLS 1.3 Support', 'status': 'Info', 'risk': 'Low', 'evidence': 'Negotiation did not use TLS 1.3', 'mitigation': MITIGATIONS['no_tls1_3']})

    summary_text = f"Findings: {len(vulnerabilities)} (High risk: {sum(1 for v in vulnerabilities if v['risk']=='High')})"

    safe_name = host.replace(':','_')
    json_path = out_dir / f"{safe_name}_ssl_tls_{ts}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'host': host,
            'port': port,
            'timestamp': ts,
            'vulnerabilities': vulnerabilities,
            'protocol_support': protocol_support,
            'certificate': cert_info,
            'summary_text': summary_text,
        }, f, indent=2)

    html = Template(HTML_TEMPLATE).render(host=host, port=port, ts=ts, vulnerabilities=vulnerabilities, protocol_support=protocol_support, cert=type('C',(),cert_info or {}), summary_text=summary_text)
    html_path = json_path.with_suffix('.html')
    html_path.write_text(html, encoding='utf-8')

    return {'json': str(json_path), 'html': str(html_path)}
