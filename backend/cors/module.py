from pathlib import Path
import json, time, random, string, os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from reports.unified import render_report

COMMON_ORIGINS = [
    "http://evil.com",
    "http://malicious.example",
    "http://localhost:3000",
    "http://127.0.0.1:8080",
]

SENSITIVE_METHODS = {"PUT", "DELETE", "PATCH"}
SENSITIVE_HEADERS = {"authorization", "x-api-key"}

HTML_TEMPLATE = None  # Legacy placeholder (unused)

MITIGATIONS = {
    "wildcard_credentials": "Never use Access-Control-Allow-Origin: * with credentials; specify explicit trusted origins.",
    "reflected_origin": "Validate the Origin header against an allowlist before echoing it.",
    "missing_vary": "Add 'Vary: Origin' when dynamically setting Access-Control-Allow-Origin.",
    "over_permissive_methods": "Restrict Access-Control-Allow-Methods to only required methods.",
    "over_permissive_headers": "Do not expose Authorization or sensitive headers via Access-Control-Allow-Headers.",
    "allow_all_origins": "Avoid wildcard; list only trusted origins.",
}


def _rand_origin():
    token = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
    return f"http://{token}.attacker.site"


def _fetch(url: str, origin: str, timeout_sec: float = 3.5):
    try:
        return requests.get(url, timeout=timeout_sec, headers={"Origin": origin, "User-Agent": "WebSecScanner/1.0"})
    except Exception:
        return None


def run(url: str, out_dir: Path):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime('%Y-%m-%d_%H-%M-%S')
    site = url
    results = []

    wildcard_flag = False
    credentials_flag = False

    # Global time budget (slightly below API timeout allowance)
    MAX_TIME = float(os.getenv("CORS_SCAN_MAX_TIME", "18"))
    start = time.time()

    # 1. Baseline random origin reflection test
    rand_origin = _rand_origin()
    r_rand = _fetch(url, rand_origin, timeout_sec=4)
    if r_rand is not None:
        acao = r_rand.headers.get('Access-Control-Allow-Origin')
        acac = r_rand.headers.get('Access-Control-Allow-Credentials')
        vary = r_rand.headers.get('Vary', '')
        if acao == '*':
            wildcard_flag = True
            results.append({
                'issue': 'Wildcard Access-Control-Allow-Origin',
                'status': 'Vulnerable',
                'risk': 'Medium',
                'evidence': f"ACAO: * (random origin {rand_origin})",
                'mitigation': MITIGATIONS['allow_all_origins']
            })
        elif acao == rand_origin:
            results.append({
                'issue': 'Reflected Origin without validation',
                'status': 'Vulnerable',
                'risk': 'High',
                'evidence': f"ACAO echoes supplied origin {rand_origin}",
                'mitigation': MITIGATIONS['reflected_origin']
            })
            if 'Origin' not in vary:
                results.append({
                    'issue': 'Missing Vary: Origin header',
                    'status': 'Vulnerable',
                    'risk': 'Medium',
                    'evidence': 'Dynamic ACAO but Vary header lacks Origin',
                    'mitigation': MITIGATIONS['missing_vary']
                })
        if acac and acac.lower() == 'true':
            credentials_flag = True
    else:
        results.append({
            'issue': 'Baseline request failed',
            'status': 'Error',
            'risk': 'Low',
            'evidence': 'No response for random origin probe',
            'mitigation': 'Verify target availability.'
        })

    # 2. Known common permissive origins (parallelized)
    if time.time() - start < MAX_TIME:
        with ThreadPoolExecutor(max_workers=min(6, len(COMMON_ORIGINS))) as ex:
            fut_map = {ex.submit(_fetch, url, o, 3): o for o in COMMON_ORIGINS}
            for fut in as_completed(fut_map):
                if time.time() - start > MAX_TIME * 0.85:
                    break
                test_origin = fut_map[fut]
                r = fut.result()
                if not r:
                    continue
                acao = r.headers.get('Access-Control-Allow-Origin')
                acac = r.headers.get('Access-Control-Allow-Credentials')
                if acao == test_origin:
                    results.append({
                        'issue': 'Permissive reflected origin',
                        'status': 'Vulnerable',
                        'risk': 'Medium',
                        'evidence': f"Origin {test_origin} accepted (ACAO: {acao})",
                        'mitigation': MITIGATIONS['reflected_origin']
                    })
                    if acac and acac.lower() == 'true' and 'Origin' not in r.headers.get('Vary', ''):
                        results.append({
                            'issue': 'Credentials with reflected origin',
                            'status': 'Vulnerable',
                            'risk': 'High',
                            'evidence': f"ACAC: true with origin {test_origin}",
                            'mitigation': MITIGATIONS['reflected_origin']
                        })

    # 3. Preflight (OPTIONS) test for methods & headers if wildcard or reflection inferred
    if (wildcard_flag or any(x['issue'].startswith('Reflected') for x in results)) and (time.time() - start < MAX_TIME * 0.9):
        try:
            headers = {
                'Origin': rand_origin,
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'Authorization, X-Api-Key'
            }
            pre = requests.options(url, timeout=4, headers=headers)
            a_methods = pre.headers.get('Access-Control-Allow-Methods', '')
            a_headers = pre.headers.get('Access-Control-Allow-Headers', '')
            if any(m in a_methods.upper().split(',') for m in SENSITIVE_METHODS):
                results.append({
                    'issue': 'Overly permissive methods',
                    'status': 'Vulnerable',
                    'risk': 'Medium',
                    'evidence': f"ACAM includes: {a_methods}",
                    'mitigation': MITIGATIONS['over_permissive_methods']
                })
            if any(h.strip().lower() in SENSITIVE_HEADERS for h in a_headers.split(',')):
                results.append({
                    'issue': 'Sensitive headers exposed',
                    'status': 'Vulnerable',
                    'risk': 'Medium',
                    'evidence': f"ACAH includes: {a_headers}",
                    'mitigation': MITIGATIONS['over_permissive_headers']
                })
            if wildcard_flag and credentials_flag:
                results.append({
                    'issue': 'Wildcard with credentials',
                    'status': 'Vulnerable',
                    'risk': 'High',
                    'evidence': 'ACAO: * with ACAC: true',
                    'mitigation': MITIGATIONS['wildcard_credentials']
                })
        except Exception:
            pass

    # Summary / fallback if nothing found
    if not results:
        results.append({
            'issue': 'No obvious CORS misconfiguration',
            'status': 'Not Vulnerable',
            'risk': 'Low',
            'evidence': 'Did not detect permissive or reflective patterns',
            'mitigation': 'Maintain explicit origin allowlist and avoid credentialed wildcards.'
        })

    elapsed = time.time() - start
    summary_text = f"Total findings: {len(results)} (vulnerabilities: {sum(1 for r in results if r['status']=='Vulnerable')}) | Elapsed: {elapsed:.2f}s"

    safe_name = site.replace('https://','').replace('http://','').replace(':','_').replace('/','_')
    json_path = out_dir / f"{safe_name}_cors_{ts}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'site': site,
            'timestamp': ts,
            'results': results,
            'summary_text': summary_text,
        }, f, indent=2)

    html_path = json_path.with_suffix('.html')
    render_report(
        category="CORS",
        target=site,
        findings=results,
        out_html=html_path,
        summary={"total_findings": len(results), "vulnerabilities": sum(1 for r in results if r['status']=='Vulnerable')},
    )

    return {"json": str(json_path), "html": str(html_path)}
