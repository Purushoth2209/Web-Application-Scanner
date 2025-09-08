import argparse
import os
import sys
import time
from pathlib import Path
from typing import List

# Allow running this file directly: python backend/main.py ...
if __package__ is None or __package__ == "":
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from broken_access.module import run as run_bac
from csrf.module import run as run_csrf
from sqli.module import run as run_sqli
from xss.module import run as run_xss


def _out_base(url: str) -> Path:
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    safe = url.replace("https://", "").replace("http://", "").replace(":", "_").replace("/", "_")
    base = Path("backend_reports") / f"cli_{safe}_{ts}"
    base.mkdir(parents=True, exist_ok=True)
    return base


def run_all(url: str) -> None:
    out = _out_base(url)
    results = []
    try:
        results.append({"scanner": "broken_access", **(run_bac(url, out_dir=out / "broken_access", depth=2) or {})})
    except Exception as e:
        results.append({"scanner": "broken_access", "status": f"failed: {e}"})
    try:
        results.append({"scanner": "csrf", **(run_csrf(url, out_dir=out / "csrf", depth=2) or {})})
    except Exception as e:
        results.append({"scanner": "csrf", "status": f"failed: {e}"})
    try:
        results.append({"scanner": "sqli", **(run_sqli(url, out_dir=out / "sqli") or {})})
    except Exception as e:
        results.append({"scanner": "sqli", "status": f"failed: {e}"})
    try:
        results.append({"scanner": "xss", **(run_xss(url, out_dir=out / "xss") or {})})
    except Exception as e:
        results.append({"scanner": "xss", "status": f"failed: {e}"})

    print("\n=== Summary ===")
    for r in results:
        print(f"- {r.get('scanner')}: {('ok' if 'html' in r or 'json' in r else r.get('status','done'))}")


def main(argv: List[str] = None) -> None:
    p = argparse.ArgumentParser(description="Unified Web App Scanners")
    p.add_argument("url", help="Target base URL (e.g., https://example.com)")
    p.add_argument("--scanner", choices=["broken_access", "csrf", "sqli", "xss", "all"], default="all", help="Which scanner to run")
    args = p.parse_args(argv)

    out = _out_base(args.url)
    if args.scanner == "broken_access":
        run_bac(args.url, out_dir=out / "broken_access", depth=2)
    elif args.scanner == "csrf":
        run_csrf(args.url, out_dir=out / "csrf", depth=2)
    elif args.scanner == "sqli":
        run_sqli(args.url, out_dir=out / "sqli")
    elif args.scanner == "xss":
        run_xss(args.url, out_dir=out / "xss")
    else:
        run_all(args.url)


if __name__ == "__main__":
    main()
