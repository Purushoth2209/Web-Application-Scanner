# runner.py
import sys
from pathlib import Path
import os
from typing import Optional

def run(base_url: str, depth: int = 2, out_dir: str = "reports") -> Optional[dict]:
    """
    Attempt to run the original CSRF suite from the Web-Application-Scanner-csrf
    folder (if present). If not present or it errors, return None.

    Returns a dict like {"scanner":"csrf","status":"completed","reports": (<html>, <json>, <html_exploited>, <json_exploited>, <curl_txt>)} or None.
    """
    # We expect the repo layout to have the CSRF engine in a sibling folder
    repo_root = Path(__file__).resolve().parents[2]
    csrf_dir = repo_root / "Web-Application-Scanner-csrf"
    if not csrf_dir.exists():
        print(f"[csrf] Source folder not found: {csrf_dir}")
        return None

    # Insert csrf_dir into sys.path so imports inside that folder work
    sys.path.insert(0, str(csrf_dir))
    # Attempt to configure output encoding (best-effort)
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    cwd_bak = os.getcwd()
    os.chdir(str(csrf_dir))
    try:
        # The "auto_full" crawler and "csrf_suite_cli" runner are expected inside that folder
        import auto_full  # type: ignore
        import csrf_suite_cli  # type: ignore

        forms, _, all_links = auto_full.crawl(base_url, depth)
        cfg = {"base_url": base_url, "actions": forms, "optional": {"visited_links": list(all_links)}}
        # run_suite returns tuple (html, json, html_exploited, json_exploited, curl_txt)
        reports = csrf_suite_cli.run_suite(cfg, out_dir)
        return {"scanner": "csrf", "status": "completed", "reports": reports}
    except Exception as e:
        print(f"[csrf] Error running external csrf engine: {e}")
        return None
    finally:
        try:
            os.chdir(cwd_bak)
        except Exception:
            pass
        try:
            sys.path.remove(str(csrf_dir))
        except ValueError:
            pass
