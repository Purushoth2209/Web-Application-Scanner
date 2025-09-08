import sys
from pathlib import Path
import os
from typing import Optional
import sys


def run(base_url: str, depth: int = 2, out_dir: str = "reports") -> Optional[dict]:
    root = Path(__file__).resolve().parents[2]
    csrf_dir = root / "Web-Application-Scanner-csrf"
    if not csrf_dir.exists():
        print(f"[csrf] Source folder not found: {csrf_dir}")
        return None

    sys.path.insert(0, str(csrf_dir))
    # Ensure unicode-safe output on Windows consoles
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass
    cwd_bak = os.getcwd()
    os.chdir(str(csrf_dir))
    try:
        import auto_full  # type: ignore
        import csrf_suite_cli  # type: ignore
        forms, _, all_links = auto_full.crawl(base_url, depth)
        cfg = {"base_url": base_url, "actions": forms, "optional": {"visited_links": list(all_links)}}
        reports = csrf_suite_cli.run_suite(cfg, out_dir)
        return {"scanner": "csrf", "status": "completed", "reports": reports}
    except Exception as e:
        print(f"[csrf] Error: {e}")
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

