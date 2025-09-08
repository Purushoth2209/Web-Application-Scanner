import sys
from pathlib import Path
import os
from typing import Optional


def run(base_url: str, payloads: str = None, dump: bool = False, crawl: bool = False) -> Optional[dict]:
    root = Path(__file__).resolve().parents[2]
    sqli_dir = root / "Web-Application-Scanner-sqli-pavi"
    if not sqli_dir.exists():
        print(f"[sqli] Source folder not found: {sqli_dir}")
        return None

    sys.path.insert(0, str(sqli_dir))
    cwd_bak = os.getcwd()
    os.chdir(str(sqli_dir))
    try:
        import sqli as sqli_mod  # type: ignore
        argv_bak = sys.argv[:]
        try:
            args = [sys.argv[0], "-u", base_url]
            if payloads: args += ["-p", payloads]
            if dump: args += ["--dump"]
            if crawl: args += ["--crawl"]
            sys.argv = args
            sqli_mod.main()
            return {"scanner": "sqli", "status": "completed"}
        finally:
            sys.argv = argv_bak
    except Exception as e:
        print(f"[sqli] Error: {e}")
        return None
    finally:
        try:
            os.chdir(cwd_bak)
        except Exception:
            pass
        try:
            sys.path.remove(str(sqli_dir))
        except ValueError:
            pass

