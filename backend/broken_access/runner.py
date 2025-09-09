import sys
from pathlib import Path
import os
from typing import Optional


def run(base_url: str, depth: int = 3) -> Optional[dict]:
    """Run the Broken Access Control scanner against base_url."""
    root = Path(__file__).resolve().parents[2]
    bac_dir = root / "Web-Application-Scanner-broken_access"
    if not bac_dir.exists():
        print(f"[broken_access] Source folder not found: {bac_dir}")
        return None

    sys.path.insert(0, str(bac_dir))
    cwd_bak = os.getcwd()
    os.chdir(str(bac_dir))
    try:
        # First try the CLI-style main which writes reports and prints a summary
        import auto_bac  # type: ignore
        argv_bak = sys.argv[:]
        try:
            sys.argv = [sys.argv[0], "--base", base_url, "--depth", str(depth)]
            auto_bac.main()
            return {"scanner": "broken_access", "status": "completed"}
        finally:
            sys.argv = argv_bak
    except Exception as e:
        # Fallback: directly call core functions if available
        try:
            import bac_scanner  # type: ignore
            import report_generator  # type: ignore
            json_report = bac_scanner.run_bac_scan(base_url, user_creds={"username": "dummy", "password": "dummy"}, max_depth=depth)
            if json_report:
                report_generator.generate_reports(json_report)
                return {"scanner": "broken_access", "status": "completed"}
        except Exception as ie:
            print(f"[broken_access] Error: {ie}")
            return None
    finally:
        try:
            os.chdir(cwd_bak)
        except Exception:
            pass
        # Remove the path we added to avoid polluting importer state for others
        try:
            sys.path.remove(str(bac_dir))
        except ValueError:
            pass

