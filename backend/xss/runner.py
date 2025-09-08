import os
import sys
from pathlib import Path
import os
from typing import Optional


def run(base_url: str, chromedriver: Optional[str] = None, headless: bool = True) -> Optional[dict]:
    root = Path(__file__).resolve().parents[2]
    xss_dir = root / "Web-Application-Scanner-purushoth"
    if not xss_dir.exists():
        print(f"[xss] Source folder not found: {xss_dir}")
        return None

    sys.path.insert(0, str(xss_dir))
    cwd_bak = os.getcwd()
    os.chdir(str(xss_dir))
    try:
        import xss_engine  # type: ignore
        import reporter  # type: ignore

        # Always use WebDriverManager for automatic version compatibility
        # XSS engine now handles ChromeDriver setup internally
        engine = xss_engine.XSSScannerEngine(headless=headless)
        try:
            report = engine.scan(base_url)
            reporter.ReportGenerator(output_dir=str(xss_dir / "reports")).save_report(report)
            return {"scanner": "xss", "status": "completed"}
        finally:
            engine.close()
    except Exception as e:
        print(f"[xss] Error: {e}")
        return None
    finally:
        try:
            os.chdir(cwd_bak)
        except Exception:
            pass
        try:
            sys.path.remove(str(xss_dir))
        except ValueError:
            pass
