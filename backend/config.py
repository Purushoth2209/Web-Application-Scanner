"""Configuration for the Web Scanner Backend"""
import os
from pathlib import Path

# Gemini API Configuration
GEMINI_API_KEY = "AIzaSyAlbMj12IXp82EoMo4PfqPHM9hUNvmuIFo"
GEMINI_MODEL = "gemini-2.0-flash"

# Backend Configuration
BACKEND_ROOT = Path(__file__).parent
REPORTS_ROOT = BACKEND_ROOT / "backend_reports"
REPORTS_ROOT.mkdir(exist_ok=True)

# Scanner Timeouts (seconds)
TIMEOUTS = {
    "broken_access": 90,
    "csrf": 60,
    "sqli": 60,
    "xss": 60
}

# PDF Generation Settings
PDF_SETTINGS = {
    "format": "A4",
    "print_background": True,
    "margin": {"top": "1cm", "bottom": "1cm", "left": "1cm", "right": "1cm"}
}
