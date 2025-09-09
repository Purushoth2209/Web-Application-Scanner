# Backend Unified Scanner

Run multiple web vulnerability scanners (Broken Access, CSRF, SQLi, XSS) from a single CLI.

## Install dependencies

Windows PowerShell:

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python -m playwright install --with-deps
```

## Usage

- Run all scanners:
```
python backend/main.py https://target.example
```

- Run a specific scanner:
```
python backend/main.py https://target.example --scanner sqli
python backend/main.py https://target.example --scanner csrf
python backend/main.py https://target.example --scanner broken_access
python backend/main.py https://target.example --scanner xss
```

Reports are written into the original project folders (e.g., Web-Application-Scanner-*/reports).