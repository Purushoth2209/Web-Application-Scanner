# 📌 B-Secure ---> (Broken Access Control Scanner)

# 🔐 Broken Access Control (BAC) Scanner

This project is an **automated vulnerability scanner** focused on detecting **Broken Access Control (BAC)** issues — one of the **OWASP Top 10** vulnerabilities.

It goes beyond the basic tests (IDOR, Force Browsing) and includes **8 attack classes**, with detailed reporting, risk ratings, and mitigation guidance.

---

## 🚀 Features

- 🌍 Works on both **static and dynamic sites** (handles Angular/React SPAs with Selenium crawling).
- 🔎 Crawls the entire target site, including hidden router links.
- 🛡️ Implements **8 Broken Access Control attack classes**:
  1. **IDOR** (Insecure Direct Object References)
  2. **Privilege Escalation**
  3. **Directory Traversal**
  4. **Method Bypass**
  5. **Force Browsing**
  6. **Header / Token Tampering**
  7. **Cookie Manipulation**
  8. **CORS Misconfiguration**

- 📊 Generates two types of reports:
  - **Full Report** → all tests attempted (with status, risk, mitigations, and discovered links).
  - **Exploited-Only Report** → only vulnerabilities found, concise for quick review.

- 🗂️ Stores all reports under `/reports/<site>/<timestamp>/`.
- 🌐 Reports can be viewed in a web browser via a simple HTTP server.

---

## ⚙️ Installation

> Tested on **Ubuntu 22.04 (WSL / Linux)** with **Python 3.10+**.

### 1. Clone the repo
```bash
git clone https://github.com/Purushoth2209/Web-Application-Scanner.git
cd Web-Application-Scanner
git checkout broken_access


---

### 2. Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip chromium-browser chromium-chromedriver
pip3 install -r requirements.txt
```

*(if `requirements.txt` is missing, manually install:)*

```bash
pip3 install flask requests beautifulsoup4 selenium lxml jinja2
```

### 3. Verify Chromedriver

```bas### 2. Example CLI output

```bash
[+] Starting BAC scan on https://juice-shop.herokuapp.com at 2025-09-01_02-33-23...
[+] Crawling https://juice-shop.herokuapp.com (depth=3) ...
[+] Found 21 links total.
[+] Crawled 21 links

[+] Scan Complete
    Site: https://juice-shop.herokuapp.com
    Total Tests: 8
    Total Findings: 51
    Vulnerabilities: 8
    Risk Breakdown → High: 3 | Medium: 4 | Low: 0

    Full Report: reports/juice-shop.herokuapp.com/2025-09-01_02-33-23/bac_report.html
    Exploited-Only Report: reports/juice-shop.herokuapp.com/2025-09-01_02-33-23/bac_report_exploited.html
```

### 3. View reports

Start a simple HTTP server:

```bash
python3 -m http.server 8001 --directory reports
```

Then open [http://localhost:8001](http://localhost:8001) in your browser.

You’ll see all previous reports neatly organized by site and timestamp.

---

## 📊 Sample Report

* **Full Report** → lists all tests attempted (vulnerable + not vulnerable).
* **Exploited-Only Report** → clean summary of only confirmed vulnerabilities.

Example output:

**Force Browsing (Exploited):**

| URL        | Status     | Risk   | Details                                 | Mitigation                           |
| ---------- | ---------- | ------ | --------------------------------------- | ------------------------------------ |
| `/admin`   | Vulnerable | Medium | Sensitive page accessible without login | Enforce authentication/authorization |
| `/config`  | Vulnerable | Medium | Sensitive page accessible without login | Enforce authentication/authorization |
| `/debug`   | Vulnerable | Medium | Sensitive page accessible without login | Enforce authentication/authorization |
| `/private` | Vulnerable | Medium | Sensitive page accessible without login | Enforce authentication/authorization |

**Header / Token Tampering:**

| URL      | Status     | Risk | Details                                           | Mitigation                           |
| -------- | ---------- | ---- | ------------------------------------------------- | ------------------------------------ |
| `/admin` | Vulnerable | High | Bypassed authorization using missing/forged token | Validate tokens strictly server-side |

---

## 📂 Project Structure

```
Web-Application-Scanner/
│── auto_bac.py              # Main entrypoint (runs BAC scan)
│── bac_scanner.py           # Orchestrates tests + reporting
│── bac_tests.py             # All BAC attack modules
│── crawler.py               # Crawls site (requests + Selenium fallback)
│── auth.py                  # Login/session handling
│── report_generator.py      # Generates HTML/JSON reports
│── templates/
│    ├── report.html         # Jinja2 template for HTML reports
│── reports/                 # Generated reports (by site + timestamp)
```

---

## 🛡️ Mitigation Recommendations

Each finding includes **custom remediation advice**.
Examples:

* **IDOR** → Use UUIDs/indirect references, enforce access checks on server.
* **Privilege Escalation** → Enforce server-side RBAC.
* **Directory Traversal** → Sanitize input, deny `../`, use whitelisting.
* **Method Bypass** → Restrict allowed HTTP methods, validate server-side.
* **Force Browsing** → Authentication/authorization on all endpoints.
* **Header/Token Tampering** → Strict server-side validation of tokens.
* **Cookie Manipulation** → Do not store roles in cookies.
* **CORS Misconfig** → Restrict `Access-Control-Allow-Origin` to trusted domains.

---

## ⚡ Demo Workflow (Stepwise)

1. **Enter Target URL** in CLI:

   ```bash
   python3 auto_bac.py --base https://target.com
   ```

2. **Scanner Crawls Site**:

   * Discovers all links (including Angular/React router links).
   * Stores them in JSON under `"links_discovered"`.

3. **Runs All BAC Tests**:

   * Each attack vector is tested automatically.

4. **Generates Reports**:

   * `bac_report.html` → Full detail.
   * `bac_report_exploited.html` → Only vulnerabilities.

5. **View Reports**:

   ```bash
   python3 -m http.server 8001 --directory reports
   open http://localhost:8001
   ```

---

## 🎯 Why This Tool?

* Judges can **see proof of crawl coverage** (`links_discovered`).
* Covers **all major BAC classes** (basic + advanced).
* Reports are **professional**: risk, mitigation, summary, and per-test breakdown.
* CLI + Web UI reporting = **easy to demo**.
