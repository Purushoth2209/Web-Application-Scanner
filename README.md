# 🔒 B-Secure — Automated CSRF Attack & Detection Suite

B-Secure is an advanced security automation tool that performs **end-to-end CSRF testing** on **any website**.

Whether the site uses:

* **Public Cookies** (e.g., PHPSESSID, language cookies)
* **Session cookies** (traditional login systems like DVWA, bWAPP)
* **JWT (JSON Web Tokens)** (modern apps like OWASP Juice Shop)

B-Secure is able to:

1. **Crawl** all subpages of the target application (static & dynamic).
2. **Detect forms and form-like inputs**.
3. **Extract authentication tokens** (cookies, JWTs).
4. **Launch a wide range of CSRF attacks** (basic + advanced).
5. **Report results** clearly: exploited ✅, not exploitable ❌, or not applicable (JWT-based).

The tool generates **5 different reports per run** so you get a **full technical view, plus a simplified exploitable-only summary**.

---

## 🚀 Why B-Secure?

CSRF (Cross-Site Request Forgery) is a **critical web vulnerability** where an attacker tricks a user into making **unintended state-changing requests** on a vulnerable site.

Typical problems with CSRF testing:

* Manual testing is slow.
* Tools often miss advanced bypass techniques.
* JWT-protected apps confuse basic scanners.

👉 **B-Secure solves all these by automating everything**: crawling, token extraction, launching multiple attack vectors, and clearly marking whether a site is exploitable or protected.

---

## 📦 Features

✅ **Automated Crawler**

* Crawls deeply through all sublinks.
* Handles both static and dynamic sites.
* Detects `<form>` tags and form-like inputs.

✅ **Token Extractor**

* Retrieves cookies (`PHPSESSID`, `JSESSIONID`, `lang`, etc.).
* Retrieves JWTs from `localStorage` / `sessionStorage`.
* Works with or without login.

✅ **CSRF Attack Suite** (Basic + Advanced)

* **Basic vectors:**

  * `img_get`, `script_get`, `iframe_get`, `meta_refresh`, `link_click`, `form_post`, `xhr_post`, `fetch_post`, `multipart_post`.
* **Advanced vectors:**

  * `noreferrer_link` (Referer bypass).
  * `duplicate_token` (token reuse).
  * `samesite_refresh` (SameSite=Lax bypass).
  * `referer_bypass` (iframe sandbox trick).
  * `subdomain_bypass` (CORS trick).
  * `method_override` (`?_method=POST` abuse).

✅ **Reporting** (5 files per run):

1. Full HTML report (all vectors, all notes).
2. Full JSON (raw machine-readable results).
3. Exploited-only HTML (easy to show demo).
4. Exploited-only JSON.
5. cURL PoC file (ready-to-run exploitation commands).

✅ **JWT Awareness**

* If a site uses JWTs for authentication, report marks CSRF as **Not Applicable**.
* Explains why JWTs resist CSRF (no auto-sent cookie).

✅ **Automation**

* Only input needed: **site URL** (optionally login credentials).
* Tool does **everything else automatically**.

---

## 📂 Project Structure

```bash
B-Secure/
│── auto_full.py          # Orchestrator: crawling, token extraction, execution
│── csrf_suite_cli.py     # Attack suite: generates payloads, classifies results
│── reports/              # Output directory for generated reports
│── requirements.txt      # Dependencies
│── README.md             # Documentation
```

---

## ⚡ Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-repo-link>/b-secure.git
cd b-secure
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Libraries used:

* `selenium` → for login simulation and dynamic token extraction.
* `requests` → for crawling and fetching HTML.
* `beautifulsoup4` → for parsing forms.
* `playwright` → for simulating attacks (with headless Chromium).
* `jinja2` → for clean HTML report generation.

### 3. Install browser drivers

```bash
playwright install chromium
```

---

## ▶️ Usage

### 🔹 1. Run against a public (no-login) site

```bash
python3 auto_full.py --base https://example.com --depth 2
```

### 🔹 2. Run against a login-protected site

Example: OWASP Juice Shop (email + password login form):

```bash
python3 auto_full.py \
  --base https://juice-shop.herokuapp.com \
  --login-path /#/login \
  --username testemail123@gmail.com \
  --password password123@24 \
  --username-field "input[name='email']" \
  --password-field "input[name='password']" \
  --login-button "button#loginButton" \
  --depth 3
```

---

## 📊 Output

For every run, you get **5 outputs in `/reports/`**:

```
site_csrf_<timestamp>.html             # Full HTML report
site_csrf_<timestamp>.json             # Full JSON results
site_csrf_<timestamp>_exploited.html   # Exploited-only HTML
site_csrf_<timestamp>_exploited.json   # Exploited-only JSON
site_csrf_<timestamp>_curl.txt         # PoC cURL commands
```

👉 To serve reports locally:

```bash
python3 -m http.server 8000 --directory reports
```

Then open:
[http://localhost:8000](http://localhost:8000)

---

## 🔎 Example Results

* **DVWA (PHP session cookie):** Exploitable ✅ → Report shows multiple vectors succeeded.
* **Juice Shop (JWT):** Not exploitable ❌ → Report says “Not Applicable (JWT-based)”.
* **LinkedIn / LeetCode:** No exploitable forms → Report says “None Exploited”.

---

## 🏗️ Internal Workflow

1. **Input:** User provides site URL.
2. **Crawler:** Visits pages recursively, extracts forms & links.
3. **Token Extractor:** Collects cookies and JWTs if present.
4. **Attack Suite:** Generates CSRF vectors (basic + advanced).
5. **Execution:** Payloads executed in a headless browser.
6. **Analysis:** Responses are checked for success/failure.
7. **Report Generation:** Outputs full + exploited-only + PoC.

---

## 🔮 Future Improvements

* 🔑 Support for OAuth / 2FA-protected sites.
* 🧩 Integration with Burp/ZAP for hybrid testing.
* 📡 Dashboard view with charts & visualizations.
* CI/CD integration for DevSecOps pipelines.

---

## 👨‍💻 Team

**Team Name:** 🛡️ B-Secure

* Mission: Automate CSRF detection & exploitation.
* Hackathon Wow Factors:

  * Works on **static + dynamic** sites.
  * Handles both **Cookies & JWTs**.
  * Provides **ready PoC (cURL)** for each exploitable vector.
  * Generates **5 reports per run** → perfect for developers & pentesters.

---

## ✅ Summary

With **B-Secure**, all you need is a **URL**.
The tool will:

* Crawl → Extract Tokens → Launch Attacks → Report Results.
* Show you whether the site is **vulnerable, not exploitable, or protected by JWTs**.

⚡ **B-Secure = One URL → Full CSRF Security Report.**

