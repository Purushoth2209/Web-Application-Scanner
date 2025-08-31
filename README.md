# 🔒 B-Secure — Automated CSRF Attack & Detection Suite

B-Secure is an automated security tool designed to **detect and exploit CSRF vulnerabilities** across **any web application** — whether it uses **cookies, JWTs, or other authentication methods**.

It crawls the target website deeply, extracts **forms and form-like endpoints**, retrieves **tokens (Cookies / JWT)**, launches **basic & advanced CSRF attack vectors**, and generates detailed reports.

---

## 🚀 Key Features

* 🌐 **Automated Crawling** — Scans all sublinks of the target site (static & dynamic).
* 📝 **Form & Endpoint Detection** — Finds all forms and form-like inputs.
* 🔑 **Token Extraction** — Retrieves Cookies and JWTs (localStorage / sessionStorage).
* 🎯 **Attack Suite** — Launches both **basic** (img/script/iframe/form) and **advanced** (samesite bypass, referer bypass, method override, duplicate token, subdomain bypass) CSRF attacks.
* 📊 **Reports** — Generates **5 files** for every run:

  * HTML (full report)
  * JSON (full raw results)
  * Exploited HTML (only successful attacks)
  * Exploited JSON (only exploited results)
  * cURL PoC file (ready-to-run Proof-of-Concept)
* 🛡️ **JWT Awareness** — Marks JWT-protected endpoints as **Not Applicable (CSRF-proof)**.
* 🤖 **Fully Automated** — Just give a **URL**, the tool does the rest.

---

## 📂 Project Structure

```
B-Secure/
│── auto_full.py          # Main orchestrator: crawling, token extraction, attack execution
│── csrf_suite_cli.py     # Core attack suite: generates payloads & reports
│── reports/              # Output directory for generated reports
│── README.md             # Documentation
```

---

## ⚡ Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/<your-repo-link>/b-secure.git
   cd b-secure
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   Required libraries include:

   * `selenium`
   * `requests`
   * `beautifulsoup4`
   * `playwright`
   * `jinja2`

3. Install browser drivers:

   ```bash
   playwright install chromium
   ```

---

## ▶️ Usage

### 1. **Basic run (public site)**

```bash
python3 auto_full.py --base https://example.com --depth 2
```

### 2. **Authenticated run (login page)**

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

For every run, **5 reports** are generated in `reports/`:

1. `site_csrf_<timestamp>.html` — Full report (all vectors).
2. `site_csrf_<timestamp>.json` — Raw JSON results.
3. `site_csrf_<timestamp>_exploited.html` — Only exploited vulnerabilities.
4. `site_csrf_<timestamp>_exploited.json` — Only exploited vulnerabilities in JSON.
5. `site_csrf_<timestamp>_curl.txt` — Ready-to-run cURL PoCs.

You can serve them locally:

```bash
python3 -m http.server 8000 --directory reports
```

Then view in your browser:
👉 [http://localhost:8000](http://localhost:8000)

---

## 🔥 Attack Flow (Diagram)

```mermaid
flowchart TD
    A[User enters URL] --> B[Crawler visits subpages]
    B --> C[Form Detection]
    C --> D["Extract Tokens (Cookies / JWT)"]
    D --> E[Launch CSRF Attack Suite]
    E --> F[Check Responses]
    F --> G[Generate Reports (HTML, JSON, PoC)]
```

---

## 🏗️ System Architecture (Diagram)

```mermaid
graph LR
    U[User enters site URL] --> C1[Crawler: Selenium + Requests]

    subgraph B-Secure
        C1 --> F1[Form Extractor]
        F1 --> T1["Token Extractor (Cookies / JWT)"]
        T1 --> A1["Attack Suite: Basic + Advanced Vectors"]
        A1 --> R1["Report Generator: Jinja2 Templates"]
    end

    R1 --> O[Outputs: HTML + JSON + Exploited + PoC (cURL)]
```

---

## 💡 Example Runs

* ✅ **DVWA (PHP session cookie)** → Exploitable → Report marks attacks as **Exploited**.
* ✅ **Juice Shop (JWT in localStorage)** → Not exploitable → Report marks as **Not Applicable (JWT)**.
* ✅ **LinkedIn / LeetCode** → No exploitable forms → Report marks as **None Exploited**.

---

## 🔮 Future Enhancements

* Support for **multi-factor login flows**.
* Integration with **BurpSuite / ZAP**.
* Automatic **report uploads (CI/CD pipelines)**.
* **Visualization dashboard** for vulnerabilities.

---

## 👨‍💻 Team

**B-Secure (Team)**

* Security-first automation
* Designed for hackathons & real-world demo
* Wow Factor ⭐ → **Fully automated, supports static/dynamic sites, JWT-aware, generates PoC automatically**

---

⚡ **B-Secure** — *One URL, Full CSRF Assessment.*

