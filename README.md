# 🛡️ B-Secure — WebSentinel-CSRF

**Automated CSRF Vulnerability Detection & Exploitation Suite**

> 🏆 Built with ❤️ by **Team B-Secure** for Hackathons & Beyond

---

## 📌 Overview

**WebSentinel-CSRF** is a **fully automated security tool** by **Team B-Secure** designed to detect and exploit **Cross-Site Request Forgery (CSRF)** vulnerabilities.

All you need to do is **enter a site URL** — our tool takes care of the rest:

1. **Crawl** → Explore all links & subpages (static + dynamic)
2. **Detect** → Extract forms & form-like requests
3. **Extract Tokens** → Grab cookies, session IDs, JWTs from storage
4. **Attack** → Launch **basic + advanced CSRF vectors**
5. **Report** → Generate professional multi-format reports

⚡ **Hackathon WOW Factor**: Truly **URL-only, zero-config automation**, with **deep crawl + exploitation + reporting**.

---

## 🎯 Why CSRF Matters

CSRF is a **high-severity vulnerability**:

* Attacker tricks a logged-in user’s browser to perform unwanted actions.
* Example: Transfer money, change password, delete account.
* Many apps still rely on **cookies** → auto-sent with requests → exploitable.
* JWT/header-only systems resist CSRF but can still be checked.

---

## 🔥 Attack Flow (Diagram)

```mermaid
flowchart TD
    A[User enters URL] --> B[Crawler visits subpages]
    B --> C[Form Detection]
    C --> D[Extract Tokens (Cookies/JWT)]
    D --> E[Launch CSRF Attack Suite]
    E --> F[Check Responses]
    F --> G[Generate Reports (HTML, JSON, PoC)]
```

---

## 🛠️ System Architecture (Diagram)

```mermaid
graph LR
    subgraph User
        U[User enters site URL]
    end

    subgraph WebSentinel-CSRF
        C1[Crawler (Selenium + Requests)] --> F1[Form Extractor]
        F1 --> T1[Token Extractor (Cookies/JWT)]
        T1 --> A1[Attack Suite (Playwright Payloads)]
        A1 --> R1[Report Generator (Jinja2 Templates)]
    end

    U --> C1
    R1 --> O[Multi-format Reports: HTML, JSON, PoCs]
```

---

## ✨ Features

* 🔎 **Deep Crawl** → Visits internal links to detect forms
* 📝 **Form Detection** → Extracts methods, hidden inputs, params
* 🔐 **Token Extraction** → Cookies, Session IDs, JWTs
* ⚔️ **CSRF Attack Suite**:

  * Basic vectors → `<img>`, `<iframe>`, `<script>`, `<form>` auto-submit, `<meta refresh>`
  * Advanced vectors → Duplicate token replay, Method override, SameSite bypass, Referer sandbox, Subdomain bypass, Multipart abuse
* 📊 **Reports (5 files/run)**:

  * Full HTML
  * Full JSON
  * Exploited-only HTML
  * Exploited-only JSON
  * `curl` PoCs file
* 💡 **Mitigation Hints** → Clear, actionable fixes

---

## ⚙️ Installation

```bash
git clone <your-repo-link>
cd websentinel-csrf
pip install -r requirements.txt
pip install playwright
playwright install
sudo apt install chromium-browser chromium-chromedriver   # Linux
```

---

## 🚀 Usage

### 1️⃣ Auto Mode (just give URL)

```bash
python3 auto_full.py --base http://localhost:9090 --depth 2
```

### 2️⃣ With Login (Juice Shop example)

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

### 3️⃣ Suite Mode (config JSON)

```bash
python3 csrf_suite_cli.py --config config.json --out reports
```

---

## 📊 Reports

Each run generates **5 reports** in `reports/`:

```
reports/
├── target_csrf_<timestamp>.html
├── target_csrf_<timestamp>.json
├── target_csrf_<timestamp>_exploited.html
├── target_csrf_<timestamp>_exploited.json
└── target_csrf_<timestamp>_curl.txt
```

✔ **HTML** → Judge-friendly, professional layout
✔ **JSON** → Developer-ready
✔ **PoC cURL file** → Instant replay

---

## 📖 Example Snippet

```
CSRF Attack Suite Report
Generated: Aug 31, 2025 | Base: http://localhost:9090 | Actions: 3 | Vectors: 16

✅ Exploited:
- form_1 → img_get (200)
- form_1 → script_get (200)

ℹ️ Not applicable:
- form_2 → jwt_based (header auth)

Mitigations:
- Use CSRF tokens
- Enforce SameSite=strict
- Validate Origin/Referer
```

---

## 🏆 Hackathon WOW Factors

* ✅ **One-click automation** → Just URL input
* ✅ **Universal** → Static + dynamic, cookies + JWTs
* ✅ **Full attack coverage** → Basic + advanced vectors
* ✅ **Professional reporting** → HTML, JSON, PoCs, mitigations
* ✅ **Built for developers & judges** → Easy to demo + clear value

---

## ⚠️ Disclaimer

* For **educational & authorized testing only**.
* Do **NOT** run on real production apps without permission.
* Team B-Secure is not responsible for misuse.

---

🔥 With **WebSentinel-CSRF by B-Secure**, you’re not just scanning — you’re **demonstrating real-world exploits** with crystal-clear reporting and automation.
