# 📖 README.md (Final Polished Version)

```markdown
# WebSentinel+ — CSRF Attack Suite

## 🚀 Overview
WebSentinel+ is a **Cross-Site Request Forgery (CSRF) attack suite** developed for the **CTS Cybersecurity Hackathon (NPN Recruitment)**.

Unlike basic scanners that only check for missing tokens, WebSentinel+:
- Launches **all major CSRF attack vectors** automatically.
- Works on both **cookie-based apps (e.g., DVWA)** and **modern JWT/header-based apps (e.g., Juice Shop)**.
- Auto-generates **timestamped reports (HTML, JSON, cURL repro)**.
- Differentiates between:
  - ✅ **Exploitable apps** (DVWA → vulnerable to CSRF).  
  - 🛡️ **Secure-by-design apps** (Juice Shop → JWT → CSRF not applicable).

This makes WebSentinel+ both a **red-team tool** and a **compliance checker**, delivering enterprise-ready results.

---

## 🌟 Features & Wow Factor
- **Full CSRF attack simulation**: img, script, iframe, meta refresh, link, noreferrer, form post, fetch, xhr, multipart, method override, cookie-refresh.
- **Universal coverage**:  
  - Exploits cookie-based apps (shows ✅ exploited).  
  - Recognizes JWT/header apps where CSRF doesn’t apply (shows 🛡️ N/A).  
- **Professional reporting**: HTML/JSON outputs with exploited vectors and cURL reproduction commands.  
- **Enterprise readiness**: Timestamped logs, reproducible results, scalable design.  

> Judges see not just detection, but **true exploitation + validation**. No false positives.

---

## 📂 Project Structure
```

websentinel-csrf/
├── auto\_run.py          # CLI wrapper for quick scans
├── csrf\_suite\_cli.py    # Core engine (attack + reporting)
├── requirements.txt     # Dependencies
├── templates/           # Optional HTML templates
└── reports/             # Generated reports (HTML/JSON/cURL)

````

---

## ⚙️ Installation

```bash
git clone https://github.com/Nerangen/b-secure-cts.git
cd b-secure-cts
git checkout csrf
pip3 install -r requirements.txt
python3 -m playwright install chromium
````

---

## 🧪 Usage

### 🔐 DVWA (Cookie-based, vulnerable)

1. Run DVWA at `http://localhost:8080`.
2. Login → Security Level = **Low**.
3. Copy `PHPSESSID` from DevTools → Cookies.
4. Run:

```bash
set +H   # disable history expansion

python3 auto_run.py \
  --base http://localhost:8080 \
  --cookie "PHPSESSID=<PASTE>" \
  --cookies "security=low" \
  --add-post "http://localhost:8080/vulnerabilities/csrf/ password_new=test123!&password_conf=test123!&Change=Change" \
  --body-format form \
  --noreferrer \
  --exploits-only
```

✅ Report shows multiple **exploited vectors** (DVWA is vulnerable).

---

### 🛡️ Juice Shop (JWT-based, secure)

1. Run `https://juice-shop.herokuapp.com`.
2. Login → DevTools → Network → copy `Authorization: Bearer <JWT>`.
3. Export JWT and password:

```bash
export JWT='<paste-long-jwt>'
export CUR='<your-current-password>'
```

4. Run:

```bash
python3 auto_run.py \
  --base https://juice-shop.herokuapp.com \
  --auth-header "Authorization: Bearer $JWT" \
  --add-post "https://juice-shop.herokuapp.com/rest/user/change-password current=$CUR&new=Attacker123!&repeat=Attacker123!" \
  --body-format json \
  --noreferrer \
  --exploits-only
```

🛡️ Report shows **“Not applicable (JWT/header-based auth)”** (correct, no CSRF possible).

---

## 📊 Viewing Reports

Reports are saved in `reports/` with domain + timestamp.

Example:

```
reports/localhost_csrf_2025-08-30_12-30-01.html
reports/juice-shop.herokuapp.com_csrf_2025-08-30_12-35-44.json
reports/juice-shop.herokuapp.com_csrf_2025-08-30_12-35-44_curl.txt
```

View in browser:

```bash
python3 -m http.server 8000 --directory reports
# then open http://localhost:8000/
```

---

## 🛠️ Modifying for New Targets

* Use `--cookie` / `--cookies` for cookie-based apps.
* Use `--auth-header` for JWT/header apps.
* Supply one or more `--add-post` endpoints for state-changing actions (password reset, transfer, etc.).
* Set `--body-format form` or `--body-format json` depending on API.
* Add multiple `--add-post` for multiple actions.

---

## 👥 Team Workflow

* Clone repo:

```bash
git clone https://github.com/Nerangen/b-secure-cts.git
cd b-secure-cts
git checkout csrf
```

* Each member → work in their branch:

```bash
git checkout -b xss-module
git push origin xss-module
```

* Merge into `csrf` for integration.

---

## 🏆 Hackathon Demo Flow

1. **Run on DVWA** → report shows ✅ exploited CSRF vectors.
2. **Run on Juice Shop** → report shows 🛡️ N/A (secure design).
3. **Explain**:

   * “Our tool doesn’t just detect CSRF — it simulates every vector.”
   * “It exploits when possible, and avoids false positives when not applicable.”
   * “This dual mode (exploit + compliance) makes it enterprise-ready.”

---

````

---

👉 Copy this entire block into your **README.md** and push again:

```bash
nano README.md   # paste and save
git add README.md
git commit -m "Polished README for hackathon presentation"
git push origin csrf
````
