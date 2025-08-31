from flask import Flask, render_template, request
from bac_scanner import run_bac_scan
from report_generator import generate_html_report

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    base_url = request.form["url"]
    user = request.form["user"]
    passwd = request.form["passwd"]
    admin = request.form.get("admin")
    admin_pass = request.form.get("admin_pass")

    user_creds = {"username": user, "password": passwd}
    admin_creds = {"username": admin, "password": admin_pass} if admin and admin_pass else None

    json_report = run_bac_scan(base_url, user_creds, admin_creds)
    html_report = generate_html_report(json_report)

    return f"Scan complete! Report: <a href='/{html_report}' target='_blank'>View Report</a>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001, debug=True)
