from flask import Flask, render_template, request, send_file
import os
from datetime import datetime
from scanner import check_headers, save_report
 # Adjust if needed

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    report = []
    if request.method == "POST":
        url = request.form.get("url")
        if url and not url.startswith("http"):
            url = "http://" + url
        check_headers(url, report)
        save_report(report)
        return render_template("index.html", report=report)
    return render_template("index.html", report=None)

@app.route("/download")
def download_report():
    files = [f for f in os.listdir() if f.startswith("scan_report_")]
    if files:
        latest_file = max(files, key=os.path.getctime)
        return send_file(latest_file, as_attachment=True)
    return "No report found", 404

if __name__ == "__main__":
    app.run(debug=True)
