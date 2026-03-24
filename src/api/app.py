"""GuardAI Web API and Dashboard."""
import os
import json
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.engine import GuardAIEngine
from src.email_service import store_inbound, get_unread, get_all_messages, mark_all_read, send_email

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "static"),
)

engine = GuardAIEngine()

# In-memory scan history (replace with DB later)
scan_history = []


@app.route("/")
def index():
    return render_template("dashboard.html", scans=scan_history)


@app.route("/scan", methods=["POST"])
def scan_code():
    """Scan code submitted via form or API."""
    # Handle JSON API requests
    if request.is_json:
        data = request.get_json()
        code = data.get("code", "")
        filename = data.get("filename", "untitled.py")
    else:
        code = request.form.get("code", "")
        filename = request.form.get("filename", "untitled.py")

    if not code.strip():
        if request.is_json:
            return jsonify({"error": "No code provided"}), 400
        return redirect(url_for("index"))

    # Write code to temp file and scan
    tmp_dir = tempfile.mkdtemp()
    try:
        tmp_file = os.path.join(tmp_dir, filename)
        Path(tmp_file).write_text(code)
        result = engine.scan(tmp_dir)

        scan_record = {
            "id": len(scan_history) + 1,
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "score": result.score,
            "findings_count": len(result.findings),
            "result": result.to_dict(),
        }
        scan_history.insert(0, scan_record)

        if request.is_json:
            return jsonify(result.to_dict())
        return render_template("results.html", result=result, scan=scan_record)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API endpoint for scanning."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json()
    code = data.get("code", "")
    filename = data.get("filename", "untitled.py")

    if not code.strip():
        return jsonify({"error": "No code provided"}), 400

    tmp_dir = tempfile.mkdtemp()
    try:
        tmp_file = os.path.join(tmp_dir, filename)
        Path(tmp_file).write_text(code)
        result = engine.scan(tmp_dir)
        return jsonify(result.to_dict())
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "version": "0.1.0"})


@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    """Handle GitHub webhook for PR scanning."""
    payload = request.get_json()

    if not payload:
        return jsonify({"error": "No payload"}), 400

    action = payload.get("action")
    if action not in ("opened", "synchronize"):
        return jsonify({"status": "ignored", "reason": f"action={action}"}), 200

    # TODO: Fetch PR diff, scan changed files, post review comments
    # This will use the GitHub API with an installation token
    return jsonify({"status": "queued", "pr": payload.get("number")}), 202


@app.route("/webhook/email", methods=["POST"])
def email_webhook():
    """Handle inbound emails from Resend webhook."""
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "No payload"}), 400

    # Resend sends the email data in the payload
    email_data = payload.get("data", payload)
    store_inbound(email_data)
    return jsonify({"status": "received"}), 200


@app.route("/api/inbox", methods=["GET"])
def get_inbox():
    """Get all inbound emails."""
    unread_only = request.args.get("unread", "false").lower() == "true"
    if unread_only:
        return jsonify({"messages": get_unread()})
    return jsonify({"messages": get_all_messages()})


@app.route("/api/inbox/mark-read", methods=["POST"])
def mark_inbox_read():
    """Mark all inbox messages as read."""
    mark_all_read()
    return jsonify({"status": "ok"})


@app.route("/api/send", methods=["POST"])
def send_email_api():
    """Send an email via API."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data"}), 400

    subject = data.get("subject", "")
    body = data.get("body", "")
    html = data.get("html")

    if not subject or not body:
        return jsonify({"error": "subject and body are required"}), 400

    result = send_email(subject, body, html)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
