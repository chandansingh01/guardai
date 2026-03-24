"""Two-way email communication system using Resend + GitHub for persistence."""
import os
import json
import base64
import requests
from datetime import datetime

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = "chandansingh01/guardai"
INBOX_PATH = "data/inbox.json"
FROM_EMAIL = "claude@fromtheconsole.com"
TO_EMAIL = "init.chandan@gmail.com"


def _github_headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }


def _get_inbox_from_github() -> tuple:
    """Fetch inbox.json from GitHub. Returns (messages_list, file_sha)."""
    resp = requests.get(
        f"https://api.github.com/repos/{REPO}/contents/{INBOX_PATH}",
        headers=_github_headers(),
    )
    if resp.status_code == 200:
        data = resp.json()
        content = base64.b64decode(data["content"]).decode("utf-8")
        return json.loads(content), data["sha"]
    return [], None


def _save_inbox_to_github(messages: list, sha: str = None):
    """Save inbox.json to GitHub repo."""
    content = base64.b64encode(json.dumps(messages, indent=2).encode()).decode()
    payload = {
        "message": "Update inbox",
        "content": content,
    }
    if sha:
        payload["sha"] = sha

    requests.put(
        f"https://api.github.com/repos/{REPO}/contents/{INBOX_PATH}",
        headers=_github_headers(),
        json=payload,
    )


def send_email(subject: str, body: str, html: str = None) -> dict:
    """Send an email via Resend API."""
    api_key = RESEND_API_KEY
    if not api_key:
        return {"error": "RESEND_API_KEY not set"}

    payload = {
        "from": f"Claude <{FROM_EMAIL}>",
        "to": [TO_EMAIL],
        "subject": subject,
        "text": body,
    }
    if html:
        payload["html"] = html

    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
    )
    return resp.json()


def store_inbound(email_data: dict):
    """Store an inbound email to GitHub-backed inbox."""
    inbox, sha = _get_inbox_from_github()
    inbox.append({
        "id": email_data.get("id", datetime.now().isoformat()),
        "from": email_data.get("from", ""),
        "subject": email_data.get("subject", ""),
        "text": email_data.get("text", ""),
        "html": email_data.get("html", ""),
        "timestamp": email_data.get("created_at", datetime.now().isoformat()),
        "read": False,
    })
    _save_inbox_to_github(inbox, sha)


def get_unread() -> list:
    """Get all unread inbound emails."""
    inbox, _ = _get_inbox_from_github()
    return [msg for msg in inbox if not msg.get("read")]


def get_all_messages() -> list:
    """Get all inbound emails."""
    inbox, _ = _get_inbox_from_github()
    return inbox


def mark_read(msg_id: str):
    """Mark a message as read."""
    inbox, sha = _get_inbox_from_github()
    for msg in inbox:
        if msg["id"] == msg_id:
            msg["read"] = True
    _save_inbox_to_github(inbox, sha)


def mark_all_read():
    """Mark all messages as read."""
    inbox, sha = _get_inbox_from_github()
    for msg in inbox:
        msg["read"] = True
    _save_inbox_to_github(inbox, sha)
