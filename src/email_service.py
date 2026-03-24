"""Two-way email communication system using Resend."""
import os
import json
import requests
from datetime import datetime
from pathlib import Path

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = "claude@fromtheconsole.com"
TO_EMAIL = "init.chandan@gmail.com"
INBOX_FILE = Path(__file__).parent.parent / "data" / "inbox.json"


def _ensure_inbox():
    INBOX_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not INBOX_FILE.exists():
        INBOX_FILE.write_text("[]")


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
    """Store an inbound email to the inbox file."""
    _ensure_inbox()
    inbox = json.loads(INBOX_FILE.read_text())
    inbox.append({
        "id": email_data.get("id", ""),
        "from": email_data.get("from", ""),
        "subject": email_data.get("subject", ""),
        "text": email_data.get("text", ""),
        "html": email_data.get("html", ""),
        "timestamp": email_data.get("created_at", datetime.now().isoformat()),
        "read": False,
    })
    INBOX_FILE.write_text(json.dumps(inbox, indent=2))


def get_unread() -> list:
    """Get all unread inbound emails."""
    _ensure_inbox()
    inbox = json.loads(INBOX_FILE.read_text())
    return [msg for msg in inbox if not msg.get("read")]


def get_all_messages() -> list:
    """Get all inbound emails."""
    _ensure_inbox()
    return json.loads(INBOX_FILE.read_text())


def mark_read(msg_id: str):
    """Mark a message as read."""
    _ensure_inbox()
    inbox = json.loads(INBOX_FILE.read_text())
    for msg in inbox:
        if msg["id"] == msg_id:
            msg["read"] = True
    INBOX_FILE.write_text(json.dumps(inbox, indent=2))


def mark_all_read():
    """Mark all messages as read."""
    _ensure_inbox()
    inbox = json.loads(INBOX_FILE.read_text())
    for msg in inbox:
        msg["read"] = True
    INBOX_FILE.write_text(json.dumps(inbox, indent=2))
