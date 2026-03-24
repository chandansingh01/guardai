#!/usr/bin/env python3
"""Local CLI for the GuardAI email system.

Usage:
    python email_cli.py send "Subject" "Body text"
    python email_cli.py check              # check for unread emails
    python email_cli.py inbox              # show all emails
    python email_cli.py mark-read          # mark all as read
"""
import sys
import json
import requests

API_BASE = "https://guardai-weld.vercel.app"
RESEND_API_KEY = "re_jTc9dyUe_Acq9tTD9cjN87fBLLTb4KMJM"
FROM_EMAIL = "Claude <claude@fromtheconsole.com>"
TO_EMAIL = "init.chandan@gmail.com"


def send_direct(subject: str, body: str):
    """Send email directly via Resend API (works offline from Vercel)."""
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": FROM_EMAIL,
            "to": [TO_EMAIL],
            "subject": subject,
            "text": body,
        },
    )
    data = resp.json()
    if "id" in data:
        print(f"Sent! (id: {data['id']})")
    else:
        print(f"Error: {data}")


def check_inbox(unread_only=True):
    """Check inbox via the deployed API."""
    try:
        resp = requests.get(f"{API_BASE}/api/inbox", params={"unread": str(unread_only).lower()})
        data = resp.json()
        messages = data.get("messages", [])
        if not messages:
            print("No unread messages." if unread_only else "Inbox is empty.")
            return
        for msg in messages:
            print(f"\n{'='*50}")
            print(f"From: {msg.get('from', 'unknown')}")
            print(f"Subject: {msg.get('subject', '(no subject)')}")
            print(f"Time: {msg.get('timestamp', '')}")
            print(f"---")
            print(msg.get("text", "(no text body)"))
        print(f"\n{'='*50}")
        print(f"{len(messages)} message(s)")
    except Exception as e:
        print(f"Error connecting to API: {e}")


def mark_read():
    """Mark all messages as read."""
    try:
        resp = requests.post(f"{API_BASE}/api/inbox/mark-read")
        print("All messages marked as read.")
    except Exception as e:
        print(f"Error: {e}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "send":
        if len(sys.argv) < 4:
            print('Usage: python email_cli.py send "Subject" "Body"')
            sys.exit(1)
        send_direct(sys.argv[2], sys.argv[3])

    elif cmd == "check":
        check_inbox(unread_only=True)

    elif cmd == "inbox":
        check_inbox(unread_only=False)

    elif cmd == "mark-read":
        mark_read()

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
