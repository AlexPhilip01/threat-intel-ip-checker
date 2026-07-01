"""
Email alerts via Gmail SMTP + an app password.

Free, no third-party account needed, plenty for a handful of alert
emails a day. If this ever needs to scale up, swap for SendGrid/Mailgun —
send_alert() is the only function anything else calls.
"""
import os
import smtplib
from email.message import EmailMessage
from typing import Any, Dict

RISK_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def risk_increased(previous_result: Dict[str, Any], new_result: Dict[str, Any]) -> bool:
    """True only when the new overall risk is strictly higher than before."""
    if not previous_result or not new_result:
        return False
    if not new_result.get("valid", True):
        return False

    prev_risk = RISK_ORDER.get(previous_result.get("overall_risk", "UNKNOWN"), 0)
    new_risk = RISK_ORDER.get(new_result.get("overall_risk", "UNKNOWN"), 0)
    return new_risk > prev_risk


def _is_configured() -> bool:
    return bool(
        os.environ.get("GMAIL_ADDRESS")
        and os.environ.get("GMAIL_APP_PASSWORD")
        and os.environ.get("ALERT_EMAIL_TO")
    )


def send_alert(ip: str, previous_result: Dict[str, Any], new_result: Dict[str, Any]) -> bool:
    """
    Send an alert email for a risk increase. Returns True if an email was
    actually sent (False if alerting isn't configured, so callers can log
    that distinctly from "sent but failed").
    """
    if not _is_configured():
        return False

    gmail_address = os.environ["GMAIL_ADDRESS"]
    gmail_app_password = os.environ["GMAIL_APP_PASSWORD"]
    alert_to = os.environ["ALERT_EMAIL_TO"]

    old_risk = previous_result.get("overall_risk", "UNKNOWN")
    new_risk = new_result.get("overall_risk", "UNKNOWN")

    message = EmailMessage()
    message["Subject"] = f"[Threat Watch] {ip} risk increased: {old_risk} -> {new_risk}"
    message["From"] = gmail_address
    message["To"] = alert_to

    lines = [
        f"IP {ip} risk level increased from {old_risk} to {new_risk}.",
        "",
        "Per-source breakdown:",
    ]
    for source in new_result.get("sources", []):
        lines.append(f"  - {source['source']}: {source['risk']} ({source['status']})")
    message.set_content("\n".join(lines))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(gmail_address, gmail_app_password)
        server.send_message(message)

    return True
