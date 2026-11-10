import os
import smtplib
from email.message import EmailMessage

from flask import current_app

from ..utils import utcnow


def send_mail(to: str, subject: str, body: str) -> None:
    cfg = current_app.config
    if cfg.get("SMTP_HOST"):
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = cfg["MAIL_FROM"], to, subject
        msg.set_content(body)
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as smtp:
            smtp.starttls()
            if cfg.get("SMTP_USER"):
                smtp.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"] or "")
            smtp.send_message(msg)
        return
    # Development fallback: write to a local outbox file (never to application logs).
    path = os.path.join(current_app.instance_path, "outbox.log")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"--- {utcnow().isoformat()}Z to={to} subject={subject}\n{body}\n\n")
