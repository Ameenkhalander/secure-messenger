from flask import request

from ..extensions import db, socketio
from ..models import SecurityLog


def request_context() -> tuple[str | None, str | None]:
    try:
        return request.remote_addr, (request.headers.get("User-Agent") or "")[:300]
    except RuntimeError:  # outside a request
        return None, None


def log_event(event: str, user_id=None, severity="info", detail=None, commit=True, alert=False):
    ip, ua = request_context()
    row = SecurityLog(user_id=user_id, event=event, severity=severity, detail=(detail or "")[:300], ip=ip, user_agent=ua)
    db.session.add(row)
    if commit:
        db.session.commit()
    if alert and user_id:
        socketio.emit("security:alert", {"event": event, "severity": severity, "detail": detail},
                      to=f"user:{user_id}")
    return row
