import hashlib
import secrets
from datetime import timedelta

from flask import current_app

from ..extensions import db, socketio
from ..models import LoginSession, PasswordResetToken, SecurityLog, User
from ..security import passwords
from ..services import presence
from ..services.mail_service import send_mail
from ..services.security_service import log_event, request_context
from ..utils import clean_text, describe_user_agent, utcnow, valid_email, valid_username

_dummy_hash = None


def _params() -> dict:
    c = current_app.config
    return dict(memory_kib=c["ARGON2_MEMORY_KIB"], iterations=c["ARGON2_ITERATIONS"], lanes=c["ARGON2_LANES"])


def hash_password(password: str) -> str:
    return passwords.hash_password(password, **_params())


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ------------------------------------------------------------------ registration
def register_user(username: str, email: str, display_name: str, password: str):
    username, email = (username or "").strip().lower(), (email or "").strip().lower()
    display_name = clean_text(display_name, 64) or username
    errors: dict[str, list[str]] = {}
    if not valid_username(username):
        errors["username"] = ["Use 3-32 characters: lowercase letters, numbers and underscores."]
    if not valid_email(email):
        errors["email"] = ["Enter a valid email address."]
    problems = passwords.password_problems(password or "", username=username, email=email)
    if problems:
        errors["password"] = problems
    if errors:
        return None, errors
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return None, {"username": ["That username or email is already registered."]}
    user = User(username=username, email=email, display_name=display_name, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    log_event("account_created", user.id)
    return user, {}


# ------------------------------------------------------------------ login
def authenticate(identifier: str, password: str):
    """Return the User on success or None. Timing and message are identical for unknown users."""
    global _dummy_hash
    ident = (identifier or "").strip().lower()
    user = User.query.filter((User.username == ident) | (User.email == ident)).first() if ident else None
    if _dummy_hash is None or not _dummy_hash.startswith("$argon2id$"):
        _dummy_hash = hash_password(secrets.token_hex(16))
    now = utcnow()
    locked = bool(user and user.locked_until and user.locked_until > now)
    ok = passwords.verify_password(password or "", user.password_hash if user else _dummy_hash)
    if user and ok and user.is_active and not locked:
        user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
        if passwords.needs_rehash(user.password_hash, **_params()):
            user.password_hash = hash_password(password)
        db.session.commit()
        return user
    if user and not locked:
        user.failed_logins += 1
        threshold = current_app.config["LOCKOUT_THRESHOLD"]
        if user.failed_logins >= threshold:
            user.locked_until = now + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
            user.failed_logins = 0
            log_event("account_locked", user.id, "critical",
                      f"Locked for {current_app.config['LOCKOUT_MINUTES']} min after repeated failed sign-ins.", alert=True)
        else:
            log_event("login_failed", user.id, "warning", "Incorrect password.", alert=user.failed_logins >= 3)
        db.session.commit()
    return None


# ------------------------------------------------------------------ sessions
def _detect_suspicious(user: User, ip, ua) -> bool:
    prior = (SecurityLog.query.filter_by(user_id=user.id, event="login_success")
             .order_by(SecurityLog.id.desc()).limit(50).all())
    if not prior:
        return False
    new_ip = ip not in {p.ip for p in prior}
    new_agent = describe_user_agent(ua) not in {describe_user_agent(p.user_agent) for p in prior}
    return new_ip and new_agent


def create_login_session(user: User):
    ip, ua = request_context()
    suspicious = _detect_suspicious(user, ip, ua)
    token = secrets.token_urlsafe(32)
    now = utcnow()
    row = LoginSession(user_id=user.id, token_hash=_sha256(token), created_at=now, last_seen_at=now,
                       expires_at=now + current_app.config["SESSION_ABSOLUTE_LIFETIME"], ip=ip, user_agent=ua)
    db.session.add(row)
    log_event("login_success", user.id, commit=False)
    if suspicious:
        log_event("suspicious_login", user.id, "warning",
                  "Signed in from a network and browser you have not used before.", commit=False)
    db.session.commit()
    if suspicious:
        socketio.emit("security:alert", {"event": "suspicious_login", "severity": "warning",
                                         "detail": "New sign-in from an unfamiliar network and browser."},
                      to=f"user:{user.id}")
    return token, row


def resolve_session(token: str | None):
    """Validate a session token: not revoked, not expired, not idle. Returns LoginSession or None."""
    if not token:
        return None
    row = LoginSession.query.filter_by(token_hash=_sha256(token)).first()
    if not row or row.revoked_at:
        return None
    now = utcnow()
    if row.expires_at <= now or now - row.last_seen_at > current_app.config["SESSION_IDLE_TIMEOUT"]:
        return None
    return row


def touch_session(row: LoginSession):
    now = utcnow()
    if (now - row.last_seen_at).total_seconds() > 60:
        row.last_seen_at = now
        db.session.commit()


def revoke_session(row: LoginSession) -> None:
    if row.revoked_at:
        return
    row.revoked_at = utcnow()
    db.session.commit()
    for sid in presence.sids_for_session(row.id):  # kill live WebSockets of that session
        try:
            socketio.server.disconnect(sid)
        except Exception:  # pragma: no cover - best effort
            pass


def revoke_all_sessions(user_id: int, except_id: int | None = None) -> int:
    count = 0
    for row in LoginSession.query.filter_by(user_id=user_id, revoked_at=None).all():
        if row.id != except_id:
            revoke_session(row)
            count += 1
    return count


# ------------------------------------------------------------------ passwords
def change_password(user: User, current: str, new: str, keep_session_id=None):
    if not passwords.verify_password(current or "", user.password_hash):
        log_event("password_change_failed", user.id, "warning", "Wrong current password.")
        return {"current_password": ["Current password is incorrect."]}
    problems = passwords.password_problems(new or "", username=user.username, email=user.email)
    if problems:
        return {"password": problems}
    user.password_hash = hash_password(new)
    db.session.commit()
    revoke_all_sessions(user.id, except_id=keep_session_id)
    log_event("password_changed", user.id, "warning", "Password changed; other sessions signed out.", alert=True)
    return {}


def start_password_reset(email: str) -> None:
    """Always behaves the same, whether or not the address exists (no account enumeration)."""
    user = User.query.filter_by(email=(email or "").strip().lower()).first()
    if not user or not user.is_active:
        return
    PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).delete()
    token = secrets.token_urlsafe(32)
    db.session.add(PasswordResetToken(
        user_id=user.id, token_hash=_sha256(token),
        expires_at=utcnow() + timedelta(minutes=current_app.config["PASSWORD_RESET_MINUTES"])))
    db.session.commit()
    log_event("password_reset_requested", user.id, "warning", "A password reset link was requested.")
    link = f"{current_app.config['PUBLIC_BASE_URL'].rstrip('/')}/reset-password/{token}"
    send_mail(user.email, "Reset your password",
              f"Use this link within {current_app.config['PASSWORD_RESET_MINUTES']} minutes:\n{link}\n\n"
              "If you did not request this, ignore this email. Your encrypted messages are not affected.")


def finish_password_reset(token: str, new_password: str):
    row = PasswordResetToken.query.filter_by(token_hash=_sha256(token or "")).first()
    if not row or row.used_at or row.expires_at <= utcnow():
        return {"token": ["This reset link is invalid or has expired."]}
    user = db.session.get(User, row.user_id)
    problems = passwords.password_problems(new_password or "", username=user.username, email=user.email)
    if problems:
        return {"password": problems}
    user.password_hash = hash_password(new_password)
    user.failed_logins, user.locked_until = 0, None
    row.used_at = utcnow()
    db.session.commit()
    revoke_all_sessions(user.id)
    log_event("password_reset", user.id, "warning", "Password reset completed; all sessions signed out.")
    return {}
