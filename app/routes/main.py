from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, url_for

from ..extensions import db, limiter
from ..models import LoginSession, SecurityLog
from ..security.auth import login_required
from ..services import auth_service, key_service
from ..utils import clean_text, utcnow

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def index():
    return redirect(url_for("main.chat" if g.user else "auth.login"))


@main_bp.get("/healthz")
@limiter.exempt
def healthz():
    return jsonify(status="ok")


@main_bp.get("/chat")
@login_required
def chat():
    return render_template("chat.html")


@main_bp.get("/security")
@login_required
def security():
    uid = g.user.id
    sessions = LoginSession.query.filter(LoginSession.user_id == uid, LoginSession.revoked_at.is_(None),
                                         LoginSession.expires_at > utcnow()).order_by(LoginSession.id.desc()).all()
    history = (SecurityLog.query.filter(SecurityLog.user_id == uid, SecurityLog.event.in_(
        ["login_success", "login_failed", "suspicious_login", "account_locked", "logout"]))
        .order_by(SecurityLog.id.desc()).limit(25).all())
    alerts = (SecurityLog.query.filter(SecurityLog.user_id == uid, SecurityLog.severity.in_(["warning", "critical"]),
                                       SecurityLog.acknowledged_at.is_(None)).order_by(SecurityLog.id.desc()).limit(25).all())
    events = SecurityLog.query.filter_by(user_id=uid).order_by(SecurityLog.id.desc()).limit(25).all()
    return render_template(
        "security.html",
        devices=key_service.list_devices(g.user),
        sessions=[s.to_dict(current=(s.id == g.login_session.id)) for s in sessions],
        history=[h.to_dict() for h in history],
        alerts=[a.to_dict() for a in alerts],
        events=[e.to_dict() for e in events],
    )


@main_bp.get("/settings")
@login_required
def settings():
    return render_template("settings.html", errors={})


@main_bp.post("/settings/profile")
@login_required
def update_profile():
    name = clean_text(request.form.get("display_name"), 64)
    if not name:
        return render_template("settings.html", errors={"display_name": ["Enter a display name."]}), 400
    g.user.display_name = name
    db.session.commit()
    flash("Profile updated.", "success")
    return redirect(url_for("main.settings"))


@main_bp.post("/settings/password")
@login_required
@limiter.limit("5 per hour")
def update_password():
    if request.form.get("password") != request.form.get("confirm"):
        return render_template("settings.html", errors={"confirm": ["Passwords do not match."]}), 400
    errors = auth_service.change_password(g.user, request.form.get("current_password", ""),
                                          request.form.get("password", ""), keep_session_id=g.login_session.id)
    if errors:
        return render_template("settings.html", errors=errors), 400
    flash("Password changed. Other sessions were signed out.", "success")
    return redirect(url_for("main.settings"))
