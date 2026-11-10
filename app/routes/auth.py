from urllib.parse import urlparse

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from ..extensions import limiter
from ..security.auth import login_required
from ..services import auth_service
from ..services.security_service import log_event

auth_bp = Blueprint("auth", __name__)


def _safe_next(target: str | None) -> str:
    """Only allow same-site relative redirects (blocks open-redirect attacks)."""
    if target and target.startswith("/") and not target.startswith("//") and not urlparse(target).netloc:
        return target
    return url_for("main.chat")


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if g.user:
        return redirect(url_for("main.chat"))
    errors, form = {}, {}
    if request.method == "POST":
        form = {k: request.form.get(k, "") for k in ("username", "email", "display_name")}
        password, confirm = request.form.get("password", ""), request.form.get("confirm", "")
        if password != confirm:
            errors["confirm"] = ["Passwords do not match."]
        else:
            user, errors = auth_service.register_user(form["username"], form["email"], form["display_name"], password)
            if user:
                flash("Account created. Sign in to continue.", "success")
                return redirect(url_for("auth.login"))
    return render_template("auth/register.html", errors=errors, form=form), (400 if errors else 200)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if g.user:
        return redirect(url_for("main.chat"))
    error = None
    if request.method == "POST":
        user = auth_service.authenticate(request.form.get("identifier", ""), request.form.get("password", ""))
        if user:
            nxt = request.args.get("next")
            session.clear()  # new session id/CSRF token on privilege change (anti-fixation)
            token, _row = auth_service.create_login_session(user)
            session["sid"] = token
            session.permanent = True
            return redirect(_safe_next(nxt))
        error = "Incorrect credentials, or the account is temporarily locked."
    return render_template("auth/login.html", error=error), (401 if error else 200)


@auth_bp.post("/logout")
@login_required
def logout():
    auth_service.revoke_session(g.login_session)
    log_event("logout", g.user.id)
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def forgot_password():
    if request.method == "POST":
        auth_service.start_password_reset(request.form.get("email", ""))
        flash("If that address is registered, a reset link is on its way.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def reset_password(token):
    errors = {}
    if request.method == "POST":
        if request.form.get("password") != request.form.get("confirm"):
            errors["confirm"] = ["Passwords do not match."]
        else:
            errors = auth_service.finish_password_reset(token, request.form.get("password", ""))
            if not errors:
                flash("Password updated. Sign in with your new password.", "success")
                return redirect(url_for("auth.login"))
    return render_template("auth/reset.html", errors=errors, token=token), (400 if errors else 200)
