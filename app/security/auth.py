"""Authentication middleware: resolves the server-side session on every request."""
from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from ..extensions import db
from ..models import User


def init_auth(app):
    @app.before_request
    def _load_user():
        from ..services import auth_service
        g.user, g.login_session = None, None
        if request.path.startswith("/static/"):
            return
        row = auth_service.resolve_session(session.get("sid"))
        if row is None:
            if "sid" in session:
                session.pop("sid", None)
            return
        user = db.session.get(User, row.user_id)
        if user is None or not user.is_active:
            return
        g.user, g.login_session = user, row
        auth_service.touch_session(row)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            if request.path.startswith("/api/"):
                return jsonify(error="Authentication required.", code="auth_required"), 401
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapper
