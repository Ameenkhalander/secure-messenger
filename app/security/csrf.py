"""Synchroniser-token CSRF protection + Origin check for every state-changing request."""
import hmac
import secrets
from urllib.parse import urlparse

from flask import abort, current_app, request, session

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def get_csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def init_csrf(app):
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    @app.before_request
    def _csrf_protect():
        if not current_app.config.get("CSRF_ENABLED", True) or request.method in SAFE_METHODS:
            return None
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.host:
            abort(403, description="Cross-origin request blocked.")
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            abort(403, description="Missing or invalid CSRF token.")
        return None
