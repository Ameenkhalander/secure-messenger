"""Secure HTTP headers (CSP without inline script/style, clickjacking, MIME sniffing, ...)."""
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:",
    "img-src 'self' data:",
    "connect-src 'self' ws: wss:",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def init_headers(app):
    @app.after_request
    def _set_headers(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if app.config.get("HSTS_ENABLED"):
            resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        from flask import request
        if not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp
