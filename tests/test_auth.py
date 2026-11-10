import re

from app import create_app
from app.extensions import db
from app.models import LoginSession, SecurityLog, User
from app.security.passwords import verify_password

from .conftest import PASSWORD


def register(client, name="alice", password=PASSWORD, **kw):
    data = {"username": name, "email": f"{name}@example.com", "display_name": name, "password": password, "confirm": password}
    data.update(kw)
    return client.post("/register", data=data)


def test_registration_success_and_password_is_argon2id(client, app):
    assert register(client).status_code == 302
    user = User.query.filter_by(username="alice").one()
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash
    assert verify_password(PASSWORD, user.password_hash)


def test_registration_validation(client):
    assert register(client, "ab").status_code == 400                       # username too short
    assert register(client, "bob", email="not-an-email").status_code == 400
    assert register(client, "carol", password="short").status_code == 400
    assert register(client, "dave", confirm="different-password-123").status_code == 400
    assert register(client, "erin", password="erin-password-1234").status_code == 400  # contains username


def test_duplicate_registration_rejected(client):
    assert register(client).status_code == 302
    assert register(client).status_code == 400


def test_login_logout_flow(client):
    register(client)
    assert client.get("/chat").status_code == 302                          # not signed in
    r = client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    assert r.status_code == 302 and r.headers["Location"].endswith("/chat")
    assert client.get("/chat").status_code == 200
    assert client.post("/logout").status_code == 302
    assert client.get("/chat").status_code == 302
    assert client.get("/api/me").status_code == 401


def test_wrong_password_and_unknown_user_look_identical(client):
    register(client)
    client.get("/login")  # consume the one-off "account created" flash message
    a = client.post("/login", data={"identifier": "alice", "password": "wrong-password-123"})
    b = client.post("/login", data={"identifier": "nobody", "password": "wrong-password-123"})
    assert a.status_code == b.status_code == 401
    assert a.data == b.data


def test_account_lockout_after_repeated_failures(client):
    register(client)
    for _ in range(5):
        client.post("/login", data={"identifier": "alice", "password": "wrong-password-123"})
    r = client.post("/login", data={"identifier": "alice", "password": PASSWORD})  # even the right password
    assert r.status_code == 401
    assert SecurityLog.query.filter_by(event="account_locked").count() == 1


def test_open_redirect_is_blocked(client):
    register(client)
    r = client.post("/login?next=https://evil.example/", data={"identifier": "alice", "password": PASSWORD})
    assert r.headers["Location"].endswith("/chat")
    client.post("/logout")
    r = client.post("/login?next=//evil.example", data={"identifier": "alice", "password": PASSWORD})
    assert "evil" not in r.headers["Location"]


def test_session_expiry_and_revocation(client, app):
    register(client)
    client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    assert client.get("/api/me").status_code == 200
    row = LoginSession.query.one()
    from datetime import timedelta
    from app.utils import utcnow
    row.last_seen_at = utcnow() - timedelta(hours=3)       # beyond the idle timeout
    db.session.commit()
    assert client.get("/api/me").status_code == 401
    client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    assert client.get("/api/me").status_code == 200
    LoginSession.query.filter(LoginSession.revoked_at.is_(None)).order_by(LoginSession.id.desc()).first().revoked_at = utcnow()
    db.session.commit()
    assert client.get("/api/me").status_code == 401


def test_password_reset_flow(client, app):
    register(client)
    client.post("/forgot-password", data={"email": "alice@example.com"})
    outbox = open(f"{app.instance_path}/outbox.log", encoding="utf-8").read()
    token = re.search(r"/reset-password/([\w-]+)", outbox).group(1)
    new = "a brand new passphrase 77"
    assert client.post(f"/reset-password/{token}", data={"password": new, "confirm": new}).status_code == 302
    assert client.post(f"/reset-password/{token}", data={"password": new, "confirm": new}).status_code == 400  # single use
    assert client.post("/login", data={"identifier": "alice", "password": PASSWORD}).status_code == 401
    assert client.post("/login", data={"identifier": "alice", "password": new}).status_code == 302


def test_forgot_password_does_not_reveal_accounts(client):
    a = client.post("/forgot-password", data={"email": "ghost@example.com"})
    register(client)
    b = client.post("/forgot-password", data={"email": "alice@example.com"})
    assert a.status_code == b.status_code == 302 and a.headers["Location"] == b.headers["Location"]


def test_change_password_signs_out_other_sessions(client, app):
    register(client)
    client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    other = app.test_client()
    other.post("/login", data={"identifier": "alice", "password": PASSWORD})
    new = "another long passphrase 99"
    r = client.post("/settings/password", data={"current_password": PASSWORD, "password": new, "confirm": new})
    assert r.status_code == 302
    assert client.get("/api/me").status_code == 200
    assert other.get("/api/me").status_code == 401


def test_csrf_blocks_requests_without_token(tmp_path):
    app = create_app("testing", {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'c.db'}", "CSRF_ENABLED": True})
    with app.app_context():
        db.create_all()
        c = app.test_client()
        assert c.post("/register", data={"username": "x"}).status_code == 403
        page = c.get("/register").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        r = c.post("/register", data={"csrf_token": token, "username": "alice", "email": "a@example.com",
                                      "display_name": "A", "password": PASSWORD, "confirm": PASSWORD})
        assert r.status_code == 302
        # cross-origin form post is rejected even with a valid token
        r = c.post("/register", headers={"Origin": "https://evil.example"}, data={"csrf_token": token})
        assert r.status_code == 403


def test_security_headers_present(client):
    r = client.get("/login")
    h = r.headers
    assert "default-src 'self'" in h["Content-Security-Policy"] and "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert "'unsafe-inline'" not in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer" and h["Cache-Control"] == "no-store"


def test_session_cookie_flags(client):
    register(client)
    r = client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_rate_limiting_on_login(tmp_path):
    app = create_app("testing", {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'r.db'}", "CSRF_ENABLED": False,
                                 "RATELIMIT_ENABLED": True})
    with app.app_context():
        db.create_all()
        c = app.test_client()
        codes = [c.post("/login", data={"identifier": "x", "password": "y"}).status_code for _ in range(12)]
        assert 429 in codes


def test_sql_injection_attempt_is_inert(client):
    register(client)
    r = client.post("/login", data={"identifier": "' OR '1'='1", "password": "' OR '1'='1"})
    assert r.status_code == 401
    client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    r = client.get("/api/users/search?q=%27%20OR%201%3D1%20--")
    assert r.status_code == 200 and r.get_json()["users"] == []


def test_xss_is_escaped_in_templates(client):
    register(client, display_name="<script>alert(1)</script>")
    client.post("/login", data={"identifier": "alice", "password": PASSWORD})
    html = client.get("/chat").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
