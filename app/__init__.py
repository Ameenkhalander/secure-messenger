import os
import secrets

from flask import Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import get_config
from .extensions import db, limiter, migrate, socketio


def _finalize_config(app: Flask) -> None:
    cfg = app.config
    if not cfg.get("SECRET_KEY"):
        if cfg["ENV_NAME"] == "production":
            raise RuntimeError("SECRET_KEY must be set in production.")
        path = os.path.join(app.instance_path, ".secret_key")  # persisted so dev sessions survive restarts
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(secrets.token_hex(32))
        with open(path, encoding="utf-8") as fh:
            cfg["SECRET_KEY"] = fh.read().strip()
    uri = cfg.get("SQLALCHEMY_DATABASE_URI")
    if not uri:
        uri = "sqlite:///" + os.path.join(app.instance_path, "messenger.db").replace("\\", "/")
    if uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    cfg["SQLALCHEMY_DATABASE_URI"] = uri
    ext = os.environ.get("RENDER_EXTERNAL_URL")  # set automatically by Render
    if ext:
        if "PUBLIC_BASE_URL" not in os.environ:
            cfg["PUBLIC_BASE_URL"] = ext
        if not cfg.get("SOCKETIO_CORS_ORIGINS"):
            cfg["SOCKETIO_CORS_ORIGINS"] = [ext]


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(get_config(config_name))
    if overrides:
        app.config.update(overrides)
    os.makedirs(app.instance_path, exist_ok=True)
    _finalize_config(app)

    n = app.config["TRUSTED_PROXY_COUNT"]
    if n:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    db.init_app(app)
    migrate.init_app(app, db)

    from . import models  # noqa: F401  (register tables)
    from .sockets import events  # noqa: F401  (must be imported BEFORE socketio.init_app)
    from .security.auth import init_auth
    from .security.csrf import init_csrf
    from .security.headers import init_headers

    init_auth(app)   # order matters: user is resolved before rate-limit key functions run
    init_csrf(app)
    limiter.init_app(app)
    init_headers(app)
    socketio.init_app(app, async_mode=app.config["SOCKETIO_ASYNC_MODE"],
                      cors_allowed_origins=app.config["SOCKETIO_CORS_ORIGINS"])

    from .routes.api import api_bp
    from .routes.auth import auth_bp
    from .routes.main import main_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def _inject():
        return {"current_user": g.get("user")}

    _register_errors(app)
    _register_cli(app)
    return app


def _register_errors(app: Flask) -> None:
    from .services.errors import ServiceError

    @app.errorhandler(ServiceError)
    def _service_error(exc):
        return jsonify(error=exc.message, code=exc.code), exc.status

    @app.errorhandler(HTTPException)
    def _http_error(exc):
        if request.path.startswith("/api/") or request.is_json:
            return jsonify(error=exc.description, code=exc.name.lower().replace(" ", "_")), exc.code
        return render_template("error.html", code=exc.code, title=exc.name, message=exc.description), exc.code

    @app.errorhandler(Exception)
    def _unhandled(exc):
        app.logger.exception("Unhandled error")
        db.session.rollback()
        if request.path.startswith("/api/"):
            return jsonify(error="Internal server error.", code="server_error"), 500
        return render_template("error.html", code=500, title="Something went wrong",
                               message="An unexpected error occurred."), 500


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db():
        """Create all tables (development). Use Flask-Migrate for production."""
        db.create_all()
        print("Database initialised.")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Create two demo accounts for LOCAL demos. Refuses to run in production."""
        from .models import User
        from .services.auth_service import hash_password
        if app.config["ENV_NAME"] == "production":
            raise SystemExit("seed-demo is disabled in production.")
        db.create_all()
        for username, name in (("alice_demo", "Alice Demo"), ("bob_demo", "Bob Demo")):
            if not User.query.filter_by(username=username).first():
                db.session.add(User(username=username, email=f"{username}@example.com", display_name=name,
                                    password_hash=hash_password("Sealed-Demo-2026!")))
        db.session.commit()
        print("Created: alice_demo and bob_demo, password: Sealed-Demo-2026!")