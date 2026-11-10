"""Development entry point:  python run.py    (production: gunicorn, see Dockerfile)"""
import os

from app import create_app
from app.extensions import db, socketio

app = create_app()

# Idempotent: creates missing tables on startup (fine for a single-process demo deployment).
# For schema changes in a long-lived production system use Flask-Migrate instead.
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    socketio.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        allow_unsafe_werkzeug=True,  # dev server only; production uses gunicorn
    )
