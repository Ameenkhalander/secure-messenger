import re

import pytest

from app import create_app
from app.extensions import db
from app.security.e2ee_protocol import Identity
from app.services import presence

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def app(tmp_path):
    presence.clear()
    app = create_app("testing", {
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "CSRF_ENABLED": False,
    })
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


class Actor:
    """A registered, logged-in user with a device identity (private keys live only here, in the test)."""

    def __init__(self, app, name):
        self.app, self.name = app, name
        self.client = app.test_client()
        self.identity = Identity()
        self.key_id = None
        self.user_id = None

    def register_and_login(self):
        r = self.client.post("/register", data={"username": self.name, "email": f"{self.name}@example.com",
                                                "display_name": self.name.title(), "password": PASSWORD, "confirm": PASSWORD})
        assert r.status_code == 302, r.data
        r = self.client.post("/login", data={"identifier": self.name, "password": PASSWORD})
        assert r.status_code == 302, r.data
        me = self.client.get("/api/me").get_json()
        self.user_id = me["user"]["id"]
        r = self.client.post("/api/devices", json=self.identity.registration_payload())
        assert r.status_code == 201, r.data
        self.key_id = r.get_json()["device"]["key"]["id"]
        return self


@pytest.fixture()
def make_user(app):
    def _make(name):
        return Actor(app, name).register_and_login()
    return _make
