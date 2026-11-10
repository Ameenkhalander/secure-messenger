from ..extensions import db
from ..utils import iso, utcnow


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)  # lowercase
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)    # lowercase
    display_name = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    last_seen_at = db.Column(db.DateTime)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime)

    def to_public(self, online: bool = False) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "online": online,
            "last_seen_at": iso(self.last_seen_at),
        }

    def to_private(self) -> dict:
        return {**self.to_public(), "email": self.email, "created_at": iso(self.created_at)}


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)  # sha256 of the emailed token
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
