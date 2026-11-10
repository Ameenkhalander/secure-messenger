from ..extensions import db
from ..utils import iso, utcnow


class Device(db.Model):
    """One browser/app installation. Private keys live ONLY on the device."""
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime)
    revoked_at = db.Column(db.DateTime)

    def to_dict(self, current_key: "PublicKey | None" = None) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": iso(self.created_at),
            "last_seen_at": iso(self.last_seen_at),
            "revoked": self.revoked_at is not None,
            "key": current_key.to_dict() if current_key else None,
        }


class PublicKey(db.Model):
    """Public half of a device identity. Rotation retires the old row and adds a new one."""
    __tablename__ = "user_public_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    enc_pub = db.Column(db.String(64), nullable=False)    # base64 X25519 (32 bytes)
    sign_pub = db.Column(db.String(64), nullable=False)   # base64 Ed25519 (32 bytes)
    fingerprint = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    retired_at = db.Column(db.DateTime)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "enc_pub": self.enc_pub,
            "sign_pub": self.sign_pub,
            "fingerprint": self.fingerprint,
            "created_at": iso(self.created_at),
            "retired": self.retired_at is not None,
        }
