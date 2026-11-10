from ..extensions import db
from ..utils import iso, utcnow


class LoginSession(db.Model):
    __tablename__ = "login_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)  # sha256(session token)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(300))

    def to_dict(self, current: bool = False) -> dict:
        from ..utils import describe_user_agent
        return {
            "id": self.id,
            "ip": self.ip,
            "agent": describe_user_agent(self.user_agent),
            "created_at": iso(self.created_at),
            "last_seen_at": iso(self.last_seen_at),
            "expires_at": iso(self.expires_at),
            "current": current,
        }


class SecurityLog(db.Model):
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    event = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="info")  # info | warning | critical
    detail = db.Column(db.String(300))
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    acknowledged_at = db.Column(db.DateTime)

    def to_dict(self) -> dict:
        from ..utils import describe_user_agent
        return {
            "id": self.id, "event": self.event, "severity": self.severity, "detail": self.detail,
            "ip": self.ip, "agent": describe_user_agent(self.user_agent),
            "created_at": iso(self.created_at), "acknowledged": self.acknowledged_at is not None,
        }
