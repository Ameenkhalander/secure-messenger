from ..extensions import db
from ..utils import iso, utcnow


class Conversation(db.Model):
    __tablename__ = "conversations"

    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(10), nullable=False)  # 'direct' | 'group'
    name = db.Column(db.String(80))
    direct_key = db.Column(db.String(40), unique=True)  # "<low_id>:<high_id>" prevents duplicate DMs
    created_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    members = db.relationship("ConversationMember", backref="conversation", cascade="all, delete-orphan")


class ConversationMember(db.Model):
    __tablename__ = "conversation_members"
    __table_args__ = (db.UniqueConstraint("conversation_id", "user_id", name="uq_member"),)

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = db.Column(db.String(10), nullable=False, default="member")  # 'admin' | 'member'
    joined_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    left_at = db.Column(db.DateTime)  # set when removed or left; row kept for history

    user = db.relationship("User")

    @property
    def active(self) -> bool:
        return self.left_at is None

    def to_dict(self) -> dict:
        return {"user_id": self.user_id, "role": self.role, "joined_at": iso(self.joined_at)}
