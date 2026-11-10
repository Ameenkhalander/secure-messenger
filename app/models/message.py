from ..extensions import db
from ..utils import utcnow


class EncryptedMessage(db.Model):
    """Only ciphertext, nonce, signature and wrapped keys are stored. No plaintext, ever."""
    __tablename__ = "encrypted_messages"
    __table_args__ = (
        db.UniqueConstraint("sender_id", "client_msg_id", name="uq_sender_client_msg"),  # replay guard
        db.Index("ix_msg_conv_id", "conversation_id", "id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    sender_key_id = db.Column(db.Integer, db.ForeignKey("user_public_keys.id"), nullable=False)
    client_msg_id = db.Column(db.String(64), nullable=False)
    client_ts = db.Column(db.BigInteger, nullable=False)  # signed client timestamp (ms)
    nonce = db.Column(db.String(32), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    signature = db.Column(db.String(128), nullable=False)
    envelopes = db.Column(db.JSON, nullable=False)  # [{k, epk, n, w}] wrapped content keys
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    deleted_at = db.Column(db.DateTime)


class MessageReceipt(db.Model):
    __tablename__ = "message_receipts"
    __table_args__ = (db.UniqueConstraint("message_id", "user_id", name="uq_receipt"),)

    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("encrypted_messages.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    delivered_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
