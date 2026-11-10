import re
import time

from flask import current_app
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..extensions import db, socketio
from ..models import Device, EncryptedMessage, MessageReceipt, PublicKey, User
from ..security import e2ee_protocol as e2ee
from ..services import conversation_service as convs
from ..services import key_service
from ..services.errors import ServiceError
from ..utils import iso, utcnow

CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
MIN_CIPHERTEXT = e2ee.PAD_BLOCK + 16  # one padded block + GCM tag
MAX_ENVELOPES = 500


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _validated_envelopes(raw, valid_key_ids: set[int], sender_key_id: int) -> list[dict]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_ENVELOPES:
        raise ServiceError("Invalid envelopes.")
    out, seen = [], set()
    try:
        for env in raw:
            if not isinstance(env, dict) or not _is_int(env.get("k")):
                raise ServiceError("Invalid envelope.")
            k = env["k"]
            if k in seen:
                raise ServiceError("Duplicate envelope.")
            if k not in valid_key_ids:
                raise ServiceError("Envelope addressed to a key that is not an active device of a member.", 400, "stale_recipients")
            seen.add(k)
            e2ee.b64d(env.get("epk"), length=e2ee.KEY_LEN)
            e2ee.b64d(env.get("n"), length=e2ee.NONCE_LEN)
            e2ee.b64d(env.get("w"), length=e2ee.WRAPPED_LEN)
            out.append({"k": k, "epk": env["epk"], "n": env["n"], "w": env["w"]})
    except e2ee.E2EEError as exc:
        raise ServiceError(f"Malformed envelope: {exc}") from exc
    if sender_key_id not in seen:
        raise ServiceError("The sender's own device must be able to read the message.")
    return out


def create_message(user, conv_id: int, data) -> EncryptedMessage:
    conv, _ = convs.require_member(conv_id, user)
    if not isinstance(data, dict):
        raise ServiceError("Invalid payload.")
    cid, ts, key_id = data.get("client_msg_id"), data.get("timestamp"), data.get("sender_key_id")
    if not isinstance(cid, str) or not CLIENT_ID_RE.fullmatch(cid):
        raise ServiceError("Invalid client_msg_id.")
    if not _is_int(ts) or not _is_int(key_id):
        raise ServiceError("Invalid timestamp or sender key.")
    skew = current_app.config["MAX_MESSAGE_SKEW_SECONDS"] * 1000
    if abs(int(time.time() * 1000) - ts) > skew:
        raise ServiceError("Message timestamp is outside the allowed window.", 400, "stale_timestamp")
    key = db.session.get(PublicKey, key_id)
    device = db.session.get(Device, key.device_id) if key else None
    if not key or key.user_id != user.id or key.retired_at or not device or device.revoked_at:
        raise ServiceError("Sender key is not an active key of yours.", 400, "bad_sender_key")
    try:
        nonce = e2ee.b64d(data.get("nonce"), length=e2ee.NONCE_LEN)
        ct = e2ee.b64d(data.get("ciphertext"), max_len=e2ee.MAX_CIPHERTEXT)
        e2ee.b64d(data.get("signature"), length=e2ee.SIG_LEN)
    except e2ee.E2EEError as exc:
        raise ServiceError(f"Malformed message: {exc}") from exc
    if len(ct) < MIN_CIPHERTEXT:
        raise ServiceError("Ciphertext too short.")
    member_keys = key_service.active_keys(convs.active_member_ids(conv.id))
    if conv.kind == "direct" and not any(k.user_id != user.id for k in member_keys):
        raise ServiceError("The other person has not opened Sealed yet, so there is nothing to encrypt to. "
                           "Ask them to sign in once, then try again.", 409, "peer_no_keys")
    valid = {k.id for k in member_keys}
    envelopes = _validated_envelopes(data.get("envelopes"), valid, key.id)
    candidate = {"conversation_id": conv.id, "client_msg_id": cid, "sender_key_id": key.id, "timestamp": ts,
                 "nonce": data["nonce"], "ciphertext": data["ciphertext"], "signature": data["signature"],
                 "envelopes": envelopes}
    # The server cannot read messages, but it CAN reject forgeries: verify the Ed25519 signature.
    if not e2ee.verify_message_signature(candidate, e2ee.b64d(key.sign_pub)):
        raise ServiceError("Invalid message signature.", 400, "bad_signature")
    if EncryptedMessage.query.filter_by(sender_id=user.id, client_msg_id=cid).first():
        raise ServiceError("Duplicate message (replay rejected).", 409, "replay")
    msg = EncryptedMessage(conversation_id=conv.id, sender_id=user.id, sender_key_id=key.id, client_msg_id=cid,
                           client_ts=ts, nonce=data["nonce"], ciphertext=data["ciphertext"],
                           signature=data["signature"], envelopes=envelopes)
    db.session.add(msg)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ServiceError("Duplicate message (replay rejected).", 409, "replay")
    payload = {"message": serialize_one(msg, user)}
    for uid in convs.active_member_ids(conv.id):
        socketio.emit("message:new", payload, to=f"user:{uid}")
    return msg


# ------------------------------------------------------------------ serialisation
def serialize_many(msgs, viewer) -> list[dict]:
    if not msgs:
        return []
    ids = [m.id for m in msgs]
    key_ids = {m.sender_key_id for m in msgs}
    keys = {k.id: k for k in PublicKey.query.filter(PublicKey.id.in_(key_ids)).all()}
    senders = {u.id: u for u in User.query.filter(User.id.in_({m.sender_id for m in msgs})).all()}
    counts = {mid: (d, r) for mid, d, r in db.session.query(
        MessageReceipt.message_id, func.count(MessageReceipt.delivered_at), func.count(MessageReceipt.read_at))
        .filter(MessageReceipt.message_id.in_(ids)).group_by(MessageReceipt.message_id).all()}
    mine = {r.message_id: r for r in MessageReceipt.query.filter(MessageReceipt.message_id.in_(ids),
                                                               MessageReceipt.user_id == viewer.id).all()}
    recipients = {}
    out = []
    for m in msgs:
        if m.conversation_id not in recipients:
            recipients[m.conversation_id] = max(len(convs.active_members(m.conversation_id)) - 1, 0)
        k, d_r = keys.get(m.sender_key_id), counts.get(m.id, (0, 0))
        deleted = m.deleted_at is not None
        out.append({
            "id": m.id, "conversation_id": m.conversation_id, "sender_id": m.sender_id,
            "sender_username": senders[m.sender_id].username if m.sender_id in senders else None,
            "sender_name": senders[m.sender_id].display_name if m.sender_id in senders else None,
            "sender_key_id": m.sender_key_id,
            "sender_key": k.to_dict() if k else None,
            "client_msg_id": m.client_msg_id, "timestamp": m.client_ts, "created_at": iso(m.created_at),
            "deleted": deleted,
            "nonce": "" if deleted else m.nonce, "ciphertext": "" if deleted else m.ciphertext,
            "signature": "" if deleted else m.signature, "envelopes": [] if deleted else m.envelopes,
            "delivered_count": d_r[0], "read_count": d_r[1], "recipient_count": recipients[m.conversation_id],
            "read_by_me": bool(mine.get(m.id) and mine[m.id].read_at),
        })
    return out


def serialize_one(msg, viewer) -> dict:
    return serialize_many([msg], viewer)[0]


def list_messages(user, conv_id: int, before_id=None, limit=50):
    conv, member = convs.require_member(conv_id, user)
    q = EncryptedMessage.query.filter(EncryptedMessage.conversation_id == conv.id,
                                      EncryptedMessage.created_at >= member.joined_at)
    if before_id:
        q = q.filter(EncryptedMessage.id < before_id)
    rows = q.order_by(EncryptedMessage.id.desc()).limit(max(1, min(limit, 100))).all()
    rows.reverse()
    return serialize_many(rows, user)


def delete_message(user, message_id: int):
    msg = db.session.get(EncryptedMessage, message_id)
    if not msg or msg.sender_id != user.id or not convs.get_member(msg.conversation_id, user.id):
        raise ServiceError("Message not found.", 404)
    if msg.deleted_at is None:
        msg.deleted_at = utcnow()
        msg.ciphertext, msg.nonce, msg.signature, msg.envelopes = "", "", "", []  # ciphertext is really erased
        db.session.commit()
        for uid in convs.active_member_ids(msg.conversation_id):
            socketio.emit("message:deleted", {"conversation_id": msg.conversation_id, "message_id": msg.id}, to=f"user:{uid}")
    return msg


def mark_receipts(user, message_ids, status: str) -> int:
    if status not in ("delivered", "read") or not isinstance(message_ids, list):
        raise ServiceError("Invalid receipt.")
    ids = [i for i in message_ids[:200] if _is_int(i)]
    if not ids:
        return 0
    now, touched, member_cache = utcnow(), [], {}
    for m in EncryptedMessage.query.filter(EncryptedMessage.id.in_(ids), EncryptedMessage.sender_id != user.id,
                                           EncryptedMessage.deleted_at.is_(None)).all():
        if m.conversation_id not in member_cache:
            member_cache[m.conversation_id] = convs.get_member(m.conversation_id, user.id)
        if not member_cache[m.conversation_id]:
            continue
        r = MessageReceipt.query.filter_by(message_id=m.id, user_id=user.id).first()
        if r is None:
            r = MessageReceipt(message_id=m.id, user_id=user.id)
            db.session.add(r)
        r.delivered_at = r.delivered_at or now
        if status == "read":
            r.read_at = r.read_at or now
        touched.append(m)
    db.session.commit()
    grouped: dict[tuple[int, int], list[int]] = {}
    for m in touched:
        grouped.setdefault((m.sender_id, m.conversation_id), []).append(m.id)
    for (sender_id, conv_id), mids in grouped.items():
        socketio.emit("receipt:update", {"conversation_id": conv_id, "message_ids": mids,
                                         "user_id": user.id, "status": status}, to=f"user:{sender_id}")
    return len(touched)