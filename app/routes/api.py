from flask import Blueprint, g, jsonify, request
from flask_limiter.util import get_remote_address
from sqlalchemy import or_

from ..extensions import db, limiter
from ..models import LoginSession, SecurityLog, User
from ..services import auth_service, conversation_service as convs, key_service, message_service, presence
from ..services.errors import ServiceError
from ..extensions import socketio
from ..utils import clean_text, utcnow

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _user_key() -> str:
    return f"user:{g.user.id}" if g.get("user") else get_remote_address()


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ServiceError("Expected a JSON object.")
    return data


@api_bp.before_request
def _require_auth():
    if g.get("user") is None:
        return jsonify(error="Authentication required.", code="auth_required"), 401
    return None


def _notify_conversation(conv_id: int, extra_user_ids=()):
    for uid in set(convs.active_member_ids(conv_id)) | set(extra_user_ids):
        socketio.emit("conversation:updated", {"conversation_id": conv_id}, to=f"user:{uid}")


# ------------------------------------------------------------------ me / users
@api_bp.get("/me")
def me():
    return jsonify(user=g.user.to_private(), login_session_id=g.login_session.id)


@api_bp.get("/users/search")
@limiter.limit("30 per minute", key_func=_user_key)
def search_users():
    q = clean_text(request.args.get("q", ""), 32).lower().lstrip("@")
    if len(q) < 2:
        return jsonify(users=[])
    like = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = (User.query.filter(User.id != g.user.id, User.is_active.is_(True),
                              or_(User.username.like(like, escape="\\"), User.display_name.ilike(like, escape="\\")))
            .order_by(User.username).limit(10).all())
    online = presence.online_ids()
    return jsonify(users=[u.to_public(u.id in online) for u in rows])


# ------------------------------------------------------------------ devices & keys
@api_bp.get("/devices")
def devices():
    return jsonify(devices=key_service.list_devices(g.user))


@api_bp.post("/devices")
@limiter.limit("10 per hour", key_func=_user_key)
def add_device():
    device, key = key_service.register_device(g.user, _body())
    return jsonify(device=device.to_dict(key)), 201


@api_bp.post("/devices/<int:device_id>/rotate")
@limiter.limit("10 per hour", key_func=_user_key)
def rotate_device(device_id):
    device, key = key_service.rotate_key(g.user, device_id, _body())
    for conv in convs.list_for(g.user):  # let peers refresh their recipient lists
        _notify_conversation(conv["id"])
    return jsonify(device=device.to_dict(key))


@api_bp.delete("/devices/<int:device_id>")
def remove_device(device_id):
    device = key_service.revoke_device(g.user, device_id)
    return jsonify(device=device.to_dict())


# ------------------------------------------------------------------ conversations
@api_bp.get("/conversations")
def list_conversations():
    return jsonify(conversations=convs.list_for(g.user))


@api_bp.post("/conversations")
@limiter.limit("30 per hour", key_func=_user_key)
def create_conversation():
    data = _body()
    if data.get("type") == "group":
        conv = convs.create_group(g.user, data.get("name"), data.get("member_ids"))
    elif data.get("type") == "direct":
        conv = convs.direct_conversation(g.user, data.get("user_id"))
    else:
        raise ServiceError("type must be 'direct' or 'group'.")
    _notify_conversation(conv.id)
    return jsonify(conversation=convs.serialize(conv, g.user)), 201


@api_bp.get("/conversations/<int:conv_id>")
def get_conversation(conv_id):
    conv, _ = convs.require_member(conv_id, g.user)
    return jsonify(conversation=convs.serialize(conv, g.user))


@api_bp.get("/conversations/<int:conv_id>/recipients")
def recipients(conv_id):
    """Public keys of every active device of every active member (used for envelope fan-out)."""
    conv, _ = convs.require_member(conv_id, g.user)
    keys = key_service.active_keys(convs.active_member_ids(conv.id))
    return jsonify(keys=[k.to_dict() for k in keys])


@api_bp.post("/conversations/<int:conv_id>/members")
def add_member(conv_id):
    conv, _ = convs.require_member(conv_id, g.user)
    convs.add_member(conv, g.user, _body().get("user_id"))
    _notify_conversation(conv.id)
    return jsonify(conversation=convs.serialize(conv, g.user)), 201


@api_bp.delete("/conversations/<int:conv_id>/members/<int:user_id>")
def remove_member(conv_id, user_id):
    conv, _ = convs.require_member(conv_id, g.user)
    convs.remove_member(conv, g.user, user_id)
    _notify_conversation(conv.id, extra_user_ids=[user_id])
    return jsonify(ok=True)


@api_bp.post("/conversations/<int:conv_id>/members/<int:user_id>/role")
def member_role(conv_id, user_id):
    conv, _ = convs.require_member(conv_id, g.user)
    convs.set_role(conv, g.user, user_id, _body().get("role"))
    _notify_conversation(conv.id)
    return jsonify(ok=True)


# ------------------------------------------------------------------ messages
@api_bp.get("/conversations/<int:conv_id>/messages")
def get_messages(conv_id):
    before = request.args.get("before_id", type=int)
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(messages=message_service.list_messages(g.user, conv_id, before, limit))


@api_bp.post("/conversations/<int:conv_id>/messages")
@limiter.limit("120 per minute", key_func=_user_key)
def send_message(conv_id):
    msg = message_service.create_message(g.user, conv_id, _body())
    return jsonify(message=message_service.serialize_one(msg, g.user)), 201


@api_bp.delete("/messages/<int:message_id>")
def delete_message(message_id):
    message_service.delete_message(g.user, message_id)
    return jsonify(ok=True)


@api_bp.post("/receipts")
@limiter.limit("300 per minute", key_func=_user_key)
def receipts():
    data = _body()
    return jsonify(updated=message_service.mark_receipts(g.user, data.get("message_ids"), data.get("status")))


# ------------------------------------------------------------------ sessions & security
@api_bp.get("/sessions")
def sessions():
    rows = LoginSession.query.filter(LoginSession.user_id == g.user.id, LoginSession.revoked_at.is_(None),
                                     LoginSession.expires_at > utcnow()).order_by(LoginSession.id.desc()).all()
    return jsonify(sessions=[s.to_dict(current=s.id == g.login_session.id) for s in rows])


@api_bp.delete("/sessions/<int:session_id>")
def revoke_session(session_id):
    row = LoginSession.query.filter_by(id=session_id, user_id=g.user.id).first()
    if not row:
        raise ServiceError("Session not found.", 404)
    auth_service.revoke_session(row)
    return jsonify(ok=True, signed_out_self=row.id == g.login_session.id)


@api_bp.post("/sessions/revoke-others")
def revoke_other_sessions():
    return jsonify(revoked=auth_service.revoke_all_sessions(g.user.id, except_id=g.login_session.id))


@api_bp.post("/security/acknowledge")
def acknowledge_alerts():
    now = utcnow()
    SecurityLog.query.filter(SecurityLog.user_id == g.user.id, SecurityLog.acknowledged_at.is_(None),
                             SecurityLog.severity != "info").update({"acknowledged_at": now})
    db.session.commit()
    return jsonify(ok=True)
