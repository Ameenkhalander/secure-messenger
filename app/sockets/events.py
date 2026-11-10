"""Socket.IO events. The WebSocket handshake is authenticated with the same server-side
session as HTTP (cookie), cross-origin handshakes are refused, and every event re-checks
that the session is still valid (so revoking a session kills its live connection)."""
from flask import request, session
from flask_socketio import emit, join_room

from ..extensions import db, socketio
from ..models import User
from ..services import auth_service, conversation_service as convs, presence
from ..utils import utcnow


def _user_for_event():
    info = presence.info(request.sid)
    row = auth_service.resolve_session(session.get("sid"))
    if not info or row is None or info[1] != row.id:
        return None
    user = db.session.get(User, row.user_id)
    return user if user and user.is_active else None


def _broadcast_presence(user: User, online: bool):
    payload = {"user_id": user.id, "online": online, "last_seen_at": user.last_seen_at.isoformat() + "Z" if user.last_seen_at else None}
    for uid in convs.contact_ids(user.id):
        socketio.emit("presence:update", payload, to=f"user:{uid}")


@socketio.on("connect")
def on_connect(auth=None):
    row = auth_service.resolve_session(session.get("sid"))
    user = db.session.get(User, row.user_id) if row else None
    if not user or not user.is_active:
        return False  # refuse the handshake
    join_room(f"user:{user.id}")
    if presence.add(request.sid, user.id, row.id):
        _broadcast_presence(user, True)
    emit("ready", {"user_id": user.id})
    return None


@socketio.on("disconnect")
def on_disconnect(*_args):
    result = presence.remove(request.sid)
    if result and result[1]:
        user = db.session.get(User, result[0])
        if user:
            user.last_seen_at = utcnow()
            db.session.commit()
            _broadcast_presence(user, False)


@socketio.on("typing")
def on_typing(data):
    user = _user_for_event()
    if user is None or not isinstance(data, dict) or not isinstance(data.get("conversation_id"), int):
        return
    conv_id = data["conversation_id"]
    if not convs.get_member(conv_id, user.id):
        return
    for uid in convs.active_member_ids(conv_id):
        if uid != user.id:
            emit("typing", {"conversation_id": conv_id, "user_id": user.id, "typing": bool(data.get("typing"))},
                 to=f"user:{uid}")
