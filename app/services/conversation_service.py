from flask import current_app
from sqlalchemy import and_, func

from ..extensions import db
from ..models import Conversation, ConversationMember, EncryptedMessage, MessageReceipt, User
from ..services import presence
from ..services.errors import ServiceError
from ..utils import clean_text, iso, utcnow


def get_member(conv_id: int, user_id: int):
    return ConversationMember.query.filter_by(conversation_id=conv_id, user_id=user_id, left_at=None).first()


def require_member(conv_id: int, user):
    """404 (not 403) for non-members so conversation ids cannot be probed."""
    member = get_member(conv_id, user.id)
    conv = db.session.get(Conversation, conv_id) if member else None
    if not conv:
        raise ServiceError("Conversation not found.", 404)
    return conv, member


def active_members(conv_id: int):
    return ConversationMember.query.filter_by(conversation_id=conv_id, left_at=None).all()


def active_member_ids(conv_id: int) -> list[int]:
    return [m.user_id for m in active_members(conv_id)]


def contact_ids(user_id: int) -> set[int]:
    conv_ids = [m.conversation_id for m in ConversationMember.query.filter_by(user_id=user_id, left_at=None).all()]
    if not conv_ids:
        return set()
    rows = (ConversationMember.query.filter(ConversationMember.conversation_id.in_(conv_ids),
                                            ConversationMember.left_at.is_(None)).all())
    return {r.user_id for r in rows} - {user_id}


def _add_member(conv: Conversation, user_id: int, role="member"):
    row = ConversationMember.query.filter_by(conversation_id=conv.id, user_id=user_id).first()
    if row:
        row.left_at, row.role, row.joined_at = None, role, utcnow()  # re-join: fresh history boundary
    else:
        db.session.add(ConversationMember(conversation_id=conv.id, user_id=user_id, role=role))
    return row


def direct_conversation(user, other_id):
    if not isinstance(other_id, int) or isinstance(other_id, bool) or other_id == user.id:
        raise ServiceError("Choose another user.")
    other = db.session.get(User, other_id)
    if not other or not other.is_active:
        raise ServiceError("User not found.", 404)
    key = f"{min(user.id, other.id)}:{max(user.id, other.id)}"
    conv = Conversation.query.filter_by(direct_key=key).first()
    if conv is None:
        conv = Conversation(kind="direct", direct_key=key, created_by=user.id)
        db.session.add(conv)
        db.session.flush()
    for uid in (user.id, other.id):
        if not get_member(conv.id, uid):
            _add_member(conv, uid)
    db.session.commit()
    return conv


def create_group(user, name, member_ids):
    name = clean_text(name, 80)
    if not name:
        raise ServiceError("Give the group a name.")
    ids = {user.id}
    for mid in member_ids if isinstance(member_ids, list) else []:
        if isinstance(mid, int) and not isinstance(mid, bool):
            ids.add(mid)
    if len(ids) > current_app.config["MAX_GROUP_MEMBERS"]:
        raise ServiceError("Too many members.")
    found = {u.id for u in User.query.filter(User.id.in_(ids), User.is_active.is_(True)).all()}
    if found != ids:
        raise ServiceError("One or more users were not found.", 404)
    conv = Conversation(kind="group", name=name, created_by=user.id)
    db.session.add(conv)
    db.session.flush()
    for uid in ids:
        _add_member(conv, uid, "admin" if uid == user.id else "member")
    db.session.commit()
    return conv


def _require_group_admin(conv: Conversation, actor):
    if conv.kind != "group":
        raise ServiceError("Only groups have members to manage.")
    member = get_member(conv.id, actor.id)
    if not member or member.role != "admin":
        raise ServiceError("Only group admins can do that.", 403)


def add_member(conv, actor, user_id):
    _require_group_admin(conv, actor)
    user = db.session.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active:
        raise ServiceError("User not found.", 404)
    if get_member(conv.id, user.id):
        raise ServiceError("Already a member.", 409)
    if len(active_members(conv.id)) >= current_app.config["MAX_GROUP_MEMBERS"]:
        raise ServiceError("Group is full.")
    _add_member(conv, user.id)
    db.session.commit()


def remove_member(conv, actor, user_id):
    if conv.kind != "group":
        raise ServiceError("Direct conversations cannot be left.")
    if user_id != actor.id:
        _require_group_admin(conv, actor)
    target = get_member(conv.id, user_id)
    if not target:
        raise ServiceError("Not a member.", 404)
    target.left_at = utcnow()
    db.session.flush()
    rest = active_members(conv.id)
    if rest and not any(m.role == "admin" for m in rest):  # never leave a group without an admin
        min(rest, key=lambda m: m.joined_at).role = "admin"
    db.session.commit()


def set_role(conv, actor, user_id, role):
    _require_group_admin(conv, actor)
    if role not in ("admin", "member"):
        raise ServiceError("Invalid role.")
    target = get_member(conv.id, user_id)
    if not target:
        raise ServiceError("Not a member.", 404)
    if target.role == "admin" and role == "member" and sum(m.role == "admin" for m in active_members(conv.id)) == 1:
        raise ServiceError("A group needs at least one admin.", 409)
    target.role = role
    db.session.commit()


def unread_count(conv_id: int, user_id: int, joined_at) -> int:
    return (db.session.query(func.count(EncryptedMessage.id))
            .outerjoin(MessageReceipt, and_(MessageReceipt.message_id == EncryptedMessage.id, MessageReceipt.user_id == user_id))
            .filter(EncryptedMessage.conversation_id == conv_id, EncryptedMessage.sender_id != user_id,
                    EncryptedMessage.deleted_at.is_(None), EncryptedMessage.created_at >= joined_at,
                    MessageReceipt.read_at.is_(None)).scalar() or 0)


def serialize(conv: Conversation, viewer, online: set[int] | None = None, with_last=True) -> dict:
    from ..services import message_service
    online = online if online is not None else presence.online_ids()
    members = active_members(conv.id)
    me = next((m for m in members if m.user_id == viewer.id), None)
    users = {u.id: u for u in User.query.filter(User.id.in_([m.user_id for m in members])).all()}
    out = {
        "id": conv.id, "kind": conv.kind, "name": conv.name, "created_at": iso(conv.created_at),
        "my_role": me.role if me else None,
        "members": [{**users[m.user_id].to_public(m.user_id in online), "role": m.role} for m in members if m.user_id in users],
        "unread": unread_count(conv.id, viewer.id, me.joined_at) if me else 0,
    }
    if conv.kind == "direct":
        peer = next((m for m in out["members"] if m["id"] != viewer.id), None)
        out["peer"] = peer
        out["name"] = peer["display_name"] if peer else "Deleted user"
    if with_last and me:
        last = (EncryptedMessage.query.filter(EncryptedMessage.conversation_id == conv.id,
                                              EncryptedMessage.created_at >= me.joined_at)
                .order_by(EncryptedMessage.id.desc()).first())
        out["last_message"] = message_service.serialize_one(last, viewer) if last else None
        out["last_activity"] = iso(last.created_at if last else conv.created_at)
    return out


def list_for(viewer) -> list[dict]:
    online = presence.online_ids()
    convs = (Conversation.query.join(ConversationMember, ConversationMember.conversation_id == Conversation.id)
             .filter(ConversationMember.user_id == viewer.id, ConversationMember.left_at.is_(None)).all())
    items = [serialize(c, viewer, online) for c in convs]
    items.sort(key=lambda c: c.get("last_activity") or "", reverse=True)
    return items
