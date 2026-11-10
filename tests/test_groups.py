from app.security.e2ee_protocol import b64d, decrypt_message

from .helpers import send


def make_group(owner, members, name="Project X"):
    r = owner.client.post("/api/conversations", json={"type": "group", "name": name, "member_ids": [m.user_id for m in members]})
    assert r.status_code == 201, r.data
    return r.get_json()["conversation"]["id"]


def read(actor, conv, index=-1):
    m = actor.client.get(f"/api/conversations/{conv}/messages").get_json()["messages"][index]
    return decrypt_message(m, my_key_id=actor.key_id, my_enc_private=actor.identity.enc_private,
                           sender_sign_pub=b64d(m["sender_key"]["sign_pub"]))["body"]


def test_group_messages_reach_every_member(make_user):
    a, b, c = make_user("alice"), make_user("bob"), make_user("carol")
    g = make_group(a, [b, c])
    assert send(b, g, "hello team")[0].status_code == 201
    assert read(a, g) == read(c, g) == read(b, g) == "hello team"


def test_only_admins_manage_members(make_user):
    a, b, c, d = (make_user(n) for n in ("alice", "bob", "carol", "dave"))
    g = make_group(a, [b])
    assert b.client.post(f"/api/conversations/{g}/members", json={"user_id": c.user_id}).status_code == 403
    assert a.client.post(f"/api/conversations/{g}/members", json={"user_id": c.user_id}).status_code == 201
    assert b.client.delete(f"/api/conversations/{g}/members/{c.user_id}").status_code == 403
    assert a.client.post(f"/api/conversations/{g}/members/{b.user_id}/role", json={"role": "admin"}).status_code == 200
    assert b.client.post(f"/api/conversations/{g}/members", json={"user_id": d.user_id}).status_code == 201


def test_removed_member_cannot_read_new_messages(make_user):
    a, b, c = make_user("alice"), make_user("bob"), make_user("carol")
    g = make_group(a, [b, c])
    send(a, g, "before removal")
    assert a.client.delete(f"/api/conversations/{g}/members/{c.user_id}").status_code == 200
    assert c.client.get(f"/api/conversations/{g}/messages").status_code == 404
    r, _ = send(a, g, "after removal")
    assert r.status_code == 201
    keys = a.client.get(f"/api/conversations/{g}/recipients").get_json()["keys"]
    assert c.key_id not in [k["id"] for k in keys]                                       # no envelope for the removed member
    assert read(b, g) == "after removal"


def test_new_member_cannot_read_history(make_user):
    a, b, c = make_user("alice"), make_user("bob"), make_user("carol")
    g = make_group(a, [b])
    send(a, g, "secret from before")
    a.client.post(f"/api/conversations/{g}/members", json={"user_id": c.user_id})
    assert c.client.get(f"/api/conversations/{g}/messages").get_json()["messages"] == []


def test_last_admin_leaving_promotes_someone(make_user):
    a, b = make_user("alice"), make_user("bob")
    g = make_group(a, [b])
    assert a.client.delete(f"/api/conversations/{g}/members/{a.user_id}").status_code == 200
    roles = {m["username"]: m["role"] for m in b.client.get(f"/api/conversations/{g}").get_json()["conversation"]["members"]}
    assert roles == {"bob": "admin"}


def test_direct_conversations_are_deduplicated_and_not_manageable(make_user):
    a, b = make_user("alice"), make_user("bob")
    r1 = a.client.post("/api/conversations", json={"type": "direct", "user_id": b.user_id}).get_json()["conversation"]["id"]
    r2 = b.client.post("/api/conversations", json={"type": "direct", "user_id": a.user_id}).get_json()["conversation"]["id"]
    assert r1 == r2
    assert a.client.post(f"/api/conversations/{r1}/members", json={"user_id": b.user_id}).status_code == 400
    assert a.client.post("/api/conversations", json={"type": "direct", "user_id": a.user_id}).status_code == 400
