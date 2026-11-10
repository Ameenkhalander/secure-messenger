import json
import time

from app.extensions import db, socketio
from app.models import EncryptedMessage, PublicKey
from app.security.e2ee_protocol import Identity, b64d, b64e, decrypt_message, validate_enc_public_key

from .helpers import direct, encrypted_payload, send


def test_device_registration_validates_keys_and_proof(make_user):
    alice = make_user("alice")
    other = Identity()
    bad_key = dict(other.registration_payload(), enc_pub=b64e(b"\x00" * 32))
    assert alice.client.post("/api/devices", json=bad_key).status_code == 400          # low-order point
    short = dict(other.registration_payload(), sign_pub=b64e(b"\x01" * 5))
    assert alice.client.post("/api/devices", json=short).status_code == 400
    forged = dict(other.registration_payload(), pop_sig=b64e(b"\x00" * 64))
    assert alice.client.post("/api/devices", json=forged).status_code == 400            # no proof of possession
    stolen = dict(alice.identity.registration_payload())                                # key already registered
    assert alice.client.post("/api/devices", json=stolen).status_code == 409
    assert alice.client.post("/api/devices", json=other.registration_payload()).status_code == 201


def test_end_to_end_delivery_and_server_cannot_decrypt(make_user, app):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    secret = "the launch code is 4711"
    r, _ = send(alice, conv, secret)
    assert r.status_code == 201

    # the server's stored data holds no plaintext and no private key material
    row = EncryptedMessage.query.one()
    stored = json.dumps([row.nonce, row.ciphertext, row.signature, row.envelopes])
    assert secret not in stored and "4711" not in stored
    for table in db.metadata.tables.values():
        assert not [c for c in table.columns if "private" in c.name or "secret" in c.name or "plaintext" in c.name]

    # bob can read it; a party holding only public keys cannot
    msgs = bob.client.get(f"/api/conversations/{conv}/messages").get_json()["messages"]
    assert len(msgs) == 1
    m = msgs[0]
    sender = m["sender_key"]
    out = decrypt_message(m, my_key_id=bob.key_id, my_enc_private=bob.identity.enc_private, sender_sign_pub=b64d(sender["sign_pub"]))
    assert out["body"] == secret
    # alice can read her own copy as well
    own = decrypt_message(m, my_key_id=alice.key_id, my_enc_private=alice.identity.enc_private, sender_sign_pub=b64d(sender["sign_pub"]))
    assert own["body"] == secret


def test_tampered_message_rejected_by_server(make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    keys = alice.client.get(f"/api/conversations/{conv}/recipients").get_json()["keys"]
    good = encrypted_payload(alice, conv, "hello", keys)
    bad = dict(good); raw = bytearray(b64d(good["ciphertext"])); raw[10] ^= 1; bad["ciphertext"] = b64e(bytes(raw))
    assert alice.client.post(f"/api/conversations/{conv}/messages", json=bad).status_code == 400
    assert EncryptedMessage.query.count() == 0
    assert alice.client.post(f"/api/conversations/{conv}/messages", json=good).status_code == 201


def test_forged_sender_rejected(make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    keys = alice.client.get(f"/api/conversations/{conv}/recipients").get_json()["keys"]
    # Bob claims to send using ALICE's key id, signing with his own key
    forged = encrypted_payload(bob, conv, "pay me", keys, sender_key_id=alice.key_id)
    assert bob.client.post(f"/api/conversations/{conv}/messages", json=forged).status_code == 400
    # Alice's key id, but signed by Bob's private key
    from app.security.e2ee_protocol import encrypt_message
    msg = encrypt_message(conv_id=conv, client_msg_id="forged-123456", timestamp=int(time.time() * 1000), payload={"body": "x"},
                          sender_key_id=alice.key_id, sender_sign_private=bob.identity.sign_private,
                          recipients=[(k["id"], b64d(k["enc_pub"])) for k in keys])
    assert alice.client.post(f"/api/conversations/{conv}/messages", json=msg).status_code == 400


def test_replay_and_stale_timestamp_rejected(make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    r, payload = send(alice, conv, "once", client_msg_id="replay-test-0001")
    assert r.status_code == 201
    again = alice.client.post(f"/api/conversations/{conv}/messages", json=payload)
    assert again.status_code == 409 and again.get_json()["code"] == "replay"
    old, _ = send(alice, conv, "old", timestamp=int(time.time() * 1000) - 3_600_000)
    assert old.status_code == 400 and old.get_json()["code"] == "stale_timestamp"


def test_envelope_to_non_member_key_rejected(make_user):
    alice, bob, eve = make_user("alice"), make_user("bob"), make_user("eve")
    conv = direct(alice, bob)
    keys = alice.client.get(f"/api/conversations/{conv}/recipients").get_json()["keys"]
    eve_key = PublicKey.query.get(eve.key_id).to_dict()
    payload = encrypted_payload(alice, conv, "leak?", keys + [eve_key])
    r = alice.client.post(f"/api/conversations/{conv}/messages", json=payload)
    assert r.status_code == 400 and r.get_json()["code"] == "stale_recipients"


def test_unauthorized_access(make_user, client):
    alice, bob, eve = make_user("alice"), make_user("bob"), make_user("eve")
    conv = direct(alice, bob)
    send(alice, conv, "private")
    assert client.get(f"/api/conversations/{conv}/messages").status_code == 401         # anonymous
    assert eve.client.get(f"/api/conversations/{conv}/messages").status_code == 404     # not a member
    assert eve.client.get(f"/api/conversations/{conv}/recipients").status_code == 404
    keys = alice.client.get(f"/api/conversations/{conv}/recipients").get_json()["keys"]
    assert eve.client.post(f"/api/conversations/{conv}/messages", json=encrypted_payload(eve, conv, "x", keys)).status_code == 404
    mid = EncryptedMessage.query.one().id
    assert eve.client.delete(f"/api/messages/{mid}").status_code == 404
    assert bob.client.delete(f"/api/messages/{mid}").status_code == 404                 # only the sender may delete


def test_receipts_unread_counter_and_delete(make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    send(alice, conv, "one"); send(alice, conv, "two")
    listing = bob.client.get("/api/conversations").get_json()["conversations"]
    assert listing[0]["unread"] == 2
    ids = [m["id"] for m in bob.client.get(f"/api/conversations/{conv}/messages").get_json()["messages"]]
    assert bob.client.post("/api/receipts", json={"message_ids": ids, "status": "delivered"}).get_json()["updated"] == 2
    seen = alice.client.get(f"/api/conversations/{conv}/messages").get_json()["messages"]
    assert all(m["delivered_count"] == 1 and m["read_count"] == 0 for m in seen)
    bob.client.post("/api/receipts", json={"message_ids": ids, "status": "read"})
    assert bob.client.get("/api/conversations").get_json()["conversations"][0]["unread"] == 0
    seen = alice.client.get(f"/api/conversations/{conv}/messages").get_json()["messages"]
    assert all(m["read_count"] == 1 for m in seen)
    assert alice.client.post("/api/receipts", json={"message_ids": ids, "status": "read"}).get_json()["updated"] == 0  # own messages
    assert alice.client.delete(f"/api/messages/{ids[0]}").status_code == 200
    gone = EncryptedMessage.query.get(ids[0])
    assert gone.deleted_at and gone.ciphertext == "" and gone.envelopes == []          # ciphertext really erased


def test_key_rotation_requires_old_key_signature(make_user):
    from app.security.e2ee_protocol import rotation_message
    alice = make_user("alice")
    dev = alice.client.get("/api/devices").get_json()["devices"][0]
    new = Identity()
    payload = new.registration_payload()
    bad = dict(payload, prev_sig=b64e(new.sign_private.sign(rotation_message(new.enc_pub, new.sign_pub))))  # signed by NEW key
    assert alice.client.post(f"/api/devices/{dev['id']}/rotate", json=bad).status_code == 400
    good = dict(payload, prev_sig=b64e(alice.identity.sign_private.sign(rotation_message(new.enc_pub, new.sign_pub))))
    r = alice.client.post(f"/api/devices/{dev['id']}/rotate", json=good)
    assert r.status_code == 200 and r.get_json()["device"]["key"]["id"] != alice.key_id
    assert PublicKey.query.get(alice.key_id).retired_at is not None


def test_revoked_device_cannot_send(make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    dev = alice.client.get("/api/devices").get_json()["devices"][0]
    assert alice.client.delete(f"/api/devices/{dev['id']}").status_code == 200
    keys = bob.client.get(f"/api/conversations/{conv}/recipients").get_json()["keys"]
    r = alice.client.post(f"/api/conversations/{conv}/messages", json=encrypted_payload(alice, conv, "hi", keys))
    assert r.status_code == 400


def test_websocket_requires_authentication(app, make_user, client):
    from app.services import presence
    anon = socketio.test_client(app, flask_test_client=client)
    assert not anon.is_connected()
    assert presence.online_ids() == set()          # rejected before any presence/room registration
    alice = make_user("alice")
    ok = socketio.test_client(app, flask_test_client=alice.client)
    assert ok.is_connected()
    assert any(e["name"] == "ready" for e in ok.get_received())
    assert presence.online_ids() == {alice.user_id}


def test_websocket_delivery_presence_and_typing(app, make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    ws_alice = socketio.test_client(app, flask_test_client=alice.client)
    ws_bob = socketio.test_client(app, flask_test_client=bob.client)
    ws_alice.get_received(); ws_bob.get_received()
    send(alice, conv, "live message")
    events = {e["name"]: e["args"][0] for e in ws_bob.get_received()}
    assert "message:new" in events and events["message:new"]["message"]["conversation_id"] == conv
    assert "live message" not in json.dumps(events["message:new"])                       # only ciphertext on the wire
    ws_alice.emit("typing", {"conversation_id": conv, "typing": True})
    assert any(e["name"] == "typing" for e in ws_bob.get_received())
    ws_bob.disconnect()
    assert any(e["name"] == "presence:update" and not e["args"][0]["online"] for e in ws_alice.get_received())


def test_revoked_session_drops_websocket_events(app, make_user):
    alice, bob = make_user("alice"), make_user("bob")
    conv = direct(alice, bob)
    ws_bob = socketio.test_client(app, flask_test_client=bob.client)
    ws_alice = socketio.test_client(app, flask_test_client=alice.client)
    ws_bob.get_received()
    sessions = alice.client.get("/api/sessions").get_json()["sessions"]
    alice.client.post("/api/sessions/revoke-others")
    alice.client.delete(f"/api/sessions/{sessions[0]['id']}")
    assert not ws_alice.is_connected()                                                   # live socket was closed
    assert not any(e["name"] == "typing" for e in ws_bob.get_received())


def test_cannot_send_to_peer_who_has_no_device_keys(make_user, app):
    from .conftest import PASSWORD
    alice = make_user("alice")
    bob = app.test_client()
    bob.post("/register", data={"username": "bob", "email": "bob@example.com", "display_name": "Bob", "password": PASSWORD, "confirm": PASSWORD})
    bob.post("/login", data={"identifier": "bob", "password": PASSWORD})
    bob_id = bob.get("/api/me").get_json()["user"]["id"]
    conv = alice.client.post("/api/conversations", json={"type": "direct", "user_id": bob_id}).get_json()["conversation"]["id"]
    r, _ = send(alice, conv, "anyone there?")
    assert r.status_code == 409 and r.get_json()["code"] == "peer_no_keys"
    assert EncryptedMessage.query.count() == 0