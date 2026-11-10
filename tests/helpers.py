import time
import uuid

from app.security.e2ee_protocol import b64d, encrypt_message


def encrypted_payload(sender, conv_id, text, recipients_json, **overrides):
    """Build a signed, encrypted message exactly as the browser client would."""
    recipients = [(k["id"], b64d(k["enc_pub"])) for k in recipients_json]
    msg = encrypt_message(
        conv_id=conv_id, client_msg_id=overrides.pop("client_msg_id", str(uuid.uuid4())),
        timestamp=overrides.pop("timestamp", int(time.time() * 1000)), payload={"t": "text", "body": text},
        sender_key_id=sender.key_id, sender_sign_private=sender.identity.sign_private, recipients=recipients)
    msg.update(overrides)
    return msg


def send(sender, conv_id, text, **overrides):
    keys = sender.client.get(f"/api/conversations/{conv_id}/recipients").get_json()["keys"]
    payload = encrypted_payload(sender, conv_id, text, keys, **overrides)
    return sender.client.post(f"/api/conversations/{conv_id}/messages", json=payload), payload


def direct(a, b):
    r = a.client.post("/api/conversations", json={"type": "direct", "user_id": b.user_id})
    assert r.status_code == 201, r.data
    return r.get_json()["conversation"]["id"]
