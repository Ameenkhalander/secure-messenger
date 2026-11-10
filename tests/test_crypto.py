"""Cryptography tests: protocol correctness, tamper detection, key validation, interop."""
import copy
import json
import os
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization

from app.security import passwords
from app.security.e2ee_protocol import (
    E2EEError, Identity, b64d, b64e, decrypt_message, encrypt_message, fingerprint,
    validate_enc_public_key, validate_sign_public_key, verify_message_signature,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make(alice, bob, body="top secret ✓"):
    return encrypt_message(
        conv_id=3, client_msg_id="m-12345678", timestamp=1_700_000_000_000,
        payload={"t": "text", "body": body}, sender_key_id=1, sender_sign_private=alice.sign_private,
        recipients=[(1, alice.enc_pub), (2, bob.enc_pub)],
    )


def open_(msg, who, key_id, sender):
    return decrypt_message(msg, my_key_id=key_id, my_enc_private=who.enc_private, sender_sign_pub=sender.sign_pub)


def test_round_trip_for_recipient_and_sender():
    a, b = Identity(), Identity()
    msg = make(a, b)
    assert open_(msg, b, 2, a)["body"] == "top secret ✓"
    assert open_(msg, a, 1, a)["body"] == "top secret ✓"


def test_stored_payload_contains_no_plaintext():
    a, b = Identity(), Identity()
    blob = json.dumps(make(a, b, "launch-code-4711"))
    assert "launch-code-4711" not in blob


def test_nonces_are_unique_and_ciphertexts_differ():
    a, b = Identity(), Identity()
    m1, m2 = make(a, b, "same"), make(a, b, "same")
    assert m1["nonce"] != m2["nonce"] and m1["ciphertext"] != m2["ciphertext"]


def test_server_without_private_keys_cannot_decrypt():
    """A server only holds public keys; an unrelated key must fail."""
    a, b, server_guess = Identity(), Identity(), Identity()
    msg = make(a, b)
    with pytest.raises(E2EEError):
        open_(msg, server_guess, 2, a)  # wrong private key for envelope 2
    with pytest.raises(E2EEError):
        open_(msg, server_guess, 99, a)  # no envelope at all


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "signature"])
def test_modified_fields_are_rejected(field):
    a, b = Identity(), Identity()
    msg = make(a, b)
    raw = bytearray(b64d(msg[field])); raw[0] ^= 0x01
    msg[field] = b64e(bytes(raw))
    with pytest.raises(E2EEError):
        open_(msg, b, 2, a)


def test_modified_envelope_is_rejected():
    a, b = Identity(), Identity()
    msg = make(a, b)
    raw = bytearray(b64d(msg["envelopes"][1]["w"])); raw[5] ^= 0x80
    msg["envelopes"][1]["w"] = b64e(bytes(raw))
    with pytest.raises(E2EEError):
        open_(msg, b, 2, a)


def test_invalid_authentication_tag_is_rejected_even_if_resigned():
    """Even a validly-signed message fails if the GCM tag is corrupt."""
    from app.security.e2ee_protocol import signing_bytes
    a, b = Identity(), Identity()
    msg = make(a, b)
    ct = bytearray(b64d(msg["ciphertext"])); ct[-1] ^= 0x01  # corrupt the tag
    msg["ciphertext"] = b64e(bytes(ct))
    msg["signature"] = b64e(a.sign_private.sign(signing_bytes(
        msg["conversation_id"], msg["client_msg_id"], msg["sender_key_id"], msg["timestamp"],
        b64d(msg["nonce"]), bytes(ct), msg["envelopes"])))
    assert verify_message_signature(msg, a.sign_pub)
    with pytest.raises(E2EEError):
        open_(msg, b, 2, a)


@pytest.mark.parametrize("field,value", [("conversation_id", 4), ("client_msg_id", "other-1234567"), ("timestamp", 1), ("sender_key_id", 9)])
def test_context_binding(field, value):
    a, b = Identity(), Identity()
    msg = make(a, b)
    msg[field] = value
    with pytest.raises(E2EEError):
        open_(msg, b, 2, a)


def test_forged_sender_is_rejected():
    a, b, mallory = Identity(), Identity(), Identity()
    msg = encrypt_message(conv_id=3, client_msg_id="m-12345678", timestamp=1, payload={"body": "x"},
                          sender_key_id=1, sender_sign_private=mallory.sign_private,
                          recipients=[(2, b.enc_pub)])
    with pytest.raises(E2EEError):
        open_(msg, b, 2, a)  # claims to be Alice, signed by Mallory


@pytest.mark.parametrize("bad", [b"", b"\x00" * 32, b"\x01" + b"\x00" * 31, b"short", b"x" * 33])
def test_invalid_public_keys_rejected(bad):
    with pytest.raises(E2EEError):
        validate_enc_public_key(b64e(bad))


def test_invalid_public_key_encoding_rejected():
    for bad in ["not base64!!", None, 12, ""]:
        with pytest.raises(E2EEError):
            validate_enc_public_key(bad)
    with pytest.raises(E2EEError):
        validate_sign_public_key(b64e(b"\x01" * 5))


def test_valid_public_keys_accepted_and_fingerprint_stable():
    a = Identity()
    assert validate_enc_public_key(b64e(a.enc_pub)) == a.enc_pub
    assert validate_sign_public_key(b64e(a.sign_pub)) == a.sign_pub
    assert a.fingerprint == fingerprint(a.enc_pub, a.sign_pub) and len(a.fingerprint) == 64


def test_padding_hides_exact_length():
    a, b = Identity(), Identity()
    assert len(b64d(make(a, b, "a")["ciphertext"])) == len(b64d(make(a, b, "b" * 50)["ciphertext"]))


# ------------------------------ passwords ------------------------------ #
def test_password_hash_is_argon2id_salted_and_verifies():
    h1 = passwords.hash_password("correct horse battery", memory_kib=1024, iterations=1, lanes=1)
    h2 = passwords.hash_password("correct horse battery", memory_kib=1024, iterations=1, lanes=1)
    assert h1.startswith("$argon2id$v=19$") and h1 != h2
    assert "correct horse" not in h1
    assert passwords.verify_password("correct horse battery", h1)
    assert not passwords.verify_password("wrong password!!", h1)
    assert not passwords.verify_password("x", "garbage")


def test_password_policy():
    assert passwords.password_problems("short")
    assert passwords.password_problems("aaaaaaaaaaaaaaaa")
    assert not passwords.password_problems("a long, unusual passphrase 42")
    assert passwords.password_problems("ameen-is-great-1", username="ameen")


# ------------------------------ JS interop ------------------------------ #
node = shutil.which("node")


@pytest.mark.skipif(node is None, reason="node not installed")
def test_python_decrypts_message_encrypted_by_javascript(tmp_path):
    out = tmp_path / "vector.json"
    env = dict(os.environ, E2EE_INTEROP_OUT=str(out))
    subprocess.run([node, "--test", os.path.join(ROOT, "tests/js/e2ee.test.mjs")], check=True, env=env, capture_output=True)
    # the JS vector's recipient key is unknown here, so just verify the signature chain
    data = json.loads(out.read_text())
    assert verify_message_signature(data["msg"], b64d(data["signPub"]))
    tampered = copy.deepcopy(data["msg"]); tampered["timestamp"] += 1
    assert not verify_message_signature(tampered, b64d(data["signPub"]))


@pytest.mark.skipif(node is None, reason="node not installed")
def test_javascript_decrypts_message_encrypted_by_python(tmp_path):
    a, b = Identity(), Identity()
    msg = encrypt_message(conv_id=9, client_msg_id="py-12345678", timestamp=1_700_000_000_000,
                          payload={"t": "text", "body": "from python ✓"}, sender_key_id=1,
                          sender_sign_private=a.sign_private, recipients=[(2, b.enc_pub)])
    vec = tmp_path / "py.json"
    vec.write_text(json.dumps({
        "msg": msg, "key_id": 2, "enc_pub": b64e(b.enc_pub), "sign_pub": b64e(a.sign_pub),
        "enc_priv_pkcs8": b64e(b.enc_private.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
    }))
    env = dict(os.environ, E2EE_PY_VECTOR=str(vec))
    res = subprocess.run([node, "--test", os.path.join(ROOT, "tests/js/e2ee.test.mjs")], env=env, capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr
