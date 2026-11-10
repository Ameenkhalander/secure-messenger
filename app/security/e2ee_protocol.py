"""End-to-end encryption protocol "E2EE-v1" (Python reference implementation).

Everything here uses the `cryptography` library (OpenSSL-backed) - no custom
primitives. The browser client (static/js/e2ee.js) implements the *same*
protocol with WebCrypto; tests/js and tests/test_crypto.py prove they interoperate.

Protocol summary
----------------
Identity   Every device owns an X25519 key pair (key agreement) and an Ed25519
           key pair (signatures). Private keys never leave the device.
Message    1. plaintext JSON is length-prefixed and zero-padded to 128-byte blocks
           2. a random 256-bit content key (CEK) + random 96-bit nonce encrypt it
              with AES-256-GCM; the AAD binds conversation, message id, sender key
              and timestamp
           3. for every recipient device: an ephemeral X25519 key is agreed with the
              device's public key -> HKDF-SHA256 -> AES-256-GCM wraps the CEK
           4. the sender signs (Ed25519) every field above, including a digest of
              all envelopes
Receiving  verify signature FIRST, then unwrap CEK, then decrypt. Any failure
           raises E2EEError and the message is rejected.

The *server* only ever calls the validation / signature-verification helpers.
encrypt_message / decrypt_message exist for tests, demos and as a reference.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PAD_BLOCK = 128
KEY_LEN = 32
NONCE_LEN = 12
SIG_LEN = 64
WRAPPED_LEN = 32 + 16  # CEK + GCM tag
MAX_CIPHERTEXT = 64 * 1024

_RAW = dict(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
)


class E2EEError(Exception):
    """Raised for any malformed, forged or undecryptable E2EE data."""


# --------------------------------------------------------------------------- #
# encoding helpers
# --------------------------------------------------------------------------- #
def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value, *, length: int | None = None, max_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise E2EEError("expected a base64 string")
    if max_len is not None and len(value) > (max_len * 4) // 3 + 8:
        raise E2EEError("value too long")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise E2EEError("invalid base64") from exc
    if length is not None and len(raw) != length:
        raise E2EEError(f"expected {length} bytes, got {len(raw)}")
    if max_len is not None and len(raw) > max_len:
        raise E2EEError("value too long")
    return raw


def encode_fields(fields) -> bytes:
    """Unambiguous length-prefixed encoding (mirrored by encodeFields in e2ee.js)."""
    out = bytearray()
    for field in fields:
        if isinstance(field, (bytes, bytearray)):
            raw = bytes(field)
        elif isinstance(field, bool):
            raise TypeError("bool is not a valid field")
        elif isinstance(field, int):
            raw = str(field).encode("ascii")
        else:
            raw = str(field).encode("utf-8")
        out += struct.pack(">I", len(raw)) + raw
    return bytes(out)


def pad(data: bytes) -> bytes:
    frame = struct.pack(">I", len(data)) + data
    return frame + b"\x00" * ((-len(frame)) % PAD_BLOCK)


def unpad(frame: bytes) -> bytes:
    if len(frame) < 4 or len(frame) % PAD_BLOCK:
        raise E2EEError("bad frame")
    (n,) = struct.unpack(">I", frame[:4])
    if n > len(frame) - 4:
        raise E2EEError("bad frame length")
    return frame[4 : 4 + n]


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #
_PROBE = X25519PrivateKey.generate()


def validate_enc_public_key(value) -> bytes:
    """Return raw X25519 public key bytes or raise E2EEError (rejects bad/low-order points)."""
    raw = b64d(value, length=KEY_LEN)
    try:
        pub = X25519PublicKey.from_public_bytes(raw)
        _PROBE.exchange(pub)  # OpenSSL rejects low-order points (all-zero secret)
    except ValueError as exc:
        raise E2EEError("invalid X25519 public key") from exc
    return raw


def validate_sign_public_key(value) -> bytes:
    raw = b64d(value, length=KEY_LEN)
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise E2EEError("invalid Ed25519 public key") from exc
    return raw


def fingerprint(enc_pub: bytes, sign_pub: bytes) -> str:
    """SHA-256 fingerprint shown to users for out-of-band verification."""
    return hashlib.sha256(b"E2EE-FP-v1" + enc_pub + sign_pub).hexdigest()


def registration_message(enc_pub: bytes, sign_pub: bytes) -> bytes:
    return encode_fields(["E2EE-KEY-REG-v1", enc_pub, sign_pub])


def rotation_message(enc_pub: bytes, sign_pub: bytes) -> bytes:
    return encode_fields(["E2EE-KEY-ROTATE-v1", enc_pub, sign_pub])


def verify_signature(sign_pub: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(sign_pub).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


class Identity:
    """A device identity (test / reference client). Holds PRIVATE keys."""

    def __init__(self):
        self.enc_private = X25519PrivateKey.generate()
        self.sign_private = Ed25519PrivateKey.generate()
        self.enc_pub = self.enc_private.public_key().public_bytes(**_RAW)
        self.sign_pub = self.sign_private.public_key().public_bytes(**_RAW)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.enc_pub, self.sign_pub)

    def registration_payload(self, name="test device") -> dict:
        return {
            "name": name,
            "enc_pub": b64e(self.enc_pub),
            "sign_pub": b64e(self.sign_pub),
            "pop_sig": b64e(
                self.sign_private.sign(registration_message(self.enc_pub, self.sign_pub))
            ),
        }


# --------------------------------------------------------------------------- #
# message signing / verification
# --------------------------------------------------------------------------- #
def envelopes_digest(envelopes) -> bytes:
    parts: list = []
    for env in sorted(envelopes, key=lambda e: int(e["k"])):
        parts += [int(env["k"]), b64d(env["epk"]), b64d(env["n"]), b64d(env["w"])]
    return hashlib.sha256(encode_fields(parts)).digest()


def signing_bytes(conv_id, client_msg_id, sender_key_id, timestamp, nonce, ciphertext, envelopes) -> bytes:
    return encode_fields(
        [
            "E2EE-SIG-v1",
            conv_id,
            client_msg_id,
            sender_key_id,
            timestamp,
            nonce,
            ciphertext,
            envelopes_digest(envelopes),
        ]
    )


def message_signing_bytes(msg: dict) -> bytes:
    return signing_bytes(
        msg["conversation_id"],
        msg["client_msg_id"],
        msg["sender_key_id"],
        msg["timestamp"],
        b64d(msg["nonce"]),
        b64d(msg["ciphertext"]),
        msg["envelopes"],
    )


def verify_message_signature(msg: dict, sender_sign_pub: bytes) -> bool:
    """Used by the SERVER on upload and by clients on receipt."""
    try:
        return verify_signature(
            sender_sign_pub, message_signing_bytes(msg), b64d(msg["signature"], length=SIG_LEN)
        )
    except (E2EEError, KeyError, TypeError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# encrypt / decrypt (reference client)
# --------------------------------------------------------------------------- #
def _content_aad(conv_id, client_msg_id, sender_key_id, timestamp) -> bytes:
    return encode_fields(["E2EE-AAD-v1", conv_id, client_msg_id, sender_key_id, timestamp])


def _wrap_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes, conv_id, client_msg_id, key_id) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub + recipient_pub,
        info=encode_fields(["E2EE-WRAP-v1", conv_id, client_msg_id, key_id]),
    ).derive(shared)


def _wrap_aad(client_msg_id, key_id) -> bytes:
    return encode_fields(["E2EE-WRAPAAD-v1", client_msg_id, key_id])


def encrypt_message(
    *,
    conv_id,
    client_msg_id: str,
    timestamp: int,
    payload: dict,
    sender_key_id: int,
    sender_sign_private: Ed25519PrivateKey,
    recipients: list[tuple[int, bytes]],
) -> dict:
    """Encrypt `payload` for every (key_id, enc_pub) recipient and sign the result."""
    frame = pad(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    cek, nonce = os.urandom(KEY_LEN), os.urandom(NONCE_LEN)
    ciphertext = AESGCM(cek).encrypt(
        nonce, frame, _content_aad(conv_id, client_msg_id, sender_key_id, timestamp)
    )
    envelopes = []
    for key_id, enc_pub in recipients:
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(**_RAW)
        shared = eph.exchange(X25519PublicKey.from_public_bytes(enc_pub))
        wrap_key = _wrap_key(shared, eph_pub, enc_pub, conv_id, client_msg_id, key_id)
        wrap_nonce = os.urandom(NONCE_LEN)
        wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, cek, _wrap_aad(client_msg_id, key_id))
        envelopes.append(
            {"k": key_id, "epk": b64e(eph_pub), "n": b64e(wrap_nonce), "w": b64e(wrapped)}
        )
    signature = sender_sign_private.sign(
        signing_bytes(conv_id, client_msg_id, sender_key_id, timestamp, nonce, ciphertext, envelopes)
    )
    return {
        "conversation_id": conv_id,
        "client_msg_id": client_msg_id,
        "timestamp": timestamp,
        "sender_key_id": sender_key_id,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "signature": b64e(signature),
        "envelopes": envelopes,
    }


def decrypt_message(msg: dict, *, my_key_id: int, my_enc_private: X25519PrivateKey, sender_sign_pub: bytes) -> dict:
    """Verify, then decrypt. Raises E2EEError for anything that is not authentic."""
    if not verify_message_signature(msg, sender_sign_pub):
        raise E2EEError("invalid signature")
    env = next((e for e in msg["envelopes"] if int(e["k"]) == my_key_id), None)
    if env is None:
        raise E2EEError("no envelope for this device")
    conv_id, mid = msg["conversation_id"], msg["client_msg_id"]
    try:
        my_pub = my_enc_private.public_key().public_bytes(**_RAW)
        eph_pub = b64d(env["epk"], length=KEY_LEN)
        shared = my_enc_private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        wrap_key = _wrap_key(shared, eph_pub, my_pub, conv_id, mid, my_key_id)
        cek = AESGCM(wrap_key).decrypt(
            b64d(env["n"], length=NONCE_LEN), b64d(env["w"], length=WRAPPED_LEN), _wrap_aad(mid, my_key_id)
        )
        frame = AESGCM(cek).decrypt(
            b64d(msg["nonce"], length=NONCE_LEN),
            b64d(msg["ciphertext"], max_len=MAX_CIPHERTEXT),
            _content_aad(conv_id, mid, msg["sender_key_id"], msg["timestamp"]),
        )
        return json.loads(unpad(frame).decode("utf-8"))
    except (InvalidTag, ValueError, KeyError) as exc:
        raise E2EEError("decryption failed") from exc
