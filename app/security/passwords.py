"""Argon2id password hashing (via the `cryptography` library, PHC string format)."""
from __future__ import annotations

import base64
import hmac
import os
import re

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# OWASP-recommended minimum profile: m=19 MiB, t=2, p=1. We default higher.
DEFAULT_MEMORY_KIB = 65536
DEFAULT_ITERATIONS = 3
DEFAULT_LANES = 4
_PREFIX = "$argon2id$v=19$"
_RE = re.compile(r"^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, *, memory_kib=DEFAULT_MEMORY_KIB, iterations=DEFAULT_ITERATIONS, lanes=DEFAULT_LANES) -> str:
    salt = os.urandom(16)
    digest = Argon2id(
        salt=salt, length=32, iterations=iterations, lanes=lanes, memory_cost=memory_kib
    ).derive(password.encode("utf-8"))
    return f"{_PREFIX}m={memory_kib},t={iterations},p={lanes}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    match = _RE.match(encoded or "")
    if not match:
        return False
    memory_kib, iterations, lanes = (int(match.group(i)) for i in (1, 2, 3))
    salt, expected = _unb64(match.group(4)), _unb64(match.group(5))
    try:
        Argon2id(
            salt=salt, length=len(expected), iterations=iterations, lanes=lanes, memory_cost=memory_kib
        ).verify(password.encode("utf-8"), expected)
        return True
    except InvalidKey:
        return False


def needs_rehash(encoded: str, *, memory_kib=DEFAULT_MEMORY_KIB, iterations=DEFAULT_ITERATIONS, lanes=DEFAULT_LANES) -> bool:
    match = _RE.match(encoded or "")
    return not match or tuple(int(match.group(i)) for i in (1, 2, 3)) != (memory_kib, iterations, lanes)


_COMMON = {
    "password1234", "123456789012", "qwertyuiop12", "iloveyou1234", "letmein12345",
    "administrator", "welcome12345", "passw0rd1234", "password12345", "changeme1234",
}


def password_problems(password: str, *, username: str = "", email: str = "") -> list[str]:
    problems = []
    if len(password) < 12:
        problems.append("Use at least 12 characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if len(set(password)) < 5:
        problems.append("Use a wider variety of characters.")
    low = password.lower()
    if low in _COMMON:
        problems.append("That password is too common.")
    for secret in (username, email.split("@")[0] if email else ""):
        if secret and len(secret) >= 3 and secret.lower() in low:
            problems.append("Do not include your username or email in the password.")
            break
    return problems


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
