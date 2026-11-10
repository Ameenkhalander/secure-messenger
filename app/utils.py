from datetime import datetime, timezone
import re


def utcnow() -> datetime:
    """Naive UTC 'now' (SQLite drops tzinfo, so the whole app uses naive UTC)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


_UA_FAMILIES = ("Edg/", "OPR/", "Firefox/", "Chrome/", "Safari/", "curl/", "python-requests", "okhttp")
_OS = (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"),
       ("Mac OS X", "macOS"), ("Linux", "Linux"))


def describe_user_agent(ua: str | None) -> str:
    ua = ua or ""
    browser = next((f.rstrip("/ ") for f in _UA_FAMILIES if f in ua), "Unknown browser")
    os_name = next((n for key, n in _OS if key in ua), "Unknown OS")
    return f"{browser} on {os_name}"


_USERNAME_RE = re.compile(r"^[a-z0-9_]{3,32}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def valid_username(value: str) -> bool:
    return bool(_USERNAME_RE.fullmatch(value or ""))


def valid_email(value: str) -> bool:
    return bool(value) and len(value) <= 254 and bool(_EMAIL_RE.fullmatch(value))


def clean_text(value, max_len: int) -> str:
    """Trim, drop control characters, cap length."""
    if not isinstance(value, str):
        return ""
    value = "".join(ch for ch in value if ch.isprintable())
    return value.strip()[:max_len]
