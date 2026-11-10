"""In-memory presence registry (single process). Use a Socket.IO message queue to scale out."""
import threading

_lock = threading.Lock()
_conns: dict[str, tuple[int, int]] = {}  # socket sid -> (user_id, login_session_id)


def add(sid: str, user_id: int, login_session_id: int) -> bool:
    """Register a connection. Returns True if this is the user's first connection."""
    with _lock:
        first = not any(u == user_id for u, _ in _conns.values())
        _conns[sid] = (user_id, login_session_id)
        return first


def remove(sid: str):
    """Drop a connection. Returns (user_id, was_last) or None."""
    with _lock:
        entry = _conns.pop(sid, None)
        if not entry:
            return None
        user_id = entry[0]
        return user_id, not any(u == user_id for u, _ in _conns.values())


def info(sid: str):
    with _lock:
        return _conns.get(sid)


def online_ids() -> set[int]:
    with _lock:
        return {u for u, _ in _conns.values()}


def is_online(user_id: int) -> bool:
    return user_id in online_ids()


def sids_for_session(login_session_id: int) -> list[str]:
    with _lock:
        return [sid for sid, (_, ls) in _conns.items() if ls == login_session_id]


def sids_for_user(user_id: int) -> list[str]:
    with _lock:
        return [sid for sid, (u, _) in _conns.items() if u == user_id]


def clear():
    with _lock:
        _conns.clear()
