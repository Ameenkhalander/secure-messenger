from flask import current_app

from ..extensions import db
from ..models import Device, PublicKey
from ..security import e2ee_protocol as e2ee
from ..services.errors import ServiceError
from ..services.security_service import log_event
from ..utils import clean_text, utcnow


def _parse_keys(data) -> tuple[bytes, bytes, bytes]:
    if not isinstance(data, dict):
        raise ServiceError("Invalid payload.")
    try:
        enc = e2ee.validate_enc_public_key(data.get("enc_pub"))
        sign = e2ee.validate_sign_public_key(data.get("sign_pub"))
        pop = e2ee.b64d(data.get("pop_sig"), length=e2ee.SIG_LEN)
    except e2ee.E2EEError as exc:
        raise ServiceError(f"Invalid public key material: {exc}", 400, "invalid_key") from exc
    # proof of possession: the device must hold the Ed25519 private key it registers
    if not e2ee.verify_signature(sign, e2ee.registration_message(enc, sign), pop):
        raise ServiceError("Proof-of-possession signature is invalid.", 400, "invalid_pop")
    return enc, sign, pop


def _ensure_unique(enc: bytes, sign: bytes):
    if PublicKey.query.filter((PublicKey.enc_pub == e2ee.b64e(enc)) | (PublicKey.sign_pub == e2ee.b64e(sign))).first():
        raise ServiceError("This key is already registered.", 409, "duplicate_key")


def current_key(device_id: int):
    return PublicKey.query.filter_by(device_id=device_id, retired_at=None).first()


def register_device(user, data):
    enc, sign, _ = _parse_keys(data)
    active = Device.query.filter_by(user_id=user.id, revoked_at=None).count()
    if active >= current_app.config["MAX_DEVICES_PER_USER"]:
        raise ServiceError("Device limit reached. Remove an old device first.", 409, "device_limit")
    _ensure_unique(enc, sign)
    device = Device(user_id=user.id, name=clean_text(data.get("name"), 80) or "Unnamed device", last_seen_at=utcnow())
    db.session.add(device)
    db.session.flush()
    key = PublicKey(user_id=user.id, device_id=device.id, enc_pub=e2ee.b64e(enc), sign_pub=e2ee.b64e(sign),
                    fingerprint=e2ee.fingerprint(enc, sign))
    db.session.add(key)
    db.session.commit()
    log_event("device_registered", user.id, "info", f"New device '{device.name}' registered.", alert=True)
    return device, key


def rotate_key(user, device_id: int, data):
    device = Device.query.filter_by(id=device_id, user_id=user.id, revoked_at=None).first()
    if not device:
        raise ServiceError("Device not found.", 404)
    enc, sign, _ = _parse_keys(data)
    old = current_key(device.id)
    try:  # rotation must be authorised by the key being replaced (continuity of trust)
        prev = e2ee.b64d(data.get("prev_sig"), length=e2ee.SIG_LEN)
    except e2ee.E2EEError as exc:
        raise ServiceError("Missing rotation signature.", 400, "invalid_rotation") from exc
    if old is None or not e2ee.verify_signature(e2ee.b64d(old.sign_pub), e2ee.rotation_message(enc, sign), prev):
        raise ServiceError("Rotation must be signed by the current key.", 400, "invalid_rotation")
    _ensure_unique(enc, sign)
    old.retired_at = utcnow()
    key = PublicKey(user_id=user.id, device_id=device.id, enc_pub=e2ee.b64e(enc), sign_pub=e2ee.b64e(sign),
                    fingerprint=e2ee.fingerprint(enc, sign))
    db.session.add(key)
    db.session.commit()
    log_event("key_rotated", user.id, "info", f"Encryption keys rotated on '{device.name}'.", alert=True)
    return device, key


def revoke_device(user, device_id: int):
    device = Device.query.filter_by(id=device_id, user_id=user.id, revoked_at=None).first()
    if not device:
        raise ServiceError("Device not found.", 404)
    now = utcnow()
    device.revoked_at = now
    for key in PublicKey.query.filter_by(device_id=device.id, retired_at=None).all():
        key.retired_at = now
    db.session.commit()
    log_event("device_revoked", user.id, "warning", f"Device '{device.name}' was removed.", alert=True)
    return device


def active_keys(user_ids):
    """Current public keys of non-revoked devices for the given users."""
    if not user_ids:
        return []
    return (PublicKey.query.join(Device, Device.id == PublicKey.device_id)
            .filter(PublicKey.user_id.in_(list(user_ids)), PublicKey.retired_at.is_(None), Device.revoked_at.is_(None))
            .order_by(PublicKey.id).all())


def list_devices(user):
    out = []
    for dev in Device.query.filter_by(user_id=user.id).order_by(Device.id).all():
        out.append(dev.to_dict(current_key(dev.id)))
    return out
