# Security model

## Protocol (E2EE-v1)
- **Keys**: each device generates X25519 (agreement) and Ed25519 (signing) key pairs in the browser with WebCrypto. Private keys are created non-extractable and stored in IndexedDB. Only public keys are uploaded, with an Ed25519 proof of possession.
- **Message**: padded JSON is encrypted with AES-256-GCM under a random 256-bit content key and random 96-bit nonce. The AAD binds conversation, message id, sender key and timestamp.
- **Key wrapping**: for every recipient device, an ephemeral X25519 key is agreed with that device's public key, run through HKDF-SHA256 (salt = ephemeral pub || recipient pub, info binds conversation/message/key ids), and used to AES-256-GCM-wrap the content key.
- **Authenticity**: the sender signs all fields plus a digest of all envelopes with Ed25519. Clients verify the signature before decrypting. The server also verifies it and rejects forgeries.
- **Groups**: sender-side fan-out to every active device of every member. Removing a member means they get no envelope for new messages. New members cannot read earlier history.
- **Replay**: unique `(sender, client_msg_id)`, a signed timestamp window (5 minutes), and context binding in AAD and signature.
- **Rotation**: new keys must be authorised by the old key's signature; retired keys stay in the DB so old messages verify.

## What the server can and cannot do
Cannot: read message text, obtain private keys, forge a message from a user whose key it does not hold. Can see: who talks to whom, when, message sizes (padded to 128 bytes), IPs, device public keys.

## Known limitations (read before any real deployment)
1. **Not audited.** This composes standard primitives in a custom protocol. For real use adopt an audited protocol such as Signal's (X3DH + Double Ratchet) or MLS for groups, and have it independently reviewed.
2. **No forward secrecy or post-compromise security per message.** A stolen device key decrypts every message addressed to it. Use key rotation; a ratchet would fix this.
3. **Key authenticity is trust-on-first-use.** A malicious server could substitute public keys at first contact. Users must compare safety numbers; the client warns when a contact's key changes.
4. **Browser trust.** The server delivers the JavaScript, so a compromised server could ship malicious code. Native or signed clients are stronger. CDN scripts are not SRI-pinned; vendor and pin them for production.
5. **Metadata is visible**, and presence/typing/receipts reveal activity.
6. **Device-bound keys.** Clearing browser data loses the keys and the ability to read old messages. There is no backup or multi-device sync.
7. **Single-process realtime.** Presence is in memory; use a Socket.IO message queue (Redis) to scale out.
8. **No attachments, no disappearing-message timers, no account deletion** in this version.

## Web hardening implemented
Argon2id passwords, lockout and generic login errors, server-side revocable sessions with idle/absolute expiry, session rotation on login, CSRF tokens plus Origin check, strict CSP (no inline script/style), clickjacking/MIME/referrer headers, HttpOnly SameSite cookies (Secure in production), rate limiting, parameterised ORM queries, Jinja autoescaping and `textContent` rendering, WebSocket session and origin checks, anti-enumeration on reset.
