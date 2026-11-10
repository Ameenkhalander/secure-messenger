# REST API

All endpoints are under `/api`, require a signed-in session cookie, and (for POST/DELETE) an `X-CSRF-Token` header whose value is in `<meta name="csrf-token">`. Errors are `{ "error": "...", "code": "..." }`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/me` | Current user |
| GET | `/api/users/search?q=` | Prefix search by username or name (min 2 chars, 30/min) |
| GET | `/api/devices` | Your devices and current public keys |
| POST | `/api/devices` | Register a device: `{name, enc_pub, sign_pub, pop_sig}` (base64; `pop_sig` is an Ed25519 proof of possession) |
| POST | `/api/devices/<id>/rotate` | Rotate keys: new keys + `pop_sig` + `prev_sig` signed by the old key |
| DELETE | `/api/devices/<id>` | Remove a device and retire its keys |
| GET | `/api/conversations` | Conversations with unread counts and last (encrypted) message |
| POST | `/api/conversations` | `{type:"direct", user_id}` or `{type:"group", name, member_ids}` |
| GET | `/api/conversations/<id>` | Conversation details |
| GET | `/api/conversations/<id>/recipients` | Active public keys of all members (for envelope fan-out) |
| POST | `/api/conversations/<id>/members` | Admin: add `{user_id}` |
| DELETE | `/api/conversations/<id>/members/<uid>` | Admin removes, or a member leaves |
| POST | `/api/conversations/<id>/members/<uid>/role` | Admin: `{role:"admin"|"member"}` |
| GET | `/api/conversations/<id>/messages?before_id=&limit=` | Encrypted messages |
| POST | `/api/conversations/<id>/messages` | Upload `{client_msg_id, timestamp, sender_key_id, nonce, ciphertext, signature, envelopes}` |
| DELETE | `/api/messages/<id>` | Sender deletes; ciphertext is erased |
| POST | `/api/receipts` | `{message_ids, status:"delivered"|"read"}` |
| GET | `/api/sessions` | Active login sessions |
| DELETE | `/api/sessions/<id>` | Sign a session out (also closes its WebSocket) |
| POST | `/api/sessions/revoke-others` | Sign out everything else |
| POST | `/api/security/acknowledge` | Mark warnings as seen |

## Socket.IO events

Server to client: `message:new`, `message:deleted`, `receipt:update`, `presence:update`, `typing`, `conversation:updated`, `security:alert`.
Client to server: `typing {conversation_id, typing}`.
The handshake uses the session cookie; cross-origin handshakes are refused; each event re-validates the session.
