# Sealed: end-to-end encrypted messenger

A private messaging app where messages are encrypted in the browser and the server only stores ciphertext. Built with Flask, Flask-SocketIO, SQLAlchemy and WebCrypto.

> Educational project. The protocol composes standard primitives but has **not** been independently audited. See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Features
- Registration, login/logout, Argon2id hashing, lockout, rate limiting, session expiry, password reset, account settings
- Client-side E2EE: X25519 + HKDF + AES-256-GCM, Ed25519 signatures, unique nonces, key rotation
- One-to-one and group chats (admins, add/remove members), real-time delivery, read receipts, typing, presence, unread counters, delete for everyone
- Security dashboard: encryption status, devices and fingerprints, active sessions, login history, suspicious-login alerts
- Dark/light themes, responsive layout (mobile and desktop)

## Screenshots
| Chat | Security dashboard |
|---|---|
| _docs/screenshots/chat.png_ | _docs/screenshots/security.png_ |

## Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (diagram) and [docs/API.md](docs/API.md).

## Run locally (Windows PowerShell)
Requires Python 3.12+ and a current browser (Chrome/Edge 137+, Firefox 130+, Safari 17+ for X25519/Ed25519 in WebCrypto). Use `http://localhost`: WebCrypto needs a secure context.

```powershell
cd secure-messenger
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
python run.py
```
Open http://localhost:5000, register two accounts in two different browsers (or one normal and one private window), and start chatting.

## Run tests
```powershell
pytest                 # backend, security and crypto tests
node --test tests/js/*.test.mjs   # browser crypto module (Node 20+)
```

## Linux
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export APP_ENV=production SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))") COOKIE_SECURE=false
python -c "from app import create_app; from app.extensions import db; a=create_app(); a.app_context().push(); db.create_all()"
gunicorn --worker-class gthread --workers 1 --threads 100 --bind 0.0.0.0:8000 run:app
```
Put it behind an HTTPS reverse proxy (set `COOKIE_SECURE=true`, `TRUSTED_PROXY_COUNT=1`, and forward WebSocket upgrades).

## Docker
```powershell
# .env must contain SECRET_KEY and POSTGRES_PASSWORD
docker compose up --build
```
Open http://localhost:8000.

## Configuration
See `.env.example`. Never commit `.env`, databases or keys (`.gitignore` covers them).

## How it works
Each browser creates its own key pairs; private keys are non-extractable and never leave it. To send, the client wraps a fresh content key for every recipient device and signs the result. The server verifies signatures and relays opaque envelopes. Details: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md). License: [MIT](LICENSE).
