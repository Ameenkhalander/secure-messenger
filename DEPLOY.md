# Deploying to Render (free, HTTPS included)

1. Push the project to GitHub (check `.env` and `instance/` are NOT committed; `.gitignore` handles this):
   ```powershell
   git init; git add .; git commit -m "Sealed messenger"
   git branch -M main
   git remote add origin https://github.com/<you>/secure-messenger.git
   git push -u origin main
   ```
2. On render.com: **New +, Blueprint**, choose the repo. Render reads `render.yaml`, creates the web service and a PostgreSQL database, and generates `SECRET_KEY`.
3. When the build finishes open the `https://<name>.onrender.com` URL, register two accounts in two browsers, and chat.

Notes
- Production mode sets Secure cookies and HSTS automatically; the app trusts Render's proxy headers (`TRUSTED_PROXY_COUNT=1`) and allows WebSocket handshakes only from its own URL.
- Free web services sleep after 15 idle minutes (first request takes about a minute) and free databases expire after a period (about 90 days when I checked); confirm current limits on Render's pricing page. Browser-held keys are unaffected, but a database reset deletes accounts and ciphertext, and users must re-register.
- If WebSockets are blocked on your plan, Socket.IO falls back to long polling automatically.
- Other hosts work too: any Docker host (Fly.io, Railway, Hugging Face Docker Space, a VPS) can run the included `Dockerfile`. Set `SECRET_KEY`, `DATABASE_URL`, `COOKIE_SECURE=true`, `TRUSTED_PROXY_COUNT=1`, and `SOCKETIO_CORS_ORIGINS=https://your-domain`.
