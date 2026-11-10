# Contributing

1. Fork, then create a branch: `git checkout -b feature/short-name`.
2. Set up: `python -m venv .venv`, install `requirements-dev.txt`.
3. Run `pytest` and `npm run test:js` (Node 20+). Both must pass.
4. Never add custom cryptography. Changes to `app/security/e2ee_protocol.py` and `app/static/js/e2ee.js` must stay byte-compatible; update both and the interop tests.
5. Never commit secrets, `.env`, databases or keys.
6. Open a pull request describing the change and its security impact.

Report vulnerabilities privately (see SECURITY.md), not in public issues.
