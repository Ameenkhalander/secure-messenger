# Architecture

```mermaid
flowchart LR
  subgraph Browser["Browser (trusted device)"]
    UI[Chat UI] --> E2EE[e2ee.js WebCrypto]
    E2EE --> KS[(IndexedDB: non-extractable private keys)]
  end
  subgraph Server["Flask server (untrusted for content)"]
    API[REST API] --> SVC[Services]
    WS[Socket.IO] --> SVC
    SVC --> DB[(SQLite / PostgreSQL: ciphertext, public keys, metadata)]
  end
  E2EE -- "ciphertext + envelopes + signature" --> API
  WS -- "message:new (ciphertext only)" --> UI
```

Layers: `routes/` (HTTP), `services/` (business rules), `models/` (SQLAlchemy), `security/` (CSRF, headers, auth middleware, passwords, E2EE protocol), `sockets/` (realtime). The Python `e2ee_protocol.py` is used by the server only to validate keys and verify signatures; encrypt/decrypt exist for tests and as a reference that is proven interoperable with `static/js/e2ee.js`.
