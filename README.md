# ZeroDay — Secure Messaging System

Peer-to-peer end-to-end encrypted messaging with a desktop-hosted blockchain key registry.

```
   Phone / Laptop / Tablet                 Phone / Laptop / Tablet
   ┌─────────────────┐                     ┌─────────────────┐
   │   Web client    │                     │   Web client    │
   │   (React PWA)   │                     │   (React PWA)   │
   └────┬──────┬─────┘                     └────┬──────┬─────┘
        │      │                                │      │
        │      │   WebRTC P2P                   │      │
        │      └────────── (encrypted) ─────────┘      │
        │                                              │
        │  HTTP + WebSocket                            │  HTTP + WebSocket
        ▼                                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │              YOUR DESKTOP (FastAPI server)              │
   │   ┌──────────────────────────────────────────────┐      │
   │   │  /api/register, /api/lookup, /api/revoke     │      │
   │   │  /api/document  (key registry + doc audit)   │      │
   │   │  /ws/signal/{user_id}  (WebRTC signaling)    │      │
   │   └──────────────────────────────────────────────┘      │
   │   ┌──────────────────────────────────────────────┐      │
   │   │  SQLite-backed blockchain (data/blockchain.db)│     │
   │   └──────────────────────────────────────────────┘      │
   └─────────────────────────────────────────────────────────┘
```

The desktop server stores the blockchain. Web clients run anywhere — phones, laptops, tablets — and connect to your server for key lookup and WebRTC signaling. Once peers connect, all chat traffic flows directly browser-to-browser. The server never sees plaintext messages.

## What's Where

```
zerodday-system/
├── server/          FastAPI + SQLite blockchain
│   ├── app/
│   │   ├── main.py        REST API + WebSocket signaling
│   │   ├── blockchain.py  Persistent chain (SQLite)
│   │   └── __init__.py
│   ├── data/              Created at runtime; SQLite DB lives here
│   ├── requirements.txt
│   ├── test_endpoints.py  REST API tests
│   └── test_signaling.py  WebSocket tests
│
├── client/          React (Vite) web app
│   └── src/
│       ├── lib/
│       │   ├── crypto.js   Ed25519 / X25519 / HKDF / AES-GCM (browser)
│       │   ├── api.js      REST client
│       │   ├── peer.js     WebRTC P2P manager
│       │   └── channel.js  Secure channel (handshake + AEAD)
│       └── App.jsx
│
└── docs/            Setup, API reference, exposing publicly
```

## Quick Start (5 minutes)

### 1. Run the blockchain server (your desktop)

```bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8765
```

The server now listens on port 8765 of your machine. Test it:

```bash
curl http://localhost:8765/api/health
```

### 2. Run the web client (any machine on your network)

```bash
cd client
npm install
npm run dev
```

Open `http://localhost:5173` and pick a username. Your Ed25519 identity key is generated locally and registered on the blockchain.

### 3. Test from another device

On a second device on the same Wi-Fi:

```bash
# In client/
VITE_API_URL=http://YOUR_DESKTOP_IP:8765 npm run dev -- --host
```

Or visit your dev URL from a phone browser.

## Exposing It to the Internet

The web client must reach your server, and the server must allow connections. Two options:

### Option A: ngrok (easiest, for demos)

```bash
ngrok http 8765
# Copy the https://*.ngrok.io URL
cd client
VITE_API_URL=https://abc123.ngrok.io npm run build
```

Now anyone with the client URL can register and chat through your blockchain.

### Option B: Direct port forwarding (permanent)

Forward port 8765 on your router to your desktop's LAN IP. Use your public IP or DDNS hostname as `VITE_API_URL`.

For HTTPS (required for WebRTC microphone, etc., but not for our text chat), put nginx in front and use Let's Encrypt.

See `docs/DEPLOYMENT.md` for production setup.

## Crypto Stack

| Layer | Algorithm | Library |
|-------|-----------|---------|
| Identity signing | Ed25519 | tweetnacl (browser) |
| Key exchange | X25519 | tweetnacl (browser) |
| Key derivation | HKDF-SHA256 | Web Crypto API |
| Message encryption | AES-256-GCM | Web Crypto API |
| Document hashing | SHA-256 | Web Crypto API |
| Server crypto | Ed25519 verify | `cryptography` (Python) |

## Security Properties

- **End-to-end encryption** — messages encrypt in browser A, decrypt only in browser B. Server never sees plaintext.
- **Identity verification** — every peer's public key is checked against the blockchain registry before handshake.
- **Forward secrecy** — fresh X25519 ephemeral keys per session.
- **Replay protection** — monotonic sequence numbers, GCM auth tags.
- **MITM detection** — handshake aborts if peer's identity key doesn't match what's on-chain.
- **No hardcoded keys** — generated at runtime in browser via `nacl.sign.keyPair()`.
- **Self-signed registration** — clients prove they own a key by signing `register:<userid>` before the server accepts the registration.

## API Reference

See `docs/API.md`.

## Running Tests

```bash
cd server
# Start server first
uvicorn app.main:app --port 8765 &

python test_endpoints.py   # 12 REST endpoint tests
python test_signaling.py   # WebSocket signaling test
```
