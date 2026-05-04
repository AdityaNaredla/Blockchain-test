# ZeroDay

End-to-end encrypted P2P messaging with on-chain identity. Off-chain
messages over WebRTC, on-chain public keys in a SQLite-backed blockchain.
The server brokers introductions and stores public keys — nothing else.

**Live demo:** [blockchain-test-snowy.vercel.app](https://blockchain-test-snowy.vercel.app)

---

## What it does

- **Register an identity.** Username + password. Browser generates an Ed25519 keypair locally; the secret key is wrapped with a key derived from your password (PBKDF2 → AES-GCM) and the wrapped blob is stored server-side. The public key is committed to the blockchain.
- **Log in from anywhere.** Username + password fetches the wrapped blob; your browser unwraps it locally. Plaintext keys never leave the device.
- **Chat 1-on-1, end-to-end encrypted.** Browsers connect directly via WebRTC. Each session does an X25519 key exchange signed with Ed25519 (verified against the chain), derives an AES-256-GCM key via HKDF, and encrypts every message with replay-protected nonces and a tamper-detection auth tag.
- **Sign documents on-chain.** Hash any file (SHA-256) in your browser, sign with your Ed25519 key, commit signer + hash + signature as a chain block. Anyone can later verify `@you signed this exact file` without trusting the server.
- **Verify signatures publicly.** A no-auth `/verify` page accepts a file, hashes it locally, and queries the chain for matching signatures. Re-runs Ed25519 verification against each signer's current on-chain key.
- **Encrypted local message history.** Per-device IndexedDB store, AES-256-GCM at rest, key derived deterministically from your Ed25519 secret. Messages survive page reload; server still sees nothing.

---

## Run it locally

```bash
# Server (terminal 1)
cd server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
JWT_SECRET=$(openssl rand -hex 32) uvicorn app.main:app --reload --port 8765

# Client (terminal 2)
cd client
npm install
npm run dev
```

Open `http://localhost:5173`. To test chat, register one user in your normal browser and another in incognito — the chat is between two browsers because messages are P2P.

For deployment to Vercel + Railway, see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). There are several non-obvious cross-site cookie issues; that doc covers them all.

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │      FastAPI server         │
                    │  ─────────────────────────  │
                    │   /api/auth/*    (cookies)  │
                    │   /api/document/verify      │
                    │   /api/lookup, /api/chain   │
                    │   /ws/signal     (ticket)   │
                    │                             │
                    │   SQLite blockchain         │
                    │   (REGISTER / REVOKE /      │
                    │    DOC_SIGNATURE)           │
                    │   + auth table (off-chain)  │
                    └────────────┬────────────────┘
                                 │
                       signaling (SDP, ICE)
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
       ┌──────▼──────┐                       ┌──────▼──────┐
       │  browser A  │                       │  browser B  │
       │             │ ◄── WebRTC P2P ────►  │             │
       │  Ed25519 +  │   AES-256-GCM         │  Ed25519 +  │
       │  X25519     │   per message         │  X25519     │
       │             │                       │             │
       │  IndexedDB  │                       │  IndexedDB  │
       │  history    │                       │  history    │
       └─────────────┘                       └─────────────┘
```

**The server sees:** signaling traffic (SDP offers/answers, ICE candidates), public-key registrations, document hashes + signatures, bcrypt'd passwords, encrypted (wrapped) private keys.

**The server never sees:** chat plaintext, unwrapped private keys, X25519 ephemerals, message history, document contents.

---

## Cryptographic stack

| Layer | Algorithm | Library |
|---|---|---|
| Identity signing | Ed25519 | `tweetnacl` (browser) |
| Key exchange | X25519 ephemeral | `tweetnacl` |
| Session key derivation | HKDF-SHA256 | Web Crypto |
| Per-message AEAD | AES-256-GCM, 96-bit nonce, replay-protected via seq | Web Crypto |
| Password key wrap | PBKDF2-SHA256 (200k iters) → AES-GCM-256 | Web Crypto |
| History encryption | AES-256-GCM, key from HKDF(Ed25519 secret) | Web Crypto |
| Server password hash | bcrypt cost 12 | Python `bcrypt` |
| Session token | JWT HS256 in httpOnly cookie | Python `pyjwt` |
| WS auth ticket | JWT HS256 (60s TTL) | Python `pyjwt` |
| Document hash | SHA-256 | Web Crypto |
| Block hash (chain) | SHA-256 over `{idx, ts, payload, prev_hash}` | Python stdlib |

### The handshake

When two browsers connect via WebRTC, before any chat traffic flows:

1. **Initiator** generates an X25519 ephemeral keypair `(a, A)`, signs the public part with their Ed25519 identity key, sends `HELLO { A, sig, identity_pubkey }`
2. **Responder** looks up the initiator's identity on the blockchain — if the published `identity_pubkey` doesn't match what's on-chain, the connection is aborted (`MITM_DETECTED`). Otherwise the signature is verified.
3. Responder generates their own ephemeral `(b, B)`, signs it, sends `HELLO_ACK { B, sig, identity_pubkey }`
4. Initiator verifies the responder against the chain the same way
5. Both sides compute the shared secret: `S = a·B = b·A` (the Diffie-Hellman magic)
6. Both derive `session_key = HKDF-SHA256(S, info="zeroday-session-key")` and a `base_nonce`
7. Application messages are AES-256-GCM encrypted with this key. The 96-bit nonce is `base_nonce XOR seq_number`. Both sides track the highest `seq` received and reject anything `≤` that — replay protection.

If the AES-GCM tag fails to verify on receive, the message is rejected (`TAMPER_DETECTED`).

---

## Routes

### Pages (client)

| Path | Purpose | Auth |
|---|---|---|
| `/` | Redirects to `/login` or `/chat` based on session | — |
| `/register` | Create identity (browser-side keygen + password wrap) | none |
| `/login` | Restore session (server-side password check + browser-side key unwrap) | none |
| `/chat` | The messenger | required |
| `/registry` | Public, read-only view of all on-chain identities | none |
| `/verify` | Drop a file → see who signed it (or didn't) on-chain | none |

### API (server)

| Method | Path | Purpose | Auth |
|---|---|---|---|
| POST | `/api/auth/register` | New user; signed proof verified, REGISTER block written | none |
| POST | `/api/auth/login` | Returns wrapped private key + sets session cookie | none |
| POST | `/api/auth/logout` | Clear session | cookie |
| GET  | `/api/auth/me` | Current session info (returns `null` if not logged in) | none |
| POST | `/api/auth/ws-ticket` | 60-second JWT for WebSocket auth | cookie |
| GET  | `/api/lookup/{user_id}` | Look up a user's current public key | none |
| GET  | `/api/users` | List all active users | none |
| POST | `/api/revoke` | Revoke your own key (signed by your identity key) | cookie |
| POST | `/api/document` | Log a document signature on-chain | cookie |
| GET  | `/api/document/verify/{hash}` | Public verification of a hash's signatures | none |
| GET  | `/api/chain` | Full block list | none |
| GET  | `/api/chain/stats` | Chain stats + integrity check | none |
| GET  | `/api/health` | Liveness | none |
| WS   | `/ws/signal?ticket=…` | WebRTC signaling, authenticated by ticket query param | ticket |

The WebSocket uses a ticket-based auth scheme rather than cookies because Chrome's incognito mode blocks third-party cookies on cross-site WS upgrades, even with `SameSite=None; Secure`. Cookies still work as a fallback for same-origin local dev.

---

## File map

```
server/
  app/
    __init__.py            version
    blockchain.py          SQLite chain + auth table
    main.py                FastAPI: REST + WebSocket
  requirements.txt
  data/
    blockchain.db          (created at runtime — mount a volume in prod)

client/
  src/
    lib/
      crypto.js            keygen, sign/verify, AES-GCM, PBKDF2 wrap/unwrap
      api.js               cookie-aware fetch + auth endpoints
      peer.js              WebRTC PeerManager (event bus, send queue)
      channel.js           SecureChannel (handshake, replay/tamper detection)
      history.js           encrypted IndexedDB message history
    components/
      AuthShell.jsx        split-screen auth frame
    pages/
      Login.jsx
      Register.jsx
      Chat.jsx             peers + chat thread + audit log + doc-sign
      Registry.jsx         public registry view
      Verify.jsx           public document verification
    App.jsx                react-router routing shell
    main.jsx               bootstrap + BrowserRouter
    index.css              Tailwind + cypherpunk theme
  vercel.json              SPA rewrite (every path → /index.html)
  vite.config.js
  tailwind.config.js
  postcss.config.js
  index.html

docs/
  DEPLOYMENT.md            Vercel + Railway setup with cross-site cookie notes
```

---

## Defenses against attacks

| Attack | Defense |
|---|---|
| **Man-in-the-middle** during handshake | Identity keys are verified against the on-chain registry. An attacker can't forge a signature without the secret key, and can't substitute their own key without the chain disagreeing. Flag: `MITM_DETECTED` |
| **Message tampering** in transit | AES-GCM auth tag fails to verify if any byte of the ciphertext or AAD is modified. Decryption is rejected. Flag: `TAMPER_DETECTED` |
| **Replay** of captured messages | Each message carries a sequence number bound into the AAD. Receiver tracks the highest seen seq; anything `≤` that is rejected. Flag: `REPLAY_DETECTED` |
| **Server compromise** | The server only stores ciphertext, signaling metadata, public keys, bcrypt'd passwords, and password-wrapped (encrypted) private keys. Plaintext messages and unwrapped keys never touch the server. |
| **Stolen device** (without password) | Private keys at rest are AES-GCM encrypted with a PBKDF2-derived key. Without the password, an attacker with disk access can't unwrap them. |
| **Stolen device** (with password) | Game over — same as any password-protected app. Mitigation: change your password (which would require a key-rotation flow not currently implemented). |

---

## Configuration

### Server environment variables

| Variable | Default | Purpose |
|---|---|---|
| `JWT_SECRET` | dev placeholder | HS256 signing key for session JWTs. **MUST** be set in production |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated CORS origins |
| `COOKIE_SECURE` | `0` | Set to `1` in production (HTTPS) |
| `COOKIE_SAMESITE` | `lax` | Set to `none` for cross-site deployment (e.g. Vercel + Railway) |

### Client environment variables

| Variable | Purpose |
|---|---|
| `VITE_API_URL` | URL of the FastAPI server. Baked in at build time |
| `VITE_TURN_URL` | (optional) TURN server URL for WebRTC NAT traversal |
| `VITE_TURN_USERNAME` | TURN credentials |
| `VITE_TURN_CREDENTIAL` | TURN credentials |

`VITE_*` variables are baked in at **build time**, not runtime. Changing them in the Vercel dashboard requires a redeploy.

---

## What this project demonstrates

This is a coursework project, not a production messenger. It exists to make these crypto + blockchain concepts concrete by implementing them rather than just reading about them:

- Asymmetric cryptography (Ed25519, X25519) — what public/private key pairs actually do
- Diffie-Hellman key exchange — agreeing on a secret over a public channel
- Authenticated encryption (AES-GCM) — confidentiality + tamper detection in one primitive
- Key derivation (HKDF, PBKDF2) — turning one secret into many keys safely
- Signature-based identity — proving who you are without a central authority
- Append-only logs — why a hash chain is harder to tamper with than a database
- Document anchoring — using a chain for proof of existence at a point in time
- WebRTC P2P — moving data without a relay server in the middle
- Browser crypto APIs — what's safely available in the platform vs. what needs a library

The ZeroDay app puts these together end-to-end into something that actually works.

---

## Limitations and known gaps

These are intentionally out of scope for the coursework version, but worth noting if you're tempted to use this for anything real:

- **No forward secrecy across sessions.** Each WebRTC connection negotiates fresh ephemeral keys, but if your long-term Ed25519 secret leaks, an attacker who recorded historical signed handshakes can validate (though not decrypt — that still needs the X25519 ephemerals, which are zeroed). For real forward secrecy across messages, you'd want a Double Ratchet (Signal protocol).
- **Single-node "blockchain".** The chain is a SQLite table on one server. If that server is malicious, it can rewrite history (clients have no copies to compare against). A real deployment would anchor periodically to a public chain like Bitcoin or Ethereum, or distribute the chain across multiple nodes with consensus.
- **No group chat.** The channel protocol is strictly 1:1. Group messaging needs MLS or sender-key fanout.
- **No key rotation flow.** If your password is compromised, the server-stored wrapped key still decrypts to the same Ed25519 keypair. There's no UI to rotate keys (which would also require revoking the old key on-chain).
- **No mobile testing.** WebRTC works in mobile browsers but the UI is desktop-first.
- **No spam/abuse controls.** Anyone can register any available username and start sending; you'd want rate limits and probably stricter username validation in production.

---

## License

This is a coursework project. Use the code as a reference; don't build a production system on it without addressing the limitations above.
