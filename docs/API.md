# ZeroDay Server API Reference

Base URL: `http://YOUR_HOST:8765`

All requests/responses are JSON. CORS is enabled for all origins by default (lock down in production).

## REST Endpoints

### `GET /api/health`

Health check + chain stats.

**Response 200:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "chain": {
    "total_blocks": 5,
    "by_type": { "REGISTER": 2, "REVOKE": 1, "DOC_SIGNATURE": 1, "GENESIS": 1 },
    "valid": true
  }
}
```

---

### `POST /api/register`

Register a new Ed25519 public key.

**Request body:**
```json
{
  "user_id": "alice",
  "public_key": "<64-char hex>",
  "signature": "<128-char hex Ed25519 sig over 'register:alice'>"
}
```

The signature is the proof that the client owns the private key for `public_key`. The server rejects registration if signature verification fails.

**Validation:**
- `user_id`: 1-64 chars, regex `^[a-zA-Z0-9_-]+$`
- `public_key`: exactly 64 lowercase hex characters (32 bytes)
- `signature`: hex Ed25519 signature

**Response 200:**
```json
{
  "user_id": "alice",
  "public_key": "07368b...",
  "block_index": 1,
  "block_hash": "7b2f30...",
  "registered_at": 1745678901.234
}
```

**Errors:**
- `400` invalid proof signature
- `409` user_id already has an active key (revoke first)

---

### `POST /api/revoke`

Revoke a previously registered key.

**Request body:**
```json
{
  "user_id": "alice",
  "public_key": "<64-char hex>",
  "signature": "<hex Ed25519 sig over 'revoke:alice'>"
}
```

Signature must come from the same key being revoked.

**Response 200:**
```json
{ "user_id": "alice", "block_index": 4, "revoked_at": 1745678905.6 }
```

---

### `GET /api/lookup/{user_id}`

Look up a user's currently active public key.

**Response 200:**
```json
{
  "user_id": "alice",
  "public_key": "07368b...",
  "block_index": 1,
  "registered_at": 1745678901.234
}
```

**Errors:**
- `404` no active key (never registered, or revoked)

---

### `GET /api/users`

List all currently active users.

**Response 200:**
```json
{
  "users": [
    { "user_id": "alice", "public_key": "07...", "block_index": 1, "registered_at": ... },
    { "user_id": "bob",   "public_key": "34...", "block_index": 2, "registered_at": ... }
  ]
}
```

---

### `POST /api/document`

Log a document signature on-chain.

**Request body:**
```json
{
  "signer_id": "alice",
  "doc_hash": "<64-char hex SHA-256>",
  "signature": "<hex Ed25519 sig over 'doc:<doc_hash>'>"
}
```

The signer must have an active registered key, and the signature is verified against that key.

**Response 200:**
```json
{
  "signer_id": "alice",
  "doc_hash": "abc123...",
  "block_index": 3,
  "block_hash": "deadbeef..."
}
```

**Errors:**
- `400` invalid signature
- `404` signer not registered

---

### `GET /api/chain`

Return all blocks in the chain.

**Response 200:**
```json
{
  "blocks": [
    { "index": 0, "timestamp": ..., "payload": {...}, "previous_hash": "00...", "block_hash": "..." },
    ...
  ],
  "valid": true
}
```

---

### `GET /api/chain/stats`

Same as the `chain` field in `/api/health`.

---

## WebSocket Signaling

### `WS /ws/signal/{user_id}`

Connect to get presence updates and exchange WebRTC signaling messages with other connected users.

**Inbound messages from server:**

`presence` — list of currently online user IDs:
```json
{ "type": "presence", "users": ["alice", "bob"] }
```

Forwarded signaling from another peer:
```json
{ "type": "offer", "from": "alice", "sdp": {...} }
{ "type": "answer", "from": "bob", "sdp": {...} }
{ "type": "candidate", "from": "alice", "candidate": {...} }
{ "type": "bye", "from": "bob" }
```

`pong` (response to client `ping`):
```json
{ "type": "pong" }
```

`error`:
```json
{ "type": "error", "message": "User 'X' not online" }
```

**Outbound messages from client:**

```json
{ "type": "offer",     "to": "bob", "sdp": {...} }
{ "type": "answer",    "to": "alice", "sdp": {...} }
{ "type": "candidate", "to": "bob", "candidate": {...} }
{ "type": "bye",       "to": "bob" }
{ "type": "ping" }
```

The server only forwards opaque payloads. After WebRTC connects, all chat traffic flows P2P — the server never sees encrypted message bodies.

---

## Chain Block Schema

Each block has shape:

```json
{
  "index": 1,
  "timestamp": 1745678901.234,
  "payload": { ...type-specific... },
  "previous_hash": "<sha256 hex of previous block>",
  "block_hash": "<sha256 hex of this block>"
}
```

The `block_hash` is `SHA-256(index || timestamp || payload || previous_hash)`. Tampering with any field breaks the chain.

**Payload types:**

| `type` | Other fields |
|---|---|
| `GENESIS` | `message` |
| `REGISTER` | `user_id`, `public_key` |
| `REVOKE` | `user_id`, `public_key` |
| `DOC_SIGNATURE` | `signer_id`, `doc_hash`, `signature` |
