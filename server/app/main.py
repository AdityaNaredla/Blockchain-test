"""
ZeroDay Blockchain Server — FastAPI

Auth model:
  - Register: client picks username + password, generates Ed25519 keypair LOCALLY,
    wraps the secret key with PBKDF2(password)→AES-GCM, sends wrapped blob +
    bcrypt(password) + public key + self-signed proof to /api/auth/register.
    Server verifies proof, stores auth record, AND adds a REGISTER block on-chain.
  - Login: POST /api/auth/login with username + password. Server returns the
    wrapped private key (client unwraps with password locally) and sets a
    session cookie. Plaintext private key NEVER leaves the browser.
  - Sessions: JWT in httpOnly cookie. The same cookie authenticates the WS
    signaling endpoint.

Endpoints:
  REST:
    POST   /api/auth/register     — username + password + wrapped key + pubkey
    POST   /api/auth/login        — returns wrapped key + sets session cookie
    POST   /api/auth/logout       — clears cookie
    GET    /api/auth/me           — current session info

    POST   /api/revoke            — revoke a key (auth required)
    GET    /api/lookup/{user_id}  — public, anyone can verify identity
    GET    /api/users             — list all active users
    POST   /api/document          — log a document signature (auth required)
    GET    /api/chain             — get all blocks
    GET    /api/chain/stats       — chain stats + integrity check
    GET    /api/health            — health check

  WebSocket:
    /ws/signal                    — WebRTC signaling (cookie auth)
"""
import json
import os
import time
import logging
from typing import Optional
from contextlib import asynccontextmanager

import bcrypt
import jwt
from fastapi import (
    FastAPI, HTTPException, WebSocket, WebSocketDisconnect,
    Cookie, Response, Request,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .blockchain import Blockchain
from . import __version__


# -------- Logging --------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("zerodday.server")


# -------- Config --------

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-change-me-in-production-please-32b")
JWT_ALG = "HS256"
COOKIE_NAME = "zerodday_session"
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days

ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
).split(",")


# -------- Models --------

class RegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=3, max_length=24,
                         pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=256)
    public_key: str = Field(..., min_length=64, max_length=64,
                            pattern=r"^[0-9a-f]+$")
    # Wrapped secret key — "salt:nonce:ciphertext" base64. The server never
    # sees the unwrapped key.
    wrapped_secret_key: str = Field(..., min_length=10, max_length=2000)
    # Self-signed proof: Ed25519(secret_key, "register:" + user_id)
    # Proves the registrant actually owns the keypair.
    signature: str = Field(..., min_length=128, max_length=128,
                           pattern=r"^[0-9a-f]+$")


class LoginRequest(BaseModel):
    user_id: str
    password: str


class RevokeRequest(BaseModel):
    public_key: str
    signature: str = Field(..., description="Ed25519 sig over 'revoke:'+user_id")


class DocumentSignatureRequest(BaseModel):
    doc_hash: str = Field(..., min_length=64, max_length=64,
                          pattern=r"^[0-9a-f]+$")
    signature: str = Field(..., description="hex-encoded Ed25519 signature")


# -------- App + lifespan --------

bc: Optional[Blockchain] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global bc
    bc = Blockchain(db_path="data/blockchain.db")
    log.info(f"Blockchain initialized: {bc.stats()}")
    if JWT_SECRET == "dev-only-change-me-in-production-please-32b":
        log.warning("Using default JWT_SECRET. Set JWT_SECRET env var for production.")
    yield
    log.info("Server shutting down")


app = FastAPI(
    title="ZeroDay Blockchain Server",
    description="Public key registry + WebRTC signaling for ZeroDay secure messaging.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Cookies require allow_credentials=True. With credentials, allow_origins
    # cannot be "*" — must be an explicit list.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------- Auth helpers --------

def _verify_proof(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), message)
        return True
    except Exception as e:
        log.warning(f"Signature verification failed: {e}")
        return False


def _issue_session_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _decode_session_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def _set_session_cookie(response: Response, token: str) -> None:
    # SameSite=None is required when the client and server are on different
    # sites (e.g. Vercel client + Railway server). Browsers also require
    # Secure=true alongside SameSite=None. For local same-origin dev,
    # SameSite=Lax is friendlier (works without HTTPS).
    samesite = os.environ.get("COOKIE_SAMESITE", "lax").lower()
    secure = os.environ.get("COOKIE_SECURE", "0") == "1"
    if samesite == "none" and not secure:
        log.warning("COOKIE_SAMESITE=none requires COOKIE_SECURE=1; "
                    "cookie will be rejected by browsers")
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path="/",
    )


def _require_user(request: Request) -> str:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Not authenticated")
    user_id = _decode_session_token(token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired session")
    return user_id


# -------- Auth endpoints --------

@app.post("/api/auth/register")
async def register(req: RegisterRequest, response: Response):
    """Register a new user.
    1. Verify self-signed proof (proves caller controls the keypair).
    2. Reject if user_id already taken (in either auth table or chain).
    3. Store wrapped private key + bcrypt(password) in auth table.
    4. Add REGISTER block to the chain.
    5. Issue session cookie.
    """
    # Proof of key ownership
    proof_msg = f"register:{req.user_id}".encode()
    if not _verify_proof(req.public_key, req.signature, proof_msg):
        log.warning(f"REGISTER denied: invalid proof for '{req.user_id}'")
        raise HTTPException(400, "Invalid proof of key ownership")

    # Username uniqueness — check both auth and the chain
    if bc.get_auth(req.user_id) is not None:
        raise HTTPException(409, f"Username '{req.user_id}' is taken")
    if bc.lookup_key(req.user_id) is not None:
        raise HTTPException(409, f"Username '{req.user_id}' is taken")

    # bcrypt the password
    pw_hash = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt(12)).decode()

    # Persist auth + chain entry. Do auth first so a chain entry without a
    # matching auth row is impossible.
    bc.create_auth(req.user_id, pw_hash, req.wrapped_secret_key, req.public_key)
    block = bc.register_key(req.user_id, req.public_key)

    log.info(f"REGISTER ok: user='{req.user_id}' "
             f"key={req.public_key[:16]}... block={block.index}")

    token = _issue_session_token(req.user_id)
    _set_session_cookie(response, token)

    return {
        "user_id": req.user_id,
        "public_key": req.public_key,
        "block_index": block.index,
        "block_hash": block.block_hash,
        "registered_at": block.timestamp,
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest, response: Response):
    """Verify password, return wrapped private key, set session cookie."""
    auth = bc.get_auth(req.user_id)
    if not auth:
        # Same response shape regardless of whether user exists, to avoid
        # username enumeration. Timing's still leaky (no bcrypt run on miss)
        # — fine for a demo; production would dummy-hash.
        raise HTTPException(401, "Invalid credentials")

    if not bcrypt.checkpw(req.password.encode(), auth["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")

    bc.touch_login(req.user_id)
    token = _issue_session_token(req.user_id)
    _set_session_cookie(response, token)

    return {
        "user_id": req.user_id,
        "public_key": auth["public_key"],
        "wrapped_secret_key": auth["wrapped_secret_key"],
    }


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request):
    """Get current session info. Returns null user if not logged in
    (200 instead of 401, so the client can check without console errors)."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return {"user": None}
    user_id = _decode_session_token(token)
    if not user_id:
        return {"user": None}
    auth = bc.get_auth(user_id)
    onchain = bc.lookup_key(user_id)
    if not auth or not onchain:
        return {"user": None}
    return {
        "user": {
            "user_id": user_id,
            "public_key": auth["public_key"],
            "block_index": onchain["block_index"],
            "registered_at": onchain["registered_at"],
        }
    }


# -------- Public registry endpoints --------

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": __version__, "chain": bc.stats()}


@app.get("/api/lookup/{user_id}")
async def lookup_key(user_id: str):
    result = bc.lookup_key(user_id)
    if not result:
        raise HTTPException(404, f"No active key for '{user_id}'")
    return result


@app.get("/api/users")
async def list_users():
    return {"users": bc.list_users()}


@app.post("/api/revoke")
async def revoke_key(req: RevokeRequest, request: Request):
    """Revoke YOUR own key. Auth required (cookie) AND requires Ed25519 sig
    proving you still hold the secret key."""
    user_id = _require_user(request)
    existing = bc.lookup_key(user_id)
    if not existing or existing["public_key"] != req.public_key:
        raise HTTPException(404, "No matching active key")

    proof_msg = f"revoke:{user_id}".encode()
    if not _verify_proof(req.public_key, req.signature, proof_msg):
        raise HTTPException(400, "Invalid revocation signature")

    block = bc.revoke_key(user_id, req.public_key)
    log.info(f"REVOKE ok: user='{user_id}' block={block.index}")
    return {"user_id": user_id, "block_index": block.index,
            "revoked_at": block.timestamp}


@app.post("/api/document")
async def log_document(req: DocumentSignatureRequest, request: Request):
    """Log a document signature on-chain. Signer is the authenticated user."""
    user_id = _require_user(request)
    user = bc.lookup_key(user_id)
    if not user:
        raise HTTPException(404, "No active key for current user")

    proof_msg = f"doc:{req.doc_hash}".encode()
    if not _verify_proof(user["public_key"], req.signature, proof_msg):
        raise HTTPException(400, "Invalid signature")

    block = bc.log_document_signature(user_id, req.doc_hash, req.signature)
    log.info(f"DOC_SIG ok: signer='{user_id}' "
             f"hash={req.doc_hash[:16]}... block={block.index}")
    return {
        "signer_id": user_id,
        "doc_hash": req.doc_hash,
        "block_index": block.index,
        "block_hash": block.block_hash,
    }


@app.get("/api/chain")
async def get_chain():
    return {"blocks": bc.all_blocks(), "valid": bc.validate_chain()}


@app.get("/api/chain/stats")
async def chain_stats():
    return bc.stats()


# -------- WebSocket signaling --------

class SignalManager:
    """Tracks online users and routes signaling messages between them.
    The server only forwards opaque payloads (SDP, ICE candidates).
    Once peers connect via WebRTC, all chat is direct browser-to-browser."""

    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        if user_id in self.connections:
            try:
                await self.connections[user_id].close(
                    code=4000, reason="Replaced by new connection"
                )
            except Exception:
                pass
        self.connections[user_id] = ws
        log.info(f"WS connected: '{user_id}' (online: {len(self.connections)})")
        await self.broadcast_presence()

    def disconnect(self, user_id: str):
        if self.connections.get(user_id):
            del self.connections[user_id]
            log.info(f"WS disconnected: '{user_id}' "
                     f"(online: {len(self.connections)})")

    async def send_to(self, user_id: str, message: dict) -> bool:
        ws = self.connections.get(user_id)
        if not ws:
            return False
        try:
            await ws.send_json(message)
            return True
        except Exception as e:
            log.warning(f"Failed to send to '{user_id}': {e}")
            return False

    async def broadcast_presence(self):
        users = list(self.connections.keys())
        msg = {"type": "presence", "users": users}
        for user_id, ws in list(self.connections.items()):
            try:
                await ws.send_json(msg)
            except Exception:
                pass


signal_mgr = SignalManager()


@app.websocket("/ws/signal")
async def signaling_endpoint(
    ws: WebSocket,
    zerodday_session: Optional[str] = Cookie(default=None),
):
    """Authenticated WebRTC signaling channel.
    user_id is taken from the session cookie, NOT a URL parameter — so a
    client cannot impersonate another user just by typing their name."""
    if not zerodday_session:
        await ws.close(code=4401, reason="Not authenticated")
        return
    user_id = _decode_session_token(zerodday_session)
    if not user_id:
        await ws.close(code=4401, reason="Invalid session")
        return
    # Confirm the user actually exists on the chain
    if not bc.lookup_key(user_id):
        await ws.close(code=4404, reason="User not registered")
        return

    await signal_mgr.connect(user_id, ws)

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type")

            if msg_type == "ping":
                await ws.send_json({"type": "pong"})
                continue

            target = data.get("to")
            if not target:
                await ws.send_json({
                    "type": "error", "message": "missing 'to' field"
                })
                continue

            forward = {**data, "from": user_id}
            forward.pop("to", None)

            delivered = await signal_mgr.send_to(target, forward)
            if not delivered:
                await ws.send_json({
                    "type": "error",
                    "message": f"User '{target}' not online",
                })
            else:
                log.info(f"signal: {user_id} -> {target} ({msg_type})")

    except WebSocketDisconnect:
        signal_mgr.disconnect(user_id)
        await signal_mgr.broadcast_presence()
    except Exception as e:
        log.error(f"WS error for '{user_id}': {e}")
        signal_mgr.disconnect(user_id)
        await signal_mgr.broadcast_presence()
