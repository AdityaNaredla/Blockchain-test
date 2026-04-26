"""
ZeroDay Blockchain Server — FastAPI
Endpoints:
  REST:
    POST   /api/register          — register an Ed25519 public key
    POST   /api/revoke            — revoke a key
    GET    /api/lookup/{user_id}  — look up a user's current public key
    GET    /api/users             — list all active users
    POST   /api/document          — log a document signature on-chain
    GET    /api/chain             — get all blocks
    GET    /api/chain/stats       — chain statistics + integrity check
    GET    /api/health            — health check

  WebSocket:
    /ws/signal/{user_id}          — WebRTC signaling channel for peer discovery
"""
import json
import time
import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
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


# -------- Models --------

class RegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    public_key: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    signature: str = Field(..., description="Self-signed proof of key ownership: Ed25519(public_key, 'register:'+user_id)")


class RevokeRequest(BaseModel):
    user_id: str
    public_key: str
    signature: str = Field(..., description="Ed25519 signature over 'revoke:'+user_id")


class DocumentSignatureRequest(BaseModel):
    signer_id: str
    doc_hash: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]+$")
    signature: str = Field(..., description="hex-encoded Ed25519 signature")


# -------- App + lifespan --------

bc: Optional[Blockchain] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global bc
    bc = Blockchain(db_path="data/blockchain.db")
    log.info(f"Blockchain initialized: {bc.stats()}")
    yield
    log.info("Server shutting down")


app = FastAPI(
    title="ZeroDay Blockchain Server",
    description="Public key registry + WebRTC signaling for the ZeroDay secure messaging system.",
    version=__version__,
    lifespan=lifespan,
)

# CORS — allow web clients from anywhere (you can lock this down for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _verify_proof(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """Verify an Ed25519 signature."""
    try:
        pk_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        pk.verify(sig_bytes, message)
        return True
    except Exception as e:
        log.warning(f"Signature verification failed: {e}")
        return False


# -------- REST endpoints --------

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": __version__,
        "chain": bc.stats(),
    }


@app.post("/api/register")
async def register_key(req: RegisterRequest):
    """Register a new Ed25519 public key under a user_id.
    Requires self-signed proof of key ownership."""

    # Reject if user_id already has an active key
    existing = bc.lookup_key(req.user_id)
    if existing:
        log.warning(f"REGISTER denied: user_id '{req.user_id}' already registered")
        raise HTTPException(409, f"user_id '{req.user_id}' is already registered. Revoke first to re-register.")

    # Verify the proof: prevents trolls from registering keys they don't own
    proof_msg = f"register:{req.user_id}".encode()
    if not _verify_proof(req.public_key, req.signature, proof_msg):
        log.warning(f"REGISTER denied: invalid proof signature for '{req.user_id}'")
        raise HTTPException(400, "Invalid proof of key ownership")

    block = bc.register_key(req.user_id, req.public_key)
    log.info(f"REGISTER ok: user='{req.user_id}' key={req.public_key[:16]}... block={block.index}")
    return {
        "user_id": req.user_id,
        "public_key": req.public_key,
        "block_index": block.index,
        "block_hash": block.block_hash,
        "registered_at": block.timestamp,
    }


@app.post("/api/revoke")
async def revoke_key(req: RevokeRequest):
    """Revoke a previously registered key. Requires signature from the same key."""
    existing = bc.lookup_key(req.user_id)
    if not existing or existing["public_key"] != req.public_key:
        raise HTTPException(404, "No matching active key")

    proof_msg = f"revoke:{req.user_id}".encode()
    if not _verify_proof(req.public_key, req.signature, proof_msg):
        log.warning(f"REVOKE denied: invalid signature for '{req.user_id}'")
        raise HTTPException(400, "Invalid revocation signature")

    block = bc.revoke_key(req.user_id, req.public_key)
    log.info(f"REVOKE ok: user='{req.user_id}' block={block.index}")
    return {"user_id": req.user_id, "block_index": block.index, "revoked_at": block.timestamp}


@app.get("/api/lookup/{user_id}")
async def lookup_key(user_id: str):
    """Look up a user's current public key."""
    result = bc.lookup_key(user_id)
    if not result:
        raise HTTPException(404, f"No active key for user_id '{user_id}'")
    return result


@app.get("/api/users")
async def list_users():
    """List all currently active users."""
    return {"users": bc.list_users()}


@app.post("/api/document")
async def log_document(req: DocumentSignatureRequest):
    """Log a document signature on-chain for non-repudiation."""
    # Verify the signer has an active key
    user = bc.lookup_key(req.signer_id)
    if not user:
        raise HTTPException(404, f"Signer '{req.signer_id}' not registered")

    # Verify signature is valid for the doc_hash
    proof_msg = f"doc:{req.doc_hash}".encode()
    if not _verify_proof(user["public_key"], req.signature, proof_msg):
        log.warning(f"DOC_SIG denied: invalid sig from '{req.signer_id}'")
        raise HTTPException(400, "Invalid signature")

    block = bc.log_document_signature(req.signer_id, req.doc_hash, req.signature)
    log.info(f"DOC_SIG ok: signer='{req.signer_id}' hash={req.doc_hash[:16]}... block={block.index}")
    return {
        "signer_id": req.signer_id,
        "doc_hash": req.doc_hash,
        "block_index": block.index,
        "block_hash": block.block_hash,
    }


@app.get("/api/chain")
async def get_chain():
    """Return all blocks."""
    return {"blocks": bc.all_blocks(), "valid": bc.validate_chain()}


@app.get("/api/chain/stats")
async def chain_stats():
    return bc.stats()


# -------- WebSocket signaling for WebRTC --------

class SignalManager:
    """Tracks online users and routes signaling messages between them.
    The server only forwards opaque signaling payloads (SDP offers/answers, ICE candidates).
    Once peers connect via WebRTC, all chat traffic is direct browser-to-browser."""

    def __init__(self):
        self.connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        # Disconnect previous session for this user_id, if any
        if user_id in self.connections:
            try:
                await self.connections[user_id].close(code=4000, reason="Replaced by new connection")
            except Exception:
                pass
        self.connections[user_id] = ws
        log.info(f"WS connected: '{user_id}' (online: {len(self.connections)})")
        # Notify everyone of the new presence
        await self.broadcast_presence()

    def disconnect(self, user_id: str):
        if user_id in self.connections:
            del self.connections[user_id]
            log.info(f"WS disconnected: '{user_id}' (online: {len(self.connections)})")

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


@app.websocket("/ws/signal/{user_id}")
async def signaling_endpoint(ws: WebSocket, user_id: str):
    """WebRTC signaling channel.
    Forwards opaque signaling payloads between named peers.
    Server NEVER sees encrypted message content — that flows P2P after connection."""

    if not user_id or len(user_id) > 64:
        await ws.close(code=4400, reason="Invalid user_id")
        return

    await signal_mgr.connect(user_id, ws)

    try:
        while True:
            data = await ws.receive_json()

            # Expected message types:
            #   {"type": "offer",     "to": "<peer>", "sdp": "..."}
            #   {"type": "answer",    "to": "<peer>", "sdp": "..."}
            #   {"type": "candidate", "to": "<peer>", "candidate": {...}}
            #   {"type": "bye",       "to": "<peer>"}
            #   {"type": "ping"}

            msg_type = data.get("type")

            if msg_type == "ping":
                await ws.send_json({"type": "pong"})
                continue

            target = data.get("to")
            if not target:
                await ws.send_json({"type": "error", "message": "missing 'to' field"})
                continue

            # Tag with sender so receiver knows who it's from
            forward = {**data, "from": user_id}
            forward.pop("to", None)

            delivered = await signal_mgr.send_to(target, forward)
            if not delivered:
                await ws.send_json({"type": "error", "message": f"User '{target}' not online"})
            else:
                log.info(f"signal: {user_id} -> {target} ({msg_type})")

    except WebSocketDisconnect:
        signal_mgr.disconnect(user_id)
        await signal_mgr.broadcast_presence()
    except Exception as e:
        log.error(f"WS error for '{user_id}': {e}")
        signal_mgr.disconnect(user_id)
        await signal_mgr.broadcast_presence()
