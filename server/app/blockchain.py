"""
ZeroDay Blockchain — Persistent single-node chain backed by SQLite.
Stores blocks for key registration, revocation, and document signatures.
"""
import sqlite3
import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional
from pathlib import Path


@dataclass
class Block:
    index: int
    timestamp: float
    payload: dict
    previous_hash: str
    block_hash: str = ""

    def compute_hash(self) -> str:
        data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }, sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()


class Blockchain:
    """SQLite-backed append-only chain."""

    def __init__(self, db_path: str = "blockchain.db"):
        self.db_path = db_path
        self._init_db()
        if self._block_count() == 0:
            self._create_genesis()

    def _conn(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    idx INTEGER PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL
                )
            """)
            c.commit()

    def _block_count(self) -> int:
        with self._conn() as c:
            r = c.execute("SELECT COUNT(*) FROM blocks").fetchone()
            return r[0]

    def _row_to_block(self, row) -> Block:
        return Block(
            index=row["idx"],
            timestamp=row["timestamp"],
            payload=json.loads(row["payload"]),
            previous_hash=row["previous_hash"],
            block_hash=row["block_hash"],
        )

    def _create_genesis(self):
        block = Block(
            index=0,
            timestamp=time.time(),
            payload={"type": "GENESIS", "message": "ZeroDay blockchain initialized"},
            previous_hash="0" * 64,
        )
        block.block_hash = block.compute_hash()
        with self._conn() as c:
            c.execute(
                "INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
                (block.index, block.timestamp, json.dumps(block.payload), block.previous_hash, block.block_hash)
            )
            c.commit()

    def _add_block(self, payload: dict) -> Block:
        with self._conn() as c:
            prev_row = c.execute("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
            prev = self._row_to_block(prev_row)
            block = Block(
                index=prev.index + 1,
                timestamp=time.time(),
                payload=payload,
                previous_hash=prev.block_hash,
            )
            block.block_hash = block.compute_hash()
            c.execute(
                "INSERT INTO blocks VALUES (?, ?, ?, ?, ?)",
                (block.index, block.timestamp, json.dumps(block.payload), block.previous_hash, block.block_hash)
            )
            c.commit()
            return block

    def register_key(self, user_id: str, public_key_hex: str) -> Block:
        """Register an Ed25519 public key on-chain."""
        return self._add_block({
            "type": "REGISTER",
            "user_id": user_id,
            "public_key": public_key_hex,
        })

    def revoke_key(self, user_id: str, public_key_hex: str) -> Block:
        """Revoke a previously registered key."""
        return self._add_block({
            "type": "REVOKE",
            "user_id": user_id,
            "public_key": public_key_hex,
        })

    def log_document_signature(self, signer_id: str, doc_hash_hex: str, signature_hex: str) -> Block:
        """Log a document signature on-chain."""
        return self._add_block({
            "type": "DOC_SIGNATURE",
            "signer_id": signer_id,
            "doc_hash": doc_hash_hex,
            "signature": signature_hex,
        })

    def lookup_key(self, user_id: str) -> Optional[dict]:
        """Find the latest active (non-revoked) key for a user."""
        latest_key = None
        latest_block = None
        revoked_keys = set()

        with self._conn() as c:
            for row in c.execute("SELECT * FROM blocks ORDER BY idx ASC"):
                block = self._row_to_block(row)
                p = block.payload
                if p.get("user_id") == user_id:
                    if p.get("type") == "REVOKE":
                        revoked_keys.add(p["public_key"])
                    elif p.get("type") == "REGISTER":
                        latest_key = p["public_key"]
                        latest_block = block

        if latest_key and latest_key not in revoked_keys:
            return {
                "user_id": user_id,
                "public_key": latest_key,
                "block_index": latest_block.index,
                "registered_at": latest_block.timestamp,
            }
        return None

    def list_users(self) -> list[dict]:
        """List all registered (non-revoked) users."""
        active = {}
        revoked = set()
        with self._conn() as c:
            for row in c.execute("SELECT * FROM blocks ORDER BY idx ASC"):
                block = self._row_to_block(row)
                p = block.payload
                user = p.get("user_id")
                if not user:
                    continue
                if p.get("type") == "REVOKE":
                    revoked.add(p["public_key"])
                elif p.get("type") == "REGISTER":
                    active[user] = {
                        "user_id": user,
                        "public_key": p["public_key"],
                        "block_index": block.index,
                        "registered_at": block.timestamp,
                    }
        return [v for v in active.values() if v["public_key"] not in revoked]

    def is_key_revoked(self, public_key_hex: str) -> bool:
        with self._conn() as c:
            r = c.execute(
                "SELECT 1 FROM blocks WHERE json_extract(payload, '$.type')='REVOKE' AND json_extract(payload, '$.public_key')=?",
                (public_key_hex,)
            ).fetchone()
            return r is not None

    def all_blocks(self) -> list[dict]:
        with self._conn() as c:
            return [
                {
                    "index": row["idx"],
                    "timestamp": row["timestamp"],
                    "payload": json.loads(row["payload"]),
                    "previous_hash": row["previous_hash"],
                    "block_hash": row["block_hash"],
                }
                for row in c.execute("SELECT * FROM blocks ORDER BY idx ASC")
            ]

    def validate_chain(self) -> bool:
        """Verify chain integrity end-to-end."""
        with self._conn() as c:
            rows = list(c.execute("SELECT * FROM blocks ORDER BY idx ASC"))
            for i in range(1, len(rows)):
                cur = self._row_to_block(rows[i])
                prv = self._row_to_block(rows[i - 1])
                if cur.block_hash != cur.compute_hash():
                    return False
                if cur.previous_hash != prv.block_hash:
                    return False
        return True

    def stats(self) -> dict:
        with self._conn() as c:
            counts = {"REGISTER": 0, "REVOKE": 0, "DOC_SIGNATURE": 0, "GENESIS": 0}
            for row in c.execute("SELECT json_extract(payload, '$.type') AS t, COUNT(*) AS c FROM blocks GROUP BY t"):
                counts[row["t"]] = row["c"]
            return {
                "total_blocks": self._block_count(),
                "by_type": counts,
                "valid": self.validate_chain(),
            }
