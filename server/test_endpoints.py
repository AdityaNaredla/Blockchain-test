"""Test all REST endpoints with real signatures."""
import requests
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization, hashes

BASE = "http://127.0.0.1:8765/api"


def hex_pk(sk):
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def main():
    # === Generate keys for Alice and Bob ===
    alice_sk = Ed25519PrivateKey.generate()
    bob_sk = Ed25519PrivateKey.generate()

    alice_pk = hex_pk(alice_sk)
    bob_pk = hex_pk(bob_sk)

    print(f"Alice pk: {alice_pk[:24]}...")
    print(f"Bob   pk: {bob_pk[:24]}...")

    # === REGISTER ===
    print("\n=== Test 1: Register Alice ===")
    sig = alice_sk.sign(b"register:alice").hex()
    r = requests.post(f"{BASE}/register", json={
        "user_id": "alice", "public_key": alice_pk, "signature": sig
    })
    print(f"  status={r.status_code}, body={r.json()}")
    assert r.status_code == 200

    print("\n=== Test 2: Register Bob ===")
    sig = bob_sk.sign(b"register:bob").hex()
    r = requests.post(f"{BASE}/register", json={
        "user_id": "bob", "public_key": bob_pk, "signature": sig
    })
    print(f"  status={r.status_code}, block={r.json()['block_index']}")
    assert r.status_code == 200

    # === LOOKUP ===
    print("\n=== Test 3: Lookup Alice's key ===")
    r = requests.get(f"{BASE}/lookup/alice")
    print(f"  status={r.status_code}, key={r.json()['public_key'][:16]}...")
    assert r.status_code == 200
    assert r.json()["public_key"] == alice_pk

    print("\n=== Test 4: Lookup unknown user (should 404) ===")
    r = requests.get(f"{BASE}/lookup/eve")
    print(f"  status={r.status_code}")
    assert r.status_code == 404

    # === REJECT INVALID PROOF ===
    print("\n=== Test 5: Reject duplicate registration ===")
    sig = alice_sk.sign(b"register:alice").hex()
    r = requests.post(f"{BASE}/register", json={
        "user_id": "alice", "public_key": alice_pk, "signature": sig
    })
    print(f"  status={r.status_code} (should be 409)")
    assert r.status_code == 409

    print("\n=== Test 6: Reject bad proof signature ===")
    eve_sk = Ed25519PrivateKey.generate()
    eve_pk = hex_pk(eve_sk)
    # Sign wrong message
    wrong_sig = eve_sk.sign(b"register:somebody_else").hex()
    r = requests.post(f"{BASE}/register", json={
        "user_id": "eve", "public_key": eve_pk, "signature": wrong_sig
    })
    print(f"  status={r.status_code} (should be 400)")
    assert r.status_code == 400

    # === LIST USERS ===
    print("\n=== Test 7: List all active users ===")
    r = requests.get(f"{BASE}/users")
    users = r.json()["users"]
    print(f"  active users: {[u['user_id'] for u in users]}")
    assert len(users) == 2

    # === DOCUMENT SIGNATURE ===
    print("\n=== Test 8: Log document signature ===")
    doc_hash = hashes.Hash(hashes.SHA256())
    doc_hash.update(b"Important contract content")
    h = doc_hash.finalize().hex()
    doc_sig = alice_sk.sign(f"doc:{h}".encode()).hex()
    r = requests.post(f"{BASE}/document", json={
        "signer_id": "alice", "doc_hash": h, "signature": doc_sig
    })
    print(f"  status={r.status_code}, block={r.json()['block_index']}")
    assert r.status_code == 200

    # === REJECT BAD DOC SIG ===
    print("\n=== Test 9: Reject doc sig from wrong key ===")
    bad_sig = eve_sk.sign(f"doc:{h}".encode()).hex()
    r = requests.post(f"{BASE}/document", json={
        "signer_id": "alice", "doc_hash": h, "signature": bad_sig
    })
    print(f"  status={r.status_code} (should be 400)")
    assert r.status_code == 400

    # === REVOKE ===
    print("\n=== Test 10: Revoke Alice's key ===")
    revoke_sig = alice_sk.sign(b"revoke:alice").hex()
    r = requests.post(f"{BASE}/revoke", json={
        "user_id": "alice", "public_key": alice_pk, "signature": revoke_sig
    })
    print(f"  status={r.status_code}, block={r.json()['block_index']}")
    assert r.status_code == 200

    print("\n=== Test 11: Lookup revoked user (should 404) ===")
    r = requests.get(f"{BASE}/lookup/alice")
    print(f"  status={r.status_code}")
    assert r.status_code == 404

    # === CHAIN STATS ===
    print("\n=== Test 12: Chain stats ===")
    r = requests.get(f"{BASE}/chain/stats")
    s = r.json()
    print(f"  blocks: {s['total_blocks']}, by_type: {s['by_type']}, valid: {s['valid']}")
    assert s["valid"]
    assert s["by_type"]["REGISTER"] == 2
    assert s["by_type"]["REVOKE"] == 1
    assert s["by_type"]["DOC_SIGNATURE"] == 1

    print("\n" + "=" * 50)
    print("ALL TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    main()
