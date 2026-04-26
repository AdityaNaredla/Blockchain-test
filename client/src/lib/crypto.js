/**
 * ZeroDay browser crypto library
 *
 * Uses native Web Crypto API where possible. For Ed25519 we use tweetnacl
 * because Web Crypto Ed25519 support is still limited across browsers.
 *
 * Primitives:
 *   - Ed25519 (tweetnacl) for identity signatures
 *   - X25519 (tweetnacl) for ephemeral key exchange
 *   - HKDF-SHA256 (Web Crypto) for session key derivation
 *   - AES-256-GCM (Web Crypto) for AEAD encryption
 *   - SHA-256 (Web Crypto) for document hashing
 */

import nacl from "tweetnacl";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- Hex encoding helpers ----------

export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

export function base64ToBytes(b64) {
  return new Uint8Array(
    atob(b64)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}

// ---------- Ed25519 identity keys ----------

export function generateIdentityKey() {
  // tweetnacl uses a 64-byte secretKey (seed + public) and 32-byte publicKey
  const kp = nacl.sign.keyPair();
  return {
    secretKey: kp.secretKey, // 64 bytes
    publicKey: kp.publicKey, // 32 bytes
    publicKeyHex: bytesToHex(kp.publicKey),
  };
}

export function signMessage(secretKey, message) {
  // Returns 64-byte signature
  return nacl.sign.detached(message, secretKey);
}

export function verifySignature(publicKey, message, signature) {
  return nacl.sign.detached.verify(message, signature, publicKey);
}

export function signString(secretKey, str) {
  return bytesToHex(signMessage(secretKey, enc.encode(str)));
}

// ---------- X25519 ephemeral keys ----------

export function generateEphemeralKey() {
  const kp = nacl.box.keyPair();
  return {
    secretKey: kp.secretKey, // 32 bytes
    publicKey: kp.publicKey, // 32 bytes
  };
}

export function computeSharedSecret(mySecret, theirPublic) {
  return nacl.scalarMult(mySecret, theirPublic);
}

// ---------- HKDF-SHA256 ----------

const PROTOCOL_SALT = enc.encode("ZeroDay-v1-salt");

async function hkdfImport(secret) {
  return crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
}

export async function deriveSessionKey(sharedSecret) {
  const baseKey = await hkdfImport(sharedSecret);
  const keyBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: PROTOCOL_SALT,
      info: enc.encode("zeroday-session-key"),
    },
    baseKey,
    256 // 32 bytes
  );
  const nonceBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: PROTOCOL_SALT,
      info: enc.encode("zeroday-base-nonce"),
    },
    baseKey,
    96 // 12 bytes
  );
  return {
    key: new Uint8Array(keyBits),
    baseNonce: new Uint8Array(nonceBits),
  };
}

// ---------- AES-256-GCM ----------

async function importAESKey(rawKey) {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

function buildNonce(baseNonce, seq) {
  // Nonce = baseNonce XOR seq (12 bytes, big-endian seq)
  const nonce = new Uint8Array(12);
  // Last 4 bytes carry seq (32-bit), XOR with base
  const seqBytes = new Uint8Array(12);
  // Pack seq as big-endian into the last bytes
  const view = new DataView(seqBytes.buffer);
  view.setUint32(8, seq, false); // false = big endian
  for (let i = 0; i < 12; i++) nonce[i] = baseNonce[i] ^ seqBytes[i];
  return nonce;
}

export async function encryptMessage(sessionKey, baseNonce, seq, plaintext, aad) {
  const key = await importAESKey(sessionKey);
  const nonce = buildNonce(baseNonce, seq);
  const ptBytes = typeof plaintext === "string" ? enc.encode(plaintext) : plaintext;
  const aadBytes = aad ? (typeof aad === "string" ? enc.encode(aad) : aad) : new Uint8Array(0);
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128 },
      key,
      ptBytes
    )
  );
  return ciphertextWithTag; // last 16 bytes is the tag
}

export async function decryptMessage(sessionKey, baseNonce, seq, ciphertextWithTag, aad) {
  const key = await importAESKey(sessionKey);
  const nonce = buildNonce(baseNonce, seq);
  const aadBytes = aad ? (typeof aad === "string" ? enc.encode(aad) : aad) : new Uint8Array(0);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128 },
    key,
    ciphertextWithTag
  );
  return new Uint8Array(plaintext);
}

export function bytesToString(bytes) {
  return dec.decode(bytes);
}

// ---------- SHA-256 ----------

export async function sha256(data) {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(hash);
}

// ---------- Identity persistence (localStorage) ----------

const STORAGE_KEY = "zerodday.identity";

export function saveIdentity(userId, identity) {
  // Store secretKey + publicKey + userId — encrypted-at-rest would be production hardening
  const data = {
    userId,
    secretKey: bytesToHex(identity.secretKey),
    publicKey: bytesToHex(identity.publicKey),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

export function loadIdentity() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    const data = JSON.parse(raw);
    return {
      userId: data.userId,
      secretKey: hexToBytes(data.secretKey),
      publicKey: hexToBytes(data.publicKey),
      publicKeyHex: data.publicKey,
    };
  } catch {
    return null;
  }
}

export function clearIdentity() {
  localStorage.removeItem(STORAGE_KEY);
}
