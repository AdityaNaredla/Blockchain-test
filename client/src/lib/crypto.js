/**
 * ZeroDay browser crypto library
 *
 * Primitives:
 *   - Ed25519 (tweetnacl) for identity signatures
 *   - X25519 (tweetnacl) for ephemeral key exchange
 *   - HKDF-SHA256 (Web Crypto) for session key derivation
 *   - AES-256-GCM (Web Crypto) for AEAD encryption
 *   - PBKDF2-SHA256 + AES-GCM (Web Crypto) for password-wrapped secret keys
 *   - SHA-256 (Web Crypto) for document hashing
 */

import nacl from "tweetnacl";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- Hex / base64 helpers ----------

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
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ---------- Ed25519 identity keys ----------

export function generateIdentityKey() {
  const kp = nacl.sign.keyPair();
  return {
    secretKey: kp.secretKey, // 64 bytes (seed + pub)
    publicKey: kp.publicKey, // 32 bytes
    publicKeyHex: bytesToHex(kp.publicKey),
  };
}

export function signMessage(secretKey, message) {
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

// ---------- HKDF-SHA256 (session keys) ----------

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
    256
  );
  const nonceBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: PROTOCOL_SALT,
      info: enc.encode("zeroday-base-nonce"),
    },
    baseKey,
    96
  );
  return {
    key: new Uint8Array(keyBits),
    baseNonce: new Uint8Array(nonceBits),
  };
}

// ---------- AES-256-GCM (per-message AEAD) ----------

async function importAESKey(rawKey) {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
    "encrypt", "decrypt",
  ]);
}

function buildNonce(baseNonce, seq) {
  const nonce = new Uint8Array(12);
  const seqBytes = new Uint8Array(12);
  new DataView(seqBytes.buffer).setUint32(8, seq, false);
  for (let i = 0; i < 12; i++) nonce[i] = baseNonce[i] ^ seqBytes[i];
  return nonce;
}

export async function encryptMessage(sessionKey, baseNonce, seq, plaintext, aad) {
  const key = await importAESKey(sessionKey);
  const nonce = buildNonce(baseNonce, seq);
  const ptBytes = typeof plaintext === "string" ? enc.encode(plaintext) : plaintext;
  const aadBytes = aad
    ? (typeof aad === "string" ? enc.encode(aad) : aad)
    : new Uint8Array(0);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128 },
      key, ptBytes
    )
  );
  return ct;
}

export async function decryptMessage(sessionKey, baseNonce, seq, ct, aad) {
  const key = await importAESKey(sessionKey);
  const nonce = buildNonce(baseNonce, seq);
  const aadBytes = aad
    ? (typeof aad === "string" ? enc.encode(aad) : aad)
    : new Uint8Array(0);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aadBytes, tagLength: 128 },
    key, ct
  );
  return new Uint8Array(pt);
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

// ---------- Password wrapping (PBKDF2 → AES-GCM) ----------
// Wrapped format: "salt:nonce:ciphertext" (all base64).
// salt: 16 bytes random, nonce: 12 bytes random, ciphertext: AES-GCM output.

const PBKDF2_ITERS = 200_000;

async function deriveAesKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wrap (encrypt) the 64-byte Ed25519 secret key with the user's password.
 * Returns "salt:nonce:ciphertext" (base64), suitable for sending to server.
 */
export async function wrapSecretKey(secretKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(password, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, secretKey)
  );
  return [bytesToBase64(salt), bytesToBase64(nonce), bytesToBase64(ct)].join(":");
}

/**
 * Unwrap (decrypt) the wrapped secret key with the password.
 * Throws if password is wrong (GCM auth tag mismatch).
 */
export async function unwrapSecretKey(blob, password) {
  const parts = blob.split(":");
  if (parts.length !== 3) throw new Error("Malformed wrapped key");
  const [saltB64, nonceB64, ctB64] = parts;
  const key = await deriveAesKey(password, base64ToBytes(saltB64));
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(nonceB64) },
    key,
    base64ToBytes(ctB64)
  );
  return new Uint8Array(pt);
}

// ---------- Identity persistence (sessionStorage, dies with tab) ----------
//
// IMPORTANT: We only persist UNWRAPPED keys in sessionStorage during an active
// tab session, so a page refresh doesn't kick the user back to login. The
// authoritative storage is the SERVER (wrapped). localStorage is no longer
// used for identity — it persists across browser restarts unencrypted, which
// is exactly what we want to avoid now that the user has a password.

const SESSION_KEY = "zerodday.identity";

export function stashIdentity(userId, identity) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    userId,
    secretKey: bytesToHex(identity.secretKey),
    publicKey: bytesToHex(identity.publicKey),
  }));
}

export function loadStashedIdentity() {
  const raw = sessionStorage.getItem(SESSION_KEY);
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

export function clearStashedIdentity() {
  sessionStorage.removeItem(SESSION_KEY);
  // Also clear the legacy localStorage key from the old version, to migrate
  // users cleanly off the unencrypted-at-rest storage.
  localStorage.removeItem("zerodday.identity");
}
