/**
 * REST API client. All requests use credentials: "include" so the
 * session cookie travels with each call.
 */
import {
  signString, sha256, bytesToHex, wrapSecretKey,
} from "./crypto";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8765";

export function getApiBase() {
  return API_BASE;
}

export function getWsBase() {
  return API_BASE.replace(/^http/, "ws");
}

async function jsonFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let body;
  try { body = await res.json(); } catch { body = null; }
  if (!res.ok) {
    const msg = body?.detail || body?.message || `${res.status} ${res.statusText}`;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return body;
}

// ---------- Auth ----------

/**
 * Register a new user. Generates the keypair, wraps the secret key with
 * the password, signs a self-proof, and POSTs everything.
 */
export async function registerAccount({ userId, password, identity }) {
  const wrapped = await wrapSecretKey(identity.secretKey, password);
  const signature = signString(identity.secretKey, `register:${userId}`);
  return jsonFetch("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({
      user_id: userId,
      password,
      public_key: identity.publicKeyHex,
      wrapped_secret_key: wrapped,
      signature,
    }),
  });
}

export async function loginAccount(userId, password) {
  return jsonFetch("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ user_id: userId, password }),
  });
}

export async function logoutAccount() {
  return jsonFetch("/api/auth/logout", { method: "POST" });
}

export async function getMe() {
  const r = await jsonFetch("/api/auth/me");
  return r.user;
}

/** Get a short-lived (60s) ticket for WebSocket auth. Browsers don't always
 *  send cookies on cross-site WS upgrades; we put this in the URL instead. */
export async function fetchWsTicket() {
  const r = await jsonFetch("/api/auth/ws-ticket", { method: "POST" });
  return r.ticket;
}

// ---------- Public registry / chain ----------

export async function lookupUser(userId) {
  return jsonFetch(`/api/lookup/${encodeURIComponent(userId)}`);
}

export async function listUsers() {
  return jsonFetch("/api/users");
}

export async function getChainStats() {
  return jsonFetch("/api/chain/stats");
}

export async function getHealth() {
  return jsonFetch("/api/health");
}

// ---------- Document signing (auth required server-side) ----------

export async function logDocumentSignature(docHashHex, identity) {
  const sig = signString(identity.secretKey, `doc:${docHashHex}`);
  return jsonFetch("/api/document", {
    method: "POST",
    body: JSON.stringify({ doc_hash: docHashHex, signature: sig }),
  });
}

/** Public — no auth required. Returns all signatures for a hash with
 *  re-verified status. Use this to prove "@alice signed this file".  */
export async function verifyDocumentHash(docHashHex) {
  return jsonFetch(`/api/document/verify/${encodeURIComponent(docHashHex)}`);
}

// ---------- Revoke ----------

export async function revokeKey(identity) {
  const sig = signString(identity.secretKey, `revoke:${identity.userId}`);
  return jsonFetch("/api/revoke", {
    method: "POST",
    body: JSON.stringify({
      public_key: identity.publicKeyHex,
      signature: sig,
    }),
  });
}
