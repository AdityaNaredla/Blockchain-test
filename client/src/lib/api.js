/**
 * REST client for the ZeroDay blockchain server.
 */

import { signString } from "./crypto";

// In production set VITE_API_URL; otherwise hits the local server
const API_BASE = import.meta.env.VITE_API_URL || "http://127.0.0.1:8765";

async function jsonRequest(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {}
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return res.json();
}

export async function getHealth() {
  return jsonRequest("/api/health");
}

export async function registerUser(userId, identity) {
  const signature = signString(identity.secretKey, `register:${userId}`);
  return jsonRequest("/api/register", {
    method: "POST",
    body: JSON.stringify({
      user_id: userId,
      public_key: identity.publicKeyHex,
      signature,
    }),
  });
}

export async function lookupUser(userId) {
  return jsonRequest(`/api/lookup/${encodeURIComponent(userId)}`);
}

export async function listUsers() {
  return jsonRequest("/api/users");
}

export async function revokeUser(userId, identity) {
  const signature = signString(identity.secretKey, `revoke:${userId}`);
  return jsonRequest("/api/revoke", {
    method: "POST",
    body: JSON.stringify({
      user_id: userId,
      public_key: identity.publicKeyHex,
      signature,
    }),
  });
}

export async function logDocumentSignature(signerId, docHashHex, identity) {
  const signature = signString(identity.secretKey, `doc:${docHashHex}`);
  return jsonRequest("/api/document", {
    method: "POST",
    body: JSON.stringify({
      signer_id: signerId,
      doc_hash: docHashHex,
      signature,
    }),
  });
}

export async function getChain() {
  return jsonRequest("/api/chain");
}

export async function getChainStats() {
  return jsonRequest("/api/chain/stats");
}

export function getApiBase() {
  return API_BASE;
}

export function getWsBase() {
  return API_BASE.replace(/^http/, "ws");
}
