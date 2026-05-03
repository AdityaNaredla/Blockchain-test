/**
 * Encrypted local message history.
 *
 * Storage: IndexedDB. One database per user (`zerodday-history-<userId>`),
 * one object store `messages`, indexed by peerId for fast per-conversation
 * loads.
 *
 * Encryption: AES-256-GCM with a key derived from the user's long-term
 * Ed25519 secret key via HKDF-SHA256(info="zeroday-history-key"). The
 * derivation is deterministic — same input yields the same key — so we
 * don't need to store the key anywhere. As long as the user can log in
 * (i.e. unwrap their secret key with their password), they can decrypt
 * their history. If they lose their password and can't unwrap, history
 * is gone — same security model as the identity keys themselves.
 *
 * What's encrypted: the plaintext message body.
 * What's NOT encrypted (but stored in plaintext locally): peerId, timestamp,
 * direction (in/out), and seq number. These are needed for indexing/sorting
 * and aren't sensitive on the user's own device.
 *
 * What the server sees: NOTHING. This is local-only.
 */

import { deriveSessionKey } from "./crypto";

const DB_VERSION = 1;
const STORE = "messages";

let cachedKey = null;     // CryptoKey for AES-GCM
let cachedKeyUserId = null;

// ---------- Key derivation ----------

async function getHistoryKey(identity) {
  if (cachedKey && cachedKeyUserId === identity.userId) return cachedKey;

  // Derive a 32-byte key from the user's Ed25519 secret key. We feed the
  // 64-byte secretKey into HKDF; the secretKey is the seed+pubkey concat,
  // so this produces a key tied to the user's identity.
  // We reuse deriveSessionKey for convenience even though "session" is a
  // misnomer here — it's HKDF-SHA256 either way. We only use the .key part.
  const derived = await deriveSessionKey(identity.secretKey);

  // Re-derive specifically with a "history" info label so it doesn't collide
  // with anything that might also feed identity.secretKey through HKDF.
  // (Belt-and-suspenders — current session derivation uses the X25519 shared
  // secret, not the Ed25519 secret, but being explicit is cheap.)
  const baseKey = await crypto.subtle.importKey(
    "raw", identity.secretKey, "HKDF", false, ["deriveKey"],
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("zeroday-history-salt"),
      info: new TextEncoder().encode("zeroday-history-aes-gcm"),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  cachedKey = aesKey;
  cachedKeyUserId = identity.userId;
  return aesKey;
}

// ---------- IndexedDB plumbing ----------

function dbName(userId) {
  return `zerodday-history-${userId}`;
}

function openDB(userId) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName(userId), DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, {
          keyPath: "id", autoIncrement: true,
        });
        store.createIndex("peerId", "peerId", { unique: false });
        store.createIndex("createdAt", "createdAt", { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const store = t.objectStore(STORE);
    let result;
    Promise.resolve(fn(store)).then((r) => { result = r; });
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

// ---------- Encrypt / decrypt ----------

async function encrypt(key, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  return { nonce, ct };
}

async function decrypt(key, nonce, ct) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    ct,
  );
  return new TextDecoder().decode(pt);
}

// ---------- Public API ----------

export async function saveMessage(identity, { peerId, dir, text, seq, time }) {
  const key = await getHistoryKey(identity);
  const { nonce, ct } = await encrypt(key, text);
  const db = await openDB(identity.userId);
  try {
    await tx(db, "readwrite", (store) => {
      store.add({
        peerId,
        dir,
        seq: seq ?? null,
        createdAt: (time instanceof Date ? time : new Date(time)).getTime(),
        nonce,
        ct,
      });
    });
  } finally {
    db.close();
  }
}

/** Load all messages with the given peer, oldest-first. */
export async function loadMessagesWithPeer(identity, peerId) {
  const key = await getHistoryKey(identity);
  const db = await openDB(identity.userId);
  try {
    const records = await tx(db, "readonly", (store) => {
      return new Promise((resolve, reject) => {
        const out = [];
        const idx = store.index("peerId");
        const req = idx.openCursor(IDBKeyRange.only(peerId));
        req.onsuccess = () => {
          const c = req.result;
          if (c) { out.push(c.value); c.continue(); }
          else { resolve(out); }
        };
        req.onerror = () => reject(req.error);
      });
    });

    // Sort by createdAt (the index ordering with a single key isn't guaranteed)
    records.sort((a, b) => a.createdAt - b.createdAt);

    const decrypted = [];
    for (const r of records) {
      try {
        const text = await decrypt(key, r.nonce, r.ct);
        decrypted.push({
          peer: r.peerId,
          dir: r.dir,
          text,
          seq: r.seq,
          time: new Date(r.createdAt),
          fromHistory: true,
        });
      } catch {
        // Decryption failed — skip silently. Most likely cause is that the
        // record was written under a different identity key (shouldn't
        // happen since the DB is per-user, but defense-in-depth).
      }
    }
    return decrypted;
  } finally {
    db.close();
  }
}

/** Wipe the entire history for the current user. */
export async function clearHistory(userId) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(dbName(userId));
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => {
      // Some other tab still has the DB open. Just resolve — caller can
      // tell the user to close other tabs if it persists.
      resolve();
    };
  });
}

/** Counts per peer, for "X messages stored" display. */
export async function historyCounts(identity) {
  try {
    const db = await openDB(identity.userId);
    try {
      return await tx(db, "readonly", (store) => {
        return new Promise((resolve, reject) => {
          const counts = {};
          const req = store.openCursor();
          req.onsuccess = () => {
            const c = req.result;
            if (c) {
              counts[c.value.peerId] = (counts[c.value.peerId] || 0) + 1;
              c.continue();
            } else {
              resolve(counts);
            }
          };
          req.onerror = () => reject(req.error);
        });
      });
    } finally {
      db.close();
    }
  } catch {
    return {};
  }
}

/** Drop the cached key (call on logout). */
export function forgetHistoryKey() {
  cachedKey = null;
  cachedKeyUserId = null;
}
