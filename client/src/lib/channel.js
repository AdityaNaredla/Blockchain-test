/**
 * SecureChannel — wraps a WebRTC P2P connection with:
 *   1. X25519 key exchange (signed with Ed25519 identity keys)
 *   2. HKDF-SHA256 session key derivation
 *   3. AES-256-GCM authenticated encryption per message
 *   4. Monotonic sequence numbers for replay protection
 *
 * Public key trust comes from the blockchain registry (lookupUser).
 * Once handshake completes, all chat messages are AEAD-encrypted.
 *
 * Changes from v0.1:
 *   - Subscribes to PeerManager events with pm.on() instead of overwriting
 *     pm.handlers.* — multiple consumers (App + this) can now coexist.
 *   - Uses its own multi-listener event bus (same shape as PeerManager).
 */

import {
  generateEphemeralKey,
  computeSharedSecret,
  deriveSessionKey,
  encryptMessage,
  decryptMessage,
  signMessage,
  verifySignature,
  hexToBytes,
  bytesToHex,
  bytesToBase64,
  base64ToBytes,
  bytesToString,
} from "./crypto";

const enc = new TextEncoder();

export class SecureChannel {
  constructor(peerManager, identity) {
    this.peer = peerManager;
    this.identity = identity;
    this.sessions = new Map(); // peerId -> session state
    this.listeners = new Map(); // event -> Set<fn>
    this.peerLookup = null;

    // Subscribe to PeerManager events. None of these clobber other listeners.
    //
    // We initiate the handshake on `dataChannelOpen`, NOT `peerConnected`.
    // RTCPeerConnection.connectionState === "connected" only means the ICE
    // layer is up; the RTCDataChannel.onopen event fires slightly later when
    // the channel is actually ready for .send(). If we initiate the
    // handshake on `peerConnected`, the first send throws because the data
    // channel hasn't opened yet.
    this._unsubscribers = [
      this.peer.on("message", (peerId, data) => this._handleData(peerId, data)),
      this.peer.on("dataChannelOpen", (peerId, isInitiator) => {
        if (!isInitiator) {
          this.log("INFO", `Data channel open with ${peerId}; awaiting HELLO`);
          return;
        }
        this.log("INFO", `Data channel open with ${peerId}; sending HELLO`);
        this._initiateHandshake(peerId).catch((e) => {
          this.log("ERROR", `Handshake init failed: ${e.message}`);
        });
      }),
      this.peer.on("peerDisconnected", (peerId) => {
        this.sessions.delete(peerId);
      }),
    ];
  }

  destroy() {
    for (const u of this._unsubscribers) u();
    this._unsubscribers = [];
    this.sessions.clear();
  }

  // ---------- Event bus ----------

  on(event, fn) {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event).add(fn);
    return () => this.off(event, fn);
  }

  off(event, fn) {
    this.listeners.get(event)?.delete(fn);
  }

  emit(event, ...args) {
    const set = this.listeners.get(event);
    if (!set) return;
    for (const fn of set) {
      try { fn(...args); } catch (e) {
        console.error(`[SecureChannel] listener for '${event}' threw:`, e);
      }
    }
  }

  log(level, msg, detail) {
    this.emit("log", { level, msg, detail, time: new Date() });
  }

  /** peerLookup: async (peerId) => { public_key: hex } | null */
  setPeerLookup(fn) {
    this.peerLookup = fn;
  }

  // ---------- Handshake (X25519 + Ed25519 signature, registry-checked) ----------

  async _initiateHandshake(peerId) {
    if (this.sessions.has(peerId)) {
      // Already handshook or in progress
      return;
    }
    const eph = generateEphemeralKey();
    const sigPayload = enc.encode(`hs:${this.peer.userId}:${peerId}`);
    const sig = signMessage(this.identity.secretKey,
                            this._concat(sigPayload, eph.publicKey));

    this.sessions.set(peerId, {
      state: "AWAITING_HELLO_ACK",
      ephSecret: eph.secretKey,
      ephPublic: eph.publicKey,
      sendSeq: 0,
      recvSeq: -1,
      role: "initiator",
    });

    this.peer.send(peerId, {
      type: "HELLO",
      from: this.peer.userId,
      ephPublic: bytesToHex(eph.publicKey),
      sig: bytesToHex(sig),
      identityPk: this.identity.publicKeyHex,
    });

    this.log("INFO", `Handshake HELLO sent to ${peerId}`);
  }

  async _handleHello(peerId, msg) {
    if (!this.peerLookup) {
      this.log("ERROR", "No peer lookup set, cannot verify identity");
      return;
    }

    // 1. Verify peer's identity matches the on-chain registry
    const onchain = await this.peerLookup(peerId);
    if (!onchain || onchain.public_key !== msg.identityPk) {
      this.log("CRITICAL", `MITM_DETECTED: identity key for ${peerId} does not match registry`);
      this.emit("securityEvent", "MITM_DETECTED", { peer: peerId });
      return;
    }

    // 2. Verify peer's signature on their ephemeral pubkey
    const peerIdentityPk = hexToBytes(msg.identityPk);
    const peerEphPk = hexToBytes(msg.ephPublic);
    const sigPayload = enc.encode(`hs:${peerId}:${this.peer.userId}`);
    const expected = this._concat(sigPayload, peerEphPk);
    if (!verifySignature(peerIdentityPk, expected, hexToBytes(msg.sig))) {
      this.log("CRITICAL", `SIG_INVALID from ${peerId}; aborting handshake`);
      this.emit("securityEvent", "SIG_INVALID", { peer: peerId });
      return;
    }

    // 3. Generate own ephemeral, derive session key from shared secret
    const eph = generateEphemeralKey();
    const shared = computeSharedSecret(eph.secretKey, peerEphPk);
    const session = await deriveSessionKey(shared);

    // 4. Sign our own ephemeral and send HELLO_ACK
    const sigPayload2 = enc.encode(`hs:${this.peer.userId}:${peerId}`);
    const sig = signMessage(this.identity.secretKey,
                            this._concat(sigPayload2, eph.publicKey));

    this.sessions.set(peerId, {
      state: "ESTABLISHED",
      sessionKey: session.key,
      baseNonce: session.baseNonce,
      sendSeq: 0,
      recvSeq: -1,
      role: "responder",
      peerIdentityPk,
    });

    this.peer.send(peerId, {
      type: "HELLO_ACK",
      from: this.peer.userId,
      ephPublic: bytesToHex(eph.publicKey),
      sig: bytesToHex(sig),
      identityPk: this.identity.publicKeyHex,
    });

    this.log("INFO", `Handshake complete with ${peerId} (responder)`);
    this.emit("handshakeComplete", peerId);
  }

  async _handleHelloAck(peerId, msg) {
    const sess = this.sessions.get(peerId);
    if (!sess || sess.state !== "AWAITING_HELLO_ACK") return;

    const onchain = await this.peerLookup(peerId);
    if (!onchain || onchain.public_key !== msg.identityPk) {
      this.log("CRITICAL", `MITM_DETECTED: identity key mismatch for ${peerId}`);
      this.emit("securityEvent", "MITM_DETECTED", { peer: peerId });
      return;
    }

    const peerIdentityPk = hexToBytes(msg.identityPk);
    const peerEphPk = hexToBytes(msg.ephPublic);
    const sigPayload = enc.encode(`hs:${peerId}:${this.peer.userId}`);
    const expected = this._concat(sigPayload, peerEphPk);
    if (!verifySignature(peerIdentityPk, expected, hexToBytes(msg.sig))) {
      this.log("CRITICAL", `SIG_INVALID from ${peerId}`);
      this.emit("securityEvent", "SIG_INVALID", { peer: peerId });
      return;
    }

    const shared = computeSharedSecret(sess.ephSecret, peerEphPk);
    const session = await deriveSessionKey(shared);

    sess.state = "ESTABLISHED";
    sess.sessionKey = session.key;
    sess.baseNonce = session.baseNonce;
    sess.peerIdentityPk = peerIdentityPk;
    // Zero out ephemerals — forward secrecy
    sess.ephSecret = null;
    sess.ephPublic = null;

    this.log("INFO", `Handshake complete with ${peerId} (initiator)`);
    this.emit("handshakeComplete", peerId);
  }

  // ---------- Application messages ----------

  async sendMessage(peerId, plaintext) {
    const sess = this.sessions.get(peerId);
    if (!sess || sess.state !== "ESTABLISHED") {
      throw new Error(`No secure session with ${peerId}`);
    }
    const seq = sess.sendSeq++;
    const aad = `${this.peer.userId}->${peerId}:${seq}`;
    const ct = await encryptMessage(sess.sessionKey, sess.baseNonce, seq,
                                    plaintext, aad);
    this.peer.send(peerId, {
      type: "MSG",
      from: this.peer.userId,
      seq,
      ct: bytesToBase64(ct),
    });
    return { seq, size: plaintext.length };
  }

  async _handleSecureMessage(peerId, msg) {
    const sess = this.sessions.get(peerId);
    if (!sess || sess.state !== "ESTABLISHED") {
      this.log("WARN", `MSG from ${peerId} before handshake; dropping`);
      return;
    }

    const seq = msg.seq;
    if (seq <= sess.recvSeq) {
      this.log("CRITICAL",
        `REPLAY_DETECTED from ${peerId}: seq=${seq} <= last=${sess.recvSeq}`);
      this.emit("securityEvent", "REPLAY_DETECTED", { peer: peerId, seq });
      return;
    }

    try {
      const ct = base64ToBytes(msg.ct);
      const aad = `${peerId}->${this.peer.userId}:${seq}`;
      const pt = await decryptMessage(sess.sessionKey, sess.baseNonce, seq,
                                       ct, aad);
      sess.recvSeq = seq;
      const text = bytesToString(pt);
      this.emit("secureMessage", { from: peerId, text, seq });
    } catch (e) {
      this.log("CRITICAL", `TAMPER_DETECTED from ${peerId}: GCM auth failed`,
               e.message);
      this.emit("securityEvent", "TAMPER_DETECTED", { peer: peerId, seq });
    }
  }

  _handleData(peerId, msg) {
    if (msg.type === "HELLO") this._handleHello(peerId, msg);
    else if (msg.type === "HELLO_ACK") this._handleHelloAck(peerId, msg);
    else if (msg.type === "MSG") this._handleSecureMessage(peerId, msg);
  }

  isSecureWith(peerId) {
    return this.sessions.get(peerId)?.state === "ESTABLISHED";
  }

  _concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }
}
