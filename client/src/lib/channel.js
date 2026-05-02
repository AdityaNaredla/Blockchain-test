/**
 * SecureChannel — wraps a WebRTC P2P connection with:
 *   1. X25519 key exchange (signed with Ed25519 identity keys)
 *   2. HKDF-SHA256 session key derivation
 *   3. AES-256-GCM authenticated encryption per message
 *   4. Monotonic sequence numbers for replay protection
 *
 * Public key trust comes from the blockchain registry (lookupUser).
 * Once handshake completes, all chat messages are authenticated AEAD-encrypted.
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
    // peerId -> session state
    this.sessions = new Map();
    this.handlers = {
      onSecureMessage: () => {},
      onHandshakeComplete: () => {},
      onLog: () => {},
      onSecurityEvent: () => {},
    };

    // Hook into the peer manager
    this.peer.handlers.onMessage = (peerId, data) => this._handleData(peerId, data);
    this.peer.handlers.onPeerConnected = (peerId) => {
  this.log("INFO", `P2P connected with ${peerId}; initiating secure handshake`);
  this._initiateHandshake(peerId);
};
    this.peer.handlers.onPeerDisconnected = (peerId) => {
      this.sessions.delete(peerId);
    };
  }

  on(event, fn) {
    const key = `on${event[0].toUpperCase()}${event.slice(1)}`;
    if (key in this.handlers) this.handlers[key] = fn;
  }

  log(level, msg, detail) {
    this.handlers.onLog({ level, msg, detail, time: new Date() });
  }

  /**
   * peerLookup: a function (peerId) => { public_key: hex } | null
   * Used to verify the peer's identity during handshake.
   */
  setPeerLookup(fn) {
    this.peerLookup = fn;
  }

  // ---------- Handshake flow ----------

  async _initiateHandshake(peerId) {
    // Initiator (the one who called) sends HELLO with ephemeral pk + sig
    const eph = generateEphemeralKey();
    const sigPayload = enc.encode(`hs:${this.peer.userId}:${peerId}`);
    const sig = signMessage(this.identity.secretKey, this._concat(sigPayload, eph.publicKey));

    this.sessions.set(peerId, {
      state: "AWAITING_HELLO",
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
    // Receiver: verify sender's identity, generate own ephemeral, respond
    if (!this.peerLookup) {
      this.log("ERROR", "No peer lookup set, cannot verify identity");
      return;
    }

    // Verify peer's identity key matches what's on the blockchain
    const onchain = await this.peerLookup(peerId);
    if (!onchain || onchain.public_key !== msg.identityPk) {
      this.log("CRITICAL", `MITM_DETECTED: identity key for ${peerId} does not match blockchain`);
      this.handlers.onSecurityEvent("MITM_DETECTED", { peer: peerId });
      return;
    }

    // Verify signature
    const peerIdentityPk = hexToBytes(msg.identityPk);
    const peerEphPk = hexToBytes(msg.ephPublic);
    const sigPayload = enc.encode(`hs:${peerId}:${this.peer.userId}`);
    const expected = this._concat(sigPayload, peerEphPk);
    if (!verifySignature(peerIdentityPk, expected, hexToBytes(msg.sig))) {
      this.log("CRITICAL", `SIG_INVALID from ${peerId}; aborting handshake`);
      this.handlers.onSecurityEvent("SIG_INVALID", { peer: peerId });
      return;
    }

    // Generate our ephemeral, derive session keys
    const eph = generateEphemeralKey();
    const shared = computeSharedSecret(eph.secretKey, peerEphPk);
    const session = await deriveSessionKey(shared);

    const sigPayload2 = enc.encode(`hs:${this.peer.userId}:${peerId}`);
    const sig = signMessage(this.identity.secretKey, this._concat(sigPayload2, eph.publicKey));

    this.sessions.set(peerId, {
      state: "ESTABLISHED",
      sessionKey: session.key,
      baseNonce: session.baseNonce,
      sendSeq: 0,
      recvSeq: -1,
      role: "responder",
      peerIdentityPk: peerIdentityPk,
    });

    this.peer.send(peerId, {
      type: "HELLO_ACK",
      from: this.peer.userId,
      ephPublic: bytesToHex(eph.publicKey),
      sig: bytesToHex(sig),
      identityPk: this.identity.publicKeyHex,
    });

    this.log("INFO", `Handshake complete with ${peerId} (responder)`);
    this.handlers.onHandshakeComplete(peerId);
  }

  async _handleHelloAck(peerId, msg) {
    const sess = this.sessions.get(peerId);
    if (!sess || sess.state !== "AWAITING_HELLO") return;

    const onchain = await this.peerLookup(peerId);
    if (!onchain || onchain.public_key !== msg.identityPk) {
      this.log("CRITICAL", `MITM_DETECTED: identity key mismatch for ${peerId}`);
      this.handlers.onSecurityEvent("MITM_DETECTED", { peer: peerId });
      return;
    }

    const peerIdentityPk = hexToBytes(msg.identityPk);
    const peerEphPk = hexToBytes(msg.ephPublic);
    const sigPayload = enc.encode(`hs:${peerId}:${this.peer.userId}`);
    const expected = this._concat(sigPayload, peerEphPk);
    if (!verifySignature(peerIdentityPk, expected, hexToBytes(msg.sig))) {
      this.log("CRITICAL", `SIG_INVALID from ${peerId}`);
      this.handlers.onSecurityEvent("SIG_INVALID", { peer: peerId });
      return;
    }

    const shared = computeSharedSecret(sess.ephSecret, peerEphPk);
    const session = await deriveSessionKey(shared);

    sess.state = "ESTABLISHED";
    sess.sessionKey = session.key;
    sess.baseNonce = session.baseNonce;
    sess.peerIdentityPk = peerIdentityPk;
    // Zero ephemeral
    sess.ephSecret = null;
    sess.ephPublic = null;

    this.log("INFO", `Handshake complete with ${peerId} (initiator)`);
    this.handlers.onHandshakeComplete(peerId);
  }

  // ---------- Message send/receive ----------

  async sendMessage(peerId, plaintext) {
    const sess = this.sessions.get(peerId);
    if (!sess || sess.state !== "ESTABLISHED") {
      throw new Error(`No secure session with ${peerId}`);
    }

    const seq = sess.sendSeq++;
    const aad = `${this.peer.userId}->${peerId}:${seq}`;
    const ct = await encryptMessage(sess.sessionKey, sess.baseNonce, seq, plaintext, aad);

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
      this.log("CRITICAL", `REPLAY_DETECTED from ${peerId}: seq=${seq} <= last=${sess.recvSeq}`);
      this.handlers.onSecurityEvent("REPLAY_DETECTED", { peer: peerId, seq });
      return;
    }

    try {
      const ct = base64ToBytes(msg.ct);
      const aad = `${peerId}->${this.peer.userId}:${seq}`;
      const pt = await decryptMessage(sess.sessionKey, sess.baseNonce, seq, ct, aad);
      sess.recvSeq = seq;
      const text = bytesToString(pt);
      this.handlers.onSecureMessage({ from: peerId, text, seq });
    } catch (e) {
      this.log("CRITICAL", `TAMPER_DETECTED from ${peerId}: GCM auth failed`, e.message);
      this.handlers.onSecurityEvent("TAMPER_DETECTED", { peer: peerId, seq });
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
