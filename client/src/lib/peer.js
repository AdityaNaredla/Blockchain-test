/**
 * WebRTC peer connection manager.
 *
 * Flow:
 *   1. Connect to authenticated signaling WebSocket (/ws/signal — cookie auth)
 *   2. To call peer: create RTCPeerConnection, generate offer, send via signaling
 *   3. Peer receives offer, generates answer, sends back
 *   4. Both exchange ICE candidates
 *   5. Once connected, RTCDataChannel handles encrypted messages directly P2P
 *
 * Server only sees signaling (SDP, ICE). After connection, all chat is P2P.
 *
 * Changes from v0.1:
 *   - Multi-listener event bus (`on`/`off`/`emit`) instead of single-handler
 *     slots. The old design let SecureChannel clobber App's handlers. Now
 *     both can subscribe to the same event independently.
 *   - WS send queue: sends before `onopen` are buffered, not silently dropped.
 *   - userId is no longer in the URL — server reads it from session cookie.
 */

import { getWsBase, fetchWsTicket } from "./api";

const RTC_CONFIG = {
  iceServers: [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun.relay.metered.ca:80" },
    // TURN credentials should come from env or a server-issued token, NOT
    // be hardcoded in source. Provide via VITE_TURN_URL etc. if needed.
  ],
  iceCandidatePoolSize: 10,
};

// Optional TURN config from environment
if (import.meta.env.VITE_TURN_URL && import.meta.env.VITE_TURN_USERNAME) {
  RTC_CONFIG.iceServers.push({
    urls: import.meta.env.VITE_TURN_URL,
    username: import.meta.env.VITE_TURN_USERNAME,
    credential: import.meta.env.VITE_TURN_CREDENTIAL,
  });
}


export class PeerManager {
  constructor(userId) {
    this.userId = userId;
    this.ws = null;
    this.peers = new Map(); // peerId -> { pc, dc, ready }
    this.listeners = new Map(); // event -> Set<fn>
    this.outQueue = []; // signals queued before WS opens
    this.wsOpen = false;
  }

  // ---------- Multi-listener event bus ----------

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
        // One bad listener shouldn't break the others.
        console.error(`[PeerManager] listener for '${event}' threw:`, e);
      }
    }
  }

  log(level, msg, detail) {
    this.emit("log", { level, msg, detail, time: new Date() });
  }

  // ---------- Connection lifecycle ----------

  async connect() {
    // Fetch a short-lived WS ticket via authenticated REST. Cross-site
    // WebSocket upgrades don't reliably carry cookies (Chrome incognito,
    // Safari, strict tracking-protection settings all drop them), so we
    // pass auth in the query string instead.
    let ticket;
    try {
      ticket = await fetchWsTicket();
    } catch (e) {
      this.log("ERROR", `Failed to obtain WS ticket: ${e.message}`);
      throw new Error(`WS ticket failed: ${e.message}`);
    }

    return new Promise((resolve, reject) => {
      const url = `${getWsBase()}/ws/signal?ticket=${encodeURIComponent(ticket)}`;
      this.log("INFO", `Connecting to signaling: ${url.replace(/ticket=[^&]+/, "ticket=***")}`);
      try {
        this.ws = new WebSocket(url);
      } catch (e) {
        return reject(e);
      }

      this.ws.onopen = () => {
        this.wsOpen = true;
        this.log("INFO", "Signaling channel connected");
        // Drain queued sends
        while (this.outQueue.length) {
          this.ws.send(JSON.stringify(this.outQueue.shift()));
        }
        resolve();
      };

      this.ws.onerror = (e) => {
        this.log("ERROR", "Signaling WebSocket error",
                 e.message || "connection failed");
        if (!this.wsOpen) reject(new Error("WebSocket failed"));
      };

      this.ws.onclose = (ev) => {
        this.wsOpen = false;
        this.log("WARN", `Signaling channel closed (code=${ev.code})`);
        this.emit("signalingClosed", ev);
      };

      this.ws.onmessage = async (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          await this._handleSignal(msg);
        } catch (e) {
          this.log("ERROR", "Bad signaling message", e.message);
        }
      };
    });
  }

  async _handleSignal(msg) {
    this.emit("signal", msg);

    if (msg.type === "presence") {
      this.emit("presence", msg.users);
      return;
    }
    if (msg.type === "pong") return;

    const peerId = msg.from;
    if (!peerId) return;

    if (msg.type === "offer") {
      this.log("INFO", `Received offer from ${peerId}`);
      await this._handleOffer(peerId, msg.sdp);
    } else if (msg.type === "answer") {
      this.log("INFO", `Received answer from ${peerId}`);
      await this._handleAnswer(peerId, msg.sdp);
    } else if (msg.type === "candidate") {
      await this._handleCandidate(peerId, msg.candidate);
    } else if (msg.type === "bye") {
      this._teardownPeer(peerId);
    } else if (msg.type === "error") {
      this.log("ERROR", `Signaling error: ${msg.message}`);
    }
  }

  /** Send to signaling server. Queues if WS not yet open. */
  _send(payload) {
    if (this.wsOpen && this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    } else {
      this.outQueue.push(payload);
    }
  }

  // ---------- WebRTC peer setup ----------

  _createPeerConnection(peerId, isInitiator) {
    const pc = new RTCPeerConnection(RTC_CONFIG);

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this._send({ type: "candidate", to: peerId, candidate: e.candidate });
      }
    };

    pc.onconnectionstatechange = () => {
      this.log("INFO", `[${peerId}] connection state: ${pc.connectionState}`);
      if (pc.connectionState === "connected") {
        this.emit("peerConnected", peerId);
      } else if (
        pc.connectionState === "disconnected" ||
        pc.connectionState === "failed" ||
        pc.connectionState === "closed"
      ) {
        this.emit("peerDisconnected", peerId);
      }
    };

    pc.ondatachannel = (e) => {
      // We're the responder — caller created the channel.
      this._wireDataChannel(peerId, e.channel, false);
    };

    // Insert into peers map BEFORE wiring the channel, so that the peer
    // record is visible to _wireDataChannel's closure when dc.onopen fires.
    const peer = { pc, dc: null, ready: false, isInitiator };
    this.peers.set(peerId, peer);

    if (isInitiator) {
      const dc = pc.createDataChannel("zerodday-msg", { ordered: true });
      peer.dc = dc;
      this._wireDataChannel(peerId, dc, true);
    }

    return peer;
  }

  _wireDataChannel(peerId, dc, isInitiator) {
    const peer = this.peers.get(peerId);
    if (peer) peer.dc = dc;

    dc.onopen = () => {
      this.log("INFO", `[${peerId}] P2P data channel OPEN — direct browser-to-browser`);
      const p = this.peers.get(peerId);
      if (p) p.ready = true;
      // Emit role so SecureChannel knows whether to initiate the handshake
      // (only the caller sends HELLO; the receiver waits for it).
      this.emit("dataChannelOpen", peerId, isInitiator);
    };
    dc.onclose = () => {
      this.log("INFO", `[${peerId}] data channel closed`);
      const p = this.peers.get(peerId);
      if (p) p.ready = false;
    };
    dc.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        this.emit("message", peerId, data);
      } catch (e) {
        this.log("ERROR", `Bad message from ${peerId}`, e.message);
      }
    };
  }

  async callPeer(peerId) {
    if (this.peers.has(peerId)) {
      this.log("WARN", `Already have a peer connection to ${peerId}`);
      return;
    }
    this.log("INFO", `Calling ${peerId}...`);
    const { pc } = this._createPeerConnection(peerId, true);
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this._send({ type: "offer", to: peerId, sdp: offer });
  }

  async _handleOffer(peerId, sdp) {
    if (this.peers.has(peerId)) {
      this._teardownPeer(peerId);
    }
    const { pc } = this._createPeerConnection(peerId, false);
    await pc.setRemoteDescription(sdp);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    this._send({ type: "answer", to: peerId, sdp: answer });
  }

  async _handleAnswer(peerId, sdp) {
    const peer = this.peers.get(peerId);
    if (!peer) return;
    await peer.pc.setRemoteDescription(sdp);
  }

  async _handleCandidate(peerId, candidate) {
    const peer = this.peers.get(peerId);
    if (!peer) return;
    try {
      await peer.pc.addIceCandidate(candidate);
    } catch (e) {
      this.log("WARN", `addIceCandidate failed for ${peerId}: ${e.message}`);
    }
  }

  _teardownPeer(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) return;
    try { peer.dc?.close(); peer.pc.close(); } catch {}
    this.peers.delete(peerId);
    this.emit("peerDisconnected", peerId);
  }

  send(peerId, payload) {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.ready) {
      throw new Error(`No active P2P channel to ${peerId}`);
    }
    peer.dc.send(JSON.stringify(payload));
  }

  isConnected(peerId) {
    return !!this.peers.get(peerId)?.ready;
  }

  hangup(peerId) {
    this._send({ type: "bye", to: peerId });
    this._teardownPeer(peerId);
  }

  disconnect() {
    for (const peerId of Array.from(this.peers.keys())) {
      this._teardownPeer(peerId);
    }
    if (this.ws) { this.ws.close(); this.ws = null; }
    this.wsOpen = false;
  }
}
