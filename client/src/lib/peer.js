/**
 * WebRTC peer connection manager.
 *
 * Flow:
 *   1. Connect to signaling WebSocket (/ws/signal/{userId})
 *   2. To call peer: create RTCPeerConnection, generate offer, send via signaling
 *   3. Peer receives offer, generates answer, sends back
 *   4. Both exchange ICE candidates via signaling
 *   5. Once connected, RTCDataChannel handles encrypted messages directly P2P
 *
 * Server only sees signaling (SDP offers/answers, ICE candidates).
 * After connection, all chat is browser-to-browser. Server never sees plaintext.
 */

import { getWsBase } from "./api";

// Use Google's public STUN server for NAT traversal
// (Production deployments would also need a TURN server for symmetric NATs)
const RTC_CONFIG = {
  iceServers: [
    { urls: "stun:stun.relay.metered.ca:80" },
    { urls: "stun:stun.l.google.com:19302" },
    {
      urls: "turn:standard.relay.metered.ca:80",
      username: "74fdb3f0a2eb7cf22ca2520f",
      credential: "VG7QXa08nF92POlV",
    },
    {
      urls: "turn:standard.relay.metered.ca:80?transport=tcp",
      username: "74fdb3f0a2eb7cf22ca2520f",
      credential: "VG7QXa08nF92POlV",
    },
    {
      urls: "turn:standard.relay.metered.ca:443",
      username: "74fdb3f0a2eb7cf22ca2520f",
      credential: "VG7QXa08nF92POlV",
    },
    {
      urls: "turns:standard.relay.metered.ca:443?transport=tcp",
      username: "74fdb3f0a2eb7cf22ca2520f",
      credential: "VG7QXa08nF92POlV",
    },
  ],
  iceCandidatePoolSize: 10,
};
export class PeerManager {
  constructor(userId) {
    this.userId = userId;
    this.ws = null;
    this.peers = new Map(); // peerId -> { pc, dc, ready }
    this.handlers = {
      onPresence: () => {},
      onMessage: () => {},
      onPeerConnected: () => {},
      onPeerDisconnected: () => {},
      onLog: () => {},
      onSignal: () => {},
    };
  }

  on(event, fn) {
    const key = `on${event[0].toUpperCase()}${event.slice(1)}`;
    if (key in this.handlers) this.handlers[key] = fn;
  }

  log(level, msg, detail) {
    this.handlers.onLog({ level, msg, detail, time: new Date() });
  }

  async connect() {
    return new Promise((resolve, reject) => {
      const url = `${getWsBase()}/ws/signal/${encodeURIComponent(this.userId)}`;
      this.log("INFO", `Connecting to signaling: ${url}`);
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        this.log("INFO", "Signaling channel connected");
        resolve();
      };

      this.ws.onerror = (e) => {
        this.log("ERROR", "Signaling WebSocket error", e.message || "connection failed");
        reject(new Error("WebSocket failed"));
      };

      this.ws.onclose = () => {
        this.log("WARN", "Signaling channel closed");
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
    this.handlers.onSignal(msg);

    if (msg.type === "presence") {
      this.handlers.onPresence(msg.users);
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

  _send(payload) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    }
  }

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
        this.handlers.onPeerConnected(peerId);
      } else if (
        pc.connectionState === "disconnected" ||
        pc.connectionState === "failed" ||
        pc.connectionState === "closed"
      ) {
        this.handlers.onPeerDisconnected(peerId);
      }
    };

    pc.ondatachannel = (e) => {
      // Receiving side gets the data channel here
      this._wireDataChannel(peerId, e.channel);
    };

    let dc = null;
    if (isInitiator) {
      dc = pc.createDataChannel("zerodday-msg", { ordered: true });
      this._wireDataChannel(peerId, dc);
    }

    const peer = { pc, dc, ready: false };
    this.peers.set(peerId, peer);
    return peer;
  }

  _wireDataChannel(peerId, dc) {
    const peer = this.peers.get(peerId);
    if (peer) peer.dc = dc;

    dc.onopen = () => {
      this.log("INFO", `[${peerId}] P2P data channel OPEN — direct browser-to-browser`);
      if (peer) peer.ready = true;
    };
    dc.onclose = () => {
      this.log("INFO", `[${peerId}] data channel closed`);
      if (peer) peer.ready = false;
    };
    dc.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        this.handlers.onMessage(peerId, data);
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
      // Glare — tear down existing
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
    try {
      peer.dc?.close();
      peer.pc.close();
    } catch {}
    this.peers.delete(peerId);
    this.handlers.onPeerDisconnected(peerId);
  }

  send(peerId, payload) {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.ready) {
      throw new Error(`No active P2P channel to ${peerId}`);
    }
    peer.dc.send(JSON.stringify(payload));
  }

  isConnected(peerId) {
    const peer = this.peers.get(peerId);
    return !!peer?.ready;
  }

  hangup(peerId) {
    this._send({ type: "bye", to: peerId });
    this._teardownPeer(peerId);
  }

  disconnect() {
    for (const peerId of Array.from(this.peers.keys())) {
      this._teardownPeer(peerId);
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}
