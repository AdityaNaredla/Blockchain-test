import { useState, useEffect, useRef } from "react";
import {
  generateIdentityKey,
  saveIdentity,
  loadIdentity,
  clearIdentity,
  sha256,
  bytesToHex,
} from "./lib/crypto";
import {
  registerUser,
  lookupUser,
  listUsers,
  getChainStats,
  logDocumentSignature,
  getApiBase,
  getHealth,
} from "./lib/api";
import { PeerManager } from "./lib/peer";
import { SecureChannel } from "./lib/channel";

const C = {
  bg: "#0A1628", card: "#0F2847", row2: "#162D50",
  accent: "#00D4AA", green: "#2ECC71", red: "#FF6B6B",
  warn: "#FECA57", purple: "#A78BFA",
  white: "#E8EDF2", bright: "#FFFFFF", muted: "#7B8FA3",
  border: "#1E3A5F",
};

const layout = {
  body: { background: C.bg, minHeight: "100vh", color: C.white, fontFamily: "'Segoe UI', system-ui, sans-serif" },
  header: { background: `linear-gradient(135deg, ${C.card} 0%, ${C.bg} 100%)`, borderBottom: `2px solid ${C.accent}`, padding: "14px 24px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 },
  card: { background: C.card, borderRadius: 8, border: `1px solid ${C.border}`, padding: 16 },
  cardHeader: { fontSize: 12, fontWeight: 700, color: C.accent, letterSpacing: 1.2, marginBottom: 12, textTransform: "uppercase" },
  input: { background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: "8px 12px", color: C.white, fontSize: 14, fontFamily: "inherit", width: "100%", boxSizing: "border-box" },
  btn: { background: C.accent, color: C.bg, border: "none", borderRadius: 6, padding: "8px 16px", fontWeight: 700, fontSize: 13, cursor: "pointer", letterSpacing: 0.5 },
  btnSecondary: { background: "transparent", color: C.accent, border: `1px solid ${C.accent}`, borderRadius: 6, padding: "8px 16px", fontWeight: 700, fontSize: 13, cursor: "pointer" },
  btnDanger: { background: "transparent", color: C.red, border: `1px solid ${C.red}`, borderRadius: 6, padding: "6px 12px", fontWeight: 700, fontSize: 12, cursor: "pointer" },
};

function Code({ children }) {
  return <code style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, background: C.bg, padding: "2px 6px", borderRadius: 3, color: C.muted }}>{children}</code>;
}

function Section({ title, children, right }) {
  return (
    <div style={{ ...layout.card, marginBottom: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div style={layout.cardHeader}>{title}</div>
        {right}
      </div>
      {children}
    </div>
  );
}

function Onboarding({ onReady }) {
  const [userId, setUserId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [serverOk, setServerOk] = useState(null);

  useEffect(() => {
    getHealth().then(() => setServerOk(true)).catch(() => setServerOk(false));
  }, []);

  async function handleRegister() {
    setErr("");
    if (!userId.match(/^[a-zA-Z0-9_\-]{1,64}$/)) {
      setErr("Username must be 1-64 chars, alphanumeric / _ / -");
      return;
    }
    setBusy(true);
    try {
      const identity = generateIdentityKey();
      await registerUser(userId, identity);
      saveIdentity(userId, identity);
      onReady({ userId, ...identity });
    } catch (e) {
      setErr(`Registration failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ ...layout.body, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ ...layout.card, maxWidth: 520, width: "100%" }}>
        <div style={{ fontSize: 28, fontWeight: 800, color: C.bright, marginBottom: 8, textAlign: "center" }}>🛡️ ZeroDay</div>
        <div style={{ fontSize: 13, color: C.muted, textAlign: "center", marginBottom: 24 }}>
          Secure peer-to-peer messaging with blockchain-backed key registry
        </div>

        <div style={{
          padding: 12,
          background: serverOk === true ? `${C.green}15` : serverOk === false ? `${C.red}15` : `${C.muted}15`,
          border: `1px solid ${serverOk === true ? C.green : serverOk === false ? C.red : C.muted}33`,
          borderRadius: 6, marginBottom: 20, fontSize: 12,
        }}>
          <div style={{ color: serverOk === true ? C.green : serverOk === false ? C.red : C.muted, fontWeight: 700 }}>
            {serverOk === true ? "✓ Connected to blockchain server" : serverOk === false ? "✗ Server unreachable" : "Checking server..."}
          </div>
          <Code>{getApiBase()}</Code>
        </div>

        <label style={{ fontSize: 12, fontWeight: 700, color: C.accent, marginBottom: 6, display: "block" }}>PICK A USERNAME</label>
        <input autoFocus value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="alice" style={layout.input}
          onKeyDown={(e) => e.key === "Enter" && !busy && handleRegister()} />
        <div style={{ fontSize: 11, color: C.muted, marginTop: 6, marginBottom: 16 }}>
          Your Ed25519 identity key will be generated locally and registered on the blockchain.
        </div>

        {err && <div style={{ padding: 10, background: `${C.red}15`, border: `1px solid ${C.red}44`, borderRadius: 6, color: C.red, fontSize: 12, marginBottom: 12 }}>{err}</div>}

        <button onClick={handleRegister} disabled={busy || serverOk !== true}
          style={{ ...layout.btn, width: "100%", padding: "12px", opacity: busy || serverOk !== true ? 0.5 : 1, cursor: busy || serverOk !== true ? "not-allowed" : "pointer" }}>
          {busy ? "Generating + Registering..." : "Generate Keys & Register"}
        </button>
      </div>
    </div>
  );
}

function App() {
  const [identity, setIdentity] = useState(() => loadIdentity());
  const [users, setUsers] = useState([]);
  const [chainStats, setChainStats] = useState(null);
  const [activePeer, setActivePeer] = useState(null);
  const [messages, setMessages] = useState([]);
  const [logs, setLogs] = useState([]);
  const [draft, setDraft] = useState("");
  const [presence, setPresence] = useState([]);
  const [secureWith, setSecureWith] = useState(new Set());
  const [docFile, setDocFile] = useState(null);
  const [docResult, setDocResult] = useState(null);
  const peerRef = useRef(null);
  const channelRef = useRef(null);
  const logEndRef = useRef(null);

  useEffect(() => {
    if (!identity) return;
    const pm = new PeerManager(identity.userId);
    const ch = new SecureChannel(pm, identity);
    ch.setPeerLookup(async (userId) => { try { return await lookupUser(userId); } catch { return null; } });

    pm.on("log", (entry) => setLogs((p) => [...p, entry]));
    pm.on("presence", (list) => setPresence(list.filter((u) => u !== identity.userId)));
    ch.on("log", (entry) => setLogs((p) => [...p, entry]));
    ch.on("handshakeComplete", (peerId) => setSecureWith((p) => new Set([...p, peerId])));
    ch.on("secureMessage", ({ from, text, seq }) => {
      setMessages((p) => [...p, { peer: from, dir: "in", text, seq, time: new Date() }]);
    });
    ch.on("securityEvent", (event, detail) => {
      setLogs((p) => [...p, { level: "CRITICAL", msg: `Security event: ${event}`, detail: JSON.stringify(detail), time: new Date() }]);
    });

    pm.connect().catch((e) => console.error("Failed to connect", e));
    peerRef.current = pm;
    channelRef.current = ch;

    return () => pm.disconnect();
  }, [identity]);

  useEffect(() => {
    if (!identity) return;
    const refresh = async () => {
      try {
        const u = await listUsers();
        setUsers(u.users);
        const s = await getChainStats();
        setChainStats(s);
      } catch (e) { console.error(e); }
    };
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [identity]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const startChat = async (peerId) => {
    setActivePeer(peerId);
    if (!peerRef.current.isConnected(peerId)) {
      await peerRef.current.callPeer(peerId);
    }
  };

  const sendMessage = async () => {
    if (!activePeer || !draft.trim()) return;
    if (!channelRef.current.isSecureWith(activePeer)) {
      setLogs((p) => [...p, { level: "WARN", msg: `No secure session with ${activePeer} yet`, time: new Date() }]);
      return;
    }
    const text = draft;
    try {
      const r = await channelRef.current.sendMessage(activePeer, text);
      setMessages((p) => [...p, { peer: activePeer, dir: "out", text, seq: r.seq, time: new Date() }]);
      setDraft("");
    } catch (e) {
      setLogs((p) => [...p, { level: "ERROR", msg: e.message, time: new Date() }]);
    }
  };

  const signDocument = async () => {
    if (!docFile) return;
    setDocResult(null);
    try {
      const buf = await docFile.arrayBuffer();
      const hash = await sha256(new Uint8Array(buf));
      const hashHex = bytesToHex(hash);
      const r = await logDocumentSignature(identity.userId, hashHex, identity);
      setDocResult({ ok: true, filename: docFile.name, hash: hashHex, block: r.block_index });
      setLogs((p) => [...p, { level: "INFO", msg: `Document signed: ${docFile.name}`, detail: `block #${r.block_index}`, time: new Date() }]);
    } catch (e) {
      setDocResult({ ok: false, error: e.message });
    }
  };

  const logout = () => {
    clearIdentity();
    setIdentity(null);
    if (peerRef.current) peerRef.current.disconnect();
  };

  if (!identity) return <Onboarding onReady={setIdentity} />;

  const messagesForPeer = messages.filter((m) => m.peer === activePeer);

  return (
    <div style={layout.body}>
      <div style={layout.header}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: `${C.accent}18`, border: `2px solid ${C.accent}`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>🛡️</div>
          <div>
            <div style={{ fontWeight: 800, fontSize: 16, color: C.bright, letterSpacing: 1 }}>ZERODDAY</div>
            <div style={{ fontSize: 11, color: C.muted }}>
              <span style={{ color: C.accent, fontWeight: 700 }}>@{identity.userId}</span>
              {" · "}
              <Code>{identity.publicKeyHex.slice(0, 16)}...</Code>
            </div>
          </div>
        </div>
        <button onClick={logout} style={layout.btnDanger}>Logout</button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr 320px", gap: 16, padding: 16, maxWidth: 1400, margin: "0 auto" }}>
        <div>
          <Section title={`👥 Users (${users.length})`}>
            {users.length === 0 && <div style={{ fontSize: 12, color: C.muted }}>No users registered yet.</div>}
            {users.filter((u) => u.user_id !== identity.userId).map((u) => {
              const online = presence.includes(u.user_id);
              const isActive = activePeer === u.user_id;
              const isSecure = secureWith.has(u.user_id);
              return (
                <div key={u.user_id} onClick={() => startChat(u.user_id)}
                  style={{ padding: "8px 10px", marginBottom: 4, borderRadius: 6, background: isActive ? `${C.accent}15` : "transparent", borderLeft: `3px solid ${isActive ? C.accent : C.border}`, cursor: "pointer", fontSize: 13 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontWeight: 600, color: isActive ? C.bright : C.white }}>@{u.user_id}</span>
                    <div style={{ display: "flex", gap: 4 }}>
                      {online && <span style={{ width: 8, height: 8, borderRadius: "50%", background: C.green }} title="Online" />}
                      {isSecure && <span style={{ fontSize: 9, color: C.green }}>🔒</span>}
                    </div>
                  </div>
                  <Code>{u.public_key.slice(0, 12)}...</Code>
                </div>
              );
            })}
          </Section>

          {chainStats && (
            <Section title="⛓️ Blockchain">
              <div style={{ fontSize: 12, lineHeight: 1.8 }}>
                <div><span style={{ color: C.muted }}>Blocks:</span> <strong>{chainStats.total_blocks}</strong></div>
                <div><span style={{ color: C.muted }}>Registered:</span> {chainStats.by_type.REGISTER || 0}</div>
                <div><span style={{ color: C.muted }}>Revoked:</span> {chainStats.by_type.REVOKE || 0}</div>
                <div><span style={{ color: C.muted }}>Doc sigs:</span> {chainStats.by_type.DOC_SIGNATURE || 0}</div>
                <div style={{ marginTop: 6, color: chainStats.valid ? C.green : C.red, fontWeight: 700 }}>
                  {chainStats.valid ? "✓ Chain integrity OK" : "✗ INTEGRITY FAILURE"}
                </div>
              </div>
            </Section>
          )}

          <Section title="📄 Sign Document">
            <input type="file" onChange={(e) => setDocFile(e.target.files?.[0] || null)} style={{ ...layout.input, padding: 6, fontSize: 12, marginBottom: 8 }} />
            <button onClick={signDocument} disabled={!docFile} style={{ ...layout.btnSecondary, width: "100%", opacity: docFile ? 1 : 0.5 }}>Hash + Sign + Log</button>
            {docResult && (
              <div style={{ marginTop: 10, padding: 8, borderRadius: 6, fontSize: 11, background: docResult.ok ? `${C.green}15` : `${C.red}15`, border: `1px solid ${docResult.ok ? C.green : C.red}44`, color: docResult.ok ? C.green : C.red }}>
                {docResult.ok ? (
                  <>
                    <div style={{ fontWeight: 700 }}>✓ Signed: {docResult.filename}</div>
                    <div style={{ marginTop: 4, color: C.muted }}>
                      Hash: <Code>{docResult.hash.slice(0, 16)}...</Code><br />
                      Block #{docResult.block}
                    </div>
                  </>
                ) : <div>Error: {docResult.error}</div>}
              </div>
            )}
          </Section>
        </div>

        <div>
          <Section title={activePeer ? `💬 Chat with @${activePeer}` : "💬 Select a user to chat"}
            right={activePeer && (
              <span style={{ fontSize: 11, fontWeight: 700, padding: "3px 8px", borderRadius: 4, color: secureWith.has(activePeer) ? C.green : C.warn, border: `1px solid ${secureWith.has(activePeer) ? C.green : C.warn}66` }}>
                {secureWith.has(activePeer) ? "🔒 SECURE" : "⏳ HANDSHAKING..."}
              </span>
            )}>
            <div style={{ minHeight: 360, maxHeight: 440, overflowY: "auto", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: 12, marginBottom: 12 }}>
              {!activePeer && <div style={{ color: C.muted, fontSize: 13, textAlign: "center", paddingTop: 80 }}>Click a user on the left to start an encrypted chat.</div>}
              {activePeer && messagesForPeer.length === 0 && (
                <div style={{ color: C.muted, fontSize: 12, textAlign: "center", paddingTop: 60 }}>
                  {secureWith.has(activePeer) ? "Secure channel established. Send a message below." : "Establishing secure channel..."}
                </div>
              )}
              {messagesForPeer.map((m, i) => (
                <div key={i} style={{ display: "flex", justifyContent: m.dir === "out" ? "flex-end" : "flex-start", marginBottom: 8 }}>
                  <div style={{ maxWidth: "70%", padding: "8px 12px", borderRadius: 12, background: m.dir === "out" ? C.accent : C.row2, color: m.dir === "out" ? C.bg : C.white, fontSize: 13, boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }}>
                    <div>{m.text}</div>
                    <div style={{ fontSize: 9, marginTop: 4, opacity: 0.7, color: m.dir === "out" ? C.bg : C.muted }}>seq {m.seq} · {m.time.toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>

            {activePeer && (
              <div style={{ display: "flex", gap: 8 }}>
                <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                  placeholder={secureWith.has(activePeer) ? "Type a message..." : "Waiting for handshake..."}
                  disabled={!secureWith.has(activePeer)} style={{ ...layout.input, flex: 1 }} />
                <button onClick={sendMessage} disabled={!secureWith.has(activePeer) || !draft.trim()}
                  style={{ ...layout.btn, opacity: secureWith.has(activePeer) && draft.trim() ? 1 : 0.5 }}>Send</button>
              </div>
            )}
          </Section>

          <Section title="🔐 Crypto Stack">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 11 }}>
              <div><span style={{ color: C.muted }}>Identity:</span> <strong>Ed25519</strong></div>
              <div><span style={{ color: C.muted }}>Key Exchange:</span> <strong>X25519</strong></div>
              <div><span style={{ color: C.muted }}>KDF:</span> <strong>HKDF-SHA256</strong></div>
              <div><span style={{ color: C.muted }}>Encryption:</span> <strong>AES-256-GCM</strong></div>
              <div><span style={{ color: C.muted }}>Doc Hash:</span> <strong>SHA-256</strong></div>
              <div><span style={{ color: C.muted }}>Transport:</span> <strong>WebRTC P2P</strong></div>
            </div>
          </Section>
        </div>

        <div>
          <Section title={`📋 Audit Log (${logs.length})`}
            right={<span style={{ fontSize: 10, color: C.red, fontWeight: 600 }}>{logs.filter((l) => l.level === "CRITICAL").length} incidents</span>}>
            <div style={{ fontFamily: "'Fira Code', monospace", fontSize: 10, maxHeight: 600, overflowY: "auto", background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }}>
              {logs.length === 0 && <div style={{ color: C.muted, textAlign: "center", padding: 20 }}>No events yet</div>}
              {logs.map((l, i) => {
                const lc = { INFO: C.accent, DEBUG: C.muted, WARN: C.warn, ERROR: C.red, CRITICAL: C.red }[l.level] || C.muted;
                return (
                  <div key={i} style={{ padding: "3px 0", borderBottom: `1px solid ${C.border}33` }}>
                    <span style={{ color: C.muted }}>{l.time.toLocaleTimeString()}</span>{" "}
                    <span style={{ color: lc, fontWeight: 700 }}>[{l.level}]</span>{" "}
                    <span style={{ color: C.white }}>{l.msg}</span>
                    {l.detail && <div style={{ color: C.muted, marginLeft: 12, fontSize: 9 }}>{l.detail}</div>}
                  </div>
                );
              })}
              <div ref={logEndRef} />
            </div>
          </Section>
        </div>
      </div>
    </div>
  );
}

export default App;
