import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { PeerManager } from "../lib/peer";
import { SecureChannel } from "../lib/channel";
import {
  listUsers, getChainStats, lookupUser,
  logDocumentSignature, logoutAccount,
} from "../lib/api";
import { sha256, bytesToHex } from "../lib/crypto";

export default function Chat({ identity, onLogout }) {
  const navigate = useNavigate();
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
  const [showIdentity, setShowIdentity] = useState(false);

  const peerRef = useRef(null);
  const channelRef = useRef(null);
  const logEndRef = useRef(null);

  // ---------- Bring up PeerManager + SecureChannel ----------
  useEffect(() => {
    const pm = new PeerManager(identity.userId);
    const ch = new SecureChannel(pm, identity);
    ch.setPeerLookup(async (peerId) => {
      try { return await lookupUser(peerId); } catch { return null; }
    });

    // Multi-listener pattern — both we and SecureChannel can subscribe
    const unsubs = [
      pm.on("log", (entry) => setLogs((p) => [...p, entry])),
      pm.on("presence", (list) => setPresence(list.filter((u) => u !== identity.userId))),
      ch.on("log", (entry) => setLogs((p) => [...p, entry])),
      ch.on("handshakeComplete", (peerId) =>
        setSecureWith((p) => new Set([...p, peerId]))),
      ch.on("secureMessage", ({ from, text, seq }) =>
        setMessages((p) => [...p, {
          peer: from, dir: "in", text, seq, time: new Date(),
        }])),
      ch.on("securityEvent", (event, detail) => setLogs((p) => [...p, {
        level: "CRITICAL",
        msg: `Security event: ${event}`,
        detail: JSON.stringify(detail),
        time: new Date(),
      }])),
      pm.on("peerDisconnected", (peerId) =>
        setSecureWith((p) => {
          const n = new Set(p); n.delete(peerId); return n;
        })),
    ];

    pm.connect().catch((e) => {
      console.error("Failed to connect signaling", e);
      setLogs((p) => [...p, {
        level: "ERROR",
        msg: `Signaling connect failed: ${e.message}`,
        time: new Date(),
      }]);
    });

    peerRef.current = pm;
    channelRef.current = ch;

    return () => {
      for (const u of unsubs) u();
      ch.destroy();
      pm.disconnect();
    };
  }, [identity]);

  // ---------- Poll users + chain stats ----------
  useEffect(() => {
    const refresh = async () => {
      try {
        const u = await listUsers();
        setUsers(u.users || []);
        const s = await getChainStats();
        setChainStats(s);
      } catch (e) { console.error(e); }
    };
    refresh();
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, []);

  // ---------- Auto-scroll audit log ----------
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // ---------- Actions ----------

  async function startChat(peerId) {
    setActivePeer(peerId);
    if (!peerRef.current.isConnected(peerId)) {
      try {
        await peerRef.current.callPeer(peerId);
      } catch (e) {
        setLogs((p) => [...p, {
          level: "ERROR", msg: `Call failed: ${e.message}`, time: new Date(),
        }]);
      }
    }
  }

  async function sendMessage() {
    if (!activePeer || !draft.trim()) return;
    if (!channelRef.current.isSecureWith(activePeer)) {
      setLogs((p) => [...p, {
        level: "WARN",
        msg: `No secure session with ${activePeer} yet`,
        time: new Date(),
      }]);
      return;
    }
    const text = draft;
    try {
      const r = await channelRef.current.sendMessage(activePeer, text);
      setMessages((p) => [...p, {
        peer: activePeer, dir: "out", text, seq: r.seq, time: new Date(),
      }]);
      setDraft("");
    } catch (e) {
      setLogs((p) => [...p, {
        level: "ERROR", msg: e.message, time: new Date(),
      }]);
    }
  }

  async function signDocument() {
    if (!docFile) return;
    setDocResult(null);
    try {
      const buf = await docFile.arrayBuffer();
      const hash = await sha256(new Uint8Array(buf));
      const hashHex = bytesToHex(hash);
      const r = await logDocumentSignature(hashHex, identity);
      setDocResult({
        ok: true, filename: docFile.name, hash: hashHex, block: r.block_index,
      });
      setLogs((p) => [...p, {
        level: "INFO",
        msg: `Document signed: ${docFile.name}`,
        detail: `block #${r.block_index}`,
        time: new Date(),
      }]);
    } catch (e) {
      setDocResult({ ok: false, error: e.message });
    }
  }

  async function handleLogout() {
    try { await logoutAccount(); } catch {}
    if (peerRef.current) peerRef.current.disconnect();
    onLogout();
    navigate("/login", { replace: true });
  }

  const messagesForPeer = useMemo(
    () => messages.filter((m) => m.peer === activePeer),
    [messages, activePeer]
  );

  return (
    <div className="min-h-screen flex flex-col">
      {/* ---------- TOP BAR ---------- */}
      <header className="border-b border-border bg-panel">
        <div className="px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 border border-phosphor flex items-center justify-center text-phosphor font-display text-sm shadow-[0_0_12px_rgba(95,255,138,0.3)]">⌬</div>
            <div className="font-display text-sm tracking-widest hidden sm:block">ZERODDAY</div>
            <span className="hidden md:inline text-[10px] text-dim/60">// secure channel</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              className="btn-ghost"
              onClick={() => setShowIdentity((v) => !v)}
              title="view your identity"
            >
              <span className="text-phosphor">@</span>
              {identity.userId}
              <span className="text-dim/60 hidden sm:inline">
                · {identity.publicKeyHex.slice(0, 8)}
              </span>
            </button>
            <Link to="/registry" className="btn-ghost hidden sm:inline-flex">registry</Link>
            <Link to="/verify" className="btn-ghost hidden sm:inline-flex">verify</Link>
            <button onClick={handleLogout} className="btn-danger">logout</button>
          </div>
        </div>

        {showIdentity && (
          <div className="px-4 sm:px-6 py-4 border-t border-border bg-bg/50 animate-slide-up">
            <div className="grid sm:grid-cols-2 gap-3 max-w-3xl text-xs">
              <Field label="username" value={`@${identity.userId}`} accent />
              <Field label="public key (ed25519)"
                     value={identity.publicKeyHex} mono />
            </div>
          </div>
        )}
      </header>

      {/* ---------- THREE-PANE BODY ---------- */}
      <div className="flex-1 grid grid-cols-1 md:grid-cols-[260px_1fr] xl:grid-cols-[260px_1fr_320px] min-h-0">
        {/* LEFT — peers + chain + doc sign */}
        <aside className="border-r border-border bg-panel/50 overflow-y-auto">
          <div className="panel-header">
            <span className="panel-title">peers</span>
            <span className="chip">{users.filter(u => u.user_id !== identity.userId).length}</span>
          </div>
          <PeerList
            users={users}
            meId={identity.userId}
            activePeer={activePeer}
            presence={presence}
            secureWith={secureWith}
            onSelect={startChat}
          />

          <div className="panel-header mt-2">
            <span className="panel-title">⛓ chain</span>
          </div>
          <div className="px-4 py-3 text-xs space-y-1 text-dim">
            {!chainStats && <div>—</div>}
            {chainStats && (
              <>
                <div>blocks: <span className="text-ink">{chainStats.total_blocks}</span></div>
                <div>register: <span className="text-ink">{chainStats.by_type.REGISTER || 0}</span></div>
                <div>revoke: <span className="text-ink">{chainStats.by_type.REVOKE || 0}</span></div>
                <div>doc sigs: <span className="text-ink">{chainStats.by_type.DOC_SIGNATURE || 0}</span></div>
                <div className={`mt-2 ${chainStats.valid ? "text-phosphor" : "text-crimson"}`}>
                  {chainStats.valid ? "✓ chain integrity ok" : "✗ INTEGRITY FAILURE"}
                </div>
              </>
            )}
          </div>

          <div className="panel-header mt-2">
            <span className="panel-title">⊞ sign doc</span>
          </div>
          <div className="px-4 py-3 text-xs space-y-2">
            <input
              type="file"
              onChange={(e) => setDocFile(e.target.files?.[0] || null)}
              className="block w-full text-[11px] text-dim file:mr-2 file:py-1 file:px-2 file:border file:border-border file:bg-bg file:text-dim file:font-mono file:text-[10px] file:uppercase file:tracking-wider hover:file:border-phosphor hover:file:text-phosphor file:transition-colors"
            />
            <button
              onClick={signDocument}
              disabled={!docFile}
              className="btn-ghost w-full"
            >
              hash · sign · log →
            </button>
            {docResult && (
              <div className={`border px-2 py-1.5 text-[10px] ${docResult.ok ? "border-phosphor/50 text-phosphor bg-phosphor/5" : "border-crimson/50 text-crimson"}`}>
                {docResult.ok ? (
                  <>
                    <div className="font-bold">✓ {docResult.filename}</div>
                    <div className="opacity-70 break-all mt-0.5">
                      {docResult.hash.slice(0, 16)}…
                    </div>
                    <div className="opacity-70">block #{docResult.block}</div>
                    <Link
                      to="/verify"
                      className="block mt-2 pt-2 border-t border-phosphor/30 text-phosphor hover:text-ink transition-colors"
                    >
                      verify this signature →
                    </Link>
                  </>
                ) : (
                  <div>error: {docResult.error}</div>
                )}
              </div>
            )}
          </div>
        </aside>

        {/* MAIN — chat thread */}
        <main className="flex flex-col min-h-0">
          {!activePeer ? (
            <EmptyState />
          ) : (
            <>
              <div className="px-4 sm:px-6 py-3 border-b border-border flex items-center justify-between flex-wrap gap-2">
                <div>
                  <div className="text-xs text-dim uppercase tracking-wider">conversation with</div>
                  <div className="font-display text-lg text-ink">{activePeer}</div>
                </div>
                <div className="flex items-center gap-2">
                  {presence.includes(activePeer)
                    ? <span className="chip border-phosphor/40 text-phosphor">online</span>
                    : <span className="chip">offline</span>}
                  {secureWith.has(activePeer)
                    ? <span className="chip border-phosphor/40 text-phosphor">🔒 secure</span>
                    : <span className="chip border-amber/40 text-amber">⏳ handshake</span>}
                </div>
              </div>

              <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-6 space-y-3">
                {messagesForPeer.length === 0 && (
                  <div className="text-center text-xs text-dim/60 py-12">
                    {secureWith.has(activePeer)
                      ? <div className="caret">secure channel ready</div>
                      : <div className="caret">establishing secure channel</div>}
                    <div className="mt-2 opacity-70">
                      Ed25519 → X25519 → HKDF-SHA256 → AES-256-GCM
                    </div>
                  </div>
                )}
                {messagesForPeer.map((m, i) => (
                  <MessageRow key={i} msg={m}
                    meName={identity.userId}
                    peerName={activePeer} />
                ))}
              </div>

              {/* Composer */}
              <div className="border-t border-border px-4 sm:px-6 py-3 flex gap-2 bg-panel/50">
                <span className="self-center text-phosphor text-sm">›</span>
                <input
                  type="text"
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                  placeholder={
                    secureWith.has(activePeer)
                      ? `message ${activePeer}…`
                      : "waiting for handshake…"
                  }
                  className="flex-1 bg-transparent border-none outline-none text-sm text-ink placeholder:text-dim/60 font-mono"
                  disabled={!secureWith.has(activePeer)}
                  autoFocus
                />
                <button
                  className="btn"
                  onClick={sendMessage}
                  disabled={!secureWith.has(activePeer) || !draft.trim()}
                >
                  send
                </button>
              </div>
            </>
          )}
        </main>

        {/* RIGHT — audit log */}
        <aside className="hidden xl:flex flex-col border-l border-border bg-panel/30 min-h-0">
          <div className="panel-header">
            <span className="panel-title">audit log</span>
            <span className="text-[10px] text-crimson font-bold">
              {logs.filter((l) => l.level === "CRITICAL").length} incidents
            </span>
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-2 text-[10px] font-mono space-y-0.5">
            {logs.length === 0 && (
              <div className="text-dim/60 text-center py-8">no events yet</div>
            )}
            {logs.map((l, i) => (
              <LogRow key={i} entry={l} />
            ))}
            <div ref={logEndRef} />
          </div>
        </aside>
      </div>
    </div>
  );
}

// ---------- subcomponents ----------

function PeerList({ users, meId, activePeer, presence, secureWith, onSelect }) {
  const others = users.filter((u) => u.user_id !== meId);
  if (others.length === 0) {
    return (
      <div className="px-4 py-4 text-[11px] text-dim/70 leading-relaxed">
        no other identities yet. open another browser / incognito and register
        a second user to start a conversation.
      </div>
    );
  }
  return (
    <ul>
      {others.map((u) => {
        const online = presence.includes(u.user_id);
        const secure = secureWith.has(u.user_id);
        const active = activePeer === u.user_id;
        return (
          <li key={u.user_id}>
            <button
              onClick={() => onSelect(u.user_id)}
              className={`w-full text-left px-4 py-3 border-b border-border/60 transition-colors flex items-center gap-3 ${
                active ? "bg-phosphor/10" : "hover:bg-panel"
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${
                online ? "bg-phosphor shadow-[0_0_8px_rgba(95,255,138,0.6)]" : "bg-dim/40"
              }`} />
              <span className="flex-1 min-w-0">
                <span className={`block text-sm truncate ${active ? "text-phosphor" : "text-ink"}`}>
                  {u.user_id}
                </span>
                <span className="block text-[10px] text-dim/70 truncate">
                  {u.public_key.slice(0, 16)}…
                </span>
              </span>
              {secure && (
                <span className="text-[10px] text-phosphor">🔒</span>
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function MessageRow({ msg, meName, peerName }) {
  const mine = msg.dir === "out";
  const time = msg.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return (
    <div className={`flex animate-slide-up ${mine ? "justify-end" : "justify-start"}`}>
      <div className={`max-w-[85%] sm:max-w-[70%] flex flex-col gap-1 ${mine ? "items-end" : "items-start"}`}>
        <div className="flex items-center gap-2 text-[10px] text-dim/70 uppercase tracking-wider px-1">
          <span className={mine ? "text-phosphor" : "text-amber"}>{mine ? meName : peerName}</span>
          <span>·</span>
          <span>seq {msg.seq}</span>
          <span>·</span>
          <span>{time}</span>
        </div>
        <div className={`px-4 py-2.5 border text-sm leading-relaxed break-words ${
          mine
            ? "border-phosphor/40 bg-phosphor/5 text-ink"
            : "border-border bg-panel text-ink"
        }`}>
          {msg.text}
        </div>
      </div>
    </div>
  );
}

function LogRow({ entry }) {
  const lc = {
    INFO: "text-phosphor",
    DEBUG: "text-dim",
    WARN: "text-amber",
    ERROR: "text-crimson",
    CRITICAL: "text-crimson",
  }[entry.level] || "text-dim";
  return (
    <div className="border-b border-border/30 py-1">
      <div className="flex items-baseline gap-2 flex-wrap">
        <span className="text-dim/60 text-[9px]">
          {entry.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
        </span>
        <span className={`${lc} font-bold`}>[{entry.level}]</span>
        <span className="text-ink break-all">{entry.msg}</span>
      </div>
      {entry.detail && (
        <div className="text-dim/60 text-[9px] pl-4 mt-0.5 break-all">{entry.detail}</div>
      )}
    </div>
  );
}

function Field({ label, value, accent, mono }) {
  return (
    <div className="border border-border bg-bg px-3 py-2">
      <div className="text-[9px] uppercase tracking-[0.2em] text-dim mb-1">{label}</div>
      <div className={`text-xs ${mono ? "font-mono" : ""} ${accent ? "text-phosphor" : "text-ink"} break-all`}>
        {value}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="text-center text-dim text-sm max-w-sm">
        <div className="font-display text-2xl text-ink mb-3">no peer selected</div>
        <p className="text-xs leading-relaxed text-dim/80">
          select a peer from the left to begin an encrypted conversation.
          if no peers are listed, open another browser window and register a
          second user.
        </p>
      </div>
    </div>
  );
}
