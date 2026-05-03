import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthShell, Spinner } from "../components/AuthShell";
import { generateIdentityKey, stashIdentity } from "../lib/crypto";
import { registerAccount, getHealth, getApiBase } from "../lib/api";

export default function Register({ onAuth }) {
  const navigate = useNavigate();
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [serverOk, setServerOk] = useState(null);
  const [stage, setStage] = useState("idle");

  useEffect(() => {
    getHealth().then(() => setServerOk(true)).catch(() => setServerOk(false));
  }, []);

  async function onSubmit(e) {
    e.preventDefault();
    setError("");

    if (!/^[a-zA-Z0-9_\-]{3,24}$/.test(userId)) {
      setError("username: 3-24 chars, alphanumeric / _ / -");
      return;
    }
    if (password.length < 8) {
      setError("password must be at least 8 characters");
      return;
    }
    if (password !== confirm) {
      setError("passwords do not match");
      return;
    }

    try {
      setStage("keygen");
      const identity = generateIdentityKey();
      await new Promise((r) => setTimeout(r, 300));

      setStage("wrapping");
      // wrapping happens inside registerAccount
      setStage("registering");
      const result = await registerAccount({ userId, password, identity });

      // Stash unwrapped keys for this session
      stashIdentity(userId, identity);

      setStage("done");
      const me = {
        userId,
        secretKey: identity.secretKey,
        publicKey: identity.publicKey,
        publicKeyHex: identity.publicKeyHex,
        block_index: result.block_index,
      };
      onAuth(me);
      navigate("/chat", { replace: true });
    } catch (err) {
      setError(err.message || "registration failed");
      setStage("idle");
    }
  }

  const busy = stage !== "idle" && stage !== "done";

  return (
    <AuthShell title="register identity" caption="// new keypair">
      <ServerStatus ok={serverOk} />
      <form onSubmit={onSubmit} className="space-y-5 mt-6">
        <div>
          <label className="label">username</label>
          <input
            className="field"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="e.g. nakamoto"
            autoComplete="username"
            required minLength={3} maxLength={24}
            pattern="[a-zA-Z0-9_\-]+"
            disabled={busy}
          />
        </div>

        <div>
          <label className="label">passphrase</label>
          <input
            type="password"
            className="field"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="min 8 chars — protects your private key"
            autoComplete="new-password"
            required minLength={8}
            disabled={busy}
          />
        </div>

        <div>
          <label className="label">confirm passphrase</label>
          <input
            type="password"
            className="field"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
            disabled={busy}
          />
        </div>

        {error && (
          <div className="border border-crimson/50 bg-crimson/10 px-3 py-2 text-xs text-crimson">
            error: {error}
          </div>
        )}

        <button type="submit" className="btn w-full" disabled={busy || serverOk !== true}>
          {stage === "idle" && <>generate &amp; register →</>}
          {stage === "keygen" && <><Spinner /> generating ed25519 keypair…</>}
          {stage === "wrapping" && <><Spinner /> wrapping with passphrase…</>}
          {stage === "registering" && <><Spinner /> publishing to chain…</>}
          {stage === "done" && <>✓ registered</>}
        </button>

        <div className="pt-2 text-center">
          <Link to="/login" className="text-xs text-dim hover:text-phosphor transition-colors">
            already have an identity? <span className="text-phosphor">login →</span>
          </Link>
        </div>

        <details className="text-[11px] text-dim/80 pt-2 group">
          <summary className="cursor-pointer hover:text-ink list-none flex items-center gap-1">
            <span className="text-phosphor">›</span>
            <span className="group-open:hidden">what happens when i register?</span>
            <span className="hidden group-open:inline">↓ key generation flow</span>
          </summary>
          <ol className="mt-3 space-y-1.5 pl-4 leading-relaxed">
            <li>1. an Ed25519 keypair is generated <em>in your browser</em></li>
            <li>2. the secret key is encrypted with AES-GCM, wrapping key derived from your passphrase via PBKDF2 (200k iters)</li>
            <li>3. the wrapped (encrypted) blob and the public key go to the server; plaintext key never leaves the browser</li>
            <li>4. a REGISTER block is added to the chain — your identity is now publicly verifiable</li>
          </ol>
        </details>
      </form>
    </AuthShell>
  );
}

function ServerStatus({ ok }) {
  const cls = ok === true
    ? "border-phosphor/40 text-phosphor"
    : ok === false
    ? "border-crimson/50 text-crimson"
    : "border-border text-dim";
  return (
    <div className={`border px-3 py-2 text-xs ${cls}`}>
      <div>
        {ok === true && "✓ chain server connected"}
        {ok === false && "✗ chain server unreachable"}
        {ok === null && "checking server…"}
      </div>
      <div className="text-[10px] opacity-70 mt-0.5">{getApiBase()}</div>
    </div>
  );
}
