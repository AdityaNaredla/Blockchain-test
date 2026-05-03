import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AuthShell, Spinner } from "../components/AuthShell";
import { unwrapSecretKey, hexToBytes, stashIdentity } from "../lib/crypto";
import { loginAccount } from "../lib/api";

export default function Login({ onAuth }) {
  const navigate = useNavigate();
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [stage, setStage] = useState("idle");

  async function onSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      setStage("auth");
      const result = await loginAccount(userId, password);

      setStage("unwrap");
      let secretKey;
      try {
        secretKey = await unwrapSecretKey(result.wrapped_secret_key, password);
      } catch {
        setError("passphrase did not unwrap key — wrong password?");
        setStage("idle");
        return;
      }

      const publicKey = hexToBytes(result.public_key);
      const identity = {
        secretKey, publicKey,
        publicKeyHex: result.public_key,
        userId,
      };
      stashIdentity(userId, identity);

      setStage("done");
      onAuth(identity);
      navigate("/chat", { replace: true });
    } catch (err) {
      setError(err.message || "login failed");
      setStage("idle");
    }
  }

  const busy = stage !== "idle" && stage !== "done";

  return (
    <AuthShell title="restore session" caption="// unlock keys">
      <form onSubmit={onSubmit} className="space-y-5">
        <div>
          <label className="label">username</label>
          <input
            className="field"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            autoComplete="username"
            required
            disabled={busy}
            autoFocus
          />
        </div>

        <div>
          <label className="label">passphrase</label>
          <input
            type="password"
            className="field"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            disabled={busy}
          />
        </div>

        {error && (
          <div className="border border-crimson/50 bg-crimson/10 px-3 py-2 text-xs text-crimson">
            error: {error}
          </div>
        )}

        <button type="submit" className="btn w-full" disabled={busy}>
          {stage === "idle" && <>authenticate →</>}
          {stage === "auth" && <><Spinner /> verifying…</>}
          {stage === "unwrap" && <><Spinner /> decrypting key…</>}
          {stage === "done" && <>✓ session restored</>}
        </button>

        <div className="pt-2 text-center">
          <Link to="/register" className="text-xs text-dim hover:text-phosphor transition-colors">
            no identity yet? <span className="text-phosphor">register →</span>
          </Link>
        </div>
      </form>
    </AuthShell>
  );
}
