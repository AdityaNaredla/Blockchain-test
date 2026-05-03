import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listUsers } from "../lib/api";

export default function Registry() {
  const [users, setUsers] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listUsers()
      .then((d) => setUsers(d.users || []))
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="min-h-screen p-4 sm:p-8">
      <div className="max-w-5xl mx-auto">
        <header className="flex items-center justify-between mb-8 pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 border border-phosphor flex items-center justify-center text-phosphor font-display text-lg shadow-[0_0_20px_rgba(95,255,138,0.3)]">⌬</div>
            <div>
              <div className="font-display text-xl text-ink">on-chain registry</div>
              <div className="text-[10px] uppercase tracking-[0.25em] text-dim">// public · read-only · v0.2</div>
            </div>
          </div>
          <Link to="/login" className="btn-ghost">← back</Link>
        </header>

        <div className="text-xs text-dim leading-relaxed mb-6 max-w-2xl">
          Every registered identity publishes its Ed25519 public key to this
          chain. Anyone can verify a user's keys without trusting the message
          server. Backed by SQLite — every block links to the previous via
          SHA-256, so tampering is detectable.
        </div>

        {error && (
          <div className="border border-crimson/50 bg-crimson/10 px-3 py-2 text-xs text-crimson mb-4">
            error: {error}
          </div>
        )}

        {users === null && !error && (
          <div className="text-dim text-sm py-12 text-center">
            <span className="caret">loading registry</span>
          </div>
        )}

        {users && users.length === 0 && (
          <div className="text-dim text-sm py-12 text-center border border-border bg-panel">
            no identities registered yet
          </div>
        )}

        {users && users.length > 0 && (
          <div className="overflow-x-auto border border-border">
            <table className="w-full text-xs font-mono">
              <thead className="bg-panel">
                <tr className="text-left text-[10px] uppercase tracking-[0.2em] text-dim">
                  <th className="px-3 py-2.5 border-b border-border">block</th>
                  <th className="px-3 py-2.5 border-b border-border">user</th>
                  <th className="px-3 py-2.5 border-b border-border">public key (ed25519)</th>
                  <th className="px-3 py-2.5 border-b border-border">registered</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.user_id} className="hover:bg-panel/60 transition-colors">
                    <td className="px-3 py-2.5 border-b border-border text-dim">
                      #{u.block_index}
                    </td>
                    <td className="px-3 py-2.5 border-b border-border text-phosphor">
                      @{u.user_id}
                    </td>
                    <td className="px-3 py-2.5 border-b border-border text-ink break-all">
                      {u.public_key.slice(0, 32)}…{u.public_key.slice(-6)}
                    </td>
                    <td className="px-3 py-2.5 border-b border-border text-dim">
                      {new Date(u.registered_at * 1000).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
