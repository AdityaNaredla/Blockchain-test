import { useState, useRef } from "react";
import { Link } from "react-router-dom";
import { sha256, bytesToHex } from "../lib/crypto";
import { verifyDocumentHash } from "../lib/api";

export default function Verify() {
  const [file, setFile] = useState(null);
  const [hash, setHash] = useState("");
  const [stage, setStage] = useState("idle"); // idle | hashing | querying | done
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);

  async function processFile(f) {
    if (!f) return;
    setFile(f);
    setHash("");
    setResult(null);
    setError("");

    try {
      setStage("hashing");
      const buf = await f.arrayBuffer();
      const hashBytes = await sha256(new Uint8Array(buf));
      const hashHex = bytesToHex(hashBytes);
      setHash(hashHex);

      setStage("querying");
      const r = await verifyDocumentHash(hashHex);
      setResult(r);
      setStage("done");
    } catch (e) {
      setError(e.message || "verification failed");
      setStage("idle");
    }
  }

  function onDrop(e) {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) processFile(f);
  }

  return (
    <div className="min-h-screen p-4 sm:p-8">
      <div className="max-w-3xl mx-auto">
        <header className="flex items-center justify-between mb-8 pb-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 border border-phosphor flex items-center justify-center text-phosphor font-display text-lg shadow-[0_0_20px_rgba(95,255,138,0.3)]">⌬</div>
            <div>
              <div className="font-display text-xl text-ink">verify document</div>
              <div className="text-[10px] uppercase tracking-[0.25em] text-dim">// public · no auth required</div>
            </div>
          </div>
          <div className="flex gap-2">
            <Link to="/registry" className="btn-ghost">registry</Link>
            <Link to="/login" className="btn-ghost">← back</Link>
          </div>
        </header>

        <div className="text-xs text-dim leading-relaxed mb-6 max-w-2xl">
          Drop a file. The browser computes its SHA-256 hash locally — your
          file never leaves this page. We then query the chain for any
          signatures that match this hash, and re-verify each one against the
          signer's current on-chain public key.
        </div>

        {/* Drop zone */}
        <div
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          className={`border-2 border-dashed p-10 text-center cursor-pointer transition-colors ${
            dragOver
              ? "border-phosphor bg-phosphor/10"
              : "border-border hover:border-phosphor/50 hover:bg-panel/50"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            className="hidden"
            onChange={(e) => processFile(e.target.files?.[0])}
          />
          <div className="font-display text-2xl text-ink mb-2">
            {file ? file.name : "drop file here"}
          </div>
          <div className="text-xs text-dim">
            {file
              ? `${file.size.toLocaleString()} bytes`
              : "or click to browse — file stays in your browser"}
          </div>
        </div>

        {/* Stage / status */}
        {stage === "hashing" && (
          <div className="mt-6 text-xs text-dim">
            <span className="caret">computing sha-256</span>
          </div>
        )}
        {stage === "querying" && (
          <div className="mt-6 text-xs text-dim">
            <span className="caret">querying chain</span>
          </div>
        )}

        {error && (
          <div className="mt-6 border border-crimson/50 bg-crimson/10 px-3 py-2 text-xs text-crimson">
            error: {error}
          </div>
        )}

        {/* Hash display */}
        {hash && (
          <div className="mt-6 panel p-4">
            <div className="text-[10px] uppercase tracking-[0.25em] text-dim mb-2">file fingerprint</div>
            <div className="text-xs font-mono text-ink break-all">{hash}</div>
          </div>
        )}

        {/* Result */}
        {result && stage === "done" && (
          <div className="mt-6">
            {result.signature_count === 0 ? (
              <div className="border border-amber/40 bg-amber/5 p-6">
                <div className="text-amber font-display text-xl mb-2">⚠ no signatures found</div>
                <div className="text-xs text-dim leading-relaxed">
                  This file has no on-chain signatures. Either nobody has signed
                  it, or the file you uploaded differs from what was signed —
                  even a single byte's difference produces a completely different
                  hash. If you expected a signature here, double-check you have
                  the exact same file.
                </div>
              </div>
            ) : (
              <div>
                <div className="text-[10px] uppercase tracking-[0.25em] text-phosphor mb-3">
                  // {result.signature_count} signature{result.signature_count > 1 ? "s" : ""} found
                </div>
                <div className="space-y-3">
                  {result.signatures.map((s) => (
                    <SignatureCard key={`${s.signer_id}-${s.block_index}`} sig={s} />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SignatureCard({ sig }) {
  const date = new Date(sig.signed_at * 1000);
  const ok = sig.signature_valid && sig.signer_registered;

  return (
    <div className={`border p-4 ${
      ok ? "border-phosphor/40 bg-phosphor/5" :
      sig.key_revoked ? "border-amber/40 bg-amber/5" :
      "border-crimson/50 bg-crimson/5"
    }`}>
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            {ok && <span className="text-phosphor text-lg">✓</span>}
            {!ok && sig.key_revoked && <span className="text-amber text-lg">⚠</span>}
            {!ok && !sig.key_revoked && <span className="text-crimson text-lg">✗</span>}
            <span className={`font-display text-lg ${
              ok ? "text-phosphor" : sig.key_revoked ? "text-amber" : "text-crimson"
            }`}>
              @{sig.signer_id}
            </span>
          </div>
          <div className="text-[11px] text-dim space-y-0.5">
            <div>signed at: <span className="text-ink">{date.toLocaleString()}</span></div>
            <div>block: <span className="text-ink">#{sig.block_index}</span></div>
          </div>
        </div>

        <div className="text-right">
          <StatusLine label="signature" ok={sig.signature_valid} />
          <StatusLine label="signer active" ok={sig.signer_registered} />
          {sig.key_revoked && (
            <div className="text-[10px] text-amber mt-1">key revoked</div>
          )}
        </div>
      </div>

      {ok && (
        <div className="mt-3 pt-3 border-t border-border text-[11px] text-dim leading-relaxed">
          Cryptographic proof: someone holding @{sig.signer_id}'s Ed25519
          private key signed this exact file content at the timestamp above.
          The signature was committed to block #{sig.block_index} of the chain
          and cannot be backdated.
        </div>
      )}
      {!ok && sig.key_revoked && (
        <div className="mt-3 pt-3 border-t border-border text-[11px] text-amber/80 leading-relaxed">
          The signer's key has been revoked or their account no longer exists.
          The signature may have been valid at the time it was made, but
          @{sig.signer_id} can no longer be trusted as an authoritative source.
        </div>
      )}
      {!ok && !sig.key_revoked && (
        <div className="mt-3 pt-3 border-t border-border text-[11px] text-crimson/80 leading-relaxed">
          Signature verification FAILED. This is unusual — it would mean the
          chain stored a malformed signature, or the signer rotated their key
          and the old signature no longer validates against their current key.
        </div>
      )}
    </div>
  );
}

function StatusLine({ label, ok }) {
  return (
    <div className="text-[10px] uppercase tracking-wider">
      <span className="text-dim">{label}: </span>
      <span className={ok ? "text-phosphor" : "text-crimson"}>
        {ok ? "✓ valid" : "✗ failed"}
      </span>
    </div>
  );
}
