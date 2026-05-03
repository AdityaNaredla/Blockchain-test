import { Link } from "react-router-dom";

export function AuthShell({ title, caption, children }) {
  return (
    <div className="min-h-screen grid lg:grid-cols-[1.1fr_1fr]">
      {/* Left — atmosphere */}
      <div className="hidden lg:flex flex-col justify-between p-10 border-r border-border scanlines bg-[radial-gradient(ellipse_at_top_left,rgba(95,255,138,0.08),transparent_60%)]">
        <div className="flex items-center gap-3">
          <Logo />
          <span className="text-xs uppercase tracking-[0.3em] text-dim">
            zerodday /// v0.2
          </span>
        </div>

        <div className="space-y-6">
          <h1 className="font-display text-5xl xl:text-7xl leading-[0.95] text-ink">
            speak<br />
            <span className="text-phosphor">in cipher.</span>
          </h1>
          <p className="max-w-md text-sm text-dim leading-relaxed">
            End-to-end encrypted messages over WebRTC. Identity keys committed
            to a SQLite blockchain. The server only sees signaling — never your
            messages, never your private keys.
          </p>

          <div className="flex flex-wrap gap-2 pt-2">
            <span className="chip">ed25519</span>
            <span className="chip">x25519</span>
            <span className="chip">hkdf-sha256</span>
            <span className="chip">aes-256-gcm</span>
            <span className="chip">webrtc p2p</span>
            <span className="chip">on-chain identity</span>
          </div>
        </div>

        <div className="text-[11px] text-dim/70 leading-relaxed">
          <span className="text-phosphor">$</span>{" "}
          openssl rand -hex 32
          <br />
          <span className="opacity-50">a4f1c2…b8e9 — generating session entropy</span>
        </div>
      </div>

      {/* Right — form */}
      <div className="flex flex-col justify-center px-6 sm:px-12 py-12 relative">
        <div className="lg:hidden flex items-center gap-3 mb-12">
          <Logo />
          <span className="text-xs uppercase tracking-[0.3em] text-dim">zerodday</span>
        </div>

        <div className="max-w-sm w-full mx-auto lg:mx-0 animate-fade-in">
          <div className="text-xs uppercase tracking-[0.3em] text-phosphor mb-3">{caption}</div>
          <h2 className="font-display text-3xl mb-10 text-ink">{title}</h2>
          {children}
        </div>

        <div className="mt-12 max-w-sm w-full mx-auto lg:mx-0 text-[11px] text-dim/70 flex justify-between gap-4">
          <span>// secure channel</span>
          <div className="flex gap-3">
            <Link to="/verify" className="hover:text-phosphor transition-colors">
              verify doc →
            </Link>
            <Link to="/registry" className="hover:text-phosphor transition-colors">
              registry →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function Logo() {
  return (
    <div className="w-9 h-9 border border-phosphor flex items-center justify-center text-phosphor font-display text-lg shadow-[0_0_20px_rgba(95,255,138,0.3)]">
      ⌬
    </div>
  );
}

export function Spinner() {
  return (
    <span className="inline-block w-3 h-3 border-2 border-phosphor border-t-transparent rounded-full animate-spin" />
  );
}
