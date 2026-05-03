import { useEffect, useState } from "react";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Chat from "./pages/Chat";
import Registry from "./pages/Registry";
import Verify from "./pages/Verify";
import { getMe } from "./lib/api";
import {
  loadStashedIdentity,
  clearStashedIdentity,
} from "./lib/crypto";

export default function App() {
  // identity = { userId, secretKey, publicKey, publicKeyHex } | null
  const [identity, setIdentity] = useState(() => loadStashedIdentity());
  const [bootChecking, setBootChecking] = useState(true);

  useEffect(() => {
    // On boot: check the session cookie. If it's valid and we have unwrapped
    // keys in sessionStorage, we're good. If session is valid but keys are
    // missing (e.g. user opened a new tab or refreshed after closing tab),
    // we still need them to login again to unwrap.
    let cancelled = false;
    (async () => {
      try {
        const me = await getMe();
        if (cancelled) return;
        if (me && identity && me.user_id !== identity.userId) {
          // Mismatch — clear stash, treat as logged out
          clearStashedIdentity();
          setIdentity(null);
        } else if (!me && identity) {
          // Session expired — clear local stash
          clearStashedIdentity();
          setIdentity(null);
        }
      } catch {
        // server down — treat as not logged in
      } finally {
        if (!cancelled) setBootChecking(false);
      }
    })();
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (bootChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center text-dim text-sm">
        <span className="caret">initializing</span>
      </div>
    );
  }

  return (
    <Routes>
      <Route
        path="/"
        element={<Navigate to={identity ? "/chat" : "/login"} replace />}
      />
      <Route
        path="/login"
        element={
          identity
            ? <Navigate to="/chat" replace />
            : <Login onAuth={setIdentity} />
        }
      />
      <Route
        path="/register"
        element={
          identity
            ? <Navigate to="/chat" replace />
            : <Register onAuth={setIdentity} />
        }
      />
      <Route
        path="/chat"
        element={
          identity
            ? <Chat identity={identity} onLogout={() => {
                clearStashedIdentity();
                setIdentity(null);
              }} />
            : <Navigate to="/login" replace />
        }
      />
      <Route path="/registry" element={<Registry />} />
      <Route path="/verify" element={<Verify />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
