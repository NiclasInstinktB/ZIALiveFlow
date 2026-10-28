import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError, setUnauthorizedHandler } from "./api";
import type { Me } from "./types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  expired: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [expired, setExpired] = useState(false);
  const idleTimer = useRef<number | null>(null);

  // Initial session check.
  useEffect(() => {
    api
      .me()
      .then(setMe)
      .catch(() => {
        /* 401 just means not signed in, which is not an error here */
      })
      .finally(() => setLoading(false));
  }, []);

  // Auto logout on an unexpected 401 (an expired token, for example).
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setMe(null);
      setExpired(true);
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  // Auto logout after inactivity (idle timer).
  useEffect(() => {
    if (!me) return;
    const ms = (me.idle_timeout_minutes || 30) * 60 * 1000;
    const reset = () => {
      if (idleTimer.current) window.clearTimeout(idleTimer.current);
      idleTimer.current = window.setTimeout(async () => {
        try {
          await api.logout();
        } catch {
          /* ignore */
        }
        setMe(null);
        setExpired(true);
      }, ms);
    };
    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      events.forEach((e) => window.removeEventListener(e, reset));
      if (idleTimer.current) window.clearTimeout(idleTimer.current);
    };
  }, [me]);

  async function login(username: string, password: string) {
    setExpired(false);
    try {
      setMe(await api.login(username, password));
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw e;
    }
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      setMe(null);
      setExpired(false);
    }
  }

  return (
    <AuthContext.Provider value={{ me, loading, expired, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
