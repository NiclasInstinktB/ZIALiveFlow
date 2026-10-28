import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAuth } from "../auth";
import { LanguageSwitcher } from "./LanguageSwitcher";

// Reason from ?sso_error=…, which the SSO callback sets when it redirects here
// after a failure.
function ssoErrorFromUrl(): string | null {
  try {
    return new URLSearchParams(window.location.search).get("sso_error");
  } catch {
    return null;
  }
}

// Known SSO failure reasons map to their own message; anything else falls back
// to the generic one. Keep the reason list in sync with backend/api/sso_routes.py.
const SSO_ERROR_KEYS: Record<string, string> = {
  noperms: "login.ssoError.noperms",
  collision: "login.ssoError.collision",
  disabled: "login.ssoError.disabled",
};

export function Login() {
  const { login, expired } = useAuth();
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoError] = useState<string | null>(ssoErrorFromUrl);
  // The instance name is configurable, and the login page renders before any session
  // exists, so it comes from the public health endpoint rather than from /auth/me.
  const [appName, setAppName] = useState("");

  // Whether SSO is offered comes from the public /api/health endpoint, which is
  // reachable before signing in.
  useEffect(() => {
    api
      .health()
      .then((h) => {
        setSsoEnabled(!!h.sso_enabled);
        if (h.app_name) {
          setAppName(h.app_name);
          document.title = h.app_name;
        }
      })
      .catch(() => setSsoEnabled(false));
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFailed(false);
    try {
      await login(username, password);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="panel login-card" onSubmit={onSubmit}>
        <h1 style={{ margin: 0 }}>{appName || "Live-Flow"}</h1>
        <p className="muted" style={{ marginTop: 4 }}>{t("login.subtitle")}</p>
        {ssoError && (
          <div className="error-box">
            {t(SSO_ERROR_KEYS[ssoError] ?? "login.ssoError.generic")}
          </div>
        )}
        {ssoEnabled && (
          <div style={{ marginBottom: 16 }}>
            <button
              type="button"
              className="primary"
              style={{ width: "100%" }}
              onClick={() => {
                window.location.href = "/api/auth/sso/login";
              }}
            >
              {t("login.withSso")}
            </button>
            <div className="muted" style={{ textAlign: "center", margin: "12px 0 0", fontSize: 12 }}>
              {t("login.orCredentials")}
            </div>
          </div>
        )}
        <div style={{ marginBottom: 12 }}>
          <label>{t("login.username")}</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label>{t("login.password")}</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        {expired && !failed && <div className="note-box">{t("login.expired")}</div>}
        {failed && <div className="error-box">{t("login.failed")}</div>}
        <button className="primary" type="submit" disabled={busy || !username || !password} style={{ width: "100%" }}>
          {busy ? t("login.signingIn") : t("login.signIn")}
        </button>
        <div style={{ marginTop: 16, textAlign: "center" }}>
          <LanguageSwitcher />
        </div>
      </form>
    </div>
  );
}
