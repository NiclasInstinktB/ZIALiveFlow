import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { OidcConfig } from "../types";

// SSO / OpenID Connect (Entra ID) in the admin backend. The client secret is
// write-only (empty = keep). Active only when "Active" is set AND issuer, client ID
// and secret are present. Groups are loaded live from AD / the global catalog, the
// same way as the AD password login (service account under "AD/LDAP"), and mapped
// to rights on the "Accounts" tab.

type Draft = Omit<OidcConfig, "oidc_client_secret_set" | "configured">;

function toDraft(c: OidcConfig): Draft {
  const { oidc_client_secret_set: _s, configured: _c, ...rest } = c;
  return rest;
}

// The callback URL the backend expects (must be listed in the Entra app registration).
function defaultRedirect(): string {
  try {
    return `${window.location.origin}/api/auth/sso/callback`;
  } catch {
    return "/api/auth/sso/callback";
  }
}

export function AdminSso() {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<OidcConfig | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [secret, setSecret] = useState("");
  const [clearSecret, setClearSecret] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const [testing, setTesting] = useState(false);

  async function load() {
    try {
      const c = await api.admin.getOidc();
      setCfg(c);
      setDraft(toDraft(c));
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("sso.loadFailed"));
    }
  }
  useEffect(() => {
    load();
  }, []);

  if (err && !cfg) return <div className="error-box">{err}</div>;
  if (!cfg || !draft) return <div className="muted center">{t("sso.loading")}</div>;

  const d = draft;
  function set<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((prev) => (prev ? { ...prev, [key]: value } : prev));
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setSaving(true);
    try {
      const changes: Record<string, unknown> = { ...d };
      if (clearSecret) changes.oidc_client_secret = "";
      else if (secret) changes.oidc_client_secret = secret;
      const c = await api.admin.saveOidc(changes);
      setCfg(c);
      setDraft(toDraft(c));
      setSecret("");
      setClearSecret(false);
      setTestResult(null);
      setMsg(t("sso.saved"));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("sso.saveFailed"));
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await api.admin.testOidc());
    } catch (e) {
      setTestResult({ ok: false, detail: e instanceof ApiError ? e.message : t("sso.testFailed") });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="cfg-page">
      <section className="panel">
        <h2 style={{ marginTop: 0 }}>
          SSO / OpenID Connect <span className="muted">{t("sso.subtitle")}</span>
        </h2>
        <p className="muted" style={{ marginTop: 0 }}>
          {t("sso.intro1")} {t("sso.intro2", { ldap: t("nav.ldap"), accounts: t("nav.accounts") })} {t("sso.status")}{" "}
          {cfg.configured ? (
            <span className="ok">{t("sso.configured")}</span>
          ) : (
            <span className="off">{t("sso.notConfigured")}</span>
          )}
        </p>
        {err && <div className="error-box">{err}</div>}
        {msg && <div className="note-box">{msg}</div>}

        <form className="cfg-form" onSubmit={save}>
          <section className="cfg-section">
            <div className="cfg-grid">
              <div className="cfg-field cfg-check col-2">
                <input
                  id="oidc_enabled"
                  type="checkbox"
                  checked={d.oidc_enabled}
                  onChange={(e) => set("oidc_enabled", e.target.checked)}
                />
                <label htmlFor="oidc_enabled">{t("sso.enabled", { label: t("login.withSso") })}</label>
              </div>
              <div className="cfg-field col-2">
                <label>{t("sso.issuer")}</label>
                <input
                  value={d.oidc_issuer}
                  placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0"
                  onChange={(e) => set("oidc_issuer", e.target.value)}
                />
                <span className="hint">{t("sso.issuerHint")}</span>
              </div>
              <div className="cfg-field col-2">
                <label>{t("sso.clientId")}</label>
                <input
                  value={d.oidc_client_id}
                  placeholder="00000000-0000-0000-0000-000000000000"
                  autoComplete="off"
                  onChange={(e) => set("oidc_client_id", e.target.value)}
                />
                <span className="hint">{t("sso.clientIdHint")}</span>
              </div>
              <div className="cfg-field">
                <label>{t("sso.clientSecret")}</label>
                <input
                  type="password"
                  value={secret}
                  disabled={clearSecret}
                  placeholder={cfg.oidc_client_secret_set ? t("sso.unchangedPh") : t("sso.notSetPh")}
                  autoComplete="new-password"
                  onChange={(e) => setSecret(e.target.value)}
                />
                <span className="hint">
                  {cfg.oidc_client_secret_set ? t("sso.secretSet") : t("sso.secretNotSet")}
                  {t("sso.keepEmpty")}
                </span>
              </div>
              {cfg.oidc_client_secret_set && (
                <div className="cfg-field cfg-check">
                  <input id="clear_secret" type="checkbox" checked={clearSecret} onChange={(e) => setClearSecret(e.target.checked)} />
                  <label htmlFor="clear_secret">{t("sso.removeSecret")}</label>
                </div>
              )}
              <div className="cfg-field col-2">
                <label>{t("sso.redirectUri")}</label>
                <input
                  value={d.oidc_redirect_url}
                  placeholder={defaultRedirect()}
                  onChange={(e) => set("oidc_redirect_url", e.target.value)}
                />
                <span className="hint">
                  {t("sso.redirectHint")} <code>{defaultRedirect()}</code>
                </span>
              </div>
              <div className="cfg-field col-2">
                <label>{t("sso.scopes")}</label>
                <input value={d.oidc_scopes} placeholder="openid profile email" onChange={(e) => set("oidc_scopes", e.target.value)} />
                <span className="hint">{t("sso.scopesHint")}</span>
              </div>
            </div>
          </section>

          <div className="form-actions">
            <button className="primary" type="submit" disabled={saving}>
              {saving ? t("sso.saving") : t("common.save")}
            </button>
            <button type="button" className="ghost" onClick={test} disabled={testing || !d.oidc_issuer.trim()}>
              {testing ? t("sso.testing") : t("sso.testDiscovery")}
            </button>
          </div>
          {testResult && (
            <div className={testResult.ok ? "note-box" : "error-box"} style={{ marginTop: 4 }}>
              {testResult.detail}
            </div>
          )}
        </form>

        <div className="note-box" style={{ marginTop: 14 }}>
          {t("sso.footnotePre")} <code>.env</code> {t("sso.footnotePost")}
        </div>
      </section>
    </div>
  );
}
