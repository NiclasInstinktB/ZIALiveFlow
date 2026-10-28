import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { LdapConfig } from "../types";

// AD/LDAP configuration in the admin backend: connection plus service account only.
// The AD group to rights mapping is maintained on the "Accounts" tab (like local
// accounts). The bind password is write-only (empty = keep). Everything is
// Fernet-encrypted and persistent.

type Draft = Omit<LdapConfig, "ldap_bind_password_set" | "configured">;

function toDraft(c: LdapConfig): Draft {
  const { ldap_bind_password_set: _p, configured: _c, ...rest } = c;
  return rest;
}

export function AdminLdap() {
  const { t } = useTranslation();
  const [cfg, setCfg] = useState<LdapConfig | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [pw, setPw] = useState("");
  const [clearPw, setClearPw] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null);
  const [testing, setTesting] = useState(false);

  async function load() {
    try {
      const c = await api.admin.getLdap();
      setCfg(c);
      setDraft(toDraft(c));
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("ldap.loadFailed"));
    }
  }
  useEffect(() => {
    load();
  }, []);

  if (err && !cfg) return <div className="error-box">{err}</div>;
  if (!cfg || !draft) return <div className="muted center">{t("ldap.loading")}</div>;

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
      if (clearPw) changes.ldap_bind_password = "";
      else if (pw) changes.ldap_bind_password = pw;
      const c = await api.admin.saveLdap(changes);
      setCfg(c);
      setDraft(toDraft(c));
      setPw("");
      setClearPw(false);
      setTestResult(null);
      setMsg(t("ldap.saved"));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("ldap.saveFailed"));
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult(await api.admin.testLdap());
    } catch (e) {
      setTestResult({ ok: false, detail: e instanceof ApiError ? e.message : t("ldap.testFailed") });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="cfg-page">
      <section className="panel">
        <h2 style={{ marginTop: 0 }}>
          {t("nav.ldap")} <span className="muted">{t("ldap.subtitle")}</span>
        </h2>
        <p className="muted" style={{ marginTop: 0 }}>
          {t("ldap.intro", { accounts: t("nav.accounts") })} {t("ldap.status")}{" "}
          {cfg.configured ? (
            <span className="ok">{t("ldap.configured")}</span>
          ) : (
            <span className="off">{t("ldap.notConfigured")}</span>
          )}
        </p>
        {err && <div className="error-box">{err}</div>}
        {msg && <div className="note-box">{msg}</div>}

        <form className="cfg-form" onSubmit={save}>
          {/* ── Connection ── */}
          <section className="cfg-section">
            <h3>{t("ldap.connection")}</h3>
            <div className="cfg-grid">
              <div className="cfg-field col-2">
                <label>{t("ldap.server")}</label>
                <input
                  value={d.ldap_server}
                  placeholder="gc://dc01.example.com, gc://dc02.example.com"
                  onChange={(e) => set("ldap_server", e.target.value)}
                />
                <span className="hint">
                  {t("ldap.serverHint")}
                  <code>ldap://</code> · <code>ldaps://</code> · <code>gc://</code> · <code>gcs://</code>{" "}
                  {t("ldap.globalCatalog")}
                </span>
              </div>
              <div className="cfg-field">
                <label>{t("ldap.domain")}</label>
                <input value={d.ldap_domain} placeholder="example.com" onChange={(e) => set("ldap_domain", e.target.value)} />
                <span className="hint">{t("ldap.domainHint")}</span>
              </div>
              <div className="cfg-field">
                <label>{t("ldap.baseDn")}</label>
                <input
                  value={d.ldap_base_dn}
                  placeholder="DC=example,DC=com"
                  onChange={(e) => set("ldap_base_dn", e.target.value)}
                />
                <span className="hint">{t("ldap.baseDnHint")}</span>
              </div>
              <div className="cfg-field">
                <label>{t("ldap.port")}</label>
                <input
                  type="number"
                  min={0}
                  max={65535}
                  value={d.ldap_port}
                  onChange={(e) => set("ldap_port", Number(e.target.value))}
                />
                <span className="hint">{t("ldap.portHint")}</span>
              </div>
              <div className="cfg-field">
                <label>{t("ldap.timeout")}</label>
                <input
                  type="number"
                  min={1}
                  max={60}
                  value={d.ldap_connect_timeout_seconds}
                  onChange={(e) => set("ldap_connect_timeout_seconds", Number(e.target.value))}
                />
              </div>
              <div className="cfg-field cfg-check col-2">
                <input
                  id="ldap_use_ssl"
                  type="checkbox"
                  checked={d.ldap_use_ssl}
                  onChange={(e) => set("ldap_use_ssl", e.target.checked)}
                />
                <label htmlFor="ldap_use_ssl">{t("ldap.useSsl")}</label>
              </div>
            </div>
          </section>

          {/* ── Service account ── */}
          <section className="cfg-section">
            <h3>
              {t("ldap.serviceAccount")} <span className="muted">{t("ldap.optional")}</span>
            </h3>
            <div className="cfg-grid">
              <div className="cfg-field col-2">
                <label>{t("ldap.bindUser")}</label>
                <input
                  value={d.ldap_bind_user}
                  placeholder="svc-ldap@example.com"
                  autoComplete="off"
                  onChange={(e) => set("ldap_bind_user", e.target.value)}
                />
                <span className="hint">{t("ldap.bindUserHint")}</span>
              </div>
              <div className="cfg-field">
                <label>{t("ldap.bindPassword")}</label>
                <input
                  type="password"
                  value={pw}
                  disabled={clearPw}
                  placeholder={cfg.ldap_bind_password_set ? t("ldap.unchangedPh") : t("ldap.notSetPh")}
                  autoComplete="new-password"
                  onChange={(e) => setPw(e.target.value)}
                />
                <span className="hint">
                  {cfg.ldap_bind_password_set ? t("ldap.pwSet") : t("ldap.pwNotSet")}
                  {t("ldap.keepEmpty")}
                </span>
              </div>
              {cfg.ldap_bind_password_set && (
                <div className="cfg-field cfg-check">
                  <input id="clear_pw" type="checkbox" checked={clearPw} onChange={(e) => setClearPw(e.target.checked)} />
                  <label htmlFor="clear_pw">{t("ldap.removePassword")}</label>
                </div>
              )}
              <div className="cfg-field">
                <label>{t("ldap.groupAttr")}</label>
                <input value={d.ldap_group_attr} onChange={(e) => set("ldap_group_attr", e.target.value)} />
                <span className="hint">{t("ldap.groupAttrHint")}</span>
              </div>
            </div>
          </section>

          <div className="form-actions">
            <button className="primary" type="submit" disabled={saving}>
              {saving ? t("ldap.saving") : t("common.save")}
            </button>
            <button type="button" className="ghost" onClick={test} disabled={testing || !cfg.configured}>
              {testing ? t("ldap.testing") : t("ldap.testConnection")}
            </button>
          </div>
          {testResult && (
            <div className={testResult.ok ? "note-box" : "error-box"} style={{ marginTop: 4 }}>
              {testResult.detail}
            </div>
          )}
        </form>

        <div className="note-box" style={{ marginTop: 14 }}>
          {t("ldap.footnotePre")} <code>.env</code> {t("ldap.footnotePost")}
        </div>
      </section>
    </div>
  );
}
