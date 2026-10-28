import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { Me } from "../types";

export function Account({ me }: { me: Me }) {
  const { t } = useTranslation();
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [nw2, setNw2] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  async function changePw(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    if (nw !== nw2) {
      setErr(t("account.mismatch"));
      return;
    }
    try {
      await api.changePassword(cur, nw);
      setCur("");
      setNw("");
      setNw2("");
      setMsg(t("account.changed"));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("account.changeFailed"));
    }
  }

  return (
    <div className="admin-grid">
      <section className="panel">
        <h2>{t("account.title")}</h2>
        <div className="kv-list">
          <div className="kv">
            <span className="kv-k">{t("account.user")}</span>
            <span className="kv-v mono">{me.username}</span>
          </div>
          <div className="kv">
            <span className="kv-k">{t("account.displayName")}</span>
            <span className="kv-v">{me.display_name}</span>
          </div>
          <div className="kv">
            <span className="kv-k">{t("account.permissions")}</span>
            <span className="kv-v">
              {me.is_admin
                ? t("account.allAdmin")
                : me.permissions.length
                  ? me.permission_catalog
                      .filter((p) => me.permissions.includes(p.key))
                      .map((p) => p.label)
                      .join(", ")
                  : "—"}
            </span>
          </div>
          <div className="kv">
            <span className="kv-k">{t("account.source")}</span>
            <span className="kv-v">
              {me.source === "ad" ? t("account.sourceAd") : t("account.sourceLocal")}
            </span>
          </div>
        </div>
      </section>

      {/* AD accounts have no password here (it lives in Active Directory), so
          the whole card is dropped for them. */}
      {me.source !== "ad" && (
        <section className="panel">
          <h2>{t("account.changePassword")}</h2>
          {err && <div className="error-box">{err}</div>}
          {msg && <div className="note-box">{msg}</div>}
          <form className="stack-form" onSubmit={changePw}>
            <label>{t("account.currentPassword")}</label>
            <input
              type="password"
              value={cur}
              onChange={(e) => setCur(e.target.value)}
              autoComplete="current-password"
            />
            <label>{t("account.newPassword")}</label>
            <input type="password" value={nw} onChange={(e) => setNw(e.target.value)} autoComplete="new-password" />
            <label>{t("account.repeatPassword")}</label>
            <input type="password" value={nw2} onChange={(e) => setNw2(e.target.value)} autoComplete="new-password" />
            <button className="primary" type="submit" disabled={!cur || nw.length < 8}>
              {t("account.changePassword")}
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
