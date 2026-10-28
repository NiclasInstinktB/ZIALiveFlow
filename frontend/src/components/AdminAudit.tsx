import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { AuditEntry, AuditResponse } from "../types";

// Event names are stable backend strings; only their label and severity are
// presentation. Unknown events fall through to the raw string rather than
// being hidden, so a new backend event still shows up here.
const EVENT_KEYS: Record<string, string> = {
  login_success: "audit.event.loginSuccess",
  login_failure: "audit.event.loginFailure",
  logout: "audit.event.logout",
  search: "audit.event.search",
};
const EVENT_SEV: Record<string, string> = {
  login_success: "good",
  login_failure: "bad",
  logout: "info",
  search: "warn",
};

export function AdminAudit() {
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<AuditResponse | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [event, setEvent] = useState("");
  const [user, setUser] = useState("");
  const [days, setDays] = useState(30);

  async function load() {
    setBusy(true);
    try {
      setData(await api.admin.audit({ event: event || undefined, user: user || undefined, days, limit: 1000 }));
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("audit.loadFailed"));
    } finally {
      setBusy(false);
    }
  }
  // Event and period reload immediately; the user filter waits for Enter/Apply.
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [event, days]);

  return (
    <div className="audit-page">
      <div className="overview-head">
        <h1 className="ov-title">{t("audit.title")}</h1>
        <div className="ov-actions">
          {data && (
            <span className="muted small">
              {t("audit.stats", {
                entries: data.stats.entries.toLocaleString(i18n.language),
                days: data.stats.retention_days,
              })}
            </span>
          )}
          <button className="ghost" onClick={load} disabled={busy}>
            {busy ? t("audit.loading") : `↻ ${t("audit.reload")}`}
          </button>
        </div>
      </div>

      <div className="panel audit-filters">
        <select value={event} onChange={(e) => setEvent(e.target.value)}>
          <option value="">{t("audit.allEvents")}</option>
          <option value="login_success">{t("audit.event.loginSuccess")}</option>
          <option value="login_failure">{t("audit.event.loginFailure")}</option>
          <option value="logout">{t("audit.event.logout")}</option>
          <option value="search">{t("audit.event.search")}</option>
        </select>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
          <option value={1}>{t("audit.lastDay")}</option>
          <option value={7}>{t("audit.lastDays", { n: 7 })}</option>
          <option value={30}>{t("audit.lastDays", { n: 30 })}</option>
        </select>
        <input
          placeholder={`🔍 ${t("audit.filterUser")}`}
          value={user}
          onChange={(e) => setUser(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && load()}
        />
        <button className="ghost" onClick={load}>
          {t("audit.apply")}
        </button>
      </div>

      {err && <div className="error-box">{err}</div>}

      <div className="table-wrap panel">
        <table className="flow-table">
          <thead>
            <tr>
              <th>{t("audit.colTime")}</th>
              <th>{t("audit.colEvent")}</th>
              <th>{t("audit.colUser")}</th>
              <th>{t("audit.colIp")}</th>
              <th>{t("audit.colDetail")}</th>
            </tr>
          </thead>
          <tbody>
            {data?.entries.map((e, i) => (
              <Row key={`${e.ts}-${i}`} e={e} locale={i18n.language} />
            ))}
            {data && data.entries.length === 0 && (
              <tr>
                <td colSpan={5} className="empty muted">
                  {t("audit.empty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Row({ e, locale }: { e: AuditEntry; locale: string }) {
  const { t } = useTranslation();
  let ts = "";
  try {
    ts = new Date(e.ts * 1000).toLocaleString(locale);
  } catch {
    ts = "";
  }
  const labelKey = EVENT_KEYS[e.event];
  return (
    <tr>
      <td className="mono nowrap">{ts}</td>
      <td>
        <span className={`verdict v-${EVENT_SEV[e.event] ?? "info"}`}>
          {labelKey ? t(labelKey) : e.event}
        </span>
      </td>
      <td className="ellip" title={e.user}>
        {e.user || "—"}
      </td>
      <td className="mono">{e.ip || "—"}</td>
      <td className="ellip" title={e.detail}>
        {e.detail || "—"}
      </td>
    </tr>
  );
}
