import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { UpdateCheck, UpdateStatus } from "../types";

export function AdminUpdate() {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<UpdateStatus | null>(null);
  const [chk, setChk] = useState<UpdateCheck | null>(null);
  const [err, setErr] = useState("");
  const [checking, setChecking] = useState(false);
  const [updating, setUpdating] = useState(false);
  const pollRef = useRef<number | null>(null);

  function fmtDate(iso?: string): string {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString(i18n.language);
    } catch {
      return iso;
    }
  }

  async function loadStatus() {
    try {
      setSt(await api.admin.updateStatus());
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("update.statusFailed"));
    }
  }
  useEffect(() => {
    loadStatus();
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function check() {
    setErr("");
    setChecking(true);
    setChk(null);
    try {
      setChk(await api.admin.updateCheck());
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("update.checkFailed"));
    } finally {
      setChecking(false);
    }
  }

  async function runUpdate() {
    const behind = chk?.behind ?? 0;
    if (!confirm(t("update.confirm", { count: behind }))) {
      return;
    }
    setErr("");
    setUpdating(true);
    try {
      await api.admin.updateRun();
      // Wait for the restart: poll health, and reload the page once it is back.
      let wasDown = false;
      pollRef.current = window.setInterval(async () => {
        try {
          await api.health();
          if (wasDown) window.location.reload();
        } catch {
          wasDown = true; // the service is restarting right now
        }
      }, 3000);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("update.triggerFailed"));
      setUpdating(false);
    }
  }

  if (err && !st) return <div className="error-box">{err}</div>;
  if (!st) return <div className="muted center">{t("update.loading")}</div>;

  return (
    <div className="admin-grid">
      <section className="panel wide">
        <h2>
          {t("nav.update")} <span className="muted">{t("update.subtitle")}</span>
        </h2>
        {err && <div className="error-box">{err}</div>}

        {!st.is_repo ? (
          <div className="note-box">{t("update.notARepo")}</div>
        ) : (
          <>
            <div className="kv-list">
              <div className="kv">
                <span className="kv-k">{t("update.current")}</span>
                <span className="kv-v mono">{st.commit_short} · {st.branch}</span>
              </div>
              <div className="kv">
                <span className="kv-k">{t("update.commit")}</span>
                <span className="kv-v">{st.subject || "—"}</span>
              </div>
              <div className="kv">
                <span className="kv-k">{t("update.date")}</span>
                <span className="kv-v">{fmtDate(st.committed_at)}</span>
              </div>
              <div className="kv">
                <span className="kv-k">{t("update.branch")}</span>
                <span className="kv-v mono">{st.update_branch}</span>
              </div>
              <div className="kv">
                <span className="kv-k">{t("update.remote")}</span>
                <span className="kv-v mono ellip" title={st.remote}>{st.remote || "—"}</span>
              </div>
              {st.dirty && (
                <div className="kv">
                  <span className="kv-k">{t("update.workingCopy")}</span>
                  <span className="kv-v warn-text">{t("update.dirty")}</span>
                </div>
              )}
            </div>

            <div className="form-actions" style={{ marginTop: 14 }}>
              <button className="ghost" onClick={check} disabled={checking || updating}>
                {checking ? t("update.checking") : t("update.checkForUpdates")}
              </button>
              {chk?.ok && chk.update_available && (
                <button className="primary" onClick={runUpdate} disabled={updating}>
                  {updating ? t("update.running") : t("update.updateNow", { n: chk.behind })}
                </button>
              )}
            </div>

            {chk && !chk.ok && chk.error && (
              <div className="error-box" style={{ marginTop: 12 }}>
                {t("update.checkFailedWith", { error: chk.error })}
              </div>
            )}
            {chk?.ok && !chk.update_available && (
              <div className="note-box" style={{ marginTop: 12 }}>
                ✓ {t("update.upToDate")} <code>origin/{chk.branch}</code>.
                {(chk.ahead ?? 0) > 0 && <> {t("update.ahead", { count: chk.ahead ?? 0 })}</>}
              </div>
            )}
            {chk?.ok && chk.update_available && (
              <div className="note-box stream-hint" style={{ marginTop: 12 }}>
                <b>{t("update.available", { count: chk.behind ?? 0 })}</b> <code>origin/{chk.branch}</code>.{" "}
                {t("update.latest")} <span className="mono">{chk.remote_latest}</span>
              </div>
            )}
            {updating && <div className="note-box" style={{ marginTop: 12 }}>{t("update.inProgress")}</div>}
          </>
        )}
      </section>

      <section className="panel">
        <h2>{t("update.howItWorks")}</h2>
        <p className="muted">
          {t("update.howItWorksBody")}
          <br />
          <span className="mono">
            git fetch → reset --hard origin/{st.update_branch} → pip → npm build → restart
          </span>
        </p>
        <p className="muted">{t("update.configNote")}</p>
      </section>
    </div>
  );
}
