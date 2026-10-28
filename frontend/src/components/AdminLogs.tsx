import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { LogEntry, LogResponse } from "../types";

// The most recent warnings and errors of the running process.
//
// These used to go to stdout and therefore into the service journal, invisible
// to anyone without server access. The very line naming the cause
// (`crypto.decrypt_failed`, `ldap.server_unreachable`) was missing exactly where
// the failure shows up.
//
// Deliberately memory-only: an error buffer is diagnostics for the running
// service, not an archive. After a restart it is empty; the audit log covers
// the long term.

function fmtFields(fields: Record<string, unknown>): string {
  return Object.entries(fields || {})
    .filter(([k]) => k !== "exception")
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join("  ");
}

export function AdminLogs() {
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<LogResponse | null>(null);
  const [err, setErr] = useState("");
  const [level, setLevel] = useState("warning");
  const [limit, setLimit] = useState(50);
  const [auto, setAuto] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.admin.logs({ limit, level }));
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("logs.loadFailed"));
    }
  }, [limit, level, t]);

  useEffect(() => {
    load();
  }, [load]);

  // When reproducing a bug you do not want to click after every attempt.
  useEffect(() => {
    if (!auto) return;
    const id = window.setInterval(() => load(), 5000);
    return () => window.clearInterval(id);
  }, [auto, load]);

  return (
    <section className="panel">
      <div className="log-head">
        <h2 style={{ margin: 0 }}>
          {t("logs.title")} <span className="muted">{t("logs.subtitle")}</span>
        </h2>
        <div className="log-head-right">
          <select value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="error">{t("logs.levelErrors")}</option>
            <option value="warning">{t("logs.levelWarnings")}</option>
          </select>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            <option value={50}>{t("logs.last", { n: 50 })}</option>
            <option value={100}>{t("logs.last", { n: 100 })}</option>
            <option value={300}>{t("logs.allBuffered")}</option>
          </select>
          <label className="log-check">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
            {t("logs.everyFiveSeconds")}
          </label>
          <button className="ghost" onClick={() => load()}>
            {t("common.refresh")}
          </button>
          <button
            className="ghost"
            onClick={() =>
              window.confirm(t("logs.clearConfirm")) &&
              api.admin
                .clearLogs()
                .then(() => load())
                .catch((e) => setErr(e instanceof ApiError ? e.message : t("logs.clearFailed")))
            }
          >
            {t("logs.clear")}
          </button>
        </div>
      </div>

      {err && <div className="error-box">{err}</div>}

      {data && (
        <p className="muted small" style={{ marginTop: 0 }}>
          {t("logs.counts", {
            errors: data.counts.errors,
            warnings: data.counts.warnings,
            total: data.counts.total,
            capacity: data.counts.capacity,
          })}{" "}
          {t("logs.bufferNote")}
        </p>
      )}

      {!data ? (
        <div className="muted center">{t("common.loading")}</div>
      ) : data.entries.length === 0 ? (
        <div className="empty">{t("logs.empty")}</div>
      ) : (
        <div>
          {data.entries.map((e) => (
            <LogRow key={e.id} entry={e} locale={i18n.language} />
          ))}
        </div>
      )}
    </section>
  );
}

function LogRow({ entry, locale }: { entry: LogEntry; locale: string }) {
  const fields = fmtFields(entry.fields);
  const exception = entry.fields?.exception as string | undefined;
  const d = new Date(entry.ts);
  const ts = isNaN(d.getTime()) ? entry.ts : d.toLocaleString(locale);
  return (
    <div className="log-row">
      <span className="muted small mono nowrap">{ts}</span>
      <span className={`log-level ${entry.level}`}>{entry.level}</span>
      <div>
        <span className="mono">{entry.event}</span>
        {entry.logger && <span className="muted small"> · {entry.logger}</span>}
        {fields && <div className="muted small log-fields mono">{fields}</div>}
        {exception && (
          <pre className="mono small" style={{ maxHeight: 220, overflow: "auto", marginTop: 4 }}>
            {exception}
          </pre>
        )}
      </div>
    </div>
  );
}
