import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api, ApiError } from "../api";
import type { AdminStatus, FeedHealth } from "../types";

function fmtUptime(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function since(epoch: number, now: number, t: TFunction): string {
  if (!epoch) return "—";
  const d = Math.max(0, Math.round(now - epoch));
  return d < 60
    ? t("overview.agoSeconds", { n: d })
    : d < 3600
      ? t("overview.agoMinutes", { n: Math.round(d / 60) })
      : t("overview.agoHours", { n: Math.round(d / 3600) });
}
function Dot({ on }: { on: boolean }) {
  return <span className={on ? "live-dot on" : "live-dot off"} />;
}

export function AdminOverview() {
  const { t, i18n } = useTranslation();
  const [st, setSt] = useState<AdminStatus | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function load(manual = false) {
    if (manual) setBusy(true);
    try {
      setSt(await api.admin.status());
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("overview.loadFailed"));
    } finally {
      if (manual) setBusy(false);
    }
  }
  useEffect(() => {
    load();
    const id = window.setInterval(() => load(false), 3000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="overview">
      <div className="overview-head">
        <h1 className="ov-title">{t("overview.title")}</h1>
        <div className="ov-actions">
          <span className="muted small">{t("overview.autoRefresh")}</span>
          <button className="ghost" onClick={() => load(true)} disabled={busy}>
            {busy ? t("overview.reloading") : t("overview.reload")}
          </button>
        </div>
      </div>
      {err && <div className="error-box">{err}</div>}
      {!st && !err && <div className="muted center">{t("overview.loading")}</div>}
      {st && (
        <>
          <div className="stat-row">
        <Stat label={t("overview.version")} value={st.version} sub={st.app_env} />
        <Stat label={t("overview.uptime")} value={fmtUptime(st.uptime_seconds)} />
        <Stat label={t("overview.activeViews")} value={String(st.throughput.active_views)} sub={t("overview.activeViewsSub")} />
        <Stat label={t("overview.buffered")} value={(st.throughput.buffered ?? 0).toLocaleString(i18n.language)} sub={t("overview.bufferedSub")} />
        <Stat label={t("overview.totalLines")} value={st.throughput.total_lines.toLocaleString(i18n.language)} sub={t("overview.totalLinesSub")} />
      </div>

      <div className="admin-grid">
        <section className="panel">
          <h2>{t("overview.ingest")}</h2>
          <div className="kv-list">
            <div className="kv"><span className="kv-k">{t("overview.ingestActive")}</span><span className="kv-v"><Dot on={st.ingest.enabled} /> {st.ingest.enabled ? t("common.yes") : t("common.no")}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.bindHost")}</span><span className="kv-v mono">{st.ingest.bind_host}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.webFeed")}</span><span className="kv-v"><Dot on={st.ingest.web_listening} /> {t("overview.port")} {st.ingest.web_port} · {st.ingest.web_listening ? t("overview.listening") : t("overview.off")}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.fwFeed")}</span><span className="kv-v"><Dot on={st.ingest.fw_listening} /> {t("overview.port")} {st.ingest.fw_port} · {st.ingest.fw_listening ? t("overview.listening") : t("overview.off")}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.dnsFeed")}</span><span className="kv-v"><Dot on={st.ingest.dns_listening} /> {t("overview.port")} {st.ingest.dns_port} · {st.ingest.dns_listening ? t("overview.listening") : t("overview.off")}</span></div>
          </div>
        </section>

        <section className="panel">
          <h2>{st.accounts ? t("overview.accountsSession") : t("overview.sessionBuffer")}</h2>
          <div className="kv-list">
            {st.accounts && (
              <>
                <div className="kv"><span className="kv-k">{t("overview.accounts")}</span><span className="kv-v">{t("overview.accountsBreakdown", { total: st.accounts.total, admins: st.accounts.admins, viewers: st.accounts.viewers })}</span></div>
                <div className="kv"><span className="kv-k">{t("overview.enabledDisabled")}</span><span className="kv-v">{st.accounts.enabled} / {st.accounts.disabled}</span></div>
              </>
            )}
            <div className="kv"><span className="kv-k">{t("overview.retention")}</span><span className="kv-v">{t("overview.minutes", { n: st.retention_minutes })}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.bufferCap")}</span><span className="kv-v">{st.buffer_max_records.toLocaleString(i18n.language)}</span></div>
            <div className="kv"><span className="kv-k">{t("overview.sessionIdleTtl")}</span><span className="kv-v">{t("overview.sessionIdleTtlValue", { idle: st.session.idle_minutes, ttl: st.session.ttl_minutes })}</span></div>
          </div>
          {st.security?.jwt_secret_is_default && (
            <div className="error-box" style={{ marginTop: 10 }}>{t("overview.jwtWarning")}</div>
          )}
          {st.is_production && !st.session.cookie_secure && (
            <div className="error-box" style={{ marginTop: 10 }}>{t("overview.cookieWarning")}</div>
          )}
        </section>
      </div>

      <section className="panel">
        <h2>{t("overview.fieldDiag")} <span className="muted">{t("overview.fieldDiagNote")}</span></h2>
        <div className="feeds-grid">
          {st.feeds.map((f) => (
            <FeedCard key={f.feed} f={f} now={st.now} port={feedPort(st, f.feed)} />
          ))}
        </div>
      </section>
        </>
      )}
    </div>
  );
}

// The configured port per feed, instead of hard-wired numbers in the hint text.
function feedPort(st: AdminStatus, feed: string): number | undefined {
  if (feed === "web") return st.ingest.web_port;
  if (feed === "fw") return st.ingest.fw_port;
  if (feed === "dns") return st.ingest.dns_port;
  return undefined;
}

function FeedCard({ f, now, port }: { f: FeedHealth; now: number; port?: number }) {
  const { t, i18n } = useTranslation();
  const fieldOk = f.lines > 0 && f.last_field_count === f.expected_cols && f.short_lines === 0;
  const noData = f.lines === 0;
  return (
    <div className="feed-card">
      <div className="feed-head">
        <b>{t("overview.feedTitle", { feed: f.feed.toUpperCase() })}</b>
        {noData ? (
          <span className="pill pill-info">{t("overview.noData")}</span>
        ) : fieldOk ? (
          <span className="pill pill-ok">{t("overview.allFields")}</span>
        ) : (
          <span className="pill pill-warn">{t("overview.fieldMismatch")}</span>
        )}
      </div>
      <div className="feed-meta muted">
        {t("overview.feedMeta", {
          lines: f.lines.toLocaleString(i18n.language),
          got: f.last_field_count,
          expected: f.expected_cols,
        })}
        {f.short_lines > 0 && <span className="warn-text"> · {t("overview.tooShort", { n: f.short_lines })}</span>} ·{" "}
        {t("overview.lastSeen", { ago: since(f.last_seen, now, t) })}
      </div>
      <div className="fill-list">
        {f.columns.map((c) => (
          <div className="fill-row" key={c.index} title={t("overview.fillTitle", { name: c.name, pct: c.fill_pct ?? "—" })}>
            <span className="fill-name mono">{c.name}</span>
            <span className="fill-bar">
              <span
                className={`fill-in ${c.fill_pct != null && c.fill_pct < 100 ? "partial" : ""}`}
                style={{ width: `${c.fill_pct ?? 0}%` }}
              />
            </span>
            <span className="fill-pct muted">{c.fill_pct == null ? "—" : `${c.fill_pct}%`}</span>
          </div>
        ))}
      </div>
      {noData && (
        <div className="note-box" style={{ marginTop: 8 }}>
          {port
            ? t("overview.noLinesYet", { feed: f.feed, port })
            : t("overview.noLinesYetPlain", { feed: f.feed })}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub muted">{sub}</div>}
    </div>
  );
}
