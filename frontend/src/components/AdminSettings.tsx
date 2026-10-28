import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import type { AppSettings, SettingSpec, SettingValue } from "../types";

// The form is generated from the catalogue the backend sends, so a new setting shows
// up here without a frontend change. Labels are translated where the key is known;
// anything new falls back to a readable form of the raw key.
function fallbackLabel(key: string): string {
  const words = key.replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function AdminSettings() {
  const { t } = useTranslation();
  const [s, setS] = useState<AppSettings | null>(null);
  const [draft, setDraft] = useState<Record<string, SettingValue>>({});
  // Number boxes the user has emptied. An empty box means "leave this one alone", it
  // does not mean zero. Number("") is 0, and 0 on ingest_web_port, ingest_fw_port and
  // ingest_dns_port means "do not start this listener", so one stray backspace plus
  // Save used to switch a whole feed off at the next restart.
  const [blankInts, setBlankInts] = useState<Set<string>>(new Set());
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [saving, setSaving] = useState(false);

  async function load() {
    try {
      const data = await api.admin.getSettings();
      setS(data);
      setDraft({ ...data.editable });
      setBlankInts(new Set());
      setErr("");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("settings.loadFailed"));
    }
  }
  useEffect(() => {
    load();
  }, []);

  const label = (key: string) => t(`settings.label.${key}`, { defaultValue: fallbackLabel(key) });

  if (err && !s) return <div className="error-box">{err}</div>;
  if (!s) return <div className="muted center">{t("settings.loading")}</div>;

  const keys = Object.keys(s.catalogue);
  const liveKeys = keys.filter((k) => s.catalogue[k].tier === "live");
  const restartKeys = keys.filter((k) => s.catalogue[k].tier === "restart");
  // Dirty is per tier, not for the whole catalogue: every panel has its own Save and
  // must write only the fields in front of it. Emptied number boxes count as unchanged.
  const changedIn = (ks: string[]) => ks.filter((k) => !blankInts.has(k) && draft[k] !== s!.editable[k]);
  const hasBlank = (ks: string[]) => ks.some((k) => blankInts.has(k));
  const liveChanged = changedIn(liveKeys);
  const restartChanged = changedIn(restartKeys);

  async function save(e: React.FormEvent, tierKeys: string[]) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setSaving(true);
    const mine = new Set(tierKeys);
    const changed = changedIn(tierKeys);
    // Edits the other panel is still holding. Nobody submitted them, so they are put
    // back on top of the fresh server state below instead of quietly disappearing.
    const keepOther = keys.filter((k) => !mine.has(k) && draft[k] !== s!.editable[k]);
    try {
      const payload: Record<string, SettingValue> = {};
      for (const k of changed) payload[k] = draft[k];
      const data = await api.admin.saveSettings(payload);
      setS(data);
      setDraft((prev) => {
        const next: Record<string, SettingValue> = { ...data.editable };
        for (const k of keepOther) next[k] = prev[k];
        return next;
      });
      // This panel is in sync with the server again, so its emptied boxes show the
      // stored value once more (that value is exactly the one that was kept).
      setBlankInts((prev) => new Set([...prev].filter((k) => !mine.has(k))));
      setMsg(
        data.restart_pending.length
          ? t("settings.restartPending", { names: data.restart_pending.map(label).join(", ") })
          : t("settings.saved")
      );
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : t("settings.saveFailed"));
    } finally {
      setSaving(false);
    }
  }

  /** Discard one panel's edits. The other panel keeps whatever the user left in it. */
  function resetTier(tierKeys: string[]) {
    const mine = new Set(tierKeys);
    setDraft((prev) => {
      const next = { ...prev };
      for (const k of tierKeys) next[k] = s!.editable[k];
      return next;
    });
    setBlankInts((prev) => new Set([...prev].filter((k) => !mine.has(k))));
  }

  function field(key: string) {
    const spec: SettingSpec = s!.catalogue[key];
    const value = draft[key];
    const blank = blankInts.has(key);
    const set = (v: SettingValue) => setDraft((d) => ({ ...d, [key]: v }));
    const range =
      spec.kind === "int" && spec.min != null && spec.max != null
        ? ` ${t("settings.range", { min: spec.min.toLocaleString(), max: spec.max.toLocaleString() })}`
        : "";
    return (
      <div className="set-row" key={key}>
        <label>
          <span className="set-label">{label(key)}</span>
          <span className="set-hint muted">
            {spec.hint}
            {range}
          </span>
        </label>
        {spec.kind === "bool" ? (
          <input type="checkbox" checked={!!value} onChange={(e) => set(e.target.checked)} />
        ) : spec.kind === "choice" ? (
          <select value={String(value ?? "")} onChange={(e) => set(e.target.value)}>
            {(spec.choices ?? []).map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        ) : spec.kind === "int" ? (
          <input
            type="number"
            min={spec.min}
            max={spec.max}
            value={blank || typeof value !== "number" ? "" : value}
            onChange={(e) => {
              const raw = e.target.value;
              // An empty box stays empty while typing (no snapping back to 0 or to the
              // old value) and the setting is left out of the save entirely.
              setBlankInts((prev) => {
                if (prev.has(key) === (raw === "")) return prev;
                const next = new Set(prev);
                if (raw === "") next.add(key);
                else next.delete(key);
                return next;
              });
              if (raw !== "") set(Number(raw));
            }}
          />
        ) : (
          <input
            type="text"
            maxLength={spec.max_length}
            value={String(value ?? "")}
            onChange={(e) => set(e.target.value)}
          />
        )}
      </div>
    );
  }

  return (
    <div className="admin-grid">
      <section className="panel">
        <h2>
          {t("settings.title")} <span className="muted">{t("settings.titleNote")}</span>
        </h2>
        {err && <div className="error-box">{err}</div>}
        {msg && <div className="note-box">{msg}</div>}
        <form className="settings-form" onSubmit={(e) => save(e, liveKeys)}>
          {liveKeys.map(field)}
          <div className="form-actions">
            <button className="primary" type="submit" disabled={!liveChanged.length || saving}>
              {saving ? t("settings.saving") : t("common.save")}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={!liveChanged.length && !hasBlank(liveKeys)}
              onClick={() => resetTier(liveKeys)}
            >
              {t("settings.reset")}
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <h2>
          {t("settings.restartTitle")} <span className="muted">{t("settings.restartNote")}</span>
        </h2>
        <form className="settings-form" onSubmit={(e) => save(e, restartKeys)}>
          {restartKeys.map(field)}
          {s.catalogue.feed_timezone && (
            <div className="note-box" style={{ marginTop: 10 }}>
              {t("settings.feedTzWarning")}
            </div>
          )}
          <div className="form-actions">
            <button className="primary" type="submit" disabled={!restartChanged.length || saving}>
              {saving ? t("settings.saving") : t("common.save")}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={!restartChanged.length && !hasBlank(restartKeys)}
              onClick={() => resetTier(restartKeys)}
            >
              {t("settings.reset")}
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <h2>
          {t("settings.readOnly")} <span className="muted">{t("settings.readOnlyNote")}</span>
        </h2>
        <div className="kv-list">
          {Object.entries(s.read_only).map(([k, v]) => (
            <div className="kv" key={k}>
              <span className="kv-k">{label(k)}</span>
              <span className="kv-v mono">
                {typeof v === "boolean" ? (v ? t("common.yes") : t("common.no")) : String(v)}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
