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
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [saving, setSaving] = useState(false);

  async function load() {
    try {
      const data = await api.admin.getSettings();
      setS(data);
      setDraft({ ...data.editable });
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
  const changed = keys.filter((k) => draft[k] !== s.editable[k]);
  const dirty = changed.length > 0;
  const liveKeys = keys.filter((k) => s.catalogue[k].tier === "live");
  const restartKeys = keys.filter((k) => s.catalogue[k].tier === "restart");

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setSaving(true);
    try {
      const payload: Record<string, SettingValue> = {};
      for (const k of changed) payload[k] = draft[k];
      const data = await api.admin.saveSettings(payload);
      setS(data);
      setDraft({ ...data.editable });
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

  function field(key: string) {
    const spec: SettingSpec = s!.catalogue[key];
    const value = draft[key];
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
            value={typeof value === "number" ? value : ""}
            onChange={(e) => set(Number(e.target.value))}
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
        <form className="settings-form" onSubmit={save}>
          {liveKeys.map(field)}
          <div className="form-actions">
            <button className="primary" type="submit" disabled={!dirty || saving}>
              {saving ? t("settings.saving") : t("common.save")}
            </button>
            <button type="button" className="ghost" disabled={!dirty} onClick={() => setDraft({ ...s.editable })}>
              {t("settings.reset")}
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <h2>
          {t("settings.restartTitle")} <span className="muted">{t("settings.restartNote")}</span>
        </h2>
        <form className="settings-form" onSubmit={save}>
          {restartKeys.map(field)}
          {s.catalogue.feed_timezone && (
            <div className="note-box" style={{ marginTop: 10 }}>
              {t("settings.feedTzWarning")}
            </div>
          )}
          <div className="form-actions">
            <button className="primary" type="submit" disabled={!dirty || saving}>
              {saving ? t("settings.saving") : t("common.save")}
            </button>
            <button type="button" className="ghost" disabled={!dirty} onClick={() => setDraft({ ...s.editable })}>
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
