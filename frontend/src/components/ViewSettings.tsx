import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import type { ChipColor, FilterField, FlowRecord, QueryChip } from "../types";
import { matchRecord, parseQuery, suggest, type Suggestion } from "../query";
import {
  ALL_FILTER_FIELDS,
  CHIP_COLORS,
  COLUMN_META,
  FIELD_LABEL_KEYS,
  allowedFilterFields,
  chipHex,
  defaultLayout,
  genChipId,
  haystack,
  mergeChipView,
  mergeLayout,
  sanitizeChips,
  type ChipScope,
  type ChipViewItem,
  type LayoutItem,
  type ScopedChip,
} from "./LiveView";

// ── Query input with autocompletion (field names / operators) ──
// Uses the same suggest() engine as the live search; without live records it
// suggests field names and operators (value suggestions come from live data).
function QueryInput({
  value,
  onChange,
  placeholder,
  onEnter,
  records,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  onEnter?: () => void;
  records: FlowRecord[];
}) {
  const ref = useRef<HTMLInputElement | null>(null);
  const [sugg, setSugg] = useState<{ start: number; end: number; items: Suggestion[] } | null>(null);
  const [idx, setIdx] = useState(0);

  function refresh(v: string, caret: number) {
    // Real sample records give field/value suggestions (Rule= → existing rules).
    const s = suggest(v, caret, records);
    setSugg(s.items.length ? s : null);
    setIdx(0);
  }
  function apply(s: Suggestion) {
    if (!sugg) return;
    const next = value.slice(0, sugg.start) + s.replace + value.slice(sugg.end);
    onChange(next);
    const caret = sugg.start + s.replace.length;
    setSugg(null);
    requestAnimationFrame(() => {
      const el = ref.current;
      if (el) {
        el.focus();
        el.setSelectionRange(caret, caret);
        refresh(next, caret);
      }
    });
  }
  return (
    <div className="query-wrap">
      <input
        ref={ref}
        className="mono"
        value={value}
        placeholder={placeholder}
        spellCheck={false}
        onChange={(e) => {
          onChange(e.target.value);
          refresh(e.target.value, e.target.selectionStart ?? e.target.value.length);
        }}
        onKeyDown={(e) => {
          if (sugg && sugg.items.length) {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setIdx((i) => (i + 1) % sugg.items.length);
              return;
            }
            if (e.key === "ArrowUp") {
              e.preventDefault();
              setIdx((i) => (i - 1 + sugg.items.length) % sugg.items.length);
              return;
            }
            if (e.key === "Tab" || e.key === "Enter") {
              e.preventDefault();
              apply(sugg.items[idx]);
              return;
            }
            if (e.key === "Escape") {
              setSugg(null);
              return;
            }
          }
          if (e.key === "Enter" && onEnter) onEnter();
        }}
        onBlur={() => window.setTimeout(() => setSugg(null), 120)}
      />
      {sugg && sugg.items.length > 0 && (
        <div className="suggest">
          {sugg.items.map((s, i) => (
            <button
              key={s.replace + i}
              className={i === idx ? "suggest-item active" : "suggest-item"}
              onMouseDown={(e) => {
                e.preventDefault();
                apply(s);
              }}
            >
              {s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

interface Editing {
  id: string | null;
  scope: ChipScope;
  label: string;
  query: string;
  color: ChipColor;
}

// `obfuscated` = the account only holds the "logs_obf" permission. The user filter is
// then locked (the backend enforces it) and the sample records for the chip preview
// arrive masked.
export function ViewSettings({ obfuscated = false }: { obfuscated?: boolean }) {
  const { t } = useTranslation();
  const selectableFields = useMemo(() => allowedFilterFields(obfuscated), [obfuscated]);
  const [layout, setLayout] = useState<LayoutItem[]>(defaultLayout);
  const [filterFields, setFilterFields] = useState<FilterField[]>(ALL_FILTER_FIELDS);
  const [personalChips, setPersonalChips] = useState<QueryChip[]>([]);
  const [globalChips, setGlobalChips] = useState<QueryChip[]>([]);
  const [chipView, setChipView] = useState<ChipViewItem[]>([]);
  const [canEditGlobal, setCanEditGlobal] = useState(false);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [saved, setSaved] = useState(false);
  const [samples, setSamples] = useState<FlowRecord[]>([]);

  function loadSamples() {
    api.samples().then((r) => setSamples(r.records)).catch(() => {});
  }
  // Fetch fresh sample logs when a chip editor is opened.
  function openEditor(e: Editing) {
    setEditing(e);
    loadSamples();
  }

  const loadedRef = useRef(false);
  const loadedPrefs = useRef<Record<string, unknown>>({});
  const pending = useRef<Record<string, unknown> | null>(null);
  const colDrag = useRef<number | null>(null);
  const chipDrag = useRef<number | null>(null);

  // ── Load ───────────────────────────────────────────────────────
  useEffect(() => {
    // A prefs read that FAILED must not look like "nothing stored": the defaults below
    // would be written straight back over the stored blob by the autosave.
    let prefsOk = true;
    Promise.all([
      api.getPrefs().catch(() => {
        prefsOk = false;
        return {} as Record<string, unknown>;
      }),
      api.getChips().catch(() => ({ global: [] as QueryChip[], can_edit_global: false })),
    ])
      .then(([p, ch]) => {
        loadedPrefs.current = p || {};
        setLayout(mergeLayout(p?.columns));
        const ff = p?.filterFields;
        if (Array.isArray(ff)) {
          const valid = (ff as string[]).filter((f): f is FilterField => (ALL_FILTER_FIELDS as string[]).includes(f));
          if (valid.length) setFilterFields(valid);
        }
        const personal = sanitizeChips(p?.personalChips);
        const glob = sanitizeChips(ch.global);
        setPersonalChips(personal);
        setGlobalChips(glob);
        setCanEditGlobal(!!ch.can_edit_global);
        setChipView(mergeChipView(p?.chipView, [...glob, ...personal]));
      })
      .finally(() => {
        loadedRef.current = prefsOk;
      });
  }, []);

  // ── Save prefs (debounced), keeping unmanaged keys ──────────────
  useEffect(() => {
    if (!loadedRef.current) return;
    const payload = { ...loadedPrefs.current, columns: layout, filterFields, personalChips, chipView };
    pending.current = payload;
    const t = window.setTimeout(() => {
      api
        .savePrefs(payload)
        .then(() => {
          // Only clear when nothing newer is waiting, otherwise a change made while this
          // request was in flight is dropped by the flush below.
          if (pending.current === payload) pending.current = null;
          setSaved(true);
          window.setTimeout(() => setSaved(false), 1200);
        })
        .catch(() => {});
    }, 500);
    return () => window.clearTimeout(t);
  }, [layout, filterFields, personalChips, chipView]);

  // Flush pending changes when leaving (tab switch), otherwise a change made just
  // before (showing a column, say) would be lost.
  useEffect(() => {
    return () => {
      if (pending.current) api.savePrefs(pending.current).catch(() => {});
    };
  }, []);

  // Load sample logs when the tab opens (for autocomplete + preview).
  useEffect(() => {
    loadSamples();
  }, []);

  // Keep the chip view in sync with the set of chips (append new, drop removed).
  useEffect(() => {
    if (!loadedRef.current) return;
    setChipView((prev) => mergeChipView(prev, [...globalChips, ...personalChips]));
  }, [globalChips, personalChips]);

  // ── Derived values ─────────────────────────────────────────────
  const allChips = useMemo<ScopedChip[]>(
    () => [
      ...globalChips.map((c) => ({ ...c, scope: "global" as const })),
      ...personalChips.map((c) => ({ ...c, scope: "personal" as const })),
    ],
    [globalChips, personalChips]
  );
  const chipById = useMemo(() => new Map(allChips.map((c) => [c.id, c])), [allChips]);
  const orderedChips = useMemo(
    () =>
      chipView
        .map((v) => {
          const c = chipById.get(v.id);
          return c ? { ...c, visible: v.visible } : null;
        })
        .filter((x): x is ScopedChip & { visible: boolean } => x !== null),
    [chipView, chipById]
  );

  // ── Chip CRUD ──────────────────────────────────────────────────
  function saveChip(chip: QueryChip, scope: ChipScope) {
    if (scope === "global") {
      const before = globalChips;
      const next = globalChips.some((c) => c.id === chip.id)
        ? globalChips.map((c) => (c.id === chip.id ? chip : c))
        : [...globalChips, chip];
      setGlobalChips(next);
      // Global chips live on the server, not in the prefs. If the write is refused the
      // list has to go back, otherwise it shows a chip nobody else has.
      api.saveGlobalChips(next).catch(() => setGlobalChips(before));
    } else {
      setPersonalChips(
        personalChips.some((c) => c.id === chip.id)
          ? personalChips.map((c) => (c.id === chip.id ? chip : c))
          : [...personalChips, chip]
      );
    }
    setEditing(null);
  }
  function deleteChip(chip: ScopedChip) {
    if (chip.scope === "global") {
      if (!canEditGlobal) return;
      const before = globalChips;
      const next = globalChips.filter((c) => c.id !== chip.id);
      setGlobalChips(next);
      api.saveGlobalChips(next).catch(() => setGlobalChips(before));
    } else {
      setPersonalChips(personalChips.filter((c) => c.id !== chip.id));
    }
  }
  function toggleChipVisible(id: string) {
    setChipView((prev) => prev.map((it) => (it.id === id ? { ...it, visible: !it.visible } : it)));
  }
  function moveChip(from: number, to: number) {
    if (from === to) return;
    setChipView((prev) => {
      const next = prev.slice();
      const [m] = next.splice(from, 1);
      next.splice(to, 0, m);
      return next;
    });
  }

  // ── Columns / filter fields ────────────────────────────────────
  function toggleColumn(key: string) {
    setLayout((prev) => prev.map((it) => (it.key === key ? { ...it, visible: !it.visible } : it)));
  }
  function moveColumn(from: number, to: number) {
    if (from === to) return;
    setLayout((prev) => {
      const next = prev.slice();
      const [m] = next.splice(from, 1);
      next.splice(to, 0, m);
      return next;
    });
  }
  function toggleFilterField(f: FilterField) {
    setFilterFields((prev) => {
      if (prev.includes(f)) {
        if (prev.length <= 1) return prev;
        return prev.filter((x) => x !== f);
      }
      return ALL_FILTER_FIELDS.filter((x) => prev.includes(x) || x === f);
    });
  }
  function resetAll() {
    setLayout(defaultLayout());
    setFilterFields(ALL_FILTER_FIELDS);
    setChipView(mergeChipView(null, [...globalChips, ...personalChips]));
  }

  const labelKey = COLUMN_META.reduce((m, c) => ((m[c.key] = c.labelKey), m), {} as Record<string, string>);

  return (
    <div className="view-page">
      <div className="overview-head">
        <h1 className="ov-title">{t("view.title")}</h1>
        <div className="ov-actions">
          <span className={saved ? "save-badge on" : "save-badge"}>
            {saved ? t("view.saved") : t("view.autosave")}
          </span>
          <button className="ghost" onClick={resetAll}>
            {t("view.resetAll")}
          </button>
        </div>
      </div>

      <div className="view-grid">
        {/* ── Chips (main area) ─────────────────────────────────── */}
        <section className="panel view-section chips-section">
          <div className="vs-head">
            <div>
              <h2>{t("view.chips")}</h2>
              <p className="muted vs-hint">
                {t("view.chipsHint")}
                {canEditGlobal ? t("view.chipsHintAdmin") : t("view.chipsHintUser")}
              </p>
            </div>
            <button
              className="primary"
              onClick={() => openEditor({ id: null, scope: "personal", label: "", query: "", color: "info" })}
            >
              {t("view.newChip")}
            </button>
          </div>

          {editing && (
            <ChipEditorInline
              editing={editing}
              canGlobal={canEditGlobal}
              samples={samples}
              onReloadSamples={loadSamples}
              onChange={setEditing}
              onSave={saveChip}
              onCancel={() => setEditing(null)}
            />
          )}

          <div className="chip-manage-list">
            {orderedChips.length === 0 && <span className="muted">{t("view.noChips")}</span>}
            {orderedChips.map((c, i) => {
              const editable = c.scope === "personal" || canEditGlobal;
              return (
                <div
                  key={c.id}
                  className="chip-manage-row"
                  draggable
                  onDragStart={() => (chipDrag.current = i)}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={() => {
                    if (chipDrag.current !== null) moveChip(chipDrag.current, i);
                    chipDrag.current = null;
                  }}
                >
                  <span className="drag-handle" title={t("view.dragTitle")}>⠿</span>
                  <input
                    type="checkbox"
                    checked={c.visible}
                    onChange={() => toggleChipVisible(c.id)}
                    title={c.visible ? t("view.visible") : t("view.hidden")}
                  />
                  <span className="vtoggle chip-preview" style={{ color: chipHex(c.color), borderColor: chipHex(c.color) }}>{c.label}</span>
                  <code className="chip-query-txt" title={c.query}>
                    {c.query}
                  </code>
                  {c.scope === "global" && <span className="chip-lock" title={t("view.globalLockTitle")}>🔒</span>}
                  <span className="chip-manage-actions">
                    {editable ? (
                      <>
                        <button
                          className="mini"
                          onClick={() =>
                            openEditor({ id: c.id, scope: c.scope, label: c.label, query: c.query, color: c.color })
                          }
                          title={t("view.editTitle")}
                        >
                          ✎
                        </button>
                        <button className="chip-x" onClick={() => deleteChip(c)} title={t("view.deleteTitle")}>
                          ×
                        </button>
                      </>
                    ) : (
                      <span className="muted small">{t("view.locked")}</span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        </section>

        {/* ── Columns ────────────────────────────────────────────── */}
        <section className="panel view-section">
          <h2>{t("view.columns")}</h2>
          <p className="muted vs-hint">{t("view.columnsHint")}</p>
          <div className="col-manage-list">
            {layout.map((it, i) => (
              <div
                key={it.key}
                className="col-item"
                draggable
                onDragStart={() => (colDrag.current = i)}
                onDragOver={(e) => e.preventDefault()}
                onDrop={() => {
                  if (colDrag.current !== null) moveColumn(colDrag.current, i);
                  colDrag.current = null;
                }}
              >
                <span className="drag-handle" title={t("view.dragTitle")}>⠿</span>
                <label className="check-row grow">
                  <input type="checkbox" checked={it.visible} onChange={() => toggleColumn(it.key)} />
                  {labelKey[it.key] ? t(labelKey[it.key]) : it.key}
                </label>
              </div>
            ))}
          </div>
        </section>

        {/* ── Filter fields ──────────────────────────────────────── */}
        <section className="panel view-section">
          <h2>{t("view.filterFields")}</h2>
          <p className="muted vs-hint">{t("view.filterFieldsHint")}</p>
          {obfuscated && <p className="muted vs-hint">{t("view.obfHint")}</p>}
          {selectableFields.map((f) => (
            <label key={f} className="check-row">
              <input type="checkbox" checked={filterFields.includes(f)} onChange={() => toggleFilterField(f)} />
              {t(FIELD_LABEL_KEYS[f])}
            </label>
          ))}
        </section>
      </div>
    </div>
  );
}

function ChipEditorInline({
  editing,
  canGlobal,
  samples,
  onReloadSamples,
  onChange,
  onSave,
  onCancel,
}: {
  editing: Editing;
  canGlobal: boolean;
  samples: FlowRecord[];
  onReloadSamples: () => void;
  onChange: (e: Editing) => void;
  onSave: (chip: QueryChip, scope: ChipScope) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const isEdit = editing.id !== null;
  function save() {
    const l = editing.label.trim();
    const q = editing.query.trim();
    if (!l || !q) return;
    onSave({ id: editing.id ?? genChipId(editing.scope), label: l, query: q, color: editing.color }, editing.scope);
  }

  // Live preview: how many of the sample logs does the current query match?
  const preview = useMemo(() => {
    const q = editing.query.trim();
    if (!q) return null;
    const terms = parseQuery(q);
    const matched = samples.filter((r) => matchRecord(r, terms, haystack(r)));
    return { count: matched.length, total: samples.length, rows: matched.slice(0, 6) };
  }, [editing.query, samples]);
  return (
    <div className="chip-editor-inline">
      <div className="cei-row">
        <label className="editor-field">
          <span>{t("view.chipLabel")}</span>
          <input
            value={editing.label}
            maxLength={40}
            placeholder={t("view.chipLabelPh")}
            onChange={(e) => onChange({ ...editing, label: e.target.value })}
          />
        </label>
        <label className="editor-field grow">
          <span>{t("view.queryLabel")}</span>
          <QueryInput
            value={editing.query}
            onChange={(v) => onChange({ ...editing, query: v })}
            onEnter={save}
            records={samples}
            placeholder={t("view.queryPh")}
          />
        </label>
      </div>
      <div className="cei-row cei-bottom">
        <div className="color-picker">
          {CHIP_COLORS.map((c) => {
            const hex = chipHex(c.key);
            return (
              <button
                key={c.key}
                type="button"
                className={`swatch ${chipHex(editing.color).toLowerCase() === hex.toLowerCase() ? "active" : ""}`}
                style={{ background: hex }}
                title={t(c.labelKey)}
                onClick={() => onChange({ ...editing, color: hex })}
              />
            );
          })}
          <input
            type="color"
            className="color-free"
            value={chipHex(editing.color)}
            onChange={(e) => onChange({ ...editing, color: e.target.value })}
            title={t("view.freeColorTitle")}
          />
        </div>
        {canGlobal && !isEdit && (
          <label className="check-row">
            <input
              type="checkbox"
              checked={editing.scope === "global"}
              onChange={(e) => onChange({ ...editing, scope: e.target.checked ? "global" : "personal" })}
            />
            {t("view.globalForAll")}
          </label>
        )}
        {isEdit && editing.scope === "global" && <span className="muted small">{t("view.globalChipNote")}</span>}
        <div className="cei-actions">
          <button className="ghost" onClick={onCancel}>
            {t("common.cancel")}
          </button>
          <button className="primary" onClick={save} disabled={!editing.label.trim() || !editing.query.trim()}>
            {t("common.save")}
          </button>
        </div>
      </div>

      {/* Live preview: how the chip hits the current sample logs */}
      {editing.query.trim() && (
        <div className="chip-preview-box">
          <div className="cpb-head">
            <span className="muted">
              {t("view.previewPre")} <b>{preview?.count ?? 0}</b>{" "}
              {t("view.previewMid", { count: preview?.total ?? samples.length })}{" "}
              {t("view.previewSampled")}
            </span>
            <button className="mini" onClick={onReloadSamples} title={t("view.reloadSamples")}>
              ↻
            </button>
          </div>
          {preview && preview.rows.length > 0 ? (
            <div className="cpb-rows">
              {preview.rows.map((r) => (
                <div className="cpb-row mono" key={r.id}>
                  <span className={`type-tag t-${r.logtype}`}>{r.logtype}</span>
                  <span className="ellip cpb-user">{r.user || "—"}</span>
                  <span className="cpb-ips">{r.src_ip || "?"}→{r.dst_ip || "?"}</span>
                  <span className="ellip cpb-rule">{r.rule || r.category || "—"}</span>
                  <span className={`verdict v-${r.severity}`}>{r.verdict}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="muted small cpb-empty">
              {samples.length === 0 ? t("view.noSamples") : t("view.noPreviewMatch")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
