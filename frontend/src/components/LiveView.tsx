import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import i18nInstance from "../i18n";
import type { TFunction } from "i18next";
import { api, notifyUnauthorized } from "../api";
import { ALL_FEEDS } from "../types";
import type {
  ChipColor,
  FeedState,
  FeedType,
  FilterField,
  FilterGroup,
  FilterOp,
  FilterPreset,
  FilterSpec,
  FlowRecord,
  QueryChip,
  StreamStats,
} from "../types";
import { matchRecord, parseQuery, suggest, type Suggestion } from "../query";

const MAX_ROWS = 2000;

// Translation keys, resolved at render time so a language switch relabels the UI.
export const FIELD_LABEL_KEYS: Record<FilterField, string> = {
  src_ip: "live.field.src_ip",
  dst_ip: "live.field.dst_ip",
  user: "live.field.user",
  location: "live.field.location",
};
export const ALL_FILTER_FIELDS: FilterField[] = ["src_ip", "dst_ip", "user", "location"];
// In the anonymised view (permission "logs_obf") the user filter is locked: the
// email is being masked, so filtering on it must not be possible either (otherwise
// "are there hits?" would give the person away). Search runs over the source IP.
// The backend enforces the same (api/stream_routes.py); this is only the matching UI.
export const OBFUSCATED_DENIED_FIELDS: FilterField[] = ["user"];
export function allowedFilterFields(obfuscated: boolean): FilterField[] {
  return obfuscated
    ? ALL_FILTER_FIELDS.filter((f) => !OBFUSCATED_DENIED_FIELDS.includes(f))
    : ALL_FILTER_FIELDS;
}

// Only for the table column "Verdict" (verdict code → translated label).
const VERDICT_KEYS: Record<string, string> = {
  allowed: "live.verdict.allowed",
  blocked: "live.verdict.blocked",
  no_response: "live.verdict.no_response",
  ssl_failed: "live.verdict.ssl_failed",
  http_error: "live.verdict.http_error",
  dns_error: "live.verdict.dns_error",
  unknown: "live.verdict.unknown",
};
function verdictLabel(verdict: string, t: TFunction): string {
  const key = VERDICT_KEYS[verdict];
  return key ? t(key) : verdict;
}

// Feed names are proper nouns and read the same in every language.
const FEED_LABELS: Record<FeedType, string> = { web: "Web", fw: "FW", dns: "DNS" };

// Four presets for quick picking; beyond those any hex colour can be chosen.
export const CHIP_COLORS: { key: ChipColor; labelKey: string }[] = [
  { key: "good", labelKey: "live.color.good" },
  { key: "bad", labelKey: "live.color.bad" },
  { key: "warn", labelKey: "live.color.warn" },
  { key: "info", labelKey: "live.color.info" },
];
const PRESET_HEX: Record<string, string> = { good: "#2ea043", bad: "#f85149", warn: "#d29922", info: "#6e7681" };
// Chip colour → concrete hex value (preset name OR already hex; grey fallback).
export function chipHex(color: string): string {
  return PRESET_HEX[color] ?? (/^#[0-9a-fA-F]{3,8}$/.test(color) ? color : "#6e7681");
}

export type ChipScope = "global" | "personal";
export type ScopedChip = QueryChip & { scope: ChipScope };

function fmtBytes(n: number): string {
  if (!n) return "0";
  const u = ["B", "K", "M", "G", "T"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)}${u[i]}`;
}
function clock(epoch: number): string {
  try {
    return new Date(epoch * 1000).toLocaleTimeString(i18nInstance.language);
  } catch {
    return "";
  }
}
// The real log time from the NSS feed. While parsing, the backend resolves the feed
// timestamp to an absolute epoch (backend/ingest/timestamps.py), including the feed
// time zone configured there. No time string is interpreted here on purpose: the web
// feed delivers local time without a zone, which cannot be resolved reliably in the
// browser. If ts_epoch is empty (unknown format), we show the server receive time.
function logDate(r: FlowRecord): Date {
  return new Date((r.ts_epoch ?? r.received_at) * 1000);
}
function logTime(r: FlowRecord): string {
  try {
    return logDate(r).toLocaleString(i18nInstance.language);
  } catch {
    return (r.ts ?? "").toString();
  }
}
function port(p: number | null): string {
  return p ? `:${p}` : "";
}

// ── Column catalogue (order + visibility are personalised per user) ──
interface Column {
  key: string;
  labelKey: string;
  render: (r: FlowRecord, t: TFunction) => ReactNode;
}
const ALL_COLUMNS: Column[] = [
  {
    key: "time",
    labelKey: "live.col.time",
    render: (r, t) => (
      <span className="mono" title={t("live.receivedAt", { time: clock(r.received_at) })}>{logTime(r)}</span>
    ),
  },
  {
    key: "verdict",
    labelKey: "live.col.verdict",
    render: (r, t) => <span className={`verdict v-${r.severity}`}>{verdictLabel(r.verdict, t)}</span>,
  },
  { key: "type", labelKey: "live.col.type", render: (r) => <span className={`type-tag t-${r.logtype}`}>{r.logtype}</span> },
  { key: "user", labelKey: "live.col.user", render: (r) => <span className="ellip" title={r.user}>{r.user || "—"}</span> },
  { key: "location", labelKey: "live.col.location", render: (r) => <span className="ellip" title={r.location}>{r.location || "—"}</span> },
  { key: "src", labelKey: "live.col.src", render: (r) => <span className="mono">{r.src_ip}{port(r.src_port)}</span> },
  { key: "dst", labelKey: "live.col.dst", render: (r) => <span className="mono">{r.dst_ip}{port(r.dst_port)}</span> },
  { key: "proto", labelKey: "live.col.proto", render: (r) => r.proto },
  { key: "action", labelKey: "live.col.action", render: (r) => r.action },
  {
    key: "bytes",
    labelKey: "live.col.bytes",
    render: (r) => <span className="mono nowrap">{fmtBytes(r.bytes_tx)} / {fmtBytes(r.bytes_rx)}</span>,
  },
  {
    key: "status",
    labelKey: "live.col.status",
    render: (r) => (
      <span className="ellip" title={r.reason}>
        {r.http_status && <span className="mono">{r.http_status} </span>}
        {r.reason}
      </span>
    ),
  },
  {
    key: "target",
    labelKey: "live.col.target",
    render: (r) => <span className="ellip target" title={r.target}>{r.target || r.category || "—"}</span>,
  },
  {
    key: "rule",
    labelKey: "live.col.rule",
    render: (r) => <span className="ellip" title={r.rule}>{r.rule || "—"}</span>,
  },
  { key: "category", labelKey: "live.col.category", render: (r) => r.category || "—" },
  { key: "tls", labelKey: "live.col.tls", render: (r) => `${r.tls_version} ${r.tls_cipher}`.trim() || "—" },
  { key: "duration", labelKey: "live.col.duration", render: (r) => (r.duration_ms != null ? `${r.duration_ms} ms` : "—") },
  { key: "server_ip", labelKey: "live.col.server_ip", render: (r) => <span className="mono">{r.server_ip || "—"}</span> },
  { key: "dept", labelKey: "live.col.dept", render: (r) => r.dept || "—" },
  { key: "host", labelKey: "live.col.host", render: (r) => <span className="ellip" title={r.host}>{r.host || "—"}</span> },
  { key: "app", labelKey: "live.col.app", render: (r) => <span className="ellip" title={r.app_name}>{r.app_name || "—"}</span> },
  {
    key: "threat",
    labelKey: "live.col.threat",
    render: (r) =>
      r.threat_name ? (
        <span className="ellip" title={`${r.threat_name} (${r.threat_category})`}>
          {r.threat_name}
          {r.risk_score != null && r.risk_score > 0 ? ` · ${r.risk_score}` : ""}
        </span>
      ) : (
        "—"
      ),
  },
  { key: "device", labelKey: "live.col.device", render: (r) => <span className="ellip" title={`${r.device_name} / ${r.device_owner}`}>{r.device_name || "—"}</span> },
  { key: "country", labelKey: "live.col.country", render: (r) => r.dest_country || "—" },
  { key: "tunnel", labelKey: "live.col.tunnel", render: (r) => r.tunnel_type || "—" },
  { key: "nwservice", labelKey: "live.col.nwservice", render: (r) => r.nwservice || "—" },
  { key: "url_class", labelKey: "live.col.url_class", render: (r) => <span className="ellip" title={r.url_class}>{r.url_class || "—"}</span> },
  { key: "rule_type", labelKey: "live.col.rule_type", render: (r) => r.rule_type || "—" },
  { key: "content_type", labelKey: "live.col.content_type", render: (r) => r.content_type || "—" },
  { key: "server_tls", labelKey: "live.col.server_tls", render: (r) => r.server_tls_version || "—" },
  { key: "client_public_ip", labelKey: "live.col.client_public_ip", render: (r) => <span className="mono">{r.client_public_ip || "—"}</span> },
  { key: "ssl_inspected", labelKey: "live.col.ssl_inspected", render: (r) => r.ssl_inspected || "—" },
  { key: "ssl_policy", labelKey: "live.col.ssl_policy", render: (r) => <span className="ellip" title={r.ssl_policy}>{r.ssl_policy || "—"}</span> },
  { key: "ssl_policy_reason", labelKey: "live.col.ssl_policy_reason", render: (r) => <span className="ellip" title={r.ssl_policy_reason}>{r.ssl_policy_reason || "—"}</span> },
  { key: "url_policy", labelKey: "live.col.url_policy", render: (r) => <span className="ellip" title={r.url_policy}>{r.url_policy || "—"}</span> },
  { key: "fwd_rule", labelKey: "live.col.fwd_rule", render: (r) => <span className="ellip" title={r.fwd_rule}>{r.fwd_rule || "—"}</span> },
  { key: "gateway", labelKey: "live.col.gateway", render: (r) => <span className="ellip" title={r.gateway}>{r.gateway || "—"}</span> },
  { key: "flow_type", labelKey: "live.col.flow_type", render: (r) => r.flow_type || "—" },
  { key: "dns_req_type", labelKey: "live.col.dns_req_type", render: (r) => r.dns_req_type || "—" },
  {
    key: "dns_response",
    labelKey: "live.col.dns_response",
    render: (r) => <span className="ellip mono" title={r.dns_response}>{r.dns_response || "—"}</span>,
  },
  { key: "dns_error", labelKey: "live.col.dns_error", render: (r) => r.dns_error || "—" },
];
const COLUMN_BY_KEY: Record<string, Column> = Object.fromEntries(ALL_COLUMNS.map((c) => [c.key, c]));
// Lightweight column metadata (key + translation key) for the view management tab.
export const COLUMN_META: { key: string; labelKey: string }[] = ALL_COLUMNS.map((c) => ({
  key: c.key,
  labelKey: c.labelKey,
}));
const DEFAULT_VISIBLE = new Set([
  "time", "verdict", "type", "user", "location", "src", "dst", "proto", "action",
  "status", "target", "rule", "rule_type", "category",
]);

// Number of rows shown (browser protection), picked by the user and persisted.
const ROW_LIMITS = [50, 100, 200, 1000];

// Column widths (px): freely draggable, stored per account; fixed width, no auto resize.
const DEFAULT_W = 130;
const COL_DEFAULT_W: Record<string, number> = {
  time: 150, verdict: 150, type: 60, proto: 72, action: 96, bytes: 92, status: 160,
  target: 300, rule: 170, rule_type: 120, category: 150, src: 150, dst: 150,
  duration: 82, country: 70, tunnel: 96, user: 180, location: 130,
  fwd_rule: 180, url_policy: 160, ssl_policy: 160, ssl_policy_reason: 160, gateway: 150,
  ssl_inspected: 90, flow_type: 90, dns_req_type: 80, dns_response: 180, dns_error: 110,
};
function colWidth(key: string, widths: Record<string, number>): number {
  return widths[key] ?? COL_DEFAULT_W[key] ?? DEFAULT_W;
}

// ── CSV export (visible columns only, filtered/queried rows) ──────
const CSV_FIELD: Record<string, string> = {
  app: "app_name",
  country: "dest_country",
  tunnel: "tunnel_type",
  server_tls: "server_tls_version",
};
function csvCell(key: string, r: FlowRecord, t: TFunction): string {
  switch (key) {
    case "time": return logTime(r);
    case "verdict": return verdictLabel(r.verdict, t);
    case "type": return r.logtype;
    case "src": return `${r.src_ip}${port(r.src_port)}`;
    case "dst": return `${r.dst_ip}${port(r.dst_port)}`;
    case "bytes": return `${r.bytes_tx}/${r.bytes_rx}`;
    case "status": return `${r.http_status} ${r.reason}`.trim();
    case "target": return r.target || r.category || "";
    case "tls": return `${r.tls_version} ${r.tls_cipher}`.trim();
    case "duration": return r.duration_ms != null ? String(r.duration_ms) : "";
    case "device": return r.device_name;
    case "threat": return r.threat_name;
    default: {
      const v = (r as unknown as Record<string, unknown>)[CSV_FIELD[key] ?? key];
      return v == null ? "" : String(v);
    }
  }
}
function csvEscape(s: string): string {
  const v = s ?? "";
  return /[";\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}
function ts2name(epoch: number): string {
  try {
    return new Date(epoch).toISOString().slice(0, 19).replace(/[:T]/g, "-");
  } catch {
    return "export";
  }
}

export interface LayoutItem {
  key: string;
  visible: boolean;
}
export function defaultLayout(): LayoutItem[] {
  return ALL_COLUMNS.map((c) => ({ key: c.key, visible: DEFAULT_VISIBLE.has(c.key) }));
}
export function mergeLayout(saved: unknown): LayoutItem[] {
  if (!Array.isArray(saved)) return defaultLayout();
  const seen = new Set<string>();
  const out: LayoutItem[] = [];
  for (const it of saved as LayoutItem[]) {
    if (it && COLUMN_BY_KEY[it.key] && !seen.has(it.key)) {
      out.push({ key: it.key, visible: !!it.visible });
      seen.add(it.key);
    }
  }
  for (const c of ALL_COLUMNS) if (!seen.has(c.key)) out.push({ key: c.key, visible: false });
  return out;
}

// ── Query chips (order + visibility per account) ──────────────────
export interface ChipViewItem {
  id: string;
  visible: boolean;
}
export function genChipId(scope: ChipScope): string {
  return `${scope === "global" ? "g" : "p"}_${Date.now().toString(36)}${Math.floor(Math.random() * 46656).toString(36)}`;
}
export function sanitizeChips(raw: unknown): QueryChip[] {
  if (!Array.isArray(raw)) return [];
  const out: QueryChip[] = [];
  for (const c of raw as Record<string, unknown>[]) {
    if (!c) continue;
    const label = String(c.label ?? "").trim().slice(0, 40);
    const query = String(c.query ?? "").trim().slice(0, 200);
    if (!label || !query) continue;
    // Keep the preset name OR a free hex value (grey otherwise); without this,
    // free colours would be lost on load.
    const rawColor = String(c.color ?? "");
    const color: ChipColor =
      ["good", "bad", "warn", "info"].includes(rawColor) || /^#[0-9a-fA-F]{3,8}$/.test(rawColor)
        ? rawColor
        : "info";
    const id = String(c.id ?? "").trim() || genChipId("personal");
    out.push({ id, label, query, color });
  }
  return out;
}
// Reconcile visibility and order with the current set of chips: keep known entries
// in order, append new ones, drop the ones that disappeared.
export function mergeChipView(saved: unknown, all: QueryChip[]): ChipViewItem[] {
  const ids = new Set(all.map((c) => c.id));
  const seen = new Set<string>();
  const out: ChipViewItem[] = [];
  if (Array.isArray(saved)) {
    for (const it of saved as ChipViewItem[]) {
      if (it && ids.has(it.id) && !seen.has(it.id)) {
        out.push({ id: it.id, visible: it.visible !== false });
        seen.add(it.id);
      }
    }
  }
  for (const c of all) if (!seen.has(c.id)) out.push({ id: c.id, visible: true });
  return out;
}

// ── Input validation (filter values) ──────────────────────────────
function isValidIPv4(v: string): boolean {
  const parts = v.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && +p >= 0 && +p <= 255);
}
function isValidIPv6(v: string): boolean {
  return v.includes(":") && /^[0-9a-fA-F:]+$/.test(v) && (v.match(/::/g)?.length ?? 0) <= 1;
}
function isValidCIDR(v: string): boolean {
  const parts = v.split("/");
  if (parts.length !== 2) return false;
  const [ip, prefix] = parts;
  if (!/^\d+$/.test(prefix)) return false;
  const n = Number(prefix);
  if (isValidIPv4(ip)) return n >= 0 && n <= 32;
  if (isValidIPv6(ip)) return n >= 0 && n <= 128;
  return false;
}
/** Validation result as a translation key plus optional interpolation values. */
interface FilterError {
  key: string;
  params?: Record<string, unknown>;
  /** The offending value when several were entered with commas. */
  part?: string;
}
function ipv4ToInt(v: string): number {
  return v.split(".").reduce((acc, p) => acc * 256 + Number(p), 0);
}
/** Range `from-to`; the IPv4 short form `10.20.30.10-50` replaces only the last octet. */
function validateRange(v: string): FilterError | null {
  const [lo, hiRaw, ...rest] = v.split("-").map((p) => p.trim());
  if (rest.length || !lo || !hiRaw) return { key: "live.err.badRange" };
  const hi = /^\d+$/.test(hiRaw) && isValidIPv4(lo) ? lo.replace(/\d+$/, hiRaw) : hiRaw;
  if (isValidIPv4(lo) && isValidIPv4(hi)) {
    // Same limit as for CIDR: at most a /23 (512 addresses), server protection
    if (Math.abs(ipv4ToInt(hi) - ipv4ToInt(lo)) + 1 > 512) return { key: "live.err.rangeTooLarge" };
    return null;
  }
  if (isValidIPv6(lo) && isValidIPv6(hi)) return null;
  return { key: "live.err.badRange" };
}
/** Several values separated by comma/semicolon: IP fields turn them into separate filters. */
function splitFilterValues(field: FilterField, value: string): string[] {
  if (field !== "src_ip" && field !== "dst_ip") return [value.trim()];
  return value.split(/[,;]/).map((p) => p.trim()).filter(Boolean);
}
function validateFilter(field: FilterField, value: string): FilterError | null {
  const parts = splitFilterValues(field, value);
  if (!parts.length) return { key: "live.err.missingValue" };
  for (const p of parts) {
    const err = validateFilterValue(field, p);
    if (err) return parts.length > 1 ? { ...err, part: p } : err;
  }
  return null;
}
function validateFilterValue(field: FilterField, value: string): FilterError | null {
  const v = value.trim();
  if (!v) return { key: "live.err.missingValue" };
  const hasWildcard = v.includes("*") || v.includes("?");
  if (field === "location") {
    return null; // Location names are free (spaces/hyphens allowed), wildcards are fine
  }
  if (field === "user") {
    if (/\s/.test(v)) return { key: "live.err.userSpaces" };
    return null;
  }
  // src_ip / dst_ip
  if (v.includes("/")) {
    if (!isValidCIDR(v)) return { key: "live.err.badCidr" };
    const [ip, prefix] = v.split("/");
    const minPrefix = ip.includes(":") ? 64 : 23; // /23 = largest allowed network (server protection)
    if (Number(prefix) < minPrefix) return { key: "live.err.netTooLarge", params: { prefix: minPrefix } };
    return null;
  }
  if (v.includes("-")) return validateRange(v);
  if (hasWildcard) {
    if (!/^[0-9a-fA-F.:*?]+$/.test(v)) return { key: "live.err.badPattern" };
    return null;
  }
  if (!isValidIPv4(v) && !isValidIPv6(v)) return { key: "live.err.badIp" };
  return null;
}

// ── Filter groups: AND/OR on two levels ───────────────────────────
// The filter used to be ONE flat list that the server joined entirely with OR, so
// "source X AND destination Y" could not be searched at all. Now the operator of a
// group applies inside it, and `join` applies between the groups. Two levels cover
// both readings and need no bracket syntax:
//   (source A OR source B) AND destination C   ·   source A OR (source B AND destination C)
export const OP_KEYS: Record<FilterOp, string> = { and: "live.opAnd", or: "live.opOr" };

export function flatFilters(groups: FilterGroup[]): FilterSpec[] {
  return groups.flatMap((g) => g.items);
}

/** Groups of a preset. Presets without `groups` are legacy (= one OR group). */
export function presetGroups(p: FilterPreset): FilterGroup[] {
  if (Array.isArray(p.groups) && p.groups.length) {
    return p.groups.filter((g) => g && Array.isArray(g.items) && g.items.length);
  }
  return p.filters.length ? [{ op: "or", items: p.filters }] : [];
}

/** Drop emptied groups: a group without filters has no meaning. */
function pruneGroups(groups: FilterGroup[]): FilterGroup[] {
  return groups.filter((g) => g.items.length > 0);
}

// Free-text haystack per record, cached per record object (records are stable).
const _hsCache = new WeakMap<FlowRecord, string>();
export function haystack(r: FlowRecord): string {
  let h = _hsCache.get(r);
  if (h === undefined) {
    h = `${r.user} ${r.location} ${r.dept} ${r.src_ip} ${r.dst_ip} ${r.server_ip} ${r.client_public_ip} ${r.target} ${r.host} ${r.reason} ${r.rule} ${r.proto} ${r.action} ${r.http_status} ${r.category} ${r.app_name} ${r.threat_name} ${r.device_name} ${r.dest_country} ${r.tls_version} ${r.logtype} ${r.verdict}`.toLowerCase();
    _hsCache.set(r, h);
  }
  return h;
}

// `userDomain` comes from the backend configuration (USER_DOMAIN_SUFFIX) and is
// appended to the user filter when no @domain was typed. Empty = append nothing.
// `obfuscated` = the account only holds the "logs_obf" permission: personal fields
// arrive already masked from the server and the user filter is locked.
export function LiveView({
  retentionMinutes,
  userDomain,
  obfuscated,
}: {
  retentionMinutes: number;
  userDomain: string;
  obfuscated: boolean;
}) {
  const { t, i18n } = useTranslation();
  const selectableFields = useMemo(() => allowedFilterFields(obfuscated), [obfuscated]);
  const [groups, setGroups] = useState<FilterGroup[]>([]);
  const [join, setJoin] = useState<FilterOp>("and"); // between the groups
  const [draftField, setDraftField] = useState<FilterField>("src_ip");
  const [draftValue, setDraftValue] = useState("");
  // Target group for the next filter: "auto" = add it to the same field (OR),
  // otherwise into a new or a specific group.
  const [draftTarget, setDraftTarget] = useState<"auto" | "new" | number>("auto");
  const [dragFilter, setDragFilter] = useState<{ g: number; i: number } | null>(null);
  const [dropGroup, setDropGroup] = useState<number | "new" | null>(null);
  const [records, setRecords] = useState<FlowRecord[]>([]);
  const [stats, setStats] = useState<StreamStats | null>(null);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  // Filter fields the server refused for this session. It drops them from the filter
  // and says so in the snapshot, so the bar must not keep showing them as active.
  const [deniedFields, setDeniedFields] = useState<FilterField[]>([]);

  // Personalisation (persisted per account).
  const [layout, setLayout] = useState<LayoutItem[]>(defaultLayout);
  const [colWidths, setColWidths] = useState<Record<string, number>>({});
  const [limit, setLimit] = useState(100);
  const [filterFields, setFilterFields] = useState<FilterField[]>(ALL_FILTER_FIELDS);
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  // Which feeds this view receives. Applied server side, on the same path as the filters.
  const [feeds, setFeeds] = useState<FeedType[]>(ALL_FEEDS);
  const [showSettings, setShowSettings] = useState(false);
  const loadedRef = useRef(false);
  const loadedPrefs = useRef<Record<string, unknown>>({});
  const dragIndex = useRef<number | null>(null);
  const chipDragIndex = useRef<number | null>(null);
  const pendingPrefs = useRef<Record<string, unknown> | null>(null);

  // Query chips: global (admin-managed, locked) + personal; the view is per account.
  const [globalChips, setGlobalChips] = useState<QueryChip[]>([]);
  const [canEditGlobal, setCanEditGlobal] = useState(false);
  const [personalChips, setPersonalChips] = useState<QueryChip[]>([]);
  const [chipView, setChipView] = useState<ChipViewItem[]>([]);
  const [activeChips, setActiveChips] = useState<Set<string>>(new Set()); // active filters (not persisted)
  const [editing, setEditing] = useState<
    | null
    | { id: string | null; scope: ChipScope; label: string; query: string; color: ChipColor }
  >(null);

  // Query-Autocomplete
  const [sugg, setSugg] = useState<{ start: number; end: number; items: Suggestion[] } | null>(null);
  const [suggIdx, setSuggIdx] = useState(0);
  const queryRef = useRef<HTMLInputElement | null>(null);

  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const wsRef = useRef<WebSocket | null>(null);
  const appliedRef = useRef<{ groups: FilterGroup[]; join: FilterOp; feeds: FeedType[] }>({
    groups: [],
    join: "and",
    feeds: ALL_FEEDS,
  });
  const reconnectRef = useRef<number | null>(null);
  const closingRef = useRef(false);

  const draftError = draftValue.trim() ? validateFilter(draftField, draftValue) : null;

  // ── Load prefs + global chips ──────────────────────────────────
  useEffect(() => {
    // A prefs read that FAILED must not look like "nothing stored". The defaults below
    // would otherwise be saved straight back over the stored blob by the debounced save,
    // and the whole personalisation would be gone after one unlucky request.
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
        if (p?.colWidths && typeof p.colWidths === "object") {
          const cw: Record<string, number> = {};
          for (const [k, v] of Object.entries(p.colWidths as Record<string, unknown>)) {
            // Same bounds as the resize drag below, otherwise a width the user is
            // allowed to drag to is thrown away again on the next load.
            if (COLUMN_BY_KEY[k] && typeof v === "number" && v >= 60 && v <= 1000) cw[k] = v;
          }
          setColWidths(cw);
        }
        if (typeof p?.limit === "number" && ROW_LIMITS.includes(p.limit)) setLimit(p.limit);
        const ff = p?.filterFields;
        if (Array.isArray(ff)) {
          const valid = (ff as string[]).filter((f): f is FilterField => (ALL_FILTER_FIELDS as string[]).includes(f));
          if (valid.length) setFilterFields(valid);
        }
        if (Array.isArray(p?.feeds)) {
          const fd = (p!.feeds as string[]).filter((f): f is FeedType => (ALL_FEEDS as string[]).includes(f));
          if (fd.length) {
            setFeeds(fd);
            appliedRef.current = { ...appliedRef.current, feeds: fd };
          }
        }
        if (Array.isArray(p?.presets)) {
          setPresets(
            (p!.presets as FilterPreset[]).filter((x) => x && typeof x.name === "string" && Array.isArray(x.filters))
          );
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

  // ── Save prefs (debounced) ─────────────────────────────────────
  useEffect(() => {
    if (!loadedRef.current) return;
    // PUT /api/prefs replaces the whole blob, so keys this view does not manage have to
    // be carried over or they are dropped.
    const payload = {
      ...loadedPrefs.current,
      columns: layout,
      colWidths,
      limit,
      filterFields,
      feeds,
      presets,
      personalChips,
      chipView,
    };
    pendingPrefs.current = payload;
    const t = window.setTimeout(() => {
      api
        .savePrefs(payload)
        .then(() => {
          // Only clear when nothing newer is waiting, otherwise a change made while this
          // request was in flight is dropped by the flush below.
          if (pendingPrefs.current === payload) pendingPrefs.current = null;
        })
        .catch(() => {});
    }, 700);
    return () => window.clearTimeout(t);
  }, [layout, colWidths, limit, filterFields, feeds, presets, personalChips, chipView]);

  // Flush pending changes when leaving (tab switch).
  useEffect(() => {
    return () => {
      if (pendingPrefs.current) api.savePrefs(pendingPrefs.current).catch(() => {});
    };
  }, []);

  // Keep the chip view in sync with the set of chips (append new, drop removed).
  useEffect(() => {
    if (!loadedRef.current) return;
    setChipView((prev) => mergeChipView(prev, [...globalChips, ...personalChips]));
  }, [globalChips, personalChips]);

  // Selectable fields = personal selection ∩ allowed fields. Never empty (you would
  // be left without a filter) and the draft always points at an allowed field, which
  // matters when switching to the anonymised view where "user" drops out.
  const availableFilterFields = useMemo(() => {
    const allowed = selectableFields.filter((f) => filterFields.includes(f));
    return allowed.length ? allowed : selectableFields;
  }, [selectableFields, filterFields]);

  useEffect(() => {
    if (!availableFilterFields.includes(draftField)) setDraftField(availableFilterFields[0]);
  }, [availableFilterFields, draftField]);

  // If the chosen target group disappears (last filter removed), fall back to
  // "automatic", otherwise the selection would point at a group that is gone.
  useEffect(() => {
    if (typeof draftTarget === "number" && draftTarget >= groups.length) setDraftTarget("auto");
  }, [groups.length, draftTarget]);

  // Presets may come from a time with the full log permission and contain a user
  // filter. In the anonymised view it is cut out (the server would discard it anyway),
  // and a preset with nothing left disappears instead of silently doing nothing on
  // load. The stored preset itself stays unchanged.
  const usablePresets = useMemo(() => {
    if (!obfuscated) return presets;
    return presets
      .map((p) => {
        const g = pruneGroups(
          presetGroups(p).map((x) => ({ ...x, items: x.items.filter((f) => selectableFields.includes(f.field)) }))
        );
        return { ...p, groups: g, filters: flatFilters(g) };
      })
      .filter((p) => p.filters.length > 0);
  }, [presets, obfuscated, selectableFields]);

  // ── WebSocket: one view per session ────────────────────────────
  // Throw out the filters the server refused, both from the bar and from what a
  // reconnect would send again. No set_filters goes back out: the server has already
  // applied this and answered with the matching snapshot.
  const dropDenied = useCallback((denied: FilterField[]) => {
    const strip = (gs: FilterGroup[]) =>
      pruneGroups(gs.map((g) => ({ ...g, items: g.items.filter((f) => !denied.includes(f.field)) })));
    setGroups((prev) => strip(prev));
    appliedRef.current = { ...appliedRef.current, groups: strip(appliedRef.current.groups) };
  }, []);

  const connect = useCallback(() => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/stream/ws`);
    wsRef.current = ws;
    ws.onopen = () => {
      setConnected(true);
      const { groups: g, join: j, feeds: fd } = appliedRef.current;
      if (g.length) {
        ws.send(JSON.stringify({ type: "set_filters", groups: g, join: j, feeds: fd, filters: flatFilters(g) }));
      }
    };
    ws.onclose = (ev) => {
      setConnected(false);
      wsRef.current = null;
      if (closingRef.current) return;
      if (ev.code === 1008) {
        // 1008 covers two very different things, and the reason string is the only way
        // to tell them apart. An older server sends none, so anything we do not know
        // keeps the old behaviour: stop reconnecting and stay quiet.
        if (ev.reason === "unauthorized") {
          // session's gone. hand it to the same path an HTTP 401 takes, so the user gets
          // the sign-out message that already exists (and is already translated) rather
          // than a second home-grown expiry notice.
          notifyUnauthorized();
        }
        return;
      }
      reconnectRef.current = window.setTimeout(connect, 2000);
    };
    ws.onmessage = (ev) => {
      let msg: {
        type: string;
        records?: FlowRecord[];
        record?: FlowRecord;
        stats?: StreamStats;
        denied_fields?: string[];
      };
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.type === "snapshot" && msg.records) {
        setRecords(msg.records.slice().reverse().slice(0, MAX_ROWS));
        if (msg.stats) setStats(msg.stats);
        setExpanded(null);
        // Fields the server threw out of the filter (someone lost the logs permission
        // mid-session, for instance). Every snapshot carries the current answer, so an
        // empty list clears the warning again.
        const denied = (msg.denied_fields ?? []).filter((f): f is FilterField =>
          (ALL_FILTER_FIELDS as string[]).includes(f)
        );
        setDeniedFields(denied);
        if (denied.length) dropDenied(denied);
      } else if (msg.type === "record" && msg.record) {
        if (pausedRef.current) return;
        const rec = msg.record;
        setRecords((prev) => [rec, ...prev].slice(0, MAX_ROWS));
      } else if (msg.type === "stats" && msg.stats) {
        setStats(msg.stats);
      }
    };
  }, [dropDenied]);

  useEffect(() => {
    closingRef.current = false;
    connect();
    return () => {
      closingRef.current = true;
      if (reconnectRef.current) window.clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  // ── Drag the column width: live and smooth, stored per account ──
  function startResize(e: React.MouseEvent, key: string) {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startW = colWidth(key, colWidths);
    document.body.classList.add("col-resizing");
    function move(ev: MouseEvent) {
      const w = Math.max(60, Math.min(1000, startW + (ev.clientX - startX)));
      setColWidths((prev) => (prev[key] === w ? prev : { ...prev, [key]: w }));
    }
    function up() {
      document.body.classList.remove("col-resizing");
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    }
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  }

  function sendFilters(
    nextGroups: FilterGroup[],
    nextJoin: FilterOp,
    nextFeeds: FeedType[] = appliedRef.current.feeds
  ) {
    appliedRef.current = { groups: nextGroups, join: nextJoin, feeds: nextFeeds };
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      // `filters` stays along as a flat list: a server that does not know groups
      // falls back to the old OR behaviour instead of running into nothing.
      ws.send(
        JSON.stringify({
          type: "set_filters",
          groups: nextGroups,
          join: nextJoin,
          feeds: nextFeeds,
          filters: flatFilters(nextGroups),
        })
      );
    }
  }
  /** Turn a feed on or off. One always stays on: with none, nothing could ever match. */
  function toggleFeed(feed: FeedType) {
    const next = feeds.includes(feed)
      ? feeds.filter((f) => f !== feed)
      : ALL_FEEDS.filter((f) => f === feed || feeds.includes(f));
    if (!next.length) return;
    setFeeds(next);
    sendFilters(groups, join, next);
  }
  /** Set groups and apply at once: there is deliberately no extra apply step. */
  function applyGroups(next: FilterGroup[], nextJoin: FilterOp = join) {
    const cleaned = pruneGroups(next);
    setGroups(cleaned);
    setJoin(nextJoin);
    sendFilters(cleaned, nextJoin);
  }

  // ── Building filters ───────────────────────────────────────────
  // Where does the new filter go? "auto" puts it into an existing OR group with the
  // same field (several source IPs are almost always meant as OR), otherwise into a
  // group of its own that is then joined with AND.
  function targetGroupIndex(field: FilterField): number {
    if (draftTarget === "new") return -1;
    if (typeof draftTarget === "number") return draftTarget < groups.length ? draftTarget : -1;
    return groups.findIndex((g) => g.op === "or" && g.items.some((f) => f.field === field));
  }
  function addDraft() {
    if (!draftValue.trim() || draftError) return;
    const exists = (v: string) =>
      groups.some((g) => g.items.some((f) => f.field === draftField && f.value.toLowerCase() === v.toLowerCase()));
    const values: string[] = [];
    for (let value of splitFilterValues(draftField, draftValue)) {
      // User without an @domain: append the configured domain suffix automatically.
      if (draftField === "user" && userDomain && !value.includes("@")) value = value + userDomain;
      if (!exists(value) && !values.some((v) => v.toLowerCase() === value.toLowerCase())) values.push(value);
    }
    if (!values.length) {
      setDraftValue("");
      return;
    }
    const specs: FilterSpec[] = values.map((value) => ({ field: draftField, value }));
    const gi = targetGroupIndex(draftField);
    const next =
      gi >= 0
        ? groups.map((g, i) => (i === gi ? { ...g, items: [...g.items, ...specs] } : g))
        : [...groups, { op: "or" as FilterOp, items: specs }];
    applyGroups(next);
    setDraftValue("");
  }
  function removeFilter(gi: number, i: number) {
    applyGroups(groups.map((g, x) => (x === gi ? { ...g, items: g.items.filter((_, y) => y !== i) } : g)));
  }
  function toggleGroupOp(gi: number) {
    applyGroups(groups.map((g, x) => (x === gi ? { ...g, op: g.op === "or" ? "and" : "or" } : g)));
  }
  function toggleJoin() {
    applyGroups(groups, join === "and" ? "or" : "and");
  }
  /** Move a filter into another (or a new) group by drag and drop. */
  function moveFilter(from: { g: number; i: number }, to: number | "new") {
    if (to === from.g) return;
    const spec = groups[from.g]?.items[from.i];
    if (!spec) return;
    const next = groups.map((g) => ({ ...g, items: g.items.slice() }));
    next[from.g].items.splice(from.i, 1);
    if (to === "new") next.push({ op: "or", items: [spec] });
    else next[to].items.push(spec);
    applyGroups(next);
  }
  function clearFilters() {
    applyGroups([]);
  }

  // ── Presets ────────────────────────────────────────────────────
  function savePreset() {
    if (!groups.length) return;
    const name = prompt(t("live.presetNamePrompt"))?.trim();
    if (!name) return;
    setPresets((prev) => [
      ...prev.filter((p) => p.name !== name),
      { name, filters: flatFilters(groups), groups, join },
    ]);
  }
  function loadPreset(p: FilterPreset) {
    applyGroups(presetGroups(p), p.join === "or" ? "or" : "and");
  }
  function deletePreset(name: string) {
    setPresets((prev) => prev.filter((p) => p.name !== name));
  }

  // ── Chips: active filters (session), view (persisted), CRUD ─────
  function toggleChipActive(id: string) {
    setActiveChips((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }
  function toggleChipVisible(id: string) {
    setChipView((prev) => prev.map((it) => (it.id === id ? { ...it, visible: !it.visible } : it)));
  }
  function moveChip(from: number, to: number) {
    if (from === to) return;
    setChipView((prev) => {
      const next = prev.slice();
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });
  }
  function openChipEditor(chip?: ScopedChip) {
    if (chip) setEditing({ id: chip.id, scope: chip.scope, label: chip.label, query: chip.query, color: chip.color });
    else setEditing({ id: null, scope: "personal", label: "", query: "", color: "info" });
  }
  function saveChip(chip: QueryChip, scope: ChipScope) {
    if (scope === "global") {
      const before = globalChips;
      const next = globalChips.some((c) => c.id === chip.id)
        ? globalChips.map((c) => (c.id === chip.id ? chip : c))
        : [...globalChips, chip];
      setGlobalChips(next);
      // Global chips live on the server, not in the prefs. If the write is refused the
      // list has to go back, otherwise the bar keeps showing a chip nobody else has.
      api.saveGlobalChips(next).catch(() => setGlobalChips(before));
    } else {
      const next = personalChips.some((c) => c.id === chip.id)
        ? personalChips.map((c) => (c.id === chip.id ? chip : c))
        : [...personalChips, chip];
      setPersonalChips(next);
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
    setActiveChips((prev) => {
      const n = new Set(prev);
      n.delete(chip.id);
      return n;
    });
  }

  // ── Personalisation (columns / filters) ────────────────────────
  function toggleColumn(key: string) {
    setLayout((prev) => prev.map((it) => (it.key === key ? { ...it, visible: !it.visible } : it)));
  }
  function moveColumn(from: number, to: number) {
    if (from === to) return;
    setLayout((prev) => {
      const next = prev.slice();
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
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
  function resetLayout() {
    setLayout(defaultLayout());
    setFilterFields(ALL_FILTER_FIELDS);
    setChipView(mergeChipView(null, [...globalChips, ...personalChips]));
    setActiveChips(new Set());
  }

  // ── Query autocomplete ─────────────────────────────────────────
  function refreshSuggest(value: string, caret: number) {
    const s = suggest(value, caret, records);
    setSugg(s.items.length ? s : null);
    setSuggIdx(0);
  }
  function onQueryChange(e: React.ChangeEvent<HTMLInputElement>) {
    const value = e.target.value;
    setQuery(value);
    refreshSuggest(value, e.target.selectionStart ?? value.length);
  }
  function applySuggestion(s: Suggestion) {
    if (!sugg) return;
    const next = query.slice(0, sugg.start) + s.replace + query.slice(sugg.end);
    setQuery(next);
    const caret = sugg.start + s.replace.length;
    setSugg(null);
    requestAnimationFrame(() => {
      const el = queryRef.current;
      if (el) {
        el.focus();
        el.setSelectionRange(caret, caret);
        refreshSuggest(next, caret);
      }
    });
  }
  function onQueryKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!sugg || !sugg.items.length) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSuggIdx((i) => (i + 1) % sugg.items.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSuggIdx((i) => (i - 1 + sugg.items.length) % sugg.items.length);
    } else if (e.key === "Tab" || e.key === "Enter") {
      e.preventDefault();
      applySuggestion(sugg.items[suggIdx]);
    } else if (e.key === "Escape") {
      setSugg(null);
    }
  }

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
  const shownChips = useMemo(() => orderedChips.filter((c) => c.visible), [orderedChips]);
  const chipParsed = useMemo(() => {
    const m = new Map<string, ReturnType<typeof parseQuery>>();
    for (const c of allChips) m.set(c.id, parseQuery(c.query));
    return m;
  }, [allChips]);

  const parsedQuery = useMemo(() => parseQuery(query), [query]);
  // Base = what the query search shows. Chip counters AND chip filters always refer
  // to this ("to what you see"), not to the whole buffer.
  const queryFiltered = useMemo(
    () => records.filter((r) => matchRecord(r, parsedQuery, haystack(r))),
    [records, parsedQuery]
  );

  const chipCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const chip of shownChips) c[chip.id] = 0;
    for (const r of queryFiltered) {
      const hs = haystack(r);
      for (const chip of shownChips) {
        const p = chipParsed.get(chip.id);
        if (p && matchRecord(r, p, hs)) c[chip.id] += 1;
      }
    }
    return c;
  }, [queryFiltered, shownChips, chipParsed]);

  const activeParsed = useMemo(
    () =>
      [...activeChips]
        .map((id) => chipParsed.get(id))
        .filter((p): p is ReturnType<typeof parseQuery> => !!p),
    [activeChips, chipParsed]
  );
  const visible = useMemo(() => {
    if (activeParsed.length === 0) return queryFiltered;
    return queryFiltered.filter((r) => {
      const hs = haystack(r);
      return activeParsed.some((p) => matchRecord(r, p, hs));
    });
  }, [queryFiltered, activeParsed]);

  const visibleCols = useMemo(
    () => layout.filter((it) => it.visible).map((it) => COLUMN_BY_KEY[it.key]).filter(Boolean),
    [layout]
  );
  // Explicit table width = sum of the column widths. With table-layout:fixed the
  // browser sticks to those widths: long content (URLs, say) is cut off in the cell,
  // the columns stay static and the rest is reachable by horizontal scrolling.
  const tableWidth = useMemo(
    () => visibleCols.reduce((sum, c) => sum + colWidth(c.key, colWidths), 0),
    [visibleCols, colWidths]
  );
  // Render only the last `limit` rows (browser protection); the buffer stays larger.
  const shown = useMemo(() => visible.slice(0, limit), [visible, limit]);

  function exportCsv() {
    if (!visible.length) return;
    const cols = visibleCols;
    const header = cols.map((c) => t(c.labelKey));
    const rows = visible.map((r) => cols.map((c) => csvCell(c.key, r, t)));
    const csv = [header, ...rows].map((row) => row.map(csvEscape).join(";")).join("\r\n");
    const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `liveflow-${ts2name(Date.now())}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const serverActive = (stats?.filters?.length ?? 0) > 0;

  return (
    <div className="live">
      {/* ── Filter bar ─────────────────────────────────────────── */}
      <div className="panel toolbar">
        <div className="filter-builder">
          <select value={draftField} onChange={(e) => setDraftField(e.target.value as FilterField)}>
            {availableFilterFields.map((f) => (
              <option key={f} value={f}>
                {t(FIELD_LABEL_KEYS[f])}
              </option>
            ))}
          </select>
          <div className="input-wrap">
            <input
              className={draftError ? "invalid" : ""}
              placeholder={
                draftField === "user"
                  ? userDomain
                    ? t("live.ph.userWithDomain", { domain: userDomain })
                    : t("live.ph.userPlain")
                  : draftField === "location"
                    ? t("live.ph.location")
                    : t("live.ph.ip")
              }
              value={draftValue}
              onChange={(e) => setDraftValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addDraft()}
            />
            {draftError && <span className="field-error">{draftError.part ? `${draftError.part}: ` : ""}{t(draftError.key, draftError.params)}</span>}
          </div>
          <button className="ghost" onClick={addDraft} disabled={!draftValue.trim() || !!draftError}>
            {t("live.addFilter")}
          </button>
          {groups.length > 0 && (
            <select
              className="group-target"
              value={String(draftTarget)}
              onChange={(e) => {
                const v = e.target.value;
                setDraftTarget(v === "auto" || v === "new" ? v : Number(v));
              }}
              title={t("live.targetGroupTitle")}
            >
              <option value="auto">{t("live.targetAuto")}</option>
              <option value="new">{t("live.targetNew")}</option>
              {groups.map((_, i) => (
                <option key={i} value={i}>
                  {t("live.targetGroup", { n: i + 1 })}
                </option>
              ))}
            </select>
          )}
        </div>

        <div className="filter-area">
          <div className="filter-groups">
            {groups.length === 0 && <span className="muted">{t("live.noFilter")}</span>}
            {groups.map((g, gi) => (
              <Fragment key={gi}>
                {gi > 0 && (
                  <button
                    className={`op-toggle join op-${join}`}
                    onClick={toggleJoin}
                    title={t("live.toggleJoinTitle")}
                  >
                    {t(OP_KEYS[join])}
                  </button>
                )}
                <div
                  className={`filter-group${dropGroup === gi ? " drop-target" : ""}`}
                  onDragOver={(e) => {
                    if (!dragFilter || dragFilter.g === gi) return;
                    e.preventDefault();
                    setDropGroup(gi);
                  }}
                  onDragLeave={() => setDropGroup((d) => (d === gi ? null : d))}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (dragFilter) moveFilter(dragFilter, gi);
                    setDragFilter(null);
                    setDropGroup(null);
                  }}
                >
                  {g.items.map((f, i) => (
                    <Fragment key={`${f.field}-${f.value}`}>
                      {i > 0 && (
                        <button
                          className={`op-toggle op-${g.op}`}
                          onClick={() => toggleGroupOp(gi)}
                          title={t("live.toggleGroupOpTitle")}
                        >
                          {t(OP_KEYS[g.op])}
                        </button>
                      )}
                      <span
                        className="chip draggable"
                        draggable
                        onDragStart={() => setDragFilter({ g: gi, i })}
                        onDragEnd={() => {
                          setDragFilter(null);
                          setDropGroup(null);
                        }}
                        title={t("live.dragFilterTitle")}
                      >
                        <b>{t(FIELD_LABEL_KEYS[f.field])}</b> {f.value}
                        <button className="chip-x" onClick={() => removeFilter(gi, i)} title={t("live.removeTitle")}>
                          ×
                        </button>
                      </span>
                    </Fragment>
                  ))}
                </div>
              </Fragment>
            ))}
            {dragFilter && (groups.length > 1 || groups[0]?.items.length > 1) && (
              <div
                className={`filter-group new-group${dropGroup === "new" ? " drop-target" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDropGroup("new");
                }}
                onDragLeave={() => setDropGroup((d) => (d === "new" ? null : d))}
                onDrop={(e) => {
                  e.preventDefault();
                  moveFilter(dragFilter, "new");
                  setDragFilter(null);
                  setDropGroup(null);
                }}
              >
                {t("live.newGroupDrop")}
              </div>
            )}
          </div>
          {flatFilters(groups).length > 1 && (
            <span className="filter-hint muted small">
              {t("live.filterHintPre")} <b>{t("live.opAnd")}</b>/<b>{t("live.opOr")}</b> {t("live.filterHintPost")}
            </span>
          )}
        </div>

        <div className="toolbar-actions">
          <div className="feed-toggle" title={t("live.feedToggle.title")}>
            {ALL_FEEDS.map((f) => (
              <button
                key={f}
                className={`feed-btn ${feeds.includes(f) ? "on" : ""}`}
                onClick={() => toggleFeed(f)}
                aria-pressed={feeds.includes(f)}
                title={t("live.feedToggle.toggle", { feed: FEED_LABELS[f] })}
              >
                {FEED_LABELS[f]}
              </button>
            ))}
          </div>
          <div className="settings-anchor">
            <PresetMenu
              presets={usablePresets}
              canSave={groups.length > 0}
              onSave={savePreset}
              onLoad={loadPreset}
              onDelete={deletePreset}
            />
          </div>
          {groups.length > 0 && (
            <button className="ghost" onClick={clearFilters} title={t("live.clearFiltersTitle")}>
              ✕ Filter
            </button>
          )}
          <button className={paused ? "ghost active" : "ghost"} onClick={() => setPaused((p) => !p)}>
            {paused ? t("live.resume") : t("live.pause")}
          </button>
          <button className="ghost" onClick={() => setRecords([])}>
            {t("live.clearRows")}
          </button>
          <select
            className="row-limit"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            title={t("live.rowLimitTitle")}
          >
            {ROW_LIMITS.map((n) => (
              <option key={n} value={n}>
                {t("live.lastN", { n })}
              </option>
            ))}
          </select>
          <button
            className="ghost"
            onClick={exportCsv}
            disabled={visible.length === 0}
            title={t("live.csvTitle")}
          >
            ⭳ CSV
          </button>
          <div className="settings-anchor">
            <button className={showSettings ? "ghost active" : "ghost"} onClick={() => setShowSettings((s) => !s)}>
              {t("live.viewMenu")}
            </button>
            {showSettings && (
              <div className="settings-menu panel">
                <div className="settings-head">
                  <b>{t("live.customizeView")}</b>
                  <button className="chip-x" onClick={() => setShowSettings(false)}>
                    ×
                  </button>
                </div>

                <div className="settings-section">
                  <span className="settings-label">{t("live.filterFields")}</span>
                  {selectableFields.map((f) => (
                    <label key={f} className="check-row">
                      <input type="checkbox" checked={filterFields.includes(f)} onChange={() => toggleFilterField(f)} />
                      {t(FIELD_LABEL_KEYS[f])}
                    </label>
                  ))}
                </div>

                <div className="settings-section">
                  <div className="settings-label-row">
                    <span className="settings-label">{t("live.chipsSortable")}</span>
                    <button className="mini" onClick={() => openChipEditor()}>
                      {t("live.newShort")}
                    </button>
                  </div>
                  {orderedChips.length === 0 && <span className="muted small">{t("live.noChipsYet")}</span>}
                  {orderedChips.map((c, i) => {
                    const editable = c.scope === "personal" || canEditGlobal;
                    return (
                      <div
                        key={c.id}
                        className="col-item"
                        draggable
                        onDragStart={() => (chipDragIndex.current = i)}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={() => {
                          if (chipDragIndex.current !== null) moveChip(chipDragIndex.current, i);
                          chipDragIndex.current = null;
                        }}
                      >
                        <span className="drag-handle" title={t("live.dragTitle")}>⠿</span>
                        <label className="check-row grow">
                          <input type="checkbox" checked={c.visible} onChange={() => toggleChipVisible(c.id)} />
                          <span className="chip-dot" style={{ background: chipHex(c.color) }} />
                          <span className="chip-row-label" title={c.query}>{c.label}</span>
                          {c.scope === "global" && <span className="chip-lock" title={t("live.globalLockTitle")}>🔒</span>}
                        </label>
                        {editable && (
                          <span className="chip-row-actions">
                            <button className="mini" onClick={() => openChipEditor(c)} title={t("live.editTitle")}>✎</button>
                            <button className="chip-x" onClick={() => deleteChip(c)} title={t("live.deleteTitle")}>×</button>
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>

                <div className="settings-section">
                  <span className="settings-label">{t("live.columnsSortable")}</span>
                  {layout.map((it, i) => (
                    <div
                      key={it.key}
                      className="col-item"
                      draggable
                      onDragStart={() => (dragIndex.current = i)}
                      onDragOver={(e) => e.preventDefault()}
                      onDrop={() => {
                        if (dragIndex.current !== null) moveColumn(dragIndex.current, i);
                        dragIndex.current = null;
                      }}
                    >
                      <span className="drag-handle" title={t("live.dragTitle")}>⠿</span>
                      <label className="check-row">
                        <input type="checkbox" checked={it.visible} onChange={() => toggleColumn(it.key)} />
                        {t(COLUMN_BY_KEY[it.key].labelKey)}
                      </label>
                    </div>
                  ))}
                </div>

                <button className="ghost" style={{ width: "100%" }} onClick={resetLayout}>
                  {t("live.reset")}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {deniedFields.length > 0 && <div className="error-box">{t("live.err.filterDenied")}</div>}

      {/* ── Query search + chip quick filters ──────────────────── */}
      <div className="subbar">
        <div className="query-wrap">
          <input
            ref={queryRef}
            className="search"
            placeholder={t("live.ph.query")}
            value={query}
            onChange={onQueryChange}
            onKeyDown={onQueryKeyDown}
            onBlur={() => window.setTimeout(() => setSugg(null), 120)}
            spellCheck={false}
          />
          {sugg && sugg.items.length > 0 && (
            <div className="suggest">
              {sugg.items.map((s, i) => (
                <button
                  key={s.replace + i}
                  className={i === suggIdx ? "suggest-item active" : "suggest-item"}
                  onMouseDown={(e) => {
                    e.preventDefault();
                    applySuggestion(s);
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="verdict-toggles">
          {shownChips.map((c) => {
            const hex = chipHex(c.color);
            const active = activeChips.has(c.id);
            return (
              <button
                key={c.id}
                className={`vtoggle chip-btn ${active ? "active" : ""}`}
                style={{ color: hex, borderColor: active ? hex : undefined, background: active ? hex + "22" : undefined }}
                onClick={() => toggleChipActive(c.id)}
                title={`${c.query}${c.scope === "global" ? t("live.chipGlobalSuffix") : ""}`}
              >
                {c.scope === "global" && <span className="chip-lock">🔒</span>}
                {c.label} <b>{chipCounts[c.id] ?? 0}</b>
              </button>
            );
          })}
          {shownChips.length === 0 && (
            <span className="muted small">{t("live.noChipsVisible")}</span>
          )}
          {activeChips.size > 0 && (
            <button className="ghost small" onClick={() => setActiveChips(new Set())} title={t("live.resetChipsTitle")}>
              ✕ Chips
            </button>
          )}
        </div>
      </div>

      {/* ── Status line ────────────────────────────────────────── */}
      <div className="statusline muted">
        <span className={connected ? "live-dot on" : "live-dot off"} />
        {connected ? t("live.connected") : t("live.disconnected")} · <FeedBadge feed={stats?.feed} t={t} /> ·{" "}
        {t("live.retention", { n: retentionMinutes })} ·{" "}
        {/* One count, not five. "shown" used to be min(visible, limit) and "buffered"
            repeated records.length, so four of the old numbers restated each other.
            What is actually worth reading is how much of the held data survived the
            query and chip filters, plus a note when the row cap is hiding some of it. */}
        {t("live.shownOf", {
          shown: visible.length.toLocaleString(i18n.language),
          held: records.length.toLocaleString(i18n.language),
        })}
        {visible.length > limit && <> · {t("live.limitActive", { n: limit })}</>}
        {stats && stats.dropped_slow > 0 && (
          <span className="warn-text"> · {t("live.droppedSlow", { n: stats.dropped_slow })}</span>
        )}
      </div>

      {obfuscated && (
        <div className="note-box obf-hint">
          <b>{t("live.obf.title")}</b> {t("live.obf.lead")} <b>{t("live.obf.fields")}</b> {t("live.obf.mid")}
          <code>***</code>
          {t("live.obf.tail")} <b>{t("live.obf.hint")}</b>.
        </div>
      )}

      {!serverActive && (
        <div className="note-box stream-hint">
          <b>{t("live.streamHint.title")}</b>{" "}
          {t("live.streamHint.body", {
            fields: availableFilterFields.map((f) => t(FIELD_LABEL_KEYS[f])).join(", "),
          })}{" "}
          <code>*</code>/<code>?</code> {t("live.streamHint.cidr")} <code>10.20.30.0/24</code>{" "}
          {t("live.streamHint.or")} <code>/23</code>. {t("live.streamHint.groups")}
        </div>
      )}

      {/* ── Live table ─────────────────────────────────────────── */}
      <div className="table-wrap panel">
        <table className="flow-table fixed" style={{ width: tableWidth }}>
          <colgroup>
            {visibleCols.map((c) => (
              <col key={c.key} style={{ width: colWidth(c.key, colWidths) }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {visibleCols.map((c) => (
                <th key={c.key}>
                  <span className="th-label">{t(c.labelKey)}</span>
                  <span
                    className="col-resize"
                    onMouseDown={(e) => startResize(e, c.key)}
                    onClick={(e) => e.stopPropagation()}
                    title={t("live.resizeTitle")}
                  />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <Fragment key={r.id}>
                <tr
                  className={`sev-${r.severity} ${expanded === r.id ? "open" : ""}`}
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  {visibleCols.map((c) => (
                    <td key={c.key}>{c.render(r, t)}</td>
                  ))}
                </tr>
                {expanded === r.id && (
                  <tr className="detail-row">
                    <td colSpan={Math.max(1, visibleCols.length)}>
                      <div className="detail-grid">
                        <Detail k={t("live.detail.logTime")} v={logTime(r)} />
                        <Detail k={t("live.detail.receivedServer")} v={clock(r.received_at)} />
                        <Detail k={t("live.detail.user")} v={r.user} />
                        {r.location && <Detail k={t("live.detail.location")} v={r.location} />}
                        {r.dept && <Detail k={t("live.detail.dept")} v={r.dept} />}
                        <Detail k={t("live.detail.src")} v={`${r.src_ip}${port(r.src_port)}`} />
                        <Detail k={t("live.detail.dst")} v={`${r.dst_ip}${port(r.dst_port)}`} />
                        {r.server_ip && <Detail k={t("live.detail.serverNat")} v={`${r.server_ip}${port(r.server_port)}`} />}
                        {r.client_public_ip && <Detail k={t("live.detail.clientPublicIp")} v={r.client_public_ip} />}
                        <Detail k={t("live.detail.proto")} v={r.proto} />
                        <Detail k={t("live.detail.action")} v={r.action} />
                        <Detail k={t("live.detail.bytes")} v={`${r.bytes_tx} / ${r.bytes_rx}`} />
                        {r.http_method && <Detail k={t("live.detail.httpMethod")} v={r.http_method} />}
                        {r.http_status && <Detail k={t("live.detail.httpStatus")} v={r.http_status} />}
                        {r.category && <Detail k={t("live.detail.category")} v={r.category} />}
                        {r.url_class && <Detail k={t("live.detail.urlClass")} v={r.url_class} />}
                        {r.app_name && <Detail k={t("live.detail.app")} v={`${r.app_name}${r.app_class ? ` (${r.app_class})` : ""}`} />}
                        {r.nwservice && <Detail k={t("live.detail.nwservice")} v={r.nwservice} />}
                        {r.tls_version && <Detail k={t("live.detail.clientTls")} v={`${r.tls_version} ${r.tls_cipher}`} />}
                        {r.server_tls_version && <Detail k={t("live.detail.serverTls")} v={r.server_tls_version} />}
                        {r.threat_name && <Detail k={t("live.detail.threat")} v={`${r.threat_name} (${r.threat_category})`} />}
                        {r.risk_score != null && r.risk_score > 0 && <Detail k={t("live.detail.riskScore")} v={String(r.risk_score)} />}
                        {r.dest_country && <Detail k={t("live.detail.destCountry")} v={r.dest_country} />}
                        {r.tunnel_type && <Detail k={t("live.detail.tunnel")} v={r.tunnel_type} />}
                        {r.device_name && <Detail k={t("live.detail.device")} v={`${r.device_name}${r.device_owner ? ` / ${r.device_owner}` : ""}`} />}
                        {r.content_type && <Detail k={t("live.detail.contentType")} v={r.content_type} />}
                        {r.duration_ms != null && <Detail k={t("live.detail.duration")} v={`${r.duration_ms} ms`} />}
                        {r.num_sessions != null && <Detail k={t("live.detail.sessions")} v={String(r.num_sessions)} />}
                        {r.user_agent && <Detail k={t("live.detail.userAgent")} v={r.user_agent} wide />}
                        {r.reason && <Detail k={t("live.detail.reason")} v={r.reason} />}
                        {r.rule && <Detail k={t("live.detail.rule")} v={`${r.rule}${r.rule_type ? ` (${r.rule_type})` : ""}`} />}
                        {r.fwd_rule && <Detail k={t("live.detail.fwdRule")} v={r.fwd_rule} />}
                        {r.url_policy && <Detail k={t("live.detail.urlPolicy")} v={r.url_policy} />}
                        {r.gateway && <Detail k={t("live.detail.gateway")} v={r.gateway} />}
                        {r.ssl_inspected && <Detail k={t("live.detail.sslInspected")} v={r.ssl_inspected} />}
                        {r.ssl_policy && <Detail k={t("live.detail.sslPolicy")} v={r.ssl_policy} />}
                        {r.ssl_policy_reason && <Detail k={t("live.detail.sslReason")} v={r.ssl_policy_reason} />}
                        {r.flow_type && <Detail k={t("live.detail.flowType")} v={r.flow_type} />}
                        {r.logtype === "dns" && (
                          <>
                            <Detail k={t("live.detail.dnsQuery")} v={`${r.dns_req_type} ${r.dns_req_action}`.trim()} />
                            {r.dns_req_rule && <Detail k={t("live.detail.dnsReqRule")} v={r.dns_req_rule} />}
                            <Detail k={t("live.detail.dnsResponse")} v={`${r.dns_res_type} ${r.dns_response}`.trim()} />
                            {r.dns_res_action && <Detail k={t("live.detail.dnsResAction")} v={r.dns_res_action} />}
                            {r.dns_res_rule && <Detail k={t("live.detail.dnsResRule")} v={r.dns_res_rule} />}
                            {r.dns_error && <Detail k={t("live.detail.dnsError")} v={r.dns_error} />}
                            {r.dns_res_ip_cat && <Detail k={t("live.detail.dnsResIpCat")} v={r.dns_res_ip_cat} />}
                          </>
                        )}
                        {r.target && (
                          <Detail
                            k={t(r.logtype === "dns" ? "live.detail.targetDns" : "live.detail.target")}
                            v={r.target}
                            wide
                          />
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {shown.length === 0 && (
              <tr>
                <td colSpan={Math.max(1, visibleCols.length)} className="empty muted">
                  {records.length === 0
                    ? serverActive
                      ? t("live.waiting")
                      : t("live.noFilterActive")
                    : t("live.noMatches")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {editing && (
        <ChipEditor initial={editing} canGlobal={canEditGlobal} onSave={saveChip} onClose={() => setEditing(null)} />
      )}
    </div>
  );
}

function ChipEditor({
  initial,
  canGlobal,
  onSave,
  onClose,
}: {
  initial: { id: string | null; scope: ChipScope; label: string; query: string; color: ChipColor };
  canGlobal: boolean;
  onSave: (chip: QueryChip, scope: ChipScope) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [label, setLabel] = useState(initial.label);
  const [query, setQuery] = useState(initial.query);
  const [color, setColor] = useState<ChipColor>(initial.color);
  const [scope, setScope] = useState<ChipScope>(initial.scope);
  const isEdit = initial.id !== null;

  function save() {
    const l = label.trim();
    const q = query.trim();
    if (!l || !q) return;
    onSave({ id: initial.id ?? genChipId(scope), label: l, query: q, color }, scope);
  }

  return (
    <div className="chip-editor-overlay" onClick={onClose}>
      <div className="chip-editor panel" onClick={(e) => e.stopPropagation()}>
        <div className="settings-head">
          <b>{isEdit ? t("live.chipEdit") : t("live.chipNew")}</b>
          <button className="chip-x" onClick={onClose}>×</button>
        </div>
        <label className="editor-field">
          <span>{t("live.chipLabel")}</span>
          <input value={label} maxLength={40} placeholder={t("live.chipLabelPh")} onChange={(e) => setLabel(e.target.value)} />
        </label>
        <label className="editor-field">
          <span>{t("live.chipQuery")}</span>
          <input
            className="mono"
            value={query}
            maxLength={200}
            placeholder={t("live.chipQueryPh")}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
          />
        </label>
        <div className="editor-field">
          <span>{t("live.chipColor")}</span>
          <div className="color-picker">
            {CHIP_COLORS.map((c) => {
              const hex = chipHex(c.key);
              return (
                <button
                  key={c.key}
                  type="button"
                  className={`swatch ${chipHex(color).toLowerCase() === hex.toLowerCase() ? "active" : ""}`}
                  style={{ background: hex }}
                  title={t(c.labelKey)}
                  onClick={() => setColor(hex)}
                />
              );
            })}
            <input
              type="color"
              className="color-free"
              value={chipHex(color)}
              onChange={(e) => setColor(e.target.value)}
              title={t("live.freeColorTitle")}
            />
          </div>
        </div>
        {canGlobal && !isEdit && (
          <label className="check-row">
            <input type="checkbox" checked={scope === "global"} onChange={(e) => setScope(e.target.checked ? "global" : "personal")} />
            {t("live.chipGlobalAll")}
          </label>
        )}
        {isEdit && initial.scope === "global" && <div className="muted small">{t("live.chipGlobalNote")}</div>}
        <div className="editor-actions">
          <button className="ghost" onClick={onClose}>{t("common.cancel")}</button>
          <button className="primary" onClick={save} disabled={!label.trim() || !query.trim()}>
            {t("common.save")}
          </button>
        </div>
        <div className="editor-hint muted">
          {t("live.syntaxPre")} <code>Feld=Wert</code>{t("live.syntaxMid")} <code>*</code>/<code>?</code>,{" "}
          <code>!=</code>{t("live.syntaxPost")} <code>bewertung=blocked</code>, <code>status=404</code>,{" "}
          <code>Typ=Web*</code>, <code>land=CN</code>.
        </div>
      </div>
    </div>
  );
}

function PresetMenu({
  presets,
  canSave,
  onSave,
  onLoad,
  onDelete,
}: {
  presets: FilterPreset[];
  canSave: boolean;
  onSave: () => void;
  onLoad: (p: FilterPreset) => void;
  onDelete: (name: string) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className={open ? "ghost active" : "ghost"} onClick={() => setOpen((o) => !o)}>
        {t("live.presets")}
        {presets.length ? ` (${presets.length})` : ""}
      </button>
      {open && (
        <div className="settings-menu panel">
          <div className="settings-head">
            <b>{t("live.filterPresets")}</b>
            <button className="chip-x" onClick={() => setOpen(false)}>
              ×
            </button>
          </div>
          <button className="ghost" style={{ width: "100%" }} disabled={!canSave} onClick={onSave}>
            {t("live.saveCurrentFilter")}
          </button>
          <div className="settings-section">
            {presets.length === 0 && <span className="muted">{t("live.noPresets")}</span>}
            {presets.map((p) => (
              <div className="preset-row" key={p.name}>
                <button
                  className="preset-load"
                  title={presetGroups(p)
                    .map((g) => `(${g.items.map((f) => `${f.field}=${f.value}`).join(` ${t(OP_KEYS[g.op])} `)})`)
                    .join(` ${t(OP_KEYS[p.join === "or" ? "or" : "and"])} `)}
                  onClick={() => {
                    onLoad(p);
                    setOpen(false);
                  }}
                >
                  {p.name} <span className="muted">({p.filters.length})</span>
                </button>
                <button className="chip-x" onClick={() => onDelete(p.name)} title={t("live.deleteTitle")}>
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

// The feed state as a dot of its own, next to the connection state.
//
// Three cases, deliberately kept apart: no data ever seen (the feed was never
// hooked up), running, and silent for X (the connection stands but is dead).
// The third one used to be invisible: an empty table looked like "no matches".
function FeedBadge({ feed, t }: { feed?: FeedState; t: TFunction }) {
  if (!feed) return <span className="feed-badge muted">{t("live.feed.unknown")}</span>;
  if (!feed.ever) {
    return (
      <span className="feed-badge warn-text" title={t("live.feed.noDataTitle")}>
        <span className="live-dot off" /> {t("live.feed.noData")}
      </span>
    );
  }
  if (feed.stale) {
    return (
      <span className="feed-badge warn-text" title={t("live.feed.staleTitle")}>
        <span className="live-dot off" /> {t("live.feed.stale", { idle: fmtIdle(feed.idle_seconds, t) })}
      </span>
    );
  }
  return (
    <span className="feed-badge" title={t("live.feed.runningTitle", { idle: fmtIdle(feed.idle_seconds, t) })}>
      <span className="live-dot on" /> {t("live.feed.running")}
    </span>
  );
}

function fmtIdle(seconds: number, t: TFunction): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return t("live.feed.idleSeconds", { n: s });
  if (s < 3600) return t("live.feed.idleMinutes", { n: Math.floor(s / 60) });
  return t("live.feed.idleHours", { h: Math.floor(s / 3600), m: Math.floor((s % 3600) / 60) });
}

function Detail({ k, v, wide }: { k: string; v: string; wide?: boolean }) {
  return (
    <div className={wide ? "detail wide" : "detail"}>
      <span className="dk">{k}</span>
      <span className="dv mono">{v || "—"}</span>
    </div>
  );
}
