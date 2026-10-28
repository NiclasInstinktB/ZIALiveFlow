// Account source: "local" = local account (password held by the app), "ad" = signed in via AD/LDAP.
export type AccountSource = "local" | "ad";
// Permission catalogue entry (key plus display name) for the UI checkboxes.
export interface PermissionCatalogItem {
  key: string;
  label: string;
}

export interface Me {
  username: string;
  display_name: string;
  is_admin: boolean;
  source: AccountSource;
  // The user's effective permissions plus the full catalogue (drives tabs and checkboxes).
  permissions: string[];
  permission_catalog: PermissionCatalogItem[];
  idle_timeout_minutes: number;
  session_ttl_minutes: number;
  retention_minutes: number;
  version: string;
  // Instance defaults from the admin backend.
  // Name shown in the header and the browser tab.
  app_name: string;
  // Language for visitors who have not picked one themselves.
  default_language: string;
  // Link to the source, shown in the footer. The AGPL expects people who use the app
  // over a network to be able to reach it.
  source_url: string;
  // Appended to a user filter containing no "@". Empty appends nothing.
  user_domain_suffix: string;
}

export type FilterField = "src_ip" | "dst_ip" | "user" | "location";

export interface FilterSpec {
  field: FilterField;
  value: string;
}

// AND/OR on two levels: inside a group its `op` joins the items, between the groups the
// `join` does. That makes both readings expressible:
//   (source A OR source B) AND destination C
//   source A OR (source B AND destination C)
// and the user never has to type parentheses or learn a precedence rule.
export type FilterOp = "and" | "or";

export interface FilterGroup {
  op: FilterOp;
  items: FilterSpec[];
}

// The NSS feeds (column 0 of every line). Selectable per view: the server only
// sends what is ticked, so a noisy feed can be switched off for this view alone.
export type FeedType = "web" | "fw" | "dns";
export const ALL_FEEDS: FeedType[] = ["web", "fw", "dns"];

export interface StreamStats {
  filters: FilterSpec[];
  groups?: FilterGroup[];
  join?: FilterOp;
  feeds?: FeedType[];
  buffered: number;
  matched: number;
  dropped_slow: number;
  // Is the NSS feed alive? Kept apart from the WebSocket connection: that one can
  // be up while no line has arrived for hours. Optional, because a server from
  // before this field simply does not send it.
  feed?: FeedState;
}

export interface FeedState {
  // Has a single line been seen since the process started?
  ever: boolean;
  // Seconds since the last line, 0 when none ever arrived.
  idle_seconds: number;
  // Lines arrived earlier, but the newest is older than the configured threshold.
  stale: boolean;
}

export type Verdict =
  | "allowed"
  | "blocked"
  | "no_response"
  | "ssl_failed"
  | "http_error"
  | "dns_error"
  | "unknown";

export interface FlowRecord {
  id: number;
  received_at: number;
  logtype: FeedType;
  ts: string;
  // ts resolved to epoch seconds (the backend knows the feed's time zone). null = not parseable.
  ts_epoch: number | null;
  user: string;
  location: string;
  dept: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  server_ip: string;
  server_port: number | null;
  client_public_ip: string;
  proto: string;
  action: string;
  target: string;
  host: string;
  reason: string;
  rule: string;
  rule_type: string;
  bytes_tx: number;
  bytes_rx: number;
  http_method: string;
  http_status: string;
  category: string;
  url_class: string;
  app_name: string;
  app_class: string;
  nwservice: string;
  tls_version: string;
  tls_cipher: string;
  server_tls_version: string;
  threat_name: string;
  threat_category: string;
  risk_score: number | null;
  user_agent: string;
  device_name: string;
  device_owner: string;
  content_type: string;
  dest_country: string;
  tunnel_type: string;
  dnat: string;
  num_sessions: number | null;
  duration_ms: number | null;
  ssl_inspected: string;
  ssl_policy: string;
  ssl_policy_reason: string;
  url_policy: string;
  fwd_rule: string;
  gateway: string;
  flow_type: string;
  dns_req_type: string;
  dns_req_action: string;
  dns_req_rule: string;
  dns_response: string;
  dns_res_type: string;
  dns_res_action: string;
  dns_res_rule: string;
  dns_error: string;
  dns_res_ip_cat: string;
  verdict: Verdict;
  severity: "good" | "warn" | "bad" | "info";
}

export interface AdminUser {
  username: string;
  display_name: string;
  // Effective permissions (read-only): they come from group membership and nothing else.
  permissions: string[];
  is_admin: boolean;
  source: AccountSource;
  enabled: boolean;
  created_at: string;
  last_login?: string;
  // Names of the groups the account is a DIRECT member of (local or ad_user).
  groups: string[];
}

// ── Admin backend: status and diagnostics ──────────────────────────
export interface FeedColumn {
  name: string;
  index: number;
  fill_pct: number | null;
}
export interface FeedHealth {
  feed: string;
  lines: number;
  expected_cols: number;
  last_field_count: number;
  field_count_min: number;
  field_count_max: number;
  short_lines: number;
  sampled: number;
  last_seen: number;
  columns: FeedColumn[];
}
export interface AdminStatus {
  version: string;
  app_env: string;
  is_production: boolean;
  started_at: number;
  uptime_seconds: number;
  now: number;
  ingest: {
    enabled: boolean;
    bind_host: string;
    web_port: number;
    fw_port: number;
    dns_port: number;
    web_listening: boolean;
    fw_listening: boolean;
    dns_listening: boolean;
  };
  throughput: { total_lines: number; other_lines: number; active_views: number; buffered: number };
  feeds: FeedHealth[];
  retention_minutes: number;
  buffer_max_records: number;
  session: { idle_minutes: number; ttl_minutes: number; cookie_secure: boolean; cookie_samesite: string };
  accounts?: { total: number; admins: number; viewers: number; enabled: number; disabled: number };
  security?: { jwt_secret_is_default: boolean };
}

// ── Admin backend: settings ────────────────────────────────────────
// The form is generated from what the backend sends, not from a list kept here.
// backend/settings_store.py SPECS is the single definition of what exists and what is
// valid; duplicating it in the frontend would guarantee the two drift apart.
export type SettingValue = string | number | boolean;

// "live" applies at once, "restart" is stored now but needs a restart to take effect.
export type SettingTier = "live" | "restart";

export interface SettingSpec {
  kind: "int" | "text" | "bool" | "choice";
  tier: SettingTier;
  hint: string;
  min?: number;
  max?: number;
  max_length?: number;
  choices?: string[];
}

export interface AppSettings {
  editable: Record<string, SettingValue>;
  catalogue: Record<string, SettingSpec>;
  restart_required: string[];
  // Settings just saved that will only take effect after a restart.
  restart_pending: string[];
  read_only: Record<string, string | number | boolean>;
}

// ── AD/LDAP configuration (admin backend) ──────────────────────────
// Connection and service account only. The bind password is write-only: the backend
// returns just ldap_bind_password_set, never the value. On save, leaving the field out
// keeps it and "" clears it. The mapping from AD group to permissions (AdGroup) now
// lives under "Accounts".
export interface LdapConfig {
  ldap_server: string;
  ldap_port: number;
  ldap_use_ssl: boolean;
  ldap_domain: string;
  ldap_base_dn: string;
  ldap_bind_user: string;
  ldap_bind_password_set: boolean;
  ldap_group_attr: string;
  ldap_connect_timeout_seconds: number;
  configured: boolean;
}

// A group is a local container: name, permissions, members. Members are local accounts,
// AD users (sAMAccountName) or AD groups (CN). A person's effective permissions are the
// union of the permissions of every group they belong to, either directly or through an
// AD group. There are NO permissions attached to an account itself.
export type MemberType = "local" | "ad_user" | "ad_group";
export interface GroupMember {
  type: MemberType;
  ref: string;
}
export interface Group {
  name: string;
  permissions: string[];
  // Full access as a flag rather than a stored list, so future permissions are picked up
  // automatically. A frozen list goes stale as soon as a new version adds a permission:
  // the full administrator would silently become a partial one, and could not even grant
  // themselves the new permission, because the escalation guard blocks that.
  all_permissions?: boolean;
  members: GroupMember[];
  created_at?: string;
}

// AD sign-in without an account: the record is only a trace (a stable UUID plus the last
// sign-in). Directory users get NO account; their permissions are recomputed from their
// AD groups on every sign-in.
export interface AdIdentity {
  id: string;
  username: string;
  display_name: string;
  first_login?: string;
  last_login?: string;
  groups: string[];
}

// A hit from the AD directory search (member picker).
export interface DirectoryEntry {
  type: "ad_user" | "ad_group";
  ref: string;
  display: string;
}
// Search result, including an unambiguous reason when nothing came back.
export type DirectoryStatus =
  | "ok"
  | "too_short"
  | "no_service_account"
  | "package_missing"
  | "bind_failed"
  | "search_failed";
export interface DirectoryResult {
  status: DirectoryStatus;
  detail: string;
  entries: DirectoryEntry[];
}

// ── SSO / OpenID Connect (admin backend) ───────────────────────────
// The client secret is write-only: the backend returns just oidc_client_secret_set, never
// the value. On save, leaving the field out keeps it and "" clears it.
export interface OidcConfig {
  oidc_enabled: boolean;
  oidc_issuer: string;
  oidc_client_id: string;
  oidc_client_secret_set: boolean;
  oidc_redirect_url: string;
  oidc_scopes: string;
  configured: boolean;
}

// ── Personalisation (prefs) ────────────────────────────────────────
// `filters` stays the flat list (older presets and the counter); `groups` and `join` carry
// the AND/OR structure. Presets without `groups` predate the grouping feature and are read
// as ONE OR group when loaded.
export interface FilterPreset {
  name: string;
  filters: FilterSpec[];
  groups?: FilterGroup[];
  join?: FilterOp;
}

// ── Query chips (quick filters on the live flow) ───────────────────
// Each chip is a stored query in the mini query language. Global chips are managed by the
// admin (locked); personal ones live in the account prefs.
// Chip colour: either a preset name (good/bad/warn/info, kept for backward compatibility)
// or a free hex value such as "#8b5cf6". chipHex() in LiveView resolves both.
export type ChipColor = string;
export interface QueryChip {
  id: string;
  label: string;
  query: string;
  color: ChipColor;
}

// ── Audit log (sign-ins and searches) ──────────────────────────────
export interface AuditEntry {
  ts: number;
  event: string;
  user: string;
  ip: string;
  detail: string;
}
export interface AuditResponse {
  entries: AuditEntry[];
  stats: { files: number; entries: number; retention_days: number; enabled: boolean };
}

// ── Error log (in-memory ring buffer of the running process) ───────
export interface LogEntry {
  id: number;
  ts: string;
  level: string;
  logger: string;
  event: string;
  // The structured extra fields of the log line (secrets are replaced with *** on the
  // server side).
  fields: Record<string, unknown>;
}

export interface LogResponse {
  entries: LogEntry[];
  counts: { total: number; errors: number; warnings: number; capacity: number };
  level: string;
}

// ── Self-update (Git) ──────────────────────────────────────────────
export interface UpdateStatus {
  is_repo: boolean;
  branch?: string;
  commit?: string;
  commit_short?: string;
  subject?: string;
  committed_at?: string;
  remote?: string;
  dirty?: boolean;
  update_branch: string;
}
export interface UpdateCheck {
  is_repo: boolean;
  ok?: boolean;
  error?: string;
  branch?: string;
  behind?: number;
  ahead?: number;
  update_available?: boolean;
  remote_latest?: string;
}
