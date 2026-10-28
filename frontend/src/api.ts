import type { AdIdentity, AdminStatus, AdminUser, AppSettings, AuditResponse, DirectoryResult, FlowRecord, Group, LdapConfig, LogResponse, Me, MemberType, OidcConfig, QueryChip, UpdateCheck, UpdateStatus } from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Wird bei unerwartetem 401 aufgerufen (Session abgelaufen) → Auto-Logout im AuthProvider.
let unauthorizedHandler: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null) {
  unauthorizedHandler = fn;
}

/** Report a dead session that was NOT discovered through an HTTP 401.
 *
 * The live stream is the case: someone watching it makes no requests at all, so the
 * session can expire without anything noticing. The WebSocket close tells us, and this
 * is how that gets into the same sign-out path instead of firing a throwaway request
 * just to collect a 401. */
export function notifyUnauthorized() {
  unauthorizedHandler?.();
}
const SILENT_401 = ["/api/auth/me", "/api/auth/login"];

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = body.detail || detail;
    } catch {
      /* ignore */
    }
    if (resp.status === 401 && unauthorizedHandler && !SILENT_401.some((p) => path.startsWith(p))) {
      unauthorizedHandler();
    }
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export const api = {
  // Public, so the login page can read branding and whether SSO is offered before
  // anyone has signed in.
  health: () =>
    request<{
      status: string;
      version: string;
      retention_minutes: number;
      ingest_enabled?: boolean;
      sso_enabled?: boolean;
      app_name?: string;
      default_language?: string;
      source_url?: string;
    }>("/api/health"),

  me: () => request<Me>("/api/auth/me"),
  login: (username: string, password: string) =>
    request<Me>("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  logout: () => request<{ status: string }>("/api/auth/logout", { method: "POST" }),
  changePassword: (current_password: string, new_password: string) =>
    request<{ status: string }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),

  // Personal UI settings (columns, chips, filter presets), stored per account.
  getPrefs: () => request<Record<string, unknown>>("/api/prefs"),
  savePrefs: (prefs: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/prefs", { method: "PUT", body: JSON.stringify({ prefs }) }),

  // Query chips: the global ones (admin managed). Personal chips live in the prefs.
  getChips: () => request<{ global: QueryChip[]; can_edit_global: boolean }>("/api/chips"),
  saveGlobalChips: (chips: QueryChip[]) =>
    request<{ chips: QueryChip[] }>("/api/chips/global", { method: "PUT", body: JSON.stringify({ chips }) }),

  // Sampled example records from the last few thousand, used for field value
  // suggestions and the chip preview.
  samples: (limit = 2000) => request<{ records: FlowRecord[] }>(`/api/stream/samples?limit=${limit}`),

  // Account management (permission "accounts"): accounts (which carry no permissions of
  // + Mitglieder) + AD-Verzeichnis-Suche fuer den Mitglieder-Picker.
  admins: {
    list: () => request<AdminUser[]>("/api/admins"),
    create: (username: string, password: string, display_name = "") =>
      request<AdminUser>("/api/admins", {
        method: "POST",
        body: JSON.stringify({ username, password, display_name }),
      }),
    update: (
      username: string,
      body: { password?: string; display_name?: string; enabled?: boolean },
    ) => request<AdminUser>(`/api/admins/${encodeURIComponent(username)}`, { method: "PUT", body: JSON.stringify(body) }),
    remove: (username: string) =>
      request<{ status: string }>(`/api/admins/${encodeURIComponent(username)}`, { method: "DELETE" }),

    // Groups: permissions plus members (local accounts, AD users, AD groups).
    groups: {
      list: () => request<Group[]>("/api/admins/groups"),
      create: (name: string, permissions: string[] = [], all_permissions = false) =>
        request<Group>("/api/admins/groups", {
          method: "POST",
          body: JSON.stringify({ name, permissions, all_permissions }),
        }),
      // Nur mitgeschickte Felder werden geaendert: { permissions } = Rechte, { name } = umbenennen.
      update: (name: string, changes: { permissions?: string[]; name?: string; all_permissions?: boolean }) =>
        request<Group>(`/api/admins/groups/${encodeURIComponent(name)}`, {
          method: "PUT",
          body: JSON.stringify(changes),
        }),
      rename: (name: string, newName: string) =>
        request<Group>(`/api/admins/groups/${encodeURIComponent(name)}`, {
          method: "PUT",
          body: JSON.stringify({ name: newName }),
        }),
      remove: (name: string) =>
        request<{ status: string }>(`/api/admins/groups/${encodeURIComponent(name)}`, { method: "DELETE" }),
      addMember: (name: string, type: MemberType, ref: string) =>
        request<Group>(`/api/admins/groups/${encodeURIComponent(name)}/members`, {
          method: "POST",
          body: JSON.stringify({ type, ref }),
        }),
      removeMember: (name: string, type: MemberType, ref: string) =>
        request<Group>(
          `/api/admins/groups/${encodeURIComponent(name)}/members?type=${encodeURIComponent(type)}&ref=${encodeURIComponent(ref)}`,
          { method: "DELETE" },
        ),
    },

    // Directory sign-ins that have no account: informational only, so UUID, display
    // name and last sign-in.
    identities: {
      list: () => request<AdIdentity[]>("/api/admins/identities"),
      forget: (username: string) =>
        request<{ status: string }>(`/api/admins/identities/${encodeURIComponent(username)}`, {
          method: "DELETE",
        }),
    },

    // AD/GC-Suche fuer den Mitglieder-Picker (braucht LDAP-Service-Account).
    // q darf Platzhalter enthalten ("*Connect*"); ohne "*" wird als Teilstring gesucht.
    directory: (q: string, kind: "user" | "group", limit = 200) =>
      request<DirectoryResult>(
        `/api/admins/directory?q=${encodeURIComponent(q)}&kind=${kind}&limit=${limit}`,
      ),
  },

  // Admin-Backend: Status/Diagnose + Einstellungen + Update (nur Admins)
  admin: {
    status: () => request<AdminStatus>("/api/admin/status"),
    getSettings: () => request<AppSettings>("/api/admin/settings"),
    // Send only the settings that changed. Values are validated in the backend
    // against settings_store.SPECS, so the shape is deliberately open here.
    saveSettings: (changes: Record<string, string | number | boolean>) =>
      request<AppSettings>("/api/admin/settings", { method: "PUT", body: JSON.stringify(changes) }),
    // AD/LDAP-Konfiguration (im Admin-Backend pflegbar). Bind-Passwort ist write-only.
    getLdap: () => request<LdapConfig>("/api/admin/ldap"),
    saveLdap: (changes: Record<string, unknown>) =>
      request<LdapConfig>("/api/admin/ldap", { method: "PUT", body: JSON.stringify(changes) }),
    testLdap: () => request<{ ok: boolean; detail: string }>("/api/admin/ldap/test", { method: "POST" }),
    // SSO / OpenID Connect (im Admin-Backend pflegbar). Client-Secret ist write-only.
    getOidc: () => request<OidcConfig>("/api/admin/oidc"),
    saveOidc: (changes: Record<string, unknown>) =>
      request<OidcConfig>("/api/admin/oidc", { method: "PUT", body: JSON.stringify(changes) }),
    testOidc: () => request<{ ok: boolean; detail: string }>("/api/admin/oidc/test", { method: "POST" }),
    updateStatus: () => request<UpdateStatus>("/api/admin/update"),
    updateCheck: () => request<UpdateCheck>("/api/admin/update/check", { method: "POST" }),
    updateRun: () => request<{ triggered: boolean; branch?: string }>("/api/admin/update/run", { method: "POST" }),
    audit: (params: { limit?: number; event?: string; user?: string; days?: number } = {}) => {
      const q = new URLSearchParams();
      if (params.limit) q.set("limit", String(params.limit));
      if (params.event) q.set("event", params.event);
      if (params.user) q.set("user", params.user);
      if (params.days) q.set("days", String(params.days));
      const qs = q.toString();
      return request<AuditResponse>(`/api/admin/audit${qs ? `?${qs}` : ""}`);
    },
    // Warnungen und Fehler des laufenden Prozesses (RAM-Ringpuffer). Der Grund
    // the reason for a failure was only ever visible in the service journal.
    logs: (params: { limit?: number; level?: string } = {}) => {
      const q = new URLSearchParams();
      if (params.limit) q.set("limit", String(params.limit));
      if (params.level) q.set("level", params.level);
      const qs = q.toString();
      return request<LogResponse>(`/api/admin/logs${qs ? `?${qs}` : ""}`);
    },
    clearLogs: () => request<{ removed: number }>("/api/admin/logs", { method: "DELETE" }),
  },
};
