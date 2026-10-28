import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api, ApiError } from "../api";
import type {
  AdIdentity, AdminUser, DirectoryEntry, DirectoryStatus, Group, GroupMember, Me, MemberType,
} from "../types";

// Central account management. Rights come EXCLUSIVELY from groups:
//  • Accounts only exist locally (break glass), without their own rights checkboxes,
//    only create/disable/delete. AD users get NO account: they are granted once as a
//    group member, and at sign-in their AD groups decide. Whoever has already signed
//    in is listed in the collapsible "AD sign-ins" section (information plus UUID).
//  • One group = rights (checkboxes) + members (local accounts · AD users · AD groups).
//    Members inherit the rights of the group. AD members are picked through a
//    directory search (service account), local ones from the account list.

const MEMBER_LABEL_KEY: Record<MemberType, string> = {
  local: "users.memberLocal",
  ad_user: "users.memberAdUser",
  ad_group: "users.memberAdGroup",
};
// The chip row is enough up to this many hits; above it the hit window opens
// (its own list with a filter), so long AD results do not blow up the card.
const INLINE_HITS = 8;
// Input without a wildcard: "*" on its own would pull the whole AD (the backend rejects it).
const queryLen = (q: string) => q.replace(/\*/g, "").trim().length;

// Every outcome of the AD search gets exactly ONE clear message (no "either … or").
function searchMessage(
  status: DirectoryStatus,
  detail: string,
  query: string,
  kind: string,
  t: TFunction
): string {
  switch (status) {
    case "ok":
      return t("users.search.noHits", { kind, query });
    case "too_short":
      return detail || t("users.search.tooShort");
    case "no_service_account":
      return t("users.search.noServiceAccount");
    case "package_missing":
      return t("users.search.packageMissing");
    case "bind_failed":
      return t("users.search.bindFailed", { detail });
    case "search_failed":
      return t("users.search.searchFailed", { detail });
  }
}
const toggle = (list: string[], key: string, on: boolean) =>
  on ? [...new Set([...list, key])] : list.filter((p) => p !== key);
const errText = (e: unknown, fallback: string) => (e instanceof ApiError ? e.message : fallback);

export function AdminUsers({ me }: { me: Me }) {
  const { t } = useTranslation();
  const catalog = me.permission_catalog;
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [identities, setIdentities] = useState<AdIdentity[]>([]);
  const [showIdentities, setShowIdentities] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  // New local account / new group.
  const [nu, setNu] = useState("");
  const [nd, setNd] = useState("");
  const [np, setNp] = useState("");
  const [ng, setNg] = useState("");

  async function load() {
    try {
      const [u, g, i] = await Promise.all([
        api.admins.list(),
        api.admins.groups.list(),
        api.admins.identities.list(),
      ]);
      setUsers(u);
      setGroups(g);
      setIdentities(i);
    } catch (e) {
      setErr(errText(e, t("users.loadFailed")));
    }
  }
  useEffect(() => {
    load();
  }, []);

  const isSelf = (u: AdminUser) => u.username.toLowerCase() === me.username.toLowerCase();

  async function act(fn: () => Promise<unknown>, okMsg = "") {
    setErr("");
    setMsg("");
    try {
      await fn();
      await load();
      if (okMsg) setMsg(okMsg);
    } catch (e) {
      setErr(errText(e, t("common.actionFailed")));
      await load();
    }
  }

  async function createAccount(e: React.FormEvent) {
    e.preventDefault();
    await act(async () => {
      await api.admins.create(nu.trim(), np, nd.trim());
      setNu("");
      setNd("");
      setNp("");
    }, t("users.accountCreated"));
  }

  async function createGroup(e: React.FormEvent) {
    e.preventDefault();
    const name = ng.trim();
    if (!name) return;
    await act(async () => {
      await api.admins.groups.create(name, []);
      setNg("");
    }, t("users.groupCreated"));
  }

  const localAccounts = users.filter((u) => u.source === "local").map((u) => u.username);

  return (
    <div className="admin-grid">
      {/* ── Accounts ── */}
      <section className="panel wide">
        <h2>{t("nav.accounts")}</h2>
        {err && <div className="error-box">{err}</div>}
        {msg && <div className="note-box">{msg}</div>}
        <p className="muted" style={{ marginTop: 0 }}>
          {t("users.accountsHint")}
        </p>

        <div style={{ overflowX: "auto" }}>
          <table className="user-table">
            <thead>
              <tr>
                <th>{t("users.colUser")}</th>
                <th>{t("users.colGroups")}</th>
                <th>{t("users.colStatus")}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.username}>
                  <td>
                    {u.username}
                    {isSelf(u) && <span className="badge"> {t("users.badgeYou")}</span>}
                    {u.is_admin && <span className="badge"> {t("users.badgeAdmin")}</span>}
                    <div className="muted" style={{ fontSize: 12 }}>{u.display_name}</div>
                  </td>
                  <td>
                    {u.groups.length === 0 ? (
                      <span className="muted" style={{ fontSize: 12 }}>{t("users.noGroups")}</span>
                    ) : (
                      <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                        {u.groups.map((g) => (
                          <span key={g} className="perm-chip" style={{ fontSize: 12 }}>{g}</span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td>
                    {u.enabled ? (
                      <span className="ok">{t("users.active")}</span>
                    ) : (
                      <span className="off">{t("users.disabled")}</span>
                    )}
                  </td>
                  <td className="row-actions">
                    <button className="ghost" onClick={() => act(() => api.admins.update(u.username, { enabled: !u.enabled }))}>
                      {u.enabled ? t("common.disable") : t("common.enable")}
                    </button>
                    {!isSelf(u) && (
                      <button
                        className="danger"
                        onClick={() => {
                          if (confirm(t("users.deleteAccountConfirm", { name: u.username })))
                            act(() => api.admins.remove(u.username));
                        }}
                      >
                        {t("common.delete")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* AD sign-ins: NOT accounts, just a trace with a stable UUID. Collapsed by
            default so the account list stays lean. */}
        <div style={{ marginTop: 12 }}>
          <button type="button" className="ghost" onClick={() => setShowIdentities((v) => !v)}>
            {showIdentities ? "▾" : "▸"} {t("users.adLogins", { n: identities.length })}
          </button>
          {showIdentities && (
            <div style={{ marginTop: 8, overflowX: "auto" }}>
              <p className="muted" style={{ fontSize: 12, marginTop: 0 }}>
                {t("users.adLoginsHint")}
              </p>
              {identities.length === 0 ? (
                <span className="muted" style={{ fontSize: 12 }}>{t("users.noAdLogins")}</span>
              ) : (
                <table className="user-table">
                  <thead>
                    <tr>
                      <th>{t("users.colUser")}</th>
                      <th>{t("users.colGroupsDirect")}</th>
                      <th>{t("users.colLastLogin")}</th>
                      <th>{t("users.colId")}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {identities.map((i) => (
                      <tr key={i.id}>
                        <td>
                          {i.username} <span className="badge">AD</span>
                          <div className="muted" style={{ fontSize: 12 }}>{i.display_name}</div>
                        </td>
                        <td>
                          {i.groups.length === 0 ? (
                            <span className="muted" style={{ fontSize: 12 }}>{t("users.onlyViaAdGroups")}</span>
                          ) : (
                            <span style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                              {i.groups.map((g) => (
                                <span key={g} className="perm-chip" style={{ fontSize: 12 }}>{g}</span>
                              ))}
                            </span>
                          )}
                        </td>
                        <td className="muted" style={{ fontSize: 12 }}>
                          {i.last_login ? new Date(i.last_login).toLocaleString() : "—"}
                        </td>
                        <td className="muted mono" style={{ fontSize: 11 }}>{i.id}</td>
                        <td className="row-actions">
                          <button
                            className="ghost"
                            title={t("users.forgetTitle")}
                            onClick={() => act(() => api.admins.identities.forget(i.username))}
                          >
                            {t("users.remove")}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>

        <h3>{t("users.newLocalAccount")}</h3>
        <form className="inline-form" onSubmit={createAccount}>
          <input placeholder={t("users.phUsername")} value={nu} onChange={(e) => setNu(e.target.value)} autoComplete="off" />
          <input placeholder={t("users.phDisplayName")} value={nd} onChange={(e) => setNd(e.target.value)} />
          <input
            type="password"
            placeholder={t("users.phPassword")}
            value={np}
            onChange={(e) => setNp(e.target.value)}
            autoComplete="new-password"
          />
          <button className="primary" type="submit" disabled={!nu.trim() || np.length < 8}>
            {t("common.create")}
          </button>
        </form>
      </section>

      {/* ── Groups ── */}
      <section className="panel wide">
        <h2>{t("users.groupsAndRights")}</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          {t("users.groupsHint")}
        </p>

        <form className="inline-form" onSubmit={createGroup} style={{ marginBottom: 14 }}>
          <input placeholder={t("users.phNewGroup")} value={ng} onChange={(e) => setNg(e.target.value)} autoComplete="off" />
          <button className="primary" type="submit" disabled={!ng.trim()}>
            {t("users.createGroup")}
          </button>
        </form>

        {groups.length === 0 && <p className="muted">{t("users.noGroupsYet")}</p>}
        {groups.map((g) => (
          <GroupCard
            key={g.name}
            group={g}
            catalog={catalog}
            localAccounts={localAccounts}
            onError={(m) => setErr(m)}
            onChanged={load}
          />
        ))}
      </section>
    </div>
  );
}

// ── One group: rights checkboxes + member editor ───────────────────
function GroupCard({
  group,
  catalog,
  localAccounts,
  onError,
  onChanged,
}: {
  group: Group;
  catalog: { key: string; label: string }[];
  localAccounts: string[];
  onError: (m: string) => void;
  onChanged: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  // Renaming (the name is only a label, rights and members stay)
  const [renaming, setRenaming] = useState(false);
  const [newName, setNewName] = useState(group.name);
  // Add member
  const [mtype, setMtype] = useState<MemberType>("ad_user");
  const [localRef, setLocalRef] = useState("");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<DirectoryEntry[]>([]);
  const [searching, setSearching] = useState(false);
  const [picker, setPicker] = useState(false);
  // Result message of the last search ("" = not searched yet, or there are hits).
  const [hint, setHint] = useState("");

  async function run(fn: () => Promise<unknown>) {
    onError("");
    setBusy(true);
    try {
      await fn();
      await onChanged();
    } catch (e) {
      onError(errText(e, t("common.actionFailed")));
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  async function setPerm(key: string, on: boolean) {
    await run(() => api.admins.groups.update(group.name, { permissions: toggle(group.permissions, key, on) }));
  }

  async function setAll(on: boolean) {
    // Deliberately ONLY the flag: with the flag set the backend already returns every
    // right as a list. Sending that list back would freeze full access as a list when
    // switching the flag off, instead of switching it off.
    await run(() => api.admins.groups.update(group.name, { all_permissions: on }));
  }

  async function saveName() {
    const name = newName.trim();
    if (!name || name === group.name) {
      setRenaming(false);
      setNewName(group.name);
      return;
    }
    await run(async () => {
      await api.admins.groups.rename(group.name, name);
      setRenaming(false);
    });
  }

  async function search() {
    onError("");
    setSearching(true);
    setHint("");
    try {
      const q = query.trim();
      const res = await api.admins.directory(q, mtype === "ad_group" ? "group" : "user");
      setResults(res.entries);
      setPicker(res.entries.length > INLINE_HITS); // many hits → own window with a filter
      if (res.entries.length === 0) {
        setHint(
          searchMessage(
            res.status,
            res.detail,
            q,
            mtype === "ad_group" ? t("users.kindAdGroups") : t("users.kindAdUsers"),
            t
          )
        );
      }
    } catch (e) {
      setResults([]);
      setHint("");
      onError(errText(e, t("users.directorySearchFailed")));
    } finally {
      setSearching(false);
    }
  }

  async function addMember(type: MemberType, ref: string) {
    if (!ref) return;
    await run(() => api.admins.groups.addMember(group.name, type, ref));
    setQuery("");
    setResults([]);
    setHint("");
    setPicker(false);
    setLocalRef("");
  }

  return (
    <div className="panel" style={{ marginBottom: 14, background: "transparent" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        {renaming ? (
          <>
            <input
              value={newName}
              autoFocus
              disabled={busy}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  saveName();
                }
                if (e.key === "Escape") {
                  setRenaming(false);
                  setNewName(group.name);
                }
              }}
            />
            <button type="button" className="primary" disabled={busy || !newName.trim()} onClick={saveName}>
              {t("common.save")}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => {
                setRenaming(false);
                setNewName(group.name);
              }}
            >
              {t("common.cancel")}
            </button>
          </>
        ) : (
          <>
            <h3 style={{ margin: 0 }}>{group.name}</h3>
            <button type="button" className="ghost" disabled={busy} onClick={() => setRenaming(true)}>
              {t("users.rename")}
            </button>
          </>
        )}
        <button
          className="danger"
          style={{ marginLeft: "auto" }}
          disabled={busy}
          onClick={() => {
            if (confirm(t("users.deleteGroupConfirm", { name: group.name })))
              run(() => api.admins.groups.remove(group.name));
          }}
        >
          {t("users.deleteGroup")}
        </button>
      </div>

      {/* Rights */}
      <label className="perm-chip" style={{ marginTop: 8, display: "inline-flex" }}>
        <input
          type="checkbox"
          checked={!!group.all_permissions}
          disabled={busy}
          onChange={(e) => setAll(e.target.checked)}
        />
        <b>{t("users.fullAccess")}</b>
      </label>
      {group.all_permissions && (
        <div className="note-box" style={{ marginTop: 6 }}>
          {t("users.fullAccessNote")}
        </div>
      )}
      <div className="perm-picker" style={{ marginTop: 8 }}>
        {catalog.map((p) => (
          <label key={p.key} className="perm-chip">
            <input
              type="checkbox"
              checked={group.all_permissions || group.permissions.includes(p.key)}
              disabled={busy || group.all_permissions}
              onChange={(e) => setPerm(p.key, e.target.checked)}
            />
            {p.label}
          </label>
        ))}
      </div>

      {/* Members */}
      <div style={{ marginTop: 10 }}>
        <label className="muted" style={{ fontSize: 12 }}>{t("users.members")}</label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
          {group.members.length === 0 && <span className="muted" style={{ fontSize: 12 }}>{t("users.noMembers")}</span>}
          {group.members.map((m: GroupMember) => (
            <span key={`${m.type}:${m.ref}`} className="perm-chip" title={t(MEMBER_LABEL_KEY[m.type])}>
              <b style={{ opacity: 0.6 }}>{t(MEMBER_LABEL_KEY[m.type])}:</b>&nbsp;{m.ref}
              <button
                type="button"
                disabled={busy}
                title={t("users.removeTitle")}
                style={{
                  marginLeft: 6, border: "none", background: "transparent", cursor: "pointer",
                  color: "inherit", fontSize: 14, lineHeight: 1, padding: 0,
                }}
                onClick={() => run(() => api.admins.groups.removeMember(group.name, m.type, m.ref))}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      </div>

      {/* Add member */}
      <div className="inline-form" style={{ marginTop: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
        <select
          value={mtype}
          onChange={(e) => {
            setMtype(e.target.value as MemberType);
            setResults([]);
            setHint("");
            setQuery("");
          }}
        >
          <option value="ad_user">{t("users.memberAdUser")}</option>
          <option value="ad_group">{t("users.memberAdGroup")}</option>
          <option value="local">{t("users.optLocalAccount")}</option>
        </select>

        {mtype === "local" ? (
          <>
            <select value={localRef} onChange={(e) => setLocalRef(e.target.value)}>
              <option value="">{t("users.optPickAccount")}</option>
              {localAccounts.map((u) => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
            <button type="button" className="ghost" disabled={busy || !localRef} onClick={() => addMember("local", localRef)}>
              {t("users.add")}
            </button>
          </>
        ) : (
          <>
            <input
              style={{ minWidth: 240 }}
              placeholder={mtype === "ad_group" ? t("users.phSearchAdGroup") : t("users.phSearchAdUser")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  if (queryLen(query) >= 2) search();
                }
              }}
            />
            <button type="button" className="ghost" disabled={searching || queryLen(query) < 2} onClick={search}>
              {searching ? t("users.searching") : t("users.doSearch")}
            </button>
            <span className="muted" style={{ fontSize: 12 }}>
              {t("users.wildcardPre")} <code>*</code> {t("users.wildcardMid")} <code>*</code>{" "}
              {t("users.wildcardPost")}
            </span>
          </>
        )}
      </div>

      {mtype !== "local" && !picker && (hint || results.length > 0) && (
        <div style={{ marginTop: 6 }}>
          {results.length === 0 ? (
            <span className="muted" style={{ fontSize: 12 }}>{hint}</span>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
              {results.slice(0, INLINE_HITS).map((r) => (
                <button
                  key={r.ref}
                  type="button"
                  className="ghost"
                  disabled={busy}
                  onClick={() => addMember(r.type, r.ref)}
                  title={t("users.addRefTitle", { ref: r.ref })}
                >
                  + {r.display} <span className="muted">({r.ref})</span>
                </button>
              ))}
              {results.length > INLINE_HITS && (
                <button type="button" className="ghost" onClick={() => setPicker(true)}>
                  {t("users.allHits", { count: results.length })}
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {picker && (
        <DirectoryPicker
          title={mtype === "ad_group" ? t("users.kindAdGroups") : t("users.kindAdUsers")}
          query={query.trim()}
          entries={results}
          busy={busy}
          onPick={(r) => addMember(r.type, r.ref)}
          onClose={() => setPicker(false)}
        />
      )}
    </div>
  );
}

// ── Hit window: long AD result lists with an instant filter ────────
// The filter works purely locally on the hits already loaded (name or identifier);
// a new AD search only runs through the search field in the group.
function DirectoryPicker({
  title,
  query,
  entries,
  busy,
  onPick,
  onClose,
}: {
  title: string;
  query: string;
  entries: DirectoryEntry[];
  busy: boolean;
  onPick: (e: DirectoryEntry) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const [filter, setFilter] = useState("");
  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? entries.filter((e) => e.display.toLowerCase().includes(needle) || e.ref.toLowerCase().includes(needle))
    : entries;

  return (
    <div className="chip-editor-overlay" onClick={onClose}>
      <div className="dir-picker panel" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.key === "Escape" && onClose()}>
        <div className="settings-head">
          <b>{t("users.pickerTitle", { title, count: entries.length, query })}</b>
          <button className="chip-x" onClick={onClose}>×</button>
        </div>
        <input
          autoFocus
          placeholder={t("users.filterList")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          style={{ width: "100%", marginBottom: 8 }}
        />
        <div className="dir-list">
          {shown.length === 0 && <span className="muted" style={{ fontSize: 12 }}>{t("users.noFilterHit")}</span>}
          {shown.map((r) => (
            <button
              key={r.ref}
              type="button"
              className="dir-row"
              disabled={busy}
              onClick={() => onPick(r)}
              title={t("users.addRefTitle", { ref: r.ref })}
            >
              <span>{r.display}</span>
              <span className="muted mono">{r.ref}</span>
            </button>
          ))}
        </div>
        {shown.length !== entries.length && (
          <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>
            {t("users.shownOf", { shown: shown.length, total: entries.length })}
          </p>
        )}
      </div>
    </div>
  );
}
