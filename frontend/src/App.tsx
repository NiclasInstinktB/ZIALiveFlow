import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import i18n from "./i18n";
import { useAuth } from "./auth";
import { Login } from "./components/Login";
import { LiveView } from "./components/LiveView";
import { ViewSettings } from "./components/ViewSettings";
import { AdminUsers } from "./components/AdminUsers";
import { AdminOverview } from "./components/AdminOverview";
import { AdminSettings } from "./components/AdminSettings";
import { AdminLogs } from "./components/AdminLogs";
import { AdminLdap } from "./components/AdminLdap";
import { AdminSso } from "./components/AdminSso";
import { AdminAudit } from "./components/AdminAudit";
import { AdminUpdate } from "./components/AdminUpdate";
import { Account } from "./components/Account";
import { LanguageSwitcher } from "./components/LanguageSwitcher";

type Tab = "live" | "view" | "overview" | "settings" | "ldap" | "admins" | "audit" | "update" | "account";

interface TabDef {
  key: Tab;
  // Translation key for the tab label, resolved at render time so switching
  // the language relabels the navigation without a reload.
  labelKey: string;
  // Required permissions, any ONE of which is enough. Omitted = visible to anyone
  // who is signed in.
  perms?: string[];
}
// Two permissions open the live flow: "logs" (plain text) and "logs_obf"
// (anonymised: personal fields are masked server-side).
const LOG_PERMS = ["logs", "logs_obf"];
const TABS: TabDef[] = [
  { key: "live", labelKey: "nav.live", perms: LOG_PERMS },
  { key: "view", labelKey: "nav.view", perms: LOG_PERMS },
  { key: "overview", labelKey: "nav.overview", perms: ["overview"] },
  { key: "settings", labelKey: "nav.settings", perms: ["settings"] },
  { key: "ldap", labelKey: "nav.ldap", perms: ["ldap"] },
  { key: "admins", labelKey: "nav.accounts", perms: ["accounts"] },
  { key: "audit", labelKey: "nav.audit", perms: ["audit"] },
  { key: "update", labelKey: "nav.update", perms: ["update"] },
  { key: "account", labelKey: "nav.account" },
];

export function App() {
  const { me, loading, logout } = useAuth();
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("live");

  // The instance name is configurable, so the browser tab follows it rather than a
  // value baked into index.html.
  const appName = me?.app_name?.trim() || "ZIA Live-Flow";
  useEffect(() => {
    document.title = appName;
  }, [appName]);

  // Apply the instance default language, but never override a choice the visitor has
  // already made. The detector stores that choice under "lang" in localStorage, so its
  // absence is what tells us nobody has picked yet.
  const fallbackLanguage = me?.default_language;
  useEffect(() => {
    if (!fallbackLanguage) return;
    let chosen: string | null = null;
    try {
      chosen = localStorage.getItem("lang");
    } catch {
      // Private mode or blocked storage. Treat it as no choice having been made.
    }
    if (!chosen && i18n.resolvedLanguage !== fallbackLanguage) {
      i18n.changeLanguage(fallbackLanguage);
    }
  }, [fallbackLanguage]);

  useEffect(() => {
    document.documentElement.lang = i18n.resolvedLanguage ?? "en";
  });

  if (loading) return <div className="center muted">{t("common.loading")}</div>;
  if (!me) return <Login />;

  const can = (perms?: string[]) => !perms || perms.some((p) => me.permissions.includes(p));
  const tabs = TABS.filter((t) => can(t.perms));
  const active = tabs.some((tb) => tb.key === tab) ? tab : (tabs[0]?.key ?? "account");
  // Anonymised view: only the restricted log permission. "logs" (plain text)
  // wins, the same rule as in the backend (Principal.logs_obfuscated).
  const obfuscated = !me.permissions.includes("logs") && me.permissions.includes("logs_obf");

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="dot" /> {appName}
        </div>
        <nav className="tabs">
          {tabs.map((tb) => (
            <button
              key={tb.key}
              className={active === tb.key ? "tab active" : "tab"}
              onClick={() => setTab(tb.key)}
            >
              {t(tb.labelKey)}
            </button>
          ))}
        </nav>
        <div className="topbar-right">
          {obfuscated && (
            <span className="role-badge role-obf" title={t("app.obfuscatedHint")}>
              {t("app.obfuscated")}
            </span>
          )}
          <span className={`role-badge role-${me.is_admin ? "admin" : "viewer"}`}>
            {me.is_admin ? t("app.roleAdmin") : t("app.roleUser")}
          </span>
          <span className="muted">{me.display_name}</span>
          <LanguageSwitcher />
          <button className="ghost" onClick={() => logout()}>
            {t("app.signOut")}
          </button>
        </div>
      </header>
      <main className="content">
        {active === "live" && (
          <LiveView
            retentionMinutes={me.retention_minutes}
            userDomain={me.user_domain_suffix ?? ""}
            obfuscated={obfuscated}
          />
        )}
        {active === "view" && <ViewSettings obfuscated={obfuscated} />}
        {active === "overview" && <AdminOverview />}
        {active === "settings" && can(["settings"]) && (
          <>
            <AdminSettings />
            {/* The logs live here because this is exactly where you look for
                them: when a setting does not take effect. Not in a tab of
                their own. */}
            <AdminLogs />
          </>
        )}
        {active === "ldap" && can(["ldap"]) && (
          <>
            <AdminLdap />
            <AdminSso />
          </>
        )}
        {active === "admins" && can(["accounts"]) && <AdminUsers me={me} />}
        {active === "audit" && can(["audit"]) && <AdminAudit />}
        {active === "update" && can(["update"]) && <AdminUpdate />}
        {active === "account" && <Account me={me} />}
      </main>
      {/* The AGPL expects people who use the app over a network to be able to get at
          its source, so the link belongs in the running interface, not only in the
          repository. The URL is configurable for forks. */}
      <footer className="appfoot">
        <span className="muted">
          {appName} {me.version}
        </span>
        {me.source_url && (
          <a className="muted" href={me.source_url} target="_blank" rel="noreferrer noopener">
            {t("app.sourceCode")}
          </a>
        )}
      </footer>
    </div>
  );
}
