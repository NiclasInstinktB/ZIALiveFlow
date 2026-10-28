"""Accounts and groups: JSON storage (PBKDF2 hashes) with **group-based permissions**.

Deliberately plain (no database): a handful of accounts for an internal tool. The file is
written atomically (temp file plus replace). Clear-text passwords are never stored.

Permission model (schema v3): permissions hang **off groups only**, no longer directly off
accounts. A group is a local container holding **permissions** (``PERMISSIONS``) and a
**member list**; members are local accounts, AD users (sAMAccountName) or AD groups (CN).
A person's effective permissions are the union of the permissions of ALL groups they are
a member of, directly or through one of their AD groups.

**Accounts exist locally only.** AD users get NO record here: they are authorized once via
a group (as an ``ad_user`` or through an ``ad_group``), and on every login their
permissions are computed live from their AD groups (:meth:`effective_for_ad`) and placed
in the session. That keeps the account list small: whoever signed in shows up in the audit
log, not in the accounts.

* Local accounts: permissions are recomputed from group membership on EVERY request, so
  changes take effect immediately.
* AD users: permissions hold for the lifetime of the session; changes take effect at the
  next login (the AD groups are not available on a per-request basis).

Lockout protection: there must always be at least ONE active **local** account with the
effective ``accounts`` permission (break glass). Actions that would violate this are
rejected (:class:`LastAdminError`).

Legacy data is **migrated once** on load: direct account permissions and AD-group-to-
permission entries without members (:meth:`AdminStore._migrate_to_v2`), then the AD
accounts that used to be created just in time (:meth:`AdminStore._migrate_to_v3`).
Since v3, personal UI settings live in their own store keyed by username so that they do
not hang off an account record (AD users do not have one).
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone

from backend.auth.models import (
    ALL_PERMISSIONS,
    MEMBER_AD_GROUP,
    MEMBER_AD_USER,
    MEMBER_LOCAL,
    PERM_ACCOUNTS,
    PERM_LOGS_OBF,
    SOURCE_AD,
    SOURCE_LOCAL,
    VIEWER_PERMISSIONS,
    normalize_member_type,
    normalize_permissions,
    normalize_source,
    permissions_for_role,
)
from backend.auth.passwords import hash_password, verify_password
from backend.config import settings
from backend.logging_config import get_logger

log = get_logger("auth.store")

SCHEMA_VERSION = 5

# The permission set of a full admin BEFORE schema v4 (before the ``logs_obf``
# permission). Only :meth:`AdminStore._migrate_to_v4` still needs it, to recognize legacy
# full admins. Do not use it as a live permission set.
_PERMISSIONS_BEFORE_V4: frozenset[str] = ALL_PERMISSIONS - {PERM_LOGS_OBF}

# The permission set of a full admin BEFORE schema v5. Only for
# :meth:`AdminStore._migrate_to_v5`; do not use it as a live permission set.
_PERMISSIONS_BEFORE_V5: frozenset[str] = ALL_PERMISSIONS


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class LastAdminError(ValueError):
    """The action would remove the last active local account manager (``accounts`` permission)."""


class AdminStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._path = settings.admin_store_file
        # Accounts: local accounts ONLY (AD users have no record).
        self._accounts: dict[str, dict] = {}
        # Groups (local containers): name → {name, permissions[], members[], created_at}.
        # Their own namespace, so a group name and an account name can never collide.
        self._groups: dict[str, dict] = {}
        # Personal UI settings per username (local AND AD), independent of any account.
        self._prefs: dict[str, dict] = {}
        # A trace of AD sign-ins (NOT accounts): username → {id(uuid), username,
        # display_name, first_login, last_login}. Information for account management only.
        self._identities: dict[str, dict] = {}
        # State of the file at the last read or write. If someone changes it from the
        # outside (the CLI on the server), it is reloaded before the next access.
        self._signature: tuple[int, int] | None = None
        self._load()

    # ── Persistence ───────────────────────────────────────────────
    def _signature_on_disk(self) -> tuple[int, int] | None:
        try:
            st = self._path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _sync(self) -> None:
        """Reload the file if it was changed from the outside.

        The service and the management CLI work on the SAME file, each with its own copy
        in memory. Without this reconciliation the service would silently overwrite the
        change just made on the server at its next write (a single login is enough), and
        the other way round.
        """
        if self._signature_on_disk() != self._signature:
            self._load()

    @contextlib.contextmanager
    def _locked(self):
        """Hold the lock AND reconcile with the file first."""
        with self._lock:
            self._sync()
            yield

    def _load(self) -> None:
        if not self._path.exists():
            self._accounts = {}
            self._groups = {}
            self._prefs = {}
            self._signature = None
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._accounts = {a["username"].lower(): a for a in data.get("accounts", [])}
            self._groups = {}
            for g in data.get("groups", []):
                name = str(g.get("group") or g.get("name") or "").strip()
                if name:
                    self._groups[name.lower()] = g
            self._prefs = {
                str(k).lower(): dict(v)
                for k, v in (data.get("prefs") or {}).items()
                if isinstance(v, dict)
            }
            self._identities = {
                str(k).lower(): dict(v)
                for k, v in (data.get("ad_identities") or {}).items()
                if isinstance(v, dict)
            }
            schema = int(data.get("schema", 1))
            if schema < SCHEMA_VERSION:
                if schema < 2:
                    self._migrate_to_v2()
                if schema < 3:
                    self._migrate_to_v3()
                self._migrate_to_v4()
                self._migrate_to_v5()
                self._save()
                log.info(
                    "admin.store_migrated", schema=SCHEMA_VERSION,
                    accounts=len(self._accounts), groups=len(self._groups),
                )
            self._signature = self._signature_on_disk()
        except (OSError, ValueError, KeyError):
            log.error("admin.store_load_failed", path=str(self._path))
            self._accounts = {}
            self._groups = {}
            self._prefs = {}
            self._identities = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA_VERSION,
            "accounts": list(self._accounts.values()),
            "groups": list(self._groups.values()),
            "prefs": self._prefs,
            "ad_identities": self._identities,
        }
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)
        self._signature = self._signature_on_disk()

    # ── Migration to schema v2 (group-based permissions) ──────────
    def _migrate_to_v2(self) -> None:
        """Lift legacy data onto the group-based model without losing anyone's access.

        * Old AD-group-to-permission entries (``{group, permissions}`` without
          ``members``) become groups with exactly that AD group as their member.
        * Direct **local** account permissions move into groups (bundled by permission
          set), and the account in question becomes a local member. Afterwards no local
          account carries permissions of its own.
        * AD accounts keep their cached ``permissions`` (an interim state until the next
          login recomputes them from the migrated AD-group groups).
        """
        migrated_groups: dict[str, dict] = {}

        def _unique_name(base: str) -> str:
            name, n = base, 2
            while name.lower() in migrated_groups:
                name, n = f"{base} {n}", n + 1
            return name

        # 1) Old AD-group-to-permission entries become groups with an ad_group member.
        for g in self._groups.values():
            if "members" in g:  # already in the new format
                migrated_groups[str(g.get("name") or g.get("group")).lower()] = self._norm_group(g)
                continue
            cn = str(g.get("group") or g.get("name") or "").strip()
            if not cn:
                continue
            rec = {
                "name": cn,
                "permissions": sorted(normalize_permissions(g.get("permissions"))),
                "members": [{"type": MEMBER_AD_GROUP, "ref": cn}],
                "created_at": g.get("created_at", "") or _now_iso(),
            }
            migrated_groups[cn.lower()] = rec

        # 2) Bundle direct account permissions into groups (by permission set).
        by_permset: dict[frozenset, list[dict]] = {}
        for a in self._accounts.values():
            if "permissions" in a:
                perms = normalize_permissions(a["permissions"])
            else:  # very old accounts: derive from the role
                perms = permissions_for_role(a.get("role"))
            if perms:
                by_permset.setdefault(perms, []).append(a)

        for perms, accs in by_permset.items():
            # ">=" rather than "==": legacy accounts do not know about permissions added
            # later (``logs_obf``), but they are still full admins (v4 then adds it).
            if _PERMISSIONS_BEFORE_V4 <= perms:
                base = "Administrators"
            elif perms == VIEWER_PERMISSIONS:
                base = "Viewers"
            else:
                base = "Migrated permissions"
            name = _unique_name(base)
            members = []
            for a in accs:
                mtype = MEMBER_AD_USER if normalize_source(a.get("source")) == SOURCE_AD else MEMBER_LOCAL
                members.append({"type": mtype, "ref": a["username"]})
            migrated_groups[name.lower()] = {
                "name": name,
                "permissions": sorted(perms),
                "members": members,
                "created_at": _now_iso(),
            }

        self._groups = migrated_groups

        # 3) Strip direct permissions from LOCAL accounts (permissions now only come from
        #    groups). AD accounts keep their cache; ``role`` disappears everywhere.
        for a in self._accounts.values():
            a.pop("role", None)
            if normalize_source(a.get("source")) == SOURCE_LOCAL:
                a.pop("permissions", None)

    # ── Migration to schema v3 (no more AD accounts) ──────────────
    def _migrate_to_v3(self) -> None:
        """Remove the **AD accounts** that used to be created just in time.

        Their authorization sits in the groups (``ad_user`` / ``ad_group`` members) and is
        left untouched; only the account record goes away. Personal UI settings
        (``prefs``) move out of the accounts into their own store so they survive for an
        AD user without an account. What remains of the account is a pure identity entry
        (UUID plus last sign-in) for account management.
        """
        for key, a in list(self._accounts.items()):
            prefs = a.pop("prefs", None)
            if isinstance(prefs, dict) and prefs:
                self._prefs.setdefault(key, prefs)
            if normalize_source(a.get("source")) == SOURCE_AD:
                self._identities.setdefault(key, {
                    "id": str(uuid.uuid4()),
                    "username": a.get("username", key),
                    "display_name": a.get("display_name") or a.get("username", key),
                    "first_login": a.get("created_at", ""),
                    "last_login": a.get("last_login", ""),
                })
                del self._accounts[key]
                log.info("admin.ad_account_dropped", username=a.get("username"))

    # ── Migration to schema v4 (new ``logs_obf`` permission) ──────
    def _migrate_to_v4(self) -> None:
        """Groups that used to hold ALL permissions also get ``logs_obf``.

        ``is_admin`` means "holds every permission". Without this step, every full-admin
        group would suddenly be a partial manager after the update, and could not even
        grant itself the new permission because of the escalation brake. Nothing changes
        in terms of access: ``logs`` (clear text) beats ``logs_obf``.

        Groups with fewer permissions are left alone: someone who sees clear-text logs
        today should not be silently switched to anonymized by an update, nor the reverse.
        """
        for g in self._groups.values():
            perms = normalize_permissions(g.get("permissions"))
            if _PERMISSIONS_BEFORE_V4 <= perms and PERM_LOGS_OBF not in perms:
                g["permissions"] = sorted(perms | {PERM_LOGS_OBF})
                log.info("admin.group_granted_logs_obf", group=g.get("name"))

    @staticmethod
    def _norm_group(g: dict) -> dict:
        members = []
        seen: set[tuple[str, str]] = set()
        for m in g.get("members", []) or []:
            mtype = normalize_member_type(m.get("type") if isinstance(m, dict) else None)
            ref = str(m.get("ref", "")).strip() if isinstance(m, dict) else ""
            if not mtype or not ref:
                continue
            key = (mtype, ref.lower())
            if key in seen:
                continue
            seen.add(key)
            members.append({"type": mtype, "ref": ref})
        return {
            "name": str(g.get("name") or g.get("group") or "").strip(),
            "permissions": sorted(normalize_permissions(g.get("permissions"))),
            # Full access is stored as a FLAG, not as a list. A list freezes today's
            # state: if a new version adds a permission, the group would not hold it, and
            # nobody could add it afterwards, because you may only grant what you hold
            # yourself.
            "all_permissions": bool(g.get("all_permissions")),
            "members": members,
            "created_at": g.get("created_at", "") or _now_iso(),
        }

    def _migrate_to_v5(self) -> None:
        """Switch full-admin groups over to the "all permissions" FLAG.

        Until now full access was a list in the file. That freezes it at the state of the
        day: if a new version adds a permission, the group does not hold it, the full
        admin is suddenly a partial manager, and cannot even grant itself the new
        permission because of the escalation brake. That is exactly what already had to
        be fixed once for ``logs_obf`` (:meth:`_migrate_to_v4`).

        So this switches over to a flag, once, which picks up future permissions
        automatically. A full-admin group is recognized by holding EVERY permission that
        existed before this version. Groups with fewer permissions are left alone: an
        update must not silently turn a partial group into a blank cheque.
        """
        upgraded = []
        for g in self._groups.values():
            if g.get("all_permissions"):
                continue
            if _PERMISSIONS_BEFORE_V5 <= normalize_permissions(g.get("permissions")):
                g["all_permissions"] = True
                upgraded.append(g.get("name", ""))
        if upgraded:
            log.info("admin.groups_full_access_flagged", groups=upgraded)

    # ── Effective permissions (always via groups) ─────────────────
    def _effective_local(self, username: str) -> frozenset[str]:
        """Permissions of a LOCAL account = the union of the groups holding it as a local
        member. Takes no lock, so call it only from methods that already hold one."""
        uname = username.strip().lower()
        if is_superadmin(uname):
            return ALL_PERMISSIONS
        perms: set[str] = set()
        for g in self._groups.values():
            for m in g.get("members", []):
                if m.get("type") == MEMBER_LOCAL and str(m.get("ref", "")).lower() == uname:
                    perms |= set(AdminStore.group_permissions(g))
                    break
        return frozenset(perms)

    def effective_for_ad(self, username: str, ad_groups) -> frozenset[str]:
        """Permissions of an AD person = the union of the groups they are a member of
        directly (ad_user) OR through one of their AD groups (ad_group). Case insensitive."""
        uname = (username or "").strip().lower()
        adg = {str(g).strip().lower() for g in (ad_groups or set())}
        if is_superadmin(uname, adg):
            return ALL_PERMISSIONS
        perms: set[str] = set()
        with self._locked():
            for g in self._groups.values():
                for m in g.get("members", []):
                    t, ref = m.get("type"), str(m.get("ref", "")).lower()
                    if (t == MEMBER_AD_USER and ref == uname) or (t == MEMBER_AD_GROUP and ref in adg):
                        perms |= set(AdminStore.group_permissions(g))
                        break
        return frozenset(perms)

    # ── Reading ───────────────────────────────────────────────────
    def list(self) -> list[dict]:
        """Accounts without the hash (for the UI and the CLI)."""
        with self._locked():
            return [self._public(a) for a in self._accounts.values()]

    def _public(self, a: dict) -> dict:
        # Accounts are local only, so permissions always come fresh from the groups.
        source = normalize_source(a.get("source"))
        perms = self._effective_local(a["username"])
        return {
            "username": a["username"],
            "display_name": a.get("display_name") or a["username"],
            "permissions": sorted(perms),
            "is_admin": ALL_PERMISSIONS <= perms,
            "source": source,
            "enabled": bool(a.get("enabled", True)),
            "created_at": a.get("created_at", ""),
            "last_login": a.get("last_login", ""),
            "groups": self._direct_group_names(a["username"], source),
        }

    def _direct_group_names(self, username: str, source: str = SOURCE_LOCAL) -> list[str]:
        """Names of the groups the account is a DIRECT member of (local or ad_user)."""
        uname = username.lower()
        want = MEMBER_LOCAL if source == SOURCE_LOCAL else MEMBER_AD_USER
        out = []
        for g in self._groups.values():
            if any(m.get("type") == want and str(m.get("ref", "")).lower() == uname for m in g.get("members", [])):
                out.append(g["name"])
        return sorted(out)

    def touch_login(self, username: str) -> None:
        with self._locked():
            rec = self._accounts.get(username.lower())
            if not rec:
                return
            rec["last_login"] = _now_iso()
            self._save()

    def count_enabled(self) -> int:
        with self._locked():
            return sum(1 for a in self._accounts.values() if a.get("enabled", True))

    def counts(self) -> dict:
        """Metrics for the admin overview."""
        with self._locked():
            accs = list(self._accounts.values())
            admins = sum(1 for a in accs if ALL_PERMISSIONS <= frozenset(self._public(a)["permissions"]))
            enabled = sum(1 for a in accs if a.get("enabled", True))
        total = len(accs)
        return {
            "total": total,
            "admins": admins,
            "viewers": total - admins,
            "enabled": enabled,
            "disabled": total - enabled,
        }

    # ── Lockout protection: the last local account manager ────────
    def _local_managers(self) -> list[str]:
        """Active LOCAL accounts with the effective ``accounts`` permission (break-glass
        managers)."""
        return [
            a["username"]
            for a in self._accounts.values()
            if normalize_source(a.get("source")) == SOURCE_LOCAL
            and a.get("enabled", True)
            and PERM_ACCOUNTS in self._effective_local(a["username"])
        ]

    def _guard_manager(self, before: int, msg: str) -> None:
        """Check after a mutation: if there was >=1 manager before and there are 0 now,
        the change is forbidden."""
        if before >= 1 and len(self._local_managers()) == 0:
            raise LastAdminError(msg)

    # ── Accounts: writing ─────────────────────────────────────────
    def create(self, username: str, password: str, display_name: str = "") -> dict:
        username = username.strip()
        if not username:
            raise ValueError("Username must not be empty.")
        if not password:
            raise ValueError("Password must not be empty.")
        with self._locked():
            if username.lower() in self._accounts:
                raise ValueError("User already exists.")
            rec = {
                "username": username,
                "display_name": display_name.strip() or username,
                "password_hash": hash_password(password),
                "source": SOURCE_LOCAL,
                "enabled": True,
                "created_at": _now_iso(),
            }
            self._accounts[username.lower()] = rec
            self._save()
            log.info("admin.created", username=username)
            return self._public(rec)

    # ── AD identities (NOT accounts) ──────────────────────────────
    # Just a trace of the AD sign-ins so far: a stable UUID, display name and last
    # sign-in. It grants no permissions at all (those only ever come through groups) and
    # is purely information for account management. It can be deleted and comes back by
    # itself at the next login.
    def record_ad_login(self, username: str, display_name: str = "") -> dict:
        username = (username or "").strip()
        if not username:
            raise ValueError("Username must not be empty.")
        key = username.lower()
        with self._locked():
            rec = self._identities.get(key)
            if rec is None:
                rec = {
                    "id": str(uuid.uuid4()),
                    "username": username,
                    "display_name": display_name.strip() or username,
                    "first_login": _now_iso(),
                    "last_login": "",
                }
                self._identities[key] = rec
                log.info("admin.ad_identity_seen", username=username, id=rec["id"])
            if display_name.strip():
                rec["display_name"] = display_name.strip()
            rec["last_login"] = _now_iso()
            self._save()
            return dict(rec)

    def list_ad_identities(self) -> list[dict]:
        """AD sign-ins, including the groups the person is a DIRECT member of (as
        ``ad_user``). Access gained through AD group membership is deliberately not shown
        here: only AD itself knows about that."""
        with self._locked():
            out = []
            for rec in self._identities.values():
                out.append({
                    **rec,
                    "groups": self._direct_group_names(rec["username"], SOURCE_AD),
                })
            return sorted(out, key=lambda r: r["username"].lower())

    def forget_ad_identity(self, username: str) -> None:
        """Remove the identity entry. Housekeeping only: permissions and groups stay."""
        key = (username or "").strip().lower()
        with self._locked():
            if key not in self._identities:
                raise KeyError(username)
            del self._identities[key]
            self._prefs.pop(key, None)
            self._save()
            log.info("admin.ad_identity_forgotten", username=username)

    def account_exists(self, username: str) -> bool:
        """Is there a (local) account with this name?

        The AD login asks this: an AD name that belongs to a local break-glass account
        must NOT sign in via AD, or it would inherit the local account's permissions.
        """
        with self._locked():
            return username.strip().lower() in self._accounts

    def update(
        self,
        username: str,
        *,
        password: str | None = None,
        display_name: str | None = None,
        enabled: bool | None = None,
    ) -> dict:
        with self._locked():
            rec = self._accounts.get(username.lower())
            if not rec:
                raise KeyError(username)
            if password:
                if normalize_source(rec.get("source")) != SOURCE_LOCAL:
                    raise ValueError("AD accounts have no local password.")
                rec["password_hash"] = hash_password(password)
            if display_name is not None:
                rec["display_name"] = display_name.strip() or rec["username"]
            if enabled is not None:
                before = len(self._local_managers())
                old = rec.get("enabled", True)
                rec["enabled"] = bool(enabled)
                try:
                    self._guard_manager(before, "The last local account with the 'accounts' permission cannot be deactivated.")
                except LastAdminError:
                    rec["enabled"] = old
                    raise
            self._save()
            log.info("admin.updated", username=rec["username"])
            return self._public(rec)

    def delete(self, username: str) -> None:
        with self._locked():
            key = username.lower()
            rec = self._accounts.get(key)
            if not rec:
                raise KeyError(username)
            before = len(self._local_managers())
            del self._accounts[key]
            try:
                self._guard_manager(before, "The last local account with the 'accounts' permission cannot be deleted.")
            except LastAdminError:
                self._accounts[key] = rec
                raise
            # Remove orphaned memberships and the personal settings along with it.
            for g in self._groups.values():
                g["members"] = [
                    m for m in g.get("members", [])
                    if not (m.get("type") == MEMBER_LOCAL and str(m.get("ref", "")).lower() == key)
                ]
            self._prefs.pop(key, None)
            self._save()
            log.info("admin.deleted", username=username)

    # ── Groups: reading ───────────────────────────────────────────
    @staticmethod
    def _public_group(g: dict) -> dict:
        return {
            "name": g["name"],
            "permissions": sorted(AdminStore.group_permissions(g)),
            "all_permissions": bool(g.get("all_permissions")),
            "members": [{"type": m["type"], "ref": m["ref"]} for m in g.get("members", [])],
            "created_at": g.get("created_at", ""),
        }

    @staticmethod
    def group_permissions(g: dict) -> frozenset[str]:
        """Effective permissions of a group: the flag beats the stored list."""
        if g.get("all_permissions"):
            return ALL_PERMISSIONS
        return normalize_permissions(g.get("permissions"))

    def list_groups(self) -> list[dict]:
        with self._locked():
            return [self._public_group(g) for g in self._groups.values()]

    # ── Groups: writing ───────────────────────────────────────────
    def create_group(self, name: str, permissions=(), members=(), all_permissions: bool = False) -> dict:
        name = name.strip()
        if not name:
            raise ValueError("Group name must not be empty.")
        with self._locked():
            if name.lower() in self._groups:
                raise ValueError("Group already exists.")
            rec = self._norm_group({
                "name": name, "permissions": permissions,
                "members": list(members), "all_permissions": all_permissions,
            })
            rec["created_at"] = _now_iso()
            self._groups[name.lower()] = rec
            self._save()
            log.info("admin.group_created", group=name, permissions=rec["permissions"])
            return self._public_group(rec)

    def set_group_permissions(self, name: str, permissions=None, all_permissions: bool | None = None) -> dict:
        """Set the permissions and/or the full-access flag. ``None`` means unchanged.

        Handling them separately is necessary because the public view of a flagged group
        already returns ALL permissions. Writing those back when the flag is switched off
        would freeze full access as a list, which is exactly what the flag is there to
        prevent.
        """
        with self._locked():
            rec = self._groups.get(name.lower())
            if not rec:
                raise KeyError(name)
            before = len(self._local_managers())
            old = rec["permissions"]
            old_flag = rec.get("all_permissions", False)
            if permissions is not None:
                rec["permissions"] = sorted(normalize_permissions(permissions))
            if all_permissions is not None:
                rec["all_permissions"] = bool(all_permissions)
            try:
                self._guard_manager(before, "This permission change would lock out the last local account manager.")
            except LastAdminError:
                rec["permissions"] = old
                rec["all_permissions"] = old_flag
                raise
            self._save()
            log.info("admin.group_updated", group=rec["name"], permissions=rec["permissions"])
            return self._public_group(rec)

    def rename_group(self, name: str, new_name: str) -> dict:
        """Rename a group. Permissions and members stay as they are: the name is only a
        label (members reference accounts and AD objects, not the group), so nobody can be
        locked out here."""
        new_name = (new_name or "").strip()
        if not new_name:
            raise ValueError("Group name must not be empty.")
        with self._locked():
            key = name.lower()
            rec = self._groups.get(key)
            if not rec:
                raise KeyError(name)
            new_key = new_name.lower()
            if new_key != key and new_key in self._groups:
                raise ValueError("Group already exists.")
            old = rec["name"]
            rec["name"] = new_name
            if new_key != key:  # swap the key in place (the ordering is preserved)
                self._groups = {(new_key if k == key else k): v for k, v in self._groups.items()}
            self._save()
            log.info("admin.group_renamed", group=new_name, previous=old)
            return self._public_group(rec)

    def delete_group(self, name: str) -> None:
        with self._locked():
            key = name.lower()
            rec = self._groups.get(key)
            if not rec:
                raise KeyError(name)
            before = len(self._local_managers())
            del self._groups[key]
            try:
                self._guard_manager(before, "This group cannot be deleted: it holds the last local account manager.")
            except LastAdminError:
                self._groups[key] = rec
                raise
            self._save()
            log.info("admin.group_deleted", group=rec["name"])

    def add_member(self, name: str, mtype: str, ref: str) -> dict:
        mtype = normalize_member_type(mtype)
        ref = (ref or "").strip()
        if not mtype or not ref:
            raise ValueError("Invalid member.")
        with self._locked():
            rec = self._groups.get(name.lower())
            if not rec:
                raise KeyError(name)
            if not any(m["type"] == mtype and m["ref"].lower() == ref.lower() for m in rec["members"]):
                rec["members"].append({"type": mtype, "ref": ref})
                self._save()
                log.info("admin.group_member_added", group=rec["name"], type=mtype, ref=ref)
            return self._public_group(rec)

    def remove_member(self, name: str, mtype: str, ref: str) -> dict:
        mtype = normalize_member_type(mtype)
        ref = (ref or "").strip()
        with self._locked():
            rec = self._groups.get(name.lower())
            if not rec:
                raise KeyError(name)
            before = len(self._local_managers())
            old = rec["members"]
            rec["members"] = [
                m for m in old if not (m["type"] == mtype and m["ref"].lower() == ref.lower())
            ]
            try:
                self._guard_manager(before, "This member cannot be removed: it is the last local account manager.")
            except LastAdminError:
                rec["members"] = old
                raise
            self._save()
            log.info("admin.group_member_removed", group=rec["name"], type=mtype, ref=ref)
            return self._public_group(rec)

    def import_legacy_groups(self, entries) -> int:
        """One-off migration of the AD-group-to-permission entries from the legacy LDAP
        config, and only while NO groups exist here yet. Each becomes a group with exactly
        that AD group as its member. Returns the number of groups imported."""
        with self._locked():
            if self._groups:
                return 0
            imported = 0
            for entry in entries or []:
                if not isinstance(entry, dict):
                    continue
                cn = str(entry.get("group", "")).strip()
                if not cn or cn.lower() in self._groups:
                    continue
                self._groups[cn.lower()] = {
                    "name": cn,
                    "permissions": sorted(normalize_permissions(entry.get("permissions"))),
                    "members": [{"type": MEMBER_AD_GROUP, "ref": cn}],
                    "created_at": _now_iso(),
                }
                imported += 1
            if imported:
                self._save()
                log.info("admin.groups_migrated", count=imported)
            return imported

    # ── Session validation ────────────────────────────────────────
    def get_active(self, username: str) -> dict | None:
        """The public account view if the account exists AND is active, otherwise None.

        Called on EVERY authenticated request. For local accounts the permissions are
        recomputed here from group membership, so changes take effect immediately."""
        with self._locked():
            rec = self._accounts.get(username.lower())
            if not rec or not rec.get("enabled", True):
                return None
            return self._public(rec)

    # ── Login ─────────────────────────────────────────────────────
    def verify_login(self, username: str, password: str) -> dict | None:
        """The public account on a valid local login, otherwise None (local accounts only)."""
        with self._locked():
            rec = self._accounts.get(username.lower())
            if not rec or not rec.get("enabled", True):
                return None
            if not verify_password(password, rec.get("password_hash", "")):
                return None
            return self._public(rec)

    # ── Personal UI settings (per username) ───────────────────────
    # Deliberately NOT attached to the account: AD users have no account record but should
    # still keep their columns, chips and filters.
    def get_prefs(self, username: str) -> dict:
        with self._locked():
            return dict(self._prefs.get(username.strip().lower()) or {})

    def set_prefs(self, username: str, prefs: dict) -> dict:
        key = username.strip().lower()
        if not key:
            raise KeyError(username)
        with self._locked():
            self._prefs[key] = prefs
            self._save()
            return dict(prefs)

    # ── Bootstrap ─────────────────────────────────────────────────
    def seed_if_empty(self) -> None:
        """On first start, create a full admin: a local account plus the group
        "Administrators" (all permissions) with that account as its member."""
        with self._locked():
            if self._accounts:
                return
        user = settings.admin_initial_user.strip() or "admin"
        pw = settings.admin_initial_password.strip()
        generated = False
        if not pw:
            pw = secrets.token_urlsafe(18)
            generated = True
        self.create(user, pw, display_name=user)
        # Flag instead of list: this group should hold future permissions automatically too.
        self.create_group(
            "Administrators", ALL_PERMISSIONS,
            members=[{"type": MEMBER_LOCAL, "ref": user}], all_permissions=True,
        )
        if generated:
            log.warning(
                "admin.bootstrap_generated",
                username=user,
                password=pw,
                hint="Initial admin created with a random password. Write it down NOW and change it.",
            )
        else:
            log.info("admin.bootstrap_from_env", username=user)


def is_superadmin(username: str, ad_groups=None) -> bool:
    """Does this account ALWAYS hold every permission?

    The only source is the configuration (``SUPERADMIN_USERS`` or
    ``SUPERADMIN_AD_GROUP``), never the user interface. That is the whole point: a
    superadmin cannot be revoked by accident through the UI. Without this route you can
    lock yourself out, because permissions only come through groups and you may only
    grant what you hold yourself.
    """
    uname = (username or "").strip().lower()
    if uname and uname in settings.superadmin_user_list:
        return True
    group = settings.superadmin_ad_group.strip().lower()
    if group and ad_groups:
        return group in {str(g).strip().lower() for g in ad_groups}
    return False


_store: AdminStore | None = None


def get_admin_store() -> AdminStore:
    global _store
    if _store is None:
        _store = AdminStore()
    return _store
