"""Account store (group based): permissions ONLY via groups, members (local/ad_user/
ad_group), lockout protection (the last local account manager), v2 migration, prefs."""
from __future__ import annotations

import json

import pytest

from backend.auth.models import ALL_PERMISSIONS, PERM_ACCOUNTS, VIEWER_PERMISSIONS
from backend.auth.store import SCHEMA_VERSION, AdminStore, LastAdminError
from backend.config import settings


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    return AdminStore()


def eff(store, username) -> set:
    """Effective permissions of an account (taken from get_active)."""
    rec = store.get_active(username)
    return set(rec["permissions"]) if rec else set()


def _member(t, ref) -> dict:
    return {"type": t, "ref": ref}


# ── Accounts no longer carry permissions of their own ──────────────
def test_new_local_account_has_no_permissions(store):
    store.create("alice", "password1")
    assert eff(store, "alice") == set()
    assert store.get_active("alice")["is_admin"] is False


def test_group_grants_permissions_to_local_member(store):
    store.create("alice", "password1")
    store.create_group("Admins", ALL_PERMISSIONS, members=[_member("local", "alice")])
    assert eff(store, "alice") == set(ALL_PERMISSIONS)
    assert store.get_active("alice")["is_admin"] is True
    assert store.get_active("alice")["groups"] == ["Admins"]


def test_permissions_are_union_of_groups(store):
    store.create("bob", "password1")
    store.create_group("Logs", {"logs"}, members=[_member("local", "bob")])
    store.create_group("Audit", {"audit"}, members=[_member("local", "bob")])
    assert eff(store, "bob") == {"logs", "audit"}


def test_unknown_group_permissions_dropped(store):
    g = store.create_group("G", {"logs", "bogus"})
    assert set(g["permissions"]) == {"logs"}


def test_group_duplicate_rejected_case_insensitive(store):
    store.create_group("G", {"logs"})
    with pytest.raises(ValueError):
        store.create_group("g", {"audit"})


# ── AD permissions via ad_user / ad_group ──────────────────────────
def test_effective_for_ad_via_ad_group_and_ad_user(store):
    store.create_group("Net", {"logs", "overview"}, members=[_member("ad_group", "ZS-Net")])
    store.create_group("Single", {"audit"}, members=[_member("ad_user", "max")])
    # Through the AD group (case insensitive):
    assert store.effective_for_ad("whoever", {"zs-net"}) == frozenset({"logs", "overview"})
    # Directly as an ad_user:
    assert store.effective_for_ad("max", set()) == frozenset({"audit"})
    # Both at once (max is in ZS-Net and named directly):
    assert store.effective_for_ad("max", {"ZS-Net"}) == frozenset({"logs", "overview", "audit"})
    # Nothing matches:
    assert store.effective_for_ad("nobody", {"other"}) == frozenset()


# ── Member management ──────────────────────────────────────────────
def test_add_and_remove_member(store):
    store.create("alice", "password1")
    store.create_group("G", {"logs"})
    assert eff(store, "alice") == set()
    store.add_member("G", "local", "alice")
    assert eff(store, "alice") == {"logs"}
    store.add_member("G", "local", "alice")  # a second time is idempotent
    assert len([m for m in store.list_groups()[0]["members"]]) == 1
    store.remove_member("G", "local", "alice")
    assert eff(store, "alice") == set()


def test_set_group_permissions(store):
    store.create("alice", "password1")
    store.create_group("G", {"logs"}, members=[_member("local", "alice")])
    store.set_group_permissions("g", {"audit", "overview"})  # case insensitive
    assert eff(store, "alice") == {"audit", "overview"}


def test_delete_group_removes_rights(store):
    store.create("alice", "password1")
    store.create_group("G", {"logs"}, members=[_member("local", "alice")])
    store.delete_group("g")
    assert eff(store, "alice") == set()
    assert store.list_groups() == []


def test_group_and_account_same_name_no_collision(store):
    store.create("alice", "password1")
    store.create_group("alice", {"audit"}, members=[_member("ad_group", "alice")])
    assert eff(store, "alice") == set()  # the local account is NOT a member
    assert store.effective_for_ad("x", {"alice"}) == frozenset({"audit"})


# ── Lockout protection: the last local account manager ─────────────
@pytest.fixture
def solo_admin(store):
    """A single local manager (root) via the group 'Admins' (all permissions)."""
    store.create("root", "password1")
    store.create_group("Admins", ALL_PERMISSIONS, members=[_member("local", "root")])
    assert PERM_ACCOUNTS in eff(store, "root")
    return store


def test_last_manager_group_perms_cannot_drop_accounts(solo_admin):
    with pytest.raises(LastAdminError):
        solo_admin.set_group_permissions("Admins", {"logs"})
    assert PERM_ACCOUNTS in eff(solo_admin, "root")  # unchanged


def test_last_manager_member_cannot_be_removed(solo_admin):
    with pytest.raises(LastAdminError):
        solo_admin.remove_member("Admins", "local", "root")
    assert PERM_ACCOUNTS in eff(solo_admin, "root")


def test_last_manager_group_cannot_be_deleted(solo_admin):
    with pytest.raises(LastAdminError):
        solo_admin.delete_group("Admins")


def test_last_manager_account_cannot_be_disabled_or_deleted(solo_admin):
    with pytest.raises(LastAdminError):
        solo_admin.update("root", enabled=False)
    with pytest.raises(LastAdminError):
        solo_admin.delete("root")


def test_second_manager_allows_removing_first(solo_admin):
    solo_admin.create("two", "password1")
    solo_admin.add_member("Admins", "local", "two")  # a second manager
    solo_admin.remove_member("Admins", "local", "root")  # now allowed
    assert PERM_ACCOUNTS not in eff(solo_admin, "root")
    assert PERM_ACCOUNTS in eff(solo_admin, "two")


def test_ad_manager_does_not_satisfy_break_glass(store):
    # Only an AD member holds 'accounts', which does NOT count as break glass, so a local
    # manager still must not be the last one.
    store.create("root", "password1")
    store.create_group("Admins", ALL_PERMISSIONS, members=[_member("local", "root"), _member("ad_group", "ZS-Admins")])
    with pytest.raises(LastAdminError):
        store.remove_member("Admins", "local", "root")


# ── Metrics ────────────────────────────────────────────────────────
def test_counts(store):
    store.create("a", "password1")
    store.create("b", "password1")
    store.create("c", "password1")
    store.create_group("Admins", ALL_PERMISSIONS, members=[_member("local", "a")])
    store.update("c", enabled=False)
    assert store.counts() == {"total": 3, "admins": 1, "viewers": 2, "enabled": 2, "disabled": 1}


# ── Migration to schema v2 ─────────────────────────────────────────
def test_migration_v2_from_direct_permissions(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    p.write_text(
        json.dumps({
            "accounts": [
                {"username": "root", "display_name": "root", "password_hash": "x", "enabled": True,
                 "permissions": sorted(ALL_PERMISSIONS)},
                {"username": "vera", "display_name": "vera", "password_hash": "y", "enabled": True,
                 "permissions": sorted(VIEWER_PERMISSIONS)},
            ],
            "groups": [{"group": "ZS-Net", "permissions": ["logs"]}],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    store = AdminStore()
    # Local accounts keep their permissions, now through the migrated groups.
    assert eff(store, "root") == set(ALL_PERMISSIONS)
    assert eff(store, "vera") == set(VIEWER_PERMISSIONS)
    # The old AD-group-to-permission entry stays effective (as an ad_group member):
    assert store.effective_for_ad("x", {"zs-net"}) == frozenset({"logs"})
    # Direct account permissions are gone, and the schema is current.
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["schema"] == SCHEMA_VERSION  # legacy data is lifted up to the current schema
    root_rec = next(a for a in data["accounts"] if a["username"] == "root")
    assert "permissions" not in root_rec


# ── Migration to schema v3: AD accounts out, permissions stay ──────
def test_migration_v3_drops_ad_accounts_but_keeps_access(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    p.write_text(
        json.dumps({
            "schema": 2,
            "accounts": [
                {"username": "root", "display_name": "root", "password_hash": "x", "enabled": True,
                 "source": "local", "prefs": {"columns": ["a"]}},
                {"username": "aduser", "display_name": "AD User", "password_hash": "", "enabled": True,
                 "source": "ad", "permissions": ["logs"], "last_login": "2026-07-01T08:00:00+00:00",
                 "prefs": {"columns": ["b"]}},
            ],
            "groups": [{"name": "Log-Readers", "permissions": ["logs"], "members": [
                {"type": "local", "ref": "root"}, {"type": "ad_user", "ref": "aduser"},
            ]}],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    store = AdminStore()
    # The account list now only contains the local account ...
    assert [a["username"] for a in store.list()] == ["root"]
    # ... but the AD user's authorization survives through the group.
    assert store.effective_for_ad("aduser", set()) == frozenset({"logs"})
    # Personal settings survive for both.
    assert store.get_prefs("root")["columns"] == ["a"]
    assert store.get_prefs("aduser")["columns"] == ["b"]
    # The AD account turns into a pure identity entry with a UUID.
    ident = store.list_ad_identities()
    assert len(ident) == 1 and ident[0]["username"] == "aduser" and len(ident[0]["id"]) == 36
    assert ident[0]["groups"] == ["Log-Readers"]


def test_import_legacy_groups_only_when_empty(store):
    n = store.import_legacy_groups([{"group": "Old", "permissions": ["logs", "bogus"]}])
    assert n == 1
    assert store.effective_for_ad("x", {"old"}) == frozenset({"logs"})
    assert store.import_legacy_groups([{"group": "New", "permissions": ["audit"]}]) == 0


# ── Bootstrap ───────────────────────────────────────────────────────
def test_seed_creates_admin_in_admin_group(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    monkeypatch.setattr(settings, "admin_initial_user", "root")
    monkeypatch.setattr(settings, "admin_initial_password", "password1")
    store = AdminStore()
    store.seed_if_empty()
    assert eff(store, "root") == set(ALL_PERMISSIONS)
    assert store.get_active("root")["is_admin"] is True


# ── Prefs ───────────────────────────────────────────────────────────
def test_prefs_roundtrip(store):
    store.create("u", "password1")
    store.set_prefs("u", {"columns": [1, 2], "presets": [{"name": "x", "filters": []}]})
    assert store.get_prefs("u")["presets"][0]["name"] == "x"
