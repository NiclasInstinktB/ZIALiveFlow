"""Superadmin (break glass) and full access as a flag.

The background: permissions only ever come through groups, and the escalation brake only
lets you grant what you hold yourself. Together those two can lock you out, because you
cannot hand yourself a permission you are missing. Two causes of that are covered here:

  1. A group holding "all permissions" as a frozen LIST goes stale as soon as a new
     version adds a permission.
  2. If the last group holding the ``accounts`` permission becomes unusable, nobody can
     reach the administration any more.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.auth import store as store_module
from backend.auth.models import (
    ALL_PERMISSIONS,
    PERM_ACCOUNTS,
    PERM_UPDATE,
)
from backend.auth.store import AdminStore, get_admin_store, is_superadmin
from backend.config import settings

# A full-admin scope missing exactly ONE permission: this is what a group looks like that
# was created as a frozen list and never picked up a permission added later.
PARTIAL_ADMIN = ALL_PERMISSIONS - {PERM_UPDATE}


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "superadmin_users", "")
    monkeypatch.setattr(settings, "superadmin_ad_group", "")
    monkeypatch.setattr(store_module, "_store", AdminStore())
    return get_admin_store()


# ── Superadmin ──────────────────────────────────────────────────────


def test_superadmin_is_recognised_by_name(monkeypatch):
    monkeypatch.setattr(settings, "superadmin_users", "admin, First.Last")
    assert is_superadmin("admin") is True
    assert is_superadmin("FIRST.LAST") is True  # case insensitive
    assert is_superadmin("bob") is False


def test_superadmin_by_ad_group(monkeypatch):
    monkeypatch.setattr(settings, "superadmin_ad_group", "ZS-Admins")
    assert is_superadmin("bob", {"ZS-Admins"}) is True
    assert is_superadmin("bob", {"some-other-group"}) is False
    assert is_superadmin("bob") is False


def test_without_configuration_nobody_is_superadmin(monkeypatch):
    monkeypatch.setattr(settings, "superadmin_users", "")
    monkeypatch.setattr(settings, "superadmin_ad_group", "")
    assert is_superadmin("admin") is False


def test_superadmin_holds_everything_without_any_group(store, monkeypatch):
    """The core of it: permissions without any group membership."""
    store.create("emergency", "password1")
    assert store.get_active("emergency")["permissions"] == []

    monkeypatch.setattr(settings, "superadmin_users", "emergency")
    account = store.get_active("emergency")
    assert set(account["permissions"]) == set(ALL_PERMISSIONS)
    assert account["is_admin"] is True


def test_superadmin_survives_losing_every_group(store, monkeypatch):
    """Exactly the lockout case: the last manager group is gone."""
    monkeypatch.setattr(settings, "superadmin_users", "emergency")
    store.create("emergency", "password1")
    store.create_group("Whatever", {"logs"}, members=[{"type": "local", "ref": "emergency"}])
    store.delete_group("Whatever")
    assert set(store.get_active("emergency")["permissions"]) == set(ALL_PERMISSIONS)


def test_superadmin_applies_to_ad_logins(store, monkeypatch):
    monkeypatch.setattr(settings, "superadmin_users", "ad.person")
    assert store.effective_for_ad("ad.person", set()) == ALL_PERMISSIONS
    assert store.effective_for_ad("other.person", set()) == frozenset()


# ── Full access as a flag instead of a frozen list ─────────────────


def test_full_access_group_picks_up_new_rights(store):
    """The actual problem: a list goes stale, a flag does not."""
    store.create("chef", "password1")
    store.create_group(
        "Administrators", ALL_PERMISSIONS,
        members=[{"type": "local", "ref": "chef"}], all_permissions=True,
    )
    perms = set(store.get_active("chef")["permissions"])
    assert perms == set(ALL_PERMISSIONS)
    # Including a permission the group was never explicitly given.
    assert PERM_UPDATE in perms


def test_frozen_list_does_not_pick_up_new_rights(store):
    """The counter-check: this is how the lockout case comes about."""
    store.create("chef", "password1")
    store.create_group(
        "Partial-Admins", PARTIAL_ADMIN, members=[{"type": "local", "ref": "chef"}]
    )
    perms = set(store.get_active("chef")["permissions"])
    assert PERM_UPDATE not in perms
    assert store.get_active("chef")["is_admin"] is False


def test_seeded_admin_group_uses_the_flag(store):
    store.seed_if_empty()
    group = next(g for g in store.list_groups() if g["name"] == "Administrators")
    assert group["all_permissions"] is True
    admin = store.list()[0]
    assert set(admin["permissions"]) == set(ALL_PERMISSIONS)


def test_migration_flags_old_full_admin_groups(tmp_path, monkeypatch):
    """An existing installation: yesterday's full-admin group gets the flag."""
    import json

    path = tmp_path / "admins.json"
    path.write_text(
        json.dumps(
            {
                "schema": 4,
                "accounts": [
                    {
                        "username": "chef", "display_name": "Chef", "password_hash": "x",
                        "source": "local", "enabled": True, "created_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
                "groups": [
                    {
                        "name": "Administrators",
                        "permissions": sorted(ALL_PERMISSIONS),
                        "members": [{"type": "local", "ref": "chef"}],
                        "created_at": "2026-01-01T00:00:00+00:00",
                    },
                    {
                        "name": "Log-Readers",
                        "permissions": ["logs"],
                        "members": [{"type": "local", "ref": "chef"}],
                        "created_at": "2026-01-01T00:00:00+00:00",
                    },
                ],
                "prefs": {}, "ad_identities": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "admin_store_path", str(path))
    monkeypatch.setattr(settings, "superadmin_users", "")
    monkeypatch.setattr(store_module, "_store", AdminStore())
    s = get_admin_store()

    groups = {g["name"]: g for g in s.list_groups()}
    assert groups["Administrators"]["all_permissions"] is True
    # An update must NOT turn a partial group into a blank cheque.
    assert groups["Log-Readers"]["all_permissions"] is False
    assert set(s.get_active("chef")["permissions"]) == set(ALL_PERMISSIONS)


# ── The escalation brake applies to the flag too ───────────────────


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(settings, "superadmin_users", "")
    monkeypatch.setattr(settings, "superadmin_ad_group", "")
    monkeypatch.setattr(store_module, "_store", AdminStore())
    s = get_admin_store()
    s.create("chef", "password1")
    s.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": "chef"}],
                   all_permissions=True)
    s.create("halfadmin", "password1")
    s.create_group("Account-Managers", {PERM_ACCOUNTS},
                   members=[{"type": "local", "ref": "halfadmin"}])
    from backend.main import app

    return TestClient(app), s


def _login(c, user):
    assert c.post("/api/auth/login", json={"username": user, "password": "password1"}).status_code == 200


def test_partial_admin_cannot_grant_full_access(client):
    """Otherwise the flag would be the most convenient permission escalation there is."""
    c, _ = client
    _login(c, "halfadmin")
    r = c.post("/api/admins/groups", json={"name": "My-Blank-Cheque", "all_permissions": True})
    assert r.status_code == 403
    # The detail text is produced in api/auth_routes.py; this assertion matches that
    # wording on purpose.
    assert "Full access can only be granted" in r.json()["detail"]


def test_full_admin_may_grant_full_access(client):
    c, s = client
    _login(c, "chef")
    r = c.post("/api/admins/groups", json={"name": "Second-Blank-Cheque", "all_permissions": True})
    assert r.status_code == 200 and r.json()["all_permissions"] is True
    assert set(r.json()["permissions"]) == set(ALL_PERMISSIONS)


def test_full_access_can_be_switched_on_for_an_existing_group(client):
    c, s = client
    _login(c, "chef")
    c.post("/api/admins/groups", json={"name": "Team", "permissions": ["logs"]})
    r = c.put("/api/admins/groups/Team", json={"all_permissions": True})
    assert r.status_code == 200 and r.json()["all_permissions"] is True
    assert set(r.json()["permissions"]) == set(ALL_PERMISSIONS)


def test_superadmin_sees_every_tab_even_without_groups(client, monkeypatch):
    c, s = client
    s.create("emergency", "password1")
    monkeypatch.setattr(settings, "superadmin_users", "emergency")
    me = c.post("/api/auth/login", json={"username": "emergency", "password": "password1"}).json()
    assert me["is_admin"] is True
    assert set(me["permissions"]) == set(ALL_PERMISSIONS)


# ── The emergency route through the CLI ────────────────────────────
# These tests have a concrete backstory: after the switch to group-based permissions the
# CLI kept calling ``store.update(permissions=...)`` and ``store.create(permissions=...)``,
# neither of which exists any more. That killed the emergency route, in precisely the
# situation it exists for.


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_cli_grants_full_access_without_the_ui(store, capsys):
    import manage

    store.create("chef", "password1")
    manage.cmd_perms(_Args(username="chef", admin=True, perms="", group="", ad=False))

    assert set(store.get_active("chef")["permissions"]) == set(ALL_PERMISSIONS)
    group = next(g for g in store.list_groups() if g["name"] == "Administrators")
    # As a flag, not as a list, or it goes stale with the next new permission.
    assert group["all_permissions"] is True


def test_cli_grants_partial_rights(store):
    import manage

    store.create("bob", "password1")
    manage.cmd_perms(_Args(username="bob", admin=False, perms="logs,overview", group="", ad=False))
    assert set(store.get_active("bob")["permissions"]) == {"logs", "overview"}


def test_cli_refuses_unknown_account(store):
    import manage

    with pytest.raises(SystemExit):
        manage.cmd_perms(_Args(username="doesnotexist", admin=True, perms="", group="", ad=False))


def test_cli_can_grant_to_an_ad_account(store):
    """AD accounts have no local account: membership goes by name."""
    import manage

    manage.cmd_perms(_Args(username="max.example", admin=True, perms="", group="", ad=True))
    assert store.effective_for_ad("max.example", set()) == ALL_PERMISSIONS


def test_cli_sets_full_access_on_an_existing_group(store):
    """The everyday case: you are authorized through a group that is missing the new
    permissions. The user interface is a dead end there, because only someone who already
    holds everything may grant full access."""
    import manage

    store.create("alice", "password1")
    store.create_group(
        "Administrators", PARTIAL_ADMIN,
        members=[{"type": "local", "ref": "alice"}, {"type": "ad_group", "ref": "ZS-Admins"}],
    )
    assert store.get_active("alice")["is_admin"] is False

    manage.cmd_group(_Args(name="Administrators", admin=True, no_admin=False, perms=""))

    assert store.get_active("alice")["is_admin"] is True
    group = next(g for g in store.list_groups() if g["name"] == "Administrators")
    assert group["all_permissions"] is True
    # Memberships stay untouched, including the AD group.
    assert {m["ref"] for m in group["members"]} == {"alice", "ZS-Admins"}


def test_cli_group_name_is_case_insensitive(store):
    import manage

    store.create_group("Administrators", {"logs"})
    manage.cmd_group(_Args(name="administrators", admin=True, no_admin=False, perms=""))
    assert next(g for g in store.list_groups() if g["name"] == "Administrators")["all_permissions"] is True


def test_cli_group_switch_off_keeps_the_rights(store):
    """Switching it off must not empty the group, or everyone loses everything."""
    import manage

    store.create_group("Team", {"logs", "overview"}, all_permissions=True)
    manage.cmd_group(_Args(name="Team", admin=False, no_admin=True, perms=""))
    group = next(g for g in store.list_groups() if g["name"] == "Team")
    assert group["all_permissions"] is False
    assert set(group["permissions"]) == {"logs", "overview"}


def test_cli_group_rejects_unknown_name(store):
    import manage

    with pytest.raises(SystemExit):
        manage.cmd_group(_Args(name="DoesNotExist", admin=True, no_admin=False, perms=""))


# ── Service and CLI on the same file ───────────────────────────────
# Backstory: on the production system the CLI set full access, and the next sign-in in the
# running service undid it again. Both hold their own copy in memory, and whoever writes
# last wins. The service writes on a login already (touch_login).


def test_running_service_does_not_clobber_cli_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "superadmin_users", "")

    service = AdminStore()
    service.create("admin", "password1")
    service.create_group(
        "Administrators", {"logs", "overview", PERM_ACCOUNTS},
        members=[{"type": "local", "ref": "admin"}],
    )

    # A second process (the CLI) sets full access.
    AdminStore().set_group_permissions("Administrators", ALL_PERMISSIONS, all_permissions=True)

    # Any write in the service; the change used to get lost right here.
    service.touch_login("admin")

    on_disk = AdminStore().list_groups()[0]
    assert on_disk["all_permissions"] is True
    assert set(on_disk["permissions"]) == set(ALL_PERMISSIONS)


def test_running_service_sees_cli_changes_without_restart(tmp_path, monkeypatch):
    """Otherwise you would have to restart the service just to grant permissions."""
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "superadmin_users", "")

    service = AdminStore()
    service.create("admin", "password1")
    service.create_group("Administrators", {"logs"}, members=[{"type": "local", "ref": "admin"}])
    assert service.get_active("admin")["is_admin"] is False

    AdminStore().set_group_permissions("Administrators", ALL_PERMISSIONS, all_permissions=True)

    assert service.get_active("admin")["is_admin"] is True


def test_external_deletion_of_a_group_is_picked_up(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "superadmin_users", "")

    service = AdminStore()
    service.create("admin", "password1")
    service.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": "admin"}],
                         all_permissions=True)
    service.create_group("Temp", {"logs"}, members=[{"type": "local", "ref": "admin"}])

    AdminStore().delete_group("Temp")
    assert [g["name"] for g in service.list_groups()] == ["Admins"]
