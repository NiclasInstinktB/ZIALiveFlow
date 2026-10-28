"""Account store integrity: a rejected write must leave nothing behind, and the file on
disk must never disagree with what the running service believes.

The account store is the only place that decides who may do what, so the failure modes
that matter here are not wrong answers but half-finished ones: a change that is applied
in memory and never persisted, a persisted change that memory never saw, and a reload
that throws away state it could not replace.
"""
from __future__ import annotations

import json
import os

import pytest

from backend.auth.models import ALL_PERMISSIONS
from backend.auth.store import AdminStore, LastAdminError
from backend.config import settings


@pytest.fixture
def path(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    monkeypatch.setattr(settings, "superadmin_users", "")
    monkeypatch.setattr(settings, "superadmin_ad_group", "")
    return p


@pytest.fixture
def solo_admin(path):
    """A store with exactly one local account manager, so the lockout guard bites."""
    s = AdminStore()
    s.create("root", "password1")
    s.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": "root"}])
    return s


def _on_disk(path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ── A rejected account update must apply nothing ───────────────────
def test_rejected_account_update_leaves_the_password_alone(solo_admin):
    """Changing password and 'enabled' in one call, where only 'enabled' is refused.

    The caller is told the whole update failed, so the old password has to keep working.
    """
    with pytest.raises(LastAdminError):
        solo_admin.update("root", password="brandnewpw", enabled=False)

    assert solo_admin.verify_login("root", "password1") is not None
    assert solo_admin.verify_login("root", "brandnewpw") is None


def test_rejected_account_update_leaves_memory_and_disk_in_step(solo_admin, path):
    with pytest.raises(LastAdminError):
        solo_admin.update("root", display_name="Renamed", enabled=False)

    assert solo_admin.get_active("root")["display_name"] == "root"
    stored = next(a for a in _on_disk(path)["accounts"] if a["username"] == "root")
    assert stored["display_name"] == "root"


def test_accepted_account_update_still_applies_everything(path):
    """The counter-check: the guard must not make a legitimate update a no-op."""
    s = AdminStore()
    s.create("root", "password1")
    s.create("second", "password1")
    s.create_group(
        "Admins", ALL_PERMISSIONS,
        members=[{"type": "local", "ref": "root"}, {"type": "local", "ref": "second"}],
    )
    s.update("root", password="brandnewpw", display_name="Renamed", enabled=False)

    assert s.get_active("root") is None  # disabled
    stored = next(a for a in _on_disk(path)["accounts"] if a["username"] == "root")
    assert stored["display_name"] == "Renamed" and stored["enabled"] is False
    s.update("root", enabled=True)
    assert s.verify_login("root", "brandnewpw") is not None


# ── Bootstrap must not stop half way ───────────────────────────────
def test_bootstrap_still_grants_full_access_when_the_name_is_taken(path, monkeypatch):
    """A legacy AD group called "Administrators" must not break the first start.

    ``import_legacy_groups`` runs before ``seed_if_empty`` and names each group after the
    AD group it came from, and "Administrators" is about the most likely CN there is. If
    the bootstrap then creates the account but fails on the group, the installation is
    dead: the account has no permissions and the store is no longer empty, so no later
    start will seed it again.
    """
    monkeypatch.setattr(settings, "admin_initial_user", "root")
    monkeypatch.setattr(settings, "admin_initial_password", "password1")
    s = AdminStore()
    s.import_legacy_groups([{"group": "Administrators", "permissions": ["logs"]}])

    s.seed_if_empty()

    assert set(s.get_active("root")["permissions"]) == set(ALL_PERMISSIONS)
    # The legacy group keeps exactly what it had: the bootstrap must not hand full access
    # to whoever happens to sit in that AD group.
    legacy = next(g for g in s.list_groups() if g["members"] == [{"type": "ad_group", "ref": "Administrators"}])
    assert legacy["permissions"] == ["logs"] and legacy["all_permissions"] is False


# ── A failed reload must not destroy the live state ────────────────
def test_unreadable_file_does_not_wipe_the_running_store(solo_admin, path):
    """A partial write or a transient read error must not empty the account database.

    ``_sync`` reloads whenever the file changed underneath, and the service then keeps
    serving from whatever that load produced. If a failed load counts as "no accounts",
    every session dies at once and the next write (a single sign-in is enough) persists
    the empty store over the file.
    """
    path.write_text('{"schema": 5, "accounts": [{"use', encoding="utf-8")

    assert [a["username"] for a in solo_admin.list()] == ["root"]
    assert solo_admin.verify_login("root", "password1") is not None
    assert [g["name"] for g in solo_admin.list_groups()] == ["Admins"]

    solo_admin.touch_login("root")
    assert [a["username"] for a in _on_disk(path)["accounts"]] == ["root"]


def test_readable_file_is_still_picked_up_after_a_failed_read(solo_admin, path):
    """The counter-check: holding on to the old state must not block the next good read."""
    path.write_text("not json at all", encoding="utf-8")
    assert [a["username"] for a in solo_admin.list()] == ["root"]

    AdminStore()  # a fresh store cannot read it either, so write a good file by hand
    good = {
        "schema": 5,
        "accounts": [{"username": "other", "display_name": "Other", "password_hash": "x",
                      "source": "local", "enabled": True, "created_at": ""}],
        "groups": [], "prefs": {}, "ad_identities": {},
    }
    path.write_text(json.dumps(good), encoding="utf-8")
    assert [a["username"] for a in solo_admin.list()] == ["other"]


# ── Two processes on one file ──────────────────────────────────────
def test_same_size_change_from_another_process_is_not_clobbered(path):
    """The CLI revokes a permission, the running service must not put it back.

    Both hold their own copy in memory and reconcile through the file. Recognising the
    file by (mtime, size) alone is not enough: file timestamps are only accurate to a few
    milliseconds, so a second write inside the same tick that happens to produce the same
    number of bytes (one permission swapped for another of equal length) looks unchanged.
    The service then writes its stale copy back and the revocation is undone.
    """
    service = AdminStore()
    service.create("admin", "password1")
    service.create_group("G", {"logs"}, members=[{"type": "local", "ref": "admin"}])
    before = path.stat()

    AdminStore().set_group_permissions("G", {"ldap"})  # same byte length as {"logs"}

    # Pin the timestamp instead of racing the clock, so the test proves the mechanism
    # rather than the granularity of whichever filesystem it runs on.
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size == before.st_size, "the two writes must be the same size"

    service.touch_login("admin")  # any write in the service
    assert _on_disk(path)["groups"][0]["permissions"] == ["ldap"]


# ── A local account and a directory user sharing a name ────────────
def test_forgetting_a_directory_identity_keeps_the_local_account(path):
    """Identities and accounts are separate namespaces, so housekeeping on one of them
    must not reach into the other. The two can coexist whenever a directory user signed
    in before a local account of that name was created."""
    s = AdminStore()
    s.record_ad_login("bob", "Bob from the directory")
    s.create("bob", "password1")
    s.set_prefs("bob", {"columns": ["a", "b"]})

    s.forget_ad_identity("bob")

    assert s.get_prefs("bob") == {"columns": ["a", "b"]}
    assert s.list_ad_identities() == []
