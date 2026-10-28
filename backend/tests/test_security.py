"""Security features: session revocation against the store, the login brake, the ingest
source allowlist, and the wildcard limit (ReDoS protection)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from backend.api.auth_routes import _ensure_grantable
from backend.auth import deps
from backend.auth.models import (
    ALL_PERMISSIONS,
    PERM_ACCOUNTS,
    PERM_LDAP,
    PERM_LOGS,
    PERM_UPDATE,
    VIEWER_PERMISSIONS,
    Principal,
)
from backend.auth.store import AdminStore
from backend.auth.throttle import LoginThrottle
from backend.auth.tokens import create_session_token
from backend.config import settings
from backend.ingest import parser, tcp_server
from backend.ingest.models import FilterField, FilterSpec


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    return AdminStore()


def _admins(store, *members: str) -> None:
    """Helper group 'Admins' (all permissions) with the named local accounts as members."""
    store.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": m} for m in members])


# ── HIGH: validate a running session against the store ─────────────
def test_get_active_returns_enabled_account(store):
    store.create("alice", "password1")
    _admins(store, "alice")
    acc = store.get_active("alice")
    assert acc and acc["is_admin"] is True


def test_get_active_none_for_disabled(store):
    store.create("alice", "password1")
    store.create("boss", "password1")
    _admins(store, "boss")
    store.update("alice", enabled=False)  # alice is not a manager, so she can be disabled
    assert store.get_active("alice") is None


def test_get_active_none_for_missing(store):
    assert store.get_active("ghost") is None


def test_get_active_case_insensitive(store):
    store.create("Alice", "password1")
    assert store.get_active("alice") is not None


def test_validated_principal_uses_store_permissions(store, monkeypatch):
    # The token carries no permissions, so they come fresh from the group membership.
    store.create("carol", "password1")
    store.create("boss", "password1")
    _admins(store, "carol", "boss")  # both are managers
    store.create_group("Logs", {"logs"}, members=[{"type": "local", "ref": "carol"}])
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("carol", "Carol")
    store.remove_member("Admins", "local", "carol")  # demoted (boss stays a manager)
    result = deps._validated_principal(token)
    assert result is not None
    principal, _ = result
    assert principal.permissions == frozenset({"logs"})
    assert principal.is_admin is False
    assert principal.has("logs") and not principal.has("accounts")


def test_validated_principal_rejects_deleted(store, monkeypatch):
    store.create("dave", "password1")
    store.create("boss", "password1")
    _admins(store, "dave", "boss")
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("dave", "Dave")
    store.delete("dave")  # "boss" stays a manager, so this is allowed
    assert deps._validated_principal(token) is None


def test_validated_principal_rejects_disabled(store, monkeypatch):
    store.create("erin", "password1")
    store.create("boss", "password1")
    _admins(store, "boss")
    store.create_group("Viewer", VIEWER_PERMISSIONS, members=[{"type": "local", "ref": "erin"}])
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    token = create_session_token("erin", "Erin")
    store.update("erin", enabled=False)
    assert deps._validated_principal(token) is None


def test_validated_principal_rejects_garbage(store, monkeypatch):
    monkeypatch.setattr(deps, "get_admin_store", lambda: store)
    assert deps._validated_principal("not-a-jwt") is None
    assert deps._validated_principal(None) is None


# ── HIGH: granting must not exceed your own permissions ────────────
def _granter(perms) -> Principal:
    return Principal("bob", "Bob", frozenset(perms))


def test_grantable_allows_subset():
    # Passing on only your own permissions is allowed (no HTTPException).
    _ensure_grantable(_granter({PERM_ACCOUNTS, PERM_LOGS}), frozenset({PERM_LOGS}))
    _ensure_grantable(_granter({PERM_ACCOUNTS}), frozenset())  # no permissions at all is fine


def test_grantable_full_admin_grants_anything():
    _ensure_grantable(_granter(ALL_PERMISSIONS), ALL_PERMISSIONS)  # no error


def test_grantable_blocks_escalation():
    # An account with ONLY 'accounts' must not hand itself 'update' or 'ldap'.
    with pytest.raises(HTTPException) as exc:
        _ensure_grantable(_granter({PERM_ACCOUNTS}), frozenset({PERM_ACCOUNTS, PERM_UPDATE, PERM_LDAP}))
    assert exc.value.status_code == 403


def test_grantable_blocks_single_excess_permission():
    with pytest.raises(HTTPException) as exc:
        _ensure_grantable(_granter({PERM_ACCOUNTS, PERM_LOGS}), frozenset({PERM_ACCOUNTS, PERM_UPDATE}))
    assert exc.value.status_code == 403


# ── Login brake (brute force) ──────────────────────────────────────
def test_throttle_generous_then_locks(monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    monkeypatch.setattr(settings, "login_window_minutes", 5)
    t = LoginThrottle()
    k = t.key("10.0.0.1", "alice")
    for _ in range(3):
        assert t.retry_after(k) == 0
        t.record_failure(k)
    assert t.retry_after(k) > 0


def test_throttle_reset_on_success(monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    t = LoginThrottle()
    k = t.key("10.0.0.1", "alice")
    for _ in range(3):
        t.record_failure(k)
    assert t.retry_after(k) > 0
    t.reset(k)
    assert t.retry_after(k) == 0


def test_throttle_key_normalizes_user_and_separates_ip():
    t = LoginThrottle()
    assert t.key("10.0.0.1", "Alice") == t.key("10.0.0.1", "alice")
    assert t.key("10.0.0.1", "a") != t.key("10.0.0.2", "a")


# ── Ingest source allowlist ────────────────────────────────────────
def test_ingest_allowlist_empty_allows_all(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "")
    assert tcp_server._peer_allowed(("10.9.9.9", 5140)) is True


def test_ingest_allowlist_single_ips(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.0.0.10, 10.0.0.11")
    assert tcp_server._peer_allowed(("10.0.0.10", 5140)) is True
    assert tcp_server._peer_allowed(("10.0.0.11", 6000)) is True
    assert tcp_server._peer_allowed(("10.0.0.99", 5140)) is False


def test_ingest_allowlist_cidr(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.1.0.0/24")
    assert tcp_server._peer_allowed(("10.1.0.55", 5140)) is True
    assert tcp_server._peer_allowed(("10.2.0.55", 5140)) is False


def test_ingest_allowlist_rejects_bad_peer(monkeypatch):
    monkeypatch.setattr(settings, "ingest_allowed_ips", "10.0.0.10")
    assert tcp_server._peer_allowed(None) is False
    assert tcp_server._peer_allowed(("not-an-ip", 5140)) is False


# ── Wildcard limit (ReDoS protection) ──────────────────────────────
def test_wildcard_three_stars_ok():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a*b*c*d")])
    assert len(specs) == 1


def test_wildcard_four_stars_rejected():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a*b*c*d*e")])
    assert specs == []


def test_wildcard_question_marks_not_limited():
    specs = parser.compile_specs([FilterSpec(field=FilterField.USER, value="a?b?c?d?e?f")])
    assert len(specs) == 1
