"""AD/LDAP: server construction (scheme/GC/failover), directory search, and AD access via
groups (AD users get NO account, only an identity entry)."""
from __future__ import annotations

import pytest

from backend.auth.ldap_client import authenticate
from backend.auth.models import ALL_PERMISSIONS, PERM_ACCOUNTS, SOURCE_AD, SOURCE_LOCAL, Principal
from backend.auth.store import AdminStore
from backend.config import settings


@pytest.fixture
def store(tmp_path, monkeypatch):
    p = tmp_path / "admins.json"
    monkeypatch.setattr(settings, "admin_store_path", str(p))
    return AdminStore()


def _perms(store) -> dict:
    return {u["username"]: set(u["permissions"]) for u in store.list()}


def test_authenticate_returns_false_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "ldap_server", "")
    monkeypatch.setattr(settings, "ldap_domain", "")
    monkeypatch.setattr(settings, "ldap_base_dn", "")
    assert authenticate("someone", "pw").ok is False


# ── Server construction: scheme/port, global catalog, failover pool ─
def test_build_server_bare_host_inherits_ssl_and_default_port(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import _build_one_server
    monkeypatch.setattr(settings, "ldap_use_ssl", True)
    monkeypatch.setattr(settings, "ldap_port", 0)
    s = _build_one_server(ldap3, "dc01.example.com")
    assert s.host == "dc01.example.com" and s.port == 636 and s.ssl is True


def test_build_server_gc_scheme_overrides_ssl_and_port(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import _build_one_server
    monkeypatch.setattr(settings, "ldap_use_ssl", True)
    monkeypatch.setattr(settings, "ldap_port", 0)
    s = _build_one_server(ldap3, "gc://dc01.example.com")
    assert s.host == "dc01.example.com" and s.port == 3268 and s.ssl is False


def test_build_server_gcs_scheme_is_ssl_3269(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import _build_one_server
    monkeypatch.setattr(settings, "ldap_port", 0)
    s = _build_one_server(ldap3, "gcs://dc01.example.com")
    assert s.port == 3269 and s.ssl is True


def test_build_server_host_port_suffix_wins(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import _build_one_server
    monkeypatch.setattr(settings, "ldap_use_ssl", False)
    monkeypatch.setattr(settings, "ldap_port", 0)
    s = _build_one_server(ldap3, "ldaps://dc01.example.com:3269")
    assert s.host == "dc01.example.com" and s.port == 3269 and s.ssl is True


def test_build_server_explicit_ldap_port_beats_scheme_default(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import _build_one_server
    monkeypatch.setattr(settings, "ldap_use_ssl", False)
    monkeypatch.setattr(settings, "ldap_port", 389)
    s = _build_one_server(ldap3, "gc://dc01.example.com")
    assert s.port == 389


def test_build_ldap_server_single_returns_server(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import build_ldap_server
    monkeypatch.setattr(settings, "ldap_port", 0)
    monkeypatch.setattr(settings, "ldap_server", "dc01.example.com")
    assert isinstance(build_ldap_server(ldap3), ldap3.Server)


def test_build_ldap_server_multiple_returns_pool_capped(monkeypatch):
    import ldap3
    from backend.auth.ldap_client import LDAP_MAX_SERVERS, build_ldap_server
    monkeypatch.setattr(settings, "ldap_port", 0)
    monkeypatch.setattr(settings, "ldap_server", "gc://a, gc://b, gc://c, gc://d, gc://e, gc://f")
    pool = build_ldap_server(ldap3)
    assert isinstance(pool, ldap3.ServerPool) and len(pool.servers) == LDAP_MAX_SERVERS


# ── AD users: permissions via groups, NO account ────────────────────
def test_ad_login_creates_no_account_only_identity(store):
    store.create_group("Log-Readers", {"logs"}, members=[{"type": "ad_user", "ref": "alice"}])
    assert store.effective_for_ad("alice", set()) == frozenset({"logs"})
    ident = store.record_ad_login("alice", "Alice B")
    assert store.list() == []                      # no accounts created
    assert len(ident["id"]) == 36 and ident["last_login"]
    assert store.account_exists("alice") is False  # no account, so no local login
    assert store.verify_login("alice", "anything") is None


def test_ad_identity_is_stable_and_forgettable(store):
    first = store.record_ad_login("u", "U")
    again = store.record_ad_login("u", "U new")
    assert again["id"] == first["id"] and again["display_name"] == "U new"
    store.forget_ad_identity("u")
    assert store.list_ad_identities() == []


def test_ad_permissions_follow_group_changes(store):
    store.create_group("G", {"logs"}, members=[{"type": "ad_group", "ref": "ZS-Net"}])
    assert store.effective_for_ad("u", {"ZS-Net"}) == frozenset({"logs"})
    store.set_group_permissions("G", {"logs", "settings"})
    assert store.effective_for_ad("u", {"zs-net"}) == frozenset({"logs", "settings"})
    store.delete_group("G")
    assert store.effective_for_ad("u", {"ZS-Net"}) == frozenset()


def test_ad_login_collision_with_local_is_detectable(store):
    # Name collision: the local break-glass account wins, and the login path rejects the
    # AD bind (an AD login must NEVER pass as a local account).
    store.create("dup", "password1")  # local
    store.create_group("Admins", ALL_PERMISSIONS, members=[{"type": "local", "ref": "dup"}])
    assert store.account_exists("DUP") is True
    rec = store.get_active("dup")
    assert rec["source"] == SOURCE_LOCAL and rec["is_admin"] is True
    assert store.verify_login("dup", "password1") is not None  # break glass still applies
    assert _perms(store)["dup"] == set(ALL_PERMISSIONS)


def test_local_account_source_is_local(store):
    store.create("alice", "password1")
    assert store.get_active("alice")["source"] == SOURCE_LOCAL


# ── Principal ───────────────────────────────────────────────────────
def test_principal_is_ad_flag():
    assert Principal("u", "U", frozenset({"logs"}), SOURCE_AD).is_ad is True
    assert Principal("u", "U", frozenset({"logs"}), SOURCE_LOCAL).is_ad is False
    assert Principal("u", "U").is_ad is False  # the default is local


# ── Filter building: the identity must not change the shape of the query ──
class _RecordingConn:
    """Stands in for a bound ldap3 connection and just records the filter."""

    def __init__(self) -> None:
        self.filters: list[str] = []
        self.entries: list = []

    def search(self, search_base=None, search_filter="", attributes=None, **kw) -> None:
        self.filters.append(search_filter)


def test_principal_lookup_escapes_the_identity(monkeypatch):
    """A sign-in name is a VALUE in the filter, never part of its structure.

    ``_ldap_escape`` exists in this module for exactly that reason, and the member picker
    uses it. The lookup behind the sign-in and the SSO group load must use it too:
    otherwise a name carrying brackets or a wildcard rewrites the query, and the groups
    of whichever account the rewritten query happens to return are the ones that decide
    the session's permissions.
    """
    from backend.auth.ldap_client import _search_principal

    monkeypatch.setattr(settings, "ldap_domain", "example.com")
    monkeypatch.setattr(settings, "ldap_base_dn", "DC=example,DC=com")
    monkeypatch.setattr(settings, "ldap_group_attr", "memberOf")

    conn = _RecordingConn()
    _search_principal(conn, "bob)(objectClass=*")
    flt = conn.filters[0]

    # Exactly the three clauses the function builds, and no fourth one smuggled in.
    assert flt.count("(") == flt.count(")")
    assert flt.count("objectClass=user") == 1
    assert "objectClass=*" not in flt
    # The wildcard is searched for literally rather than matching every account.
    assert "=*" not in flt.replace("objectClass=*", "")


def test_principal_lookup_leaves_an_ordinary_name_alone(monkeypatch):
    from backend.auth.ldap_client import _search_principal

    monkeypatch.setattr(settings, "ldap_domain", "example.com")
    monkeypatch.setattr(settings, "ldap_base_dn", "DC=example,DC=com")
    monkeypatch.setattr(settings, "ldap_group_attr", "memberOf")

    conn = _RecordingConn()
    _search_principal(conn, "max.example@example.com")
    flt = conn.filters[0]
    assert "(userPrincipalName=max.example@example.com)" in flt
    assert "(sAMAccountName=max.example)" in flt
