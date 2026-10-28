"""Anonymized log view (the ``logs_obf`` permission).

Covers the three places where the anonymization stands or falls: masking the fields,
blocking the user filter, and the permission migration (an update must not take the admin
status away from existing full admins).
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.api.stream_routes import _parse_filters
from backend.auth import store as store_module
from backend.auth.models import (
    ALL_PERMISSIONS,
    PERM_LOGS,
    PERM_LOGS_OBF,
    PERM_OVERVIEW,
    Principal,
)
from backend.auth.store import AdminStore, get_admin_store
from backend.config import settings
from backend.ingest.hub import Hub
from backend.ingest.models import FilterField
from backend.ingest.redact import MASK, REDACTED_FIELDS, redact, redact_all


def _web(src="10.0.0.1", user="max.muster@example.com"):
    """One web line (39 fields, order matching WEB_COLUMNS), as in test_hub.py."""
    return [
        "web", src, "1.1.1.1", user, "Site-1", "Mon Jul 21 10:00:00 2026", "IT-Operations", "Allowed", "",
        "HTTPS", "GET", "200", "800", "24000", "https://host/path", "host", "Cat", "Class",
        "App", "AppClass", "Rule", "RuleType", "TLSv1.3", "TLS_AES", "TLSv1.3", "", "", "0",
        "203.0.113.9", "UA", "NB-EXAMPLE", "Max Example", "text/html",
        "Yes", "SSL-Pol", "", "URL-Pol", "Fwd-Rule", "GW-DE",
    ]


# ── Masking ────────────────────────────────────────────────────────
def test_redact_masks_personal_fields():
    hub = Hub()
    for _ in range(16):  # the sample buffer fills on a sample basis (every 16th line)
        hub.handle_fields(_web())
    record = hub.recent_samples()[-1]
    assert record["user"] == "max.muster@example.com"  # precondition: clear text in the buffer

    masked = redact(record)
    assert masked["user"] == MASK
    assert masked["dept"] == MASK
    assert masked["device_name"] == MASK
    assert masked["device_owner"] == MASK
    # Everything that is not personal stays usable for troubleshooting.
    assert masked["src_ip"] == "10.0.0.1"
    assert masked["target"] == "https://host/path"
    assert masked["location"] == "Site-1"
    assert masked["verdict"] == record["verdict"]


def test_redact_does_not_mutate_original():
    # The hub hands ONE payload dict to all views, so masking in place would black out
    # the clear-text view of the other (authorized) users as well.
    original = {"user": "a@b.de", "dept": "IT", "src_ip": "10.0.0.1"}
    masked = redact(original)
    assert original["user"] == "a@b.de" and original["dept"] == "IT"
    assert masked["user"] == MASK and masked is not original


def test_redact_keeps_empty_fields_empty():
    # Empty stays empty, or "***" would suggest a value that never existed.
    masked = redact({f: "" for f in REDACTED_FIELDS})
    assert all(masked[f] == "" for f in REDACTED_FIELDS)


def test_redact_all_masks_every_record():
    records = redact_all([{"user": "a@b.de"}, {"user": "c@d.de"}])
    assert [r["user"] for r in records] == [MASK, MASK]


# ── Permission logic ───────────────────────────────────────────────
def _p(*perms) -> Principal:
    return Principal("u", "U", frozenset(perms))


def test_permission_matrix():
    assert _p(PERM_LOGS).can_read_logs and not _p(PERM_LOGS).logs_obfuscated
    assert _p(PERM_LOGS_OBF).can_read_logs and _p(PERM_LOGS_OBF).logs_obfuscated
    # Clear text wins: whoever holds both sees everything.
    both = _p(PERM_LOGS, PERM_LOGS_OBF)
    assert both.can_read_logs and not both.logs_obfuscated
    # No log permission means no access.
    assert not _p(PERM_OVERVIEW).can_read_logs


# ── Filter block (the user field) ──────────────────────────────────
def _specs(groups):
    return [s for g in groups for s in g.items]


def test_user_filter_denied_when_obfuscated():
    raw = [{"field": "user", "value": "max@example.com"}, {"field": "src_ip", "value": "10.0.0.1"}]
    groups, _join, denied = _parse_filters({"filters": raw}, obfuscated=True)
    assert denied == ["user"]
    assert [s.field for s in _specs(groups)] == [FilterField.SRC_IP]


def test_user_filter_allowed_in_plaintext_view():
    raw = [{"field": "user", "value": "max@example.com"}]
    groups, _join, denied = _parse_filters({"filters": raw}, obfuscated=False)
    assert denied == [] and [s.field for s in _specs(groups)] == [FilterField.USER]


def test_other_fields_survive_obfuscation():
    raw = [{"field": "dst_ip", "value": "1.1.1.1"}, {"field": "location", "value": "Site-1"}]
    groups, _join, denied = _parse_filters({"filters": raw}, obfuscated=True)
    assert denied == [] and len(_specs(groups)) == 2


def test_user_filter_denied_inside_group():
    """The user filter is blocked in the group form too: a group that would be left with
    nothing but the user drops out entirely."""
    msg = {
        "join": "and",
        "groups": [
            {"op": "or", "items": [{"field": "user", "value": "max@example.com"}]},
            {"op": "or", "items": [{"field": "src_ip", "value": "10.0.0.1"}]},
        ],
    }
    groups, join, denied = _parse_filters(msg, obfuscated=True)
    assert denied == ["user"]
    assert join.value == "and"
    assert len(groups) == 1
    assert [s.field for s in _specs(groups)] == [FilterField.SRC_IP]


# ── Store migration v4 ─────────────────────────────────────────────
def test_migration_grants_logs_obf_to_full_admins(tmp_path, monkeypatch):
    """A schema 3 data set: the full-admin group does not know ``logs_obf`` yet. After the
    migration it must hold it, or every admin would suddenly be only a partial manager
    (``is_admin`` means "holds every permission")."""
    old_perms = sorted(ALL_PERMISSIONS - {PERM_LOGS_OBF})
    path = tmp_path / "admins.json"
    path.write_text(
        json.dumps({
            "schema": 3,
            "accounts": [{
                "username": "admin", "display_name": "Admin", "source": "local",
                "enabled": True, "password_hash": "x", "created_at": "2026-01-01T00:00:00+00:00",
            }],
            "groups": [
                {"name": "Administrators", "permissions": old_perms,
                 "members": [{"type": "local", "ref": "admin"}], "created_at": ""},
                {"name": "Viewers", "permissions": ["logs", "overview"],
                 "members": [{"type": "ad_group", "ref": "ZS-Readers"}], "created_at": ""},
            ],
            "prefs": {}, "ad_identities": {},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "admin_store_path", str(path))
    store = AdminStore()

    groups = {g["name"]: set(g["permissions"]) for g in store.list_groups()}
    assert groups["Administrators"] == set(ALL_PERMISSIONS)
    assert store.get_active("admin")["is_admin"] is True
    # Partial groups stay untouched: whoever sees clear text is not silently anonymized.
    assert groups["Viewers"] == {"logs", "overview"}


# ── HTTP / WebSocket layer ─────────────────────────────────────────
@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    s = get_admin_store()
    s.create("admin", "password1")
    s.create_group("Administrators", ALL_PERMISSIONS, members=[{"type": "local", "ref": "admin"}])
    s.create("obf", "password1")
    s.create_group("Anonymized", {PERM_LOGS_OBF}, members=[{"type": "local", "ref": "obf"}])
    s.create("blind", "password1")
    s.create_group("No-Logs", {PERM_OVERVIEW}, members=[{"type": "local", "ref": "blind"}])

    from backend.main import app

    def login(username: str) -> TestClient:
        c = TestClient(app)
        assert c.post("/api/auth/login", json={"username": username, "password": "password1"}).status_code == 200
        return c

    return login


def test_samples_endpoint_masked_for_obfuscated_user(env):
    from backend.ingest import hub as hub_module

    hub = hub_module.get_hub()
    for _ in range(16):
        hub.handle_fields(_web())

    plain = env("admin").get("/api/stream/samples").json()["records"]
    assert plain and plain[-1]["user"] == "max.muster@example.com"

    masked = env("obf").get("/api/stream/samples").json()["records"]
    assert masked and masked[-1]["user"] == MASK
    assert masked[-1]["device_owner"] == MASK and masked[-1]["dept"] == MASK
    # The restricted permission is what opens the endpoint at all; with none it is a 403.
    assert env("blind").get("/api/stream/samples").status_code == 403


def test_ws_rejects_user_filter_when_obfuscated(env):
    with env("obf").websocket_connect("/api/stream/ws") as ws:
        ws.receive_json()  # the greeting snapshot
        ws.send_json({"type": "set_filters", "filters": [
            {"field": "user", "value": "max.muster@example.com"},
            {"field": "src_ip", "value": "10.0.0.1"},
        ]})
        msg = ws.receive_json()
        assert msg["denied_fields"] == ["user"]
        # Only the IP filter made it to the server.
        assert [f["field"] for f in msg["stats"]["filters"]] == ["src_ip"]


def test_ws_allows_user_filter_in_plaintext_view(env):
    with env("admin").websocket_connect("/api/stream/ws") as ws:
        ws.receive_json()
        ws.send_json({"type": "set_filters", "filters": [{"field": "user", "value": "max.muster@example.com"}]})
        msg = ws.receive_json()
        assert msg["denied_fields"] == []
        assert [f["field"] for f in msg["stats"]["filters"]] == ["user"]


def test_ws_accepts_filter_groups(env):
    """The group form over the wire: (source A OR source B) AND destination C."""
    with env("admin").websocket_connect("/api/stream/ws") as ws:
        ws.receive_json()
        ws.send_json({
            "type": "set_filters",
            "join": "and",
            "groups": [
                {"op": "or", "items": [
                    {"field": "src_ip", "value": "10.6.32.0/24"},
                    {"field": "src_ip", "value": "10.6.34.0/24"},
                ]},
                {"op": "or", "items": [{"field": "dst_ip", "value": "198.51.100.135"}]},
            ],
        })
        stats = ws.receive_json()["stats"]
        assert stats["join"] == "and"
        assert [g["op"] for g in stats["groups"]] == ["or", "or"]
        assert [len(g["items"]) for g in stats["groups"]] == [2, 1]
        # The flat list is kept for counters and display.
        assert [f["field"] for f in stats["filters"]] == ["src_ip", "src_ip", "dst_ip"]


def test_ws_closed_without_any_log_permission(env):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with env("blind").websocket_connect("/api/stream/ws") as ws:
            ws.receive_json()


def test_parse_feeds_from_set_filters():
    from backend.api.stream_routes import _parse_feeds

    assert _parse_feeds({}) is None                          # older client, so all feeds
    assert _parse_feeds({"feeds": ["WEB", "dns"]}) == frozenset({"web", "dns"})
    assert _parse_feeds({"feeds": ["smtp"]}) is None         # nothing known, so all feeds
    assert _parse_feeds({"feeds": "dns"}) is None            # not an array, so ignored


def test_ws_stats_carry_feed_state(env):
    """Every stats payload states whether the feed is alive, so an empty table can be
    told apart from a dead connection."""
    with env("admin").websocket_connect("/api/stream/ws") as ws:
        feed = ws.receive_json()["stats"]["feed"]
        assert set(feed) == {"ever", "stale", "idle_seconds"}
        assert isinstance(feed["ever"], bool) and isinstance(feed["stale"], bool)
        assert isinstance(feed["idle_seconds"], int)
        ws.send_json({
            "type": "set_filters",
            "feeds": ["dns"],
            "groups": [{"op": "or", "items": [{"field": "src_ip", "value": "10.0.0.1"}]}],
        })
        stats = ws.receive_json()["stats"]
        assert stats["feeds"] == ["dns"]
        assert set(stats["feed"]) == {"ever", "stale", "idle_seconds"}


def test_feed_state_reports_silence(monkeypatch):
    """A feed that has gone quiet must be distinguishable from one that never ran."""
    from backend.api import stream_routes
    from backend.ingest import hub as hub_module

    fresh = Hub()
    monkeypatch.setattr(hub_module, "_hub", fresh)
    assert stream_routes._feed_state() == {"ever": False, "stale": False, "idle_seconds": 0}

    fresh.handle_fields(_web())
    state = stream_routes._feed_state()
    assert state["ever"] is True and state["stale"] is False

    # Threshold of 0 seconds: the line that just arrived already counts as too old.
    monkeypatch.setattr(settings, "feed_stale_after_seconds", 0)
    assert stream_routes._feed_state()["stale"] is True


# ── Losing the clear-text permission while the stream runs ─────────
def test_ws_drops_the_user_filter_when_clear_text_is_revoked(env, monkeypatch):
    """Masking a running stream is only half the job.

    The stream re-checks the session every few seconds and starts masking when the
    clear-text permission goes away. A ``user`` filter set while the permission was
    still there keeps running though, and that is exactly the oracle the filter block
    exists to prevent: the records arrive masked, but every one of them belongs to the
    named person, and the source IP, device and target are not masked at all.
    """
    from backend.api import stream_routes

    monkeypatch.setattr(stream_routes, "_STATS_INTERVAL_S", 0.05)
    store = get_admin_store()
    store.create("both", "password1")
    store.create_group("Both", {PERM_LOGS, PERM_LOGS_OBF},
                       members=[{"type": "local", "ref": "both"}])

    with env("both").websocket_connect("/api/stream/ws") as ws:
        ws.receive_json()
        ws.send_json({"type": "set_filters",
                      "filters": [{"field": "user", "value": "max.muster@example.com"}]})
        assert [f["field"] for f in ws.receive_json()["stats"]["filters"]] == ["user"]

        # Clear text revoked: the account keeps only the anonymized permission.
        store.set_group_permissions("Both", {PERM_LOGS_OBF})

        filters = None
        for _ in range(60):
            msg = ws.receive_json()
            filters = msg["stats"]["filters"]
            if not filters:
                break
        assert filters == [], f"the user filter is still running while masked: {filters}"


def test_ws_closes_when_every_log_permission_is_revoked(env, monkeypatch):
    """Losing clear text masks the stream; losing both permissions has to end it."""
    from starlette.websockets import WebSocketDisconnect

    from backend.api import stream_routes

    monkeypatch.setattr(stream_routes, "_STATS_INTERVAL_S", 0.05)
    store = get_admin_store()
    store.create("fleeting", "password1")
    store.create_group("Fleeting", {PERM_LOGS_OBF},
                       members=[{"type": "local", "ref": "fleeting"}])

    with pytest.raises(WebSocketDisconnect):
        with env("fleeting").websocket_connect("/api/stream/ws") as ws:
            ws.receive_json()
            store.set_group_permissions("Fleeting", {PERM_OVERVIEW})
            for _ in range(60):
                ws.receive_json()
