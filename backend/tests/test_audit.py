"""Tests for the audit log (record/query/prune/stats, one JSONL file per day)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend import audit
from backend.config import settings


def _use_tmp(tmp_path, monkeypatch):
    d = tmp_path / "audit"
    monkeypatch.setattr(audit, "_DIR", d)
    monkeypatch.setattr(settings, "audit_enabled", True)
    monkeypatch.setattr(settings, "audit_retention_days", 30)
    return d


def test_record_and_query(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    audit.record(audit.LOGIN_OK, user="alice", ip="1.2.3.4", detail="role=admin")
    audit.record(audit.SEARCH, user="alice", ip="1.2.3.4", detail="src_ip=10.0.0.1")
    audit.record(audit.LOGIN_FAIL, user="bob", ip="5.6.7.8")

    entries = audit.query(limit=10)
    assert len(entries) == 3
    assert entries[0]["event"] == audit.LOGIN_FAIL  # newest first

    only_search = audit.query(event=audit.SEARCH)
    assert len(only_search) == 1 and only_search[0]["user"] == "alice"

    assert len(audit.query(user="ALICE")) == 2  # substring, case insensitive


def test_query_limit(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    for i in range(20):
        audit.record(audit.SEARCH, user="u", detail=f"n={i}")
    assert len(audit.query(limit=5)) == 5


def test_disabled_is_noop(tmp_path, monkeypatch):
    d = _use_tmp(tmp_path, monkeypatch)
    monkeypatch.setattr(settings, "audit_enabled", False)
    audit.record(audit.LOGIN_OK, user="x")
    assert audit.query() == []
    assert not d.exists()


def test_prune_removes_old(tmp_path, monkeypatch):
    d = _use_tmp(tmp_path, monkeypatch)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=40)).timestamp()
    audit.record(audit.LOGIN_OK, user="old", ts=old_ts)
    audit.record(audit.LOGIN_OK, user="new")
    assert len(list(d.glob("audit-*.jsonl"))) == 2

    removed = audit.prune()
    assert removed == 1
    assert len(list(d.glob("audit-*.jsonl"))) == 1
    assert all(e["user"] != "old" for e in audit.query())


def test_stats(tmp_path, monkeypatch):
    _use_tmp(tmp_path, monkeypatch)
    audit.record(audit.LOGIN_OK, user="a")
    audit.record(audit.SEARCH, user="a", detail="x=1")
    s = audit.stats()
    assert s["entries"] == 2 and s["files"] == 1 and s["retention_days"] == 30


# ── Which address ends up in the entry ─────────────────────────────
# The peer address is the one the server observed. ``X-Forwarded-For`` is a plain
# request header that any client can set, so an entry built from it is worthless as
# evidence, and the login brake keyed on it (see ``api/auth_routes``) can be stepped
# around by sending a different value on every attempt.
def test_client_ip_uses_the_peer_address():
    assert audit.client_ip({}, "10.0.0.7") == "10.0.0.7"


def test_client_ip_ignores_a_spoofed_forwarded_for():
    headers = {"x-forwarded-for": "203.0.113.9, 198.51.100.1"}
    assert audit.client_ip(headers, "10.0.0.7") == "10.0.0.7"


def test_client_ip_without_a_peer_is_empty():
    assert audit.client_ip({"X-Forwarded-For": "203.0.113.9"}, "") == ""


def test_client_ip_is_length_capped():
    assert len(audit.client_ip({}, "9" * 300)) == 64
