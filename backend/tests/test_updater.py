"""The self-update path: who may fire it, what reaches git, and what a failure does.

The updater shells out to git and writes a trigger file that a systemd ``.path`` unit
watches. Three things matter here: the branch name comes from the admin form, so it
must never become part of a command; a failure has to reach the caller instead of
reporting a successful start; and the trigger needs the ``update`` permission.
"""
from __future__ import annotations

import subprocess

import pytest
from fastapi.testclient import TestClient

from backend import updater
from backend.auth import store as store_module
from backend.auth.models import PERM_OVERVIEW, PERM_UPDATE
from backend.auth.store import AdminStore
from backend.config import settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    store = store_module.get_admin_store()
    for name, perms in (("updater", {PERM_UPDATE}), ("watcher", {PERM_OVERVIEW})):
        store.create(name, "password1")
        store.create_group(f"G-{name}", perms, members=[{"type": "local", "ref": name}])

    from backend.main import app

    def login(username: str) -> TestClient:
        c = TestClient(app)
        assert c.post(
            "/api/auth/login", json={"username": username, "password": "password1"}
        ).status_code == 200
        return c

    return login


# ── Who may fire it ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "method,path",
    [("get", "/api/admin/update"), ("post", "/api/admin/update/check"), ("post", "/api/admin/update/run")],
)
def test_update_endpoints_need_the_update_permission(client, method, path):
    assert getattr(client("watcher"), method)(path).status_code == 403


def test_update_endpoints_reject_an_anonymous_caller(client):
    from backend.main import app

    anonymous = TestClient(app)
    assert anonymous.post("/api/admin/update/run").status_code == 401


# ── The branch name never becomes a command ────────────────────────
def test_branch_name_is_one_argument_and_no_shell(monkeypatch):
    """``update_branch`` is free text in the admin form.

    git is called with an argument list and without a shell, so metacharacters stay
    part of the revision name and cannot start a second command.
    """
    calls: list[dict] = []

    def fake_run(args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        done = subprocess.CompletedProcess(args, 0, stdout="true", stderr="")
        if args[1:3] == ["rev-list", "--count"]:
            done.stdout = "0"
        return done

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    monkeypatch.setattr(settings, "update_branch", "main; touch pwned")
    result = updater.check()

    assert result["ok"] is True
    assert calls, "git was never called"
    for call in calls:
        assert isinstance(call["args"], list) and call["args"][0] == "git"
        assert not call["kwargs"].get("shell")
        for arg in call["args"]:
            assert ";" not in arg or arg.startswith(("origin/", "HEAD..origin/"))
    revisions = [a for c in calls for a in c["args"] if "touch pwned" in a]
    assert revisions and all(r.startswith(("origin/", "HEAD..origin/")) for r in revisions)


# ── A failure is reported, not swallowed ───────────────────────────
def test_failed_fetch_is_reported(monkeypatch):
    def fake_run(args, **kwargs):
        if args[1] == "rev-parse":
            return subprocess.CompletedProcess(args, 0, stdout="true", stderr="")
        return subprocess.CompletedProcess(args, 128, stdout="", stderr="fatal: could not read from remote")

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    result = updater.check()
    assert result["ok"] is False
    assert "could not read from remote" in result["error"]


def test_fetch_timeout_is_reported(monkeypatch):
    def fake_run(args, **kwargs):
        if args[1] == "rev-parse":
            return subprocess.CompletedProcess(args, 0, stdout="true", stderr="")
        raise subprocess.TimeoutExpired(args, 45)

    monkeypatch.setattr(updater.subprocess, "run", fake_run)
    assert updater.check()["ok"] is False


def test_unwritable_trigger_is_reported(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(updater, "_TRIGGER", blocker / "logs" / "update.trigger")
    result = updater.trigger_update()
    assert result["triggered"] is False and result["error"]


def test_route_turns_a_failed_trigger_into_an_error(client, monkeypatch):
    from backend.api import admin_routes

    monkeypatch.setattr(
        admin_routes.updater, "trigger_update", lambda: {"triggered": False, "error": "disk full"}
    )
    resp = client("updater").post("/api/admin/update/run")
    assert resp.status_code == 500
    assert "disk full" in resp.text


def test_successful_trigger_writes_the_file(client, tmp_path, monkeypatch):
    from backend.api import admin_routes

    target = tmp_path / "logs" / "update.trigger"
    monkeypatch.setattr(admin_routes.updater, "_TRIGGER", target)
    monkeypatch.setattr(updater, "_TRIGGER", target)
    resp = client("updater").post("/api/admin/update/run")
    assert resp.status_code == 200 and resp.json()["triggered"] is True
    assert target.exists()
