"""Self-update from the git repository, driven from the admin backend.

The backend itself performs NO ``git reset`` and NO restart (the service runs
unprivileged). Instead it writes a **trigger** (``logs/update.trigger``); a systemd
``.path`` unit picks that up and runs ``deploy/update.sh`` as the app user, which then
does ``git fetch`` plus ``reset --hard origin/<branch>`` plus the build, and restarts the
service through a narrow sudoers rule.

``status()`` and ``check()`` are read-only (git rev-parse / fetch) and run directly.
"""
from __future__ import annotations

import subprocess
import time

from backend.config import PROJECT_ROOT, settings
from backend.logging_config import get_logger

log = get_logger("updater")

_TRIGGER = PROJECT_ROOT / "logs" / "update.trigger"


def _git(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _is_repo() -> bool:
    try:
        r = _git("rev-parse", "--is-inside-work-tree", timeout=5)
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def status() -> dict:
    """Local git state (fast, no network)."""
    if not _is_repo():
        return {"is_repo": False, "update_branch": settings.update_branch}

    def out(*a: str) -> str:
        try:
            r = _git(*a, timeout=8)
        except subprocess.SubprocessError:
            return ""
        return r.stdout.strip() if r.returncode == 0 else ""

    return {
        "is_repo": True,
        "branch": out("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": out("rev-parse", "HEAD"),
        "commit_short": out("rev-parse", "--short", "HEAD"),
        "subject": out("log", "-1", "--pretty=%s"),
        "committed_at": out("log", "-1", "--pretty=%cI"),
        "remote": out("remote", "get-url", "origin"),
        "dirty": bool(out("status", "--porcelain")),
        "update_branch": settings.update_branch,
    }


def check() -> dict:
    """``git fetch`` plus the number of new commits on origin/<update_branch>."""
    if not _is_repo():
        return {"is_repo": False, "ok": False, "error": "not a git repository"}
    branch = settings.update_branch
    try:
        fetch = _git("fetch", "--prune", "origin", timeout=45)
    except subprocess.SubprocessError as e:
        return {"is_repo": True, "ok": False, "error": f"fetch timeout: {e}"}
    if fetch.returncode != 0:
        return {"is_repo": True, "ok": False, "error": (fetch.stderr or "fetch failed").strip()[:300]}

    def count(rng: str) -> int:
        r = _git("rev-list", "--count", rng, timeout=10)
        try:
            return int(r.stdout.strip()) if r.returncode == 0 else 0
        except ValueError:
            return 0

    behind = count(f"HEAD..origin/{branch}")
    ahead = count(f"origin/{branch}..HEAD")
    latest = _git("log", "-1", "--pretty=%h %s", f"origin/{branch}", timeout=10)
    return {
        "is_repo": True,
        "ok": True,
        "branch": branch,
        "behind": behind,
        "ahead": ahead,
        "update_available": behind > 0,
        "remote_latest": latest.stdout.strip() if latest.returncode == 0 else "",
    }


def trigger_update() -> dict:
    """Kick off an update: write the trigger file (the systemd .path unit runs update.sh)."""
    try:
        _TRIGGER.parent.mkdir(parents=True, exist_ok=True)
        _TRIGGER.write_text(str(int(time.time())), encoding="utf-8")
    except OSError as e:
        log.error("updater.trigger_failed", error=str(e))
        return {"triggered": False, "error": str(e)}
    log.warning("updater.triggered", branch=settings.update_branch, trigger=str(_TRIGGER))
    return {"triggered": True, "branch": settings.update_branch}
