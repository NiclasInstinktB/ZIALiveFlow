"""In-memory brake against login brute force.

Deliberately plain and **generous**: failed attempts are counted per key (IP plus
username) in a sliding window. Only from ``login_max_failures`` failures on does a short,
**rolling** lockout kick in (HTTP 429), and it expires by itself as soon as the oldest
failures drop out of the window. A successful login clears the counter right away
(``reset``), i.e. "off once you are logged in".

The state lives purely in process memory (single-worker uvicorn): nothing is persisted,
and resetting on restart is intended and harmless.
"""
from __future__ import annotations

import threading
import time

from backend.config import settings


class LoginThrottle:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key → ascending list of failure timestamps (epoch s)
        self._fails: dict[str, list[float]] = {}

    @staticmethod
    def key(ip: str, username: str) -> str:
        return f"{(ip or '?').strip()}|{(username or '').strip().lower()}"

    def _window_seconds(self) -> float:
        return settings.login_window_minutes * 60

    def _prune(self, key: str, now: float) -> list[float]:
        """Drop failures outside the window; remove keys that end up empty."""
        cutoff = now - self._window_seconds()
        items = [t for t in self._fails.get(key, ()) if t >= cutoff]
        if items:
            self._fails[key] = items
        else:
            self._fails.pop(key, None)
        return items

    def retry_after(self, key: str) -> int:
        """0 = free to try. Otherwise the seconds until the next attempt is allowed."""
        now = time.time()
        limit = settings.login_max_failures
        with self._lock:
            items = self._prune(key, now)
            if len(items) < limit:
                return 0
            # Locked until the limit-th most recent failure drops out of the window.
            oldest_relevant = items[-limit]
            wait = int(oldest_relevant + self._window_seconds() - now)
            return max(1, wait)

    def record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            items = self._prune(key, now)
            items.append(now)
            self._fails[key] = items

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


_throttle: LoginThrottle | None = None


def get_throttle() -> LoginThrottle:
    global _throttle
    if _throttle is None:
        _throttle = LoginThrottle()
    return _throttle
