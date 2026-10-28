"""Signed session tokens (JWT): stateless sessions with no server-side storage.

The token carries the identity (``sub``/``name``), the source (``src``) and the issue and
expiry times.

* **Local** sessions (``src="local"``): the **permissions** are read fresh from the account
  store on every request (see ``auth.deps._validated_principal``), so changes take effect
  immediately.
* **AD sessions** (``src="ad"``): AD users have no account in the store, so the permissions
  computed from their AD groups at login travel along inside the signed token (``perm``).
  Group changes take effect at the next login.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from backend.config import settings


def create_session_token(
    username: str,
    display_name: str,
    source: str = "local",
    permissions=(),
    session_start: int | None = None,
) -> str:
    """Mint a session token.

    ``session_start`` is when the person actually signed in, and it survives every
    renewal. ``iat`` moves each time the cookie is refreshed, so on its own it cannot
    answer "how long has this session been going", which is what the renewal cap in
    deps.py needs.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "name": display_name,
        "src": "ad" if source == "ad" else "local",
        "iat": int(now.timestamp()),
        "sst": int(session_start if session_start is not None else now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.session_ttl_minutes)).timestamp()),
    }
    if payload["src"] == "ad":
        payload["perm"] = sorted(permissions or ())
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_session_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None
