"""Test isolation: the suite must not depend on local configuration.

Without this, the developer's ``.env`` decides the outcome. Concretely,
``SESSION_COOKIE_SECURE=true`` makes the test client throw away every session cookie
(httpx does not send Secure cookies over ``http://testserver``), which makes around
twenty tests fail with HTTP 401 even though the code is fine.

So the env file is switched off and a fixed, harmless set of values is applied BEFORE
``backend.config`` is imported for the first time. pytest loads this module ahead of all
test modules, so that ordering holds reliably.
"""
from __future__ import annotations

import os

# Read no env file (see backend/config.py: APP_ENV_FILE).
os.environ["APP_ENV_FILE"] = ""

# Explicit test values. In pydantic-settings, environment variables take precedence over
# the env file, but we disable that file anyway; this is the authoritative state.
os.environ.update(
    {
        "APP_ENV": "dev",
        "JWT_SECRET": "test-secret-not-used-in-production-but-long-enough",
        # The core of the problem: over http:// the cookie must not be Secure.
        "SESSION_COOKIE_SECURE": "false",
        "SESSION_COOKIE_SAMESITE": "lax",
        # No bootstrap admin: the tests create their own accounts.
        "ADMIN_INITIAL_USER": "",
        "ADMIN_INITIAL_PASSWORD": "",
        "SUPERADMIN_USERS": "",
        "SUPERADMIN_AD_GROUP": "",
        # Directory service and SSO off, so that no network access happens.
        "LDAP_SERVER": "",
        "LDAP_DOMAIN": "",
        "LDAP_BASE_DN": "",
        "LDAP_BIND_USER": "",
        "LDAP_BIND_PASSWORD": "",
        "OIDC_ENABLED": "false",
        "OIDC_ISSUER": "",
        "OIDC_CLIENT_ID": "",
        "OIDC_CLIENT_SECRET": "",
        # No TCP listeners in tests: parallel runs would otherwise collide on the ports.
        "INGEST_ENABLED": "false",
        # Fixed UI defaults, so that expected values in tests stay stable.
        "APP_NAME": "ZIA Live-Flow",
        "DEFAULT_LANGUAGE": "en",
        "USER_DOMAIN_SUFFIX": "@example.com",
        "FEED_TIMEZONE": "UTC",
    }
)


# ── Settings isolation between tests ───────────────────────────────
# ``backend.config.settings`` is a module-level singleton, and several modules change
# it directly rather than through monkeypatch (``oidc_config.update`` and
# ``ldap_config.update`` both do, because that is exactly their job at runtime). A
# value left behind by one test therefore reaches the next one, which showed up as
# tests that pass alone and alone fail in a full run.
#
# Snapshotting every field around each test removes that whole class of flakiness,
# instead of patching whichever assertion happened to notice it.
import pytest  # noqa: E402  (must come after the environment is prepared above)

from backend.config import _OVERLAY, settings  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_settings():
    before = {name: getattr(settings, name) for name in type(settings).model_fields}
    overlay_token = _OVERLAY.set({})
    try:
        yield
    finally:
        _OVERLAY.reset(overlay_token)
        for name, value in before.items():
            if getattr(settings, name) != value:
                setattr(settings, name, value)
