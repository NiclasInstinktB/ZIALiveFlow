# ============================================================================
#  ZIA Live-Flow backend
# ============================================================================
"""FastAPI entry point: app factory, lifespan, routers, TCP ingest, frontend.

Start (locally):
    uvicorn backend.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend import __version__ as APP_VERSION
from backend import runtime  # sets the process start time (uptime)  # noqa: F401
from backend import audit, chips_store, ldap_config, oidc_config, settings_store
from backend.api import (
    admin_routes,
    auth_routes,
    chips_routes,
    prefs_routes,
    sso_routes,
    stream_routes,
)
from backend.auth.store import get_admin_store
from backend.config import PROJECT_ROOT, settings
from backend.ingest.tcp_server import start_ingest, stop_ingest
from backend.ingest.timestamps import zone_label
from backend.logging_config import get_logger, setup_logging

setup_logging()
log = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Apply the stored admin settings before anything else reads them. The hardening
    # checks, the time zone resolution and the startup log below all report settings,
    # so running this later would make them describe the env file instead of what the
    # instance is actually configured to do. serve.py has already done this, which is
    # how the bind address gets applied; calling it again here is cheap and keeps a
    # bare "uvicorn backend.main:app" correct for everything except the bind address.
    settings_store.load_and_apply()
    # Remember what we actually came up with, so the admin UI can still say "needs a
    # restart" after a page reload rather than only in the reply to the save.
    settings_store.mark_boot_state()

    log.info(
        "app.startup",
        version=APP_VERSION,
        app_env=settings.app_env,
        ingest_enabled=settings.ingest_enabled,
        retention_minutes=settings.retention_minutes,
    )

    # ── Hardening checks ──────────────────────────────────────────
    if settings.is_production and settings.jwt_secret_is_default:
        raise RuntimeError(
            "Production detected, but JWT_SECRET is still the placeholder. Please set a long, "
            "random JWT_SECRET (e.g. `python -c \"import secrets;print(secrets.token_urlsafe(48))\"`)."
        )
    if settings.is_production and not settings.session_cookie_secure:
        log.warning("security.cookie_insecure", hint="Production: set SESSION_COOKIE_SECURE=true behind TLS.")

    # Apply the persisted LDAP config (admin backend); .env is only bootstrap/fallback.
    ldap_config.load_and_apply()

    # One-off migration: pull the old AD-group-to-permission mapping out of the LDAP
    # config and into the account store (AD groups are now maintained under "Accounts",
    # just like local accounts). Default permissions are dropped without replacement.
    _legacy_groups = ldap_config.take_legacy_group_permissions()
    if _legacy_groups:
        get_admin_store().import_legacy_groups(_legacy_groups)

    # AD/LDAP login (optional, in parallel with local accounts). Just a note in the log,
    # so it is immediately visible in operation whether the shared AD login is active.
    if settings.ldap_configured:
        log.info(
            "auth.ldap_enabled",
            server=settings.ldap_server,
            domain=settings.ldap_domain,
            group_mappings=len(get_admin_store().list_groups()),
        )
    elif any(v.strip() for v in (settings.ldap_server, settings.ldap_domain, settings.ldap_base_dn)):
        log.warning(
            "auth.ldap_partial_config",
            hint="LDAP_SERVER, LDAP_DOMAIN and LDAP_BASE_DN must ALL be set, otherwise the AD login stays off.",
        )

    # Apply the persisted OIDC/SSO config (admin backend); .env is only a fallback.
    oidc_config.load_and_apply()
    if settings.oidc_configured:
        log.info("auth.sso_enabled", issuer=settings.oidc_issuer, client_id=settings.oidc_client_id)
    elif settings.oidc_enabled:
        log.warning(
            "auth.sso_partial_config",
            hint="OIDC_ENABLED=true, but issuer, client ID or client secret is incomplete, so SSO stays off.",
        )

    # Resolve the feed zone early: a typo in FEED_TIMEZONE would otherwise only surface
    # with the first web record, and then as a silently wrong time.
    # zone_label() logs the error and falls back to UTC.
    log.info("feed.timezone", value=zone_label())

    # Create the first admin (if the store is empty).
    get_admin_store().seed_if_empty()

    # Seed the global query chips with the verdict filters on first start.
    chips_store.seed_if_empty()

    # Clean up expired daily audit files (retention).
    audit.prune()

    # Start the TCP feed listeners.
    await start_ingest()

    yield

    await stop_ingest()
    log.info("app.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=APP_VERSION,
        description="Live troubleshooting for ZIA web and firewall logs (NSS stream, filtered, scored).",
        lifespan=lifespan,
    )

    # "*" together with credentials is not "open to everyone", it is worse than it
    # looks: Starlette answers a cookie-carrying request by echoing the requesting
    # origin back with Access-Control-Allow-Credentials, so ANY page on the internet
    # could call this API with the visitor's session and read the answer, which undoes
    # the permission check on every route. An operator who types "*" into the settings
    # form gets the wildcard they asked for, but without credentials.
    origins = settings.cors_origin_list
    allow_credentials = "*" not in origins
    if not allow_credentials:
        log.warning(
            "security.cors_wildcard",
            hint="CORS_ORIGINS='*' cannot carry the session cookie. List the origins explicitly.",
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health", tags=["system"])
    async def health() -> dict:
        return {
            "status": "ok",
            "version": APP_VERSION,
            "retention_minutes": settings.retention_minutes,
            "ingest_enabled": settings.ingest_enabled,
            # Tells the public login page whether to offer the SSO button.
            "sso_enabled": settings.oidc_configured,
            # Branding for the login page, which renders before any session exists and
            # therefore cannot read these from /api/auth/me.
            "app_name": settings.app_name.strip(),
            "default_language": settings.default_language.strip().lower(),
            "source_url": settings.source_url.strip(),
        }

    app.include_router(auth_routes.router)
    app.include_router(sso_routes.router)
    app.include_router(prefs_routes.router)
    app.include_router(chips_routes.router)
    app.include_router(stream_routes.router)
    app.include_router(admin_routes.router)

    # Serve the frontend build (if present) under /, for a single-origin deployment.
    dist = PROJECT_ROOT / "frontend" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="frontend")
        log.info("frontend.mounted", path=str(dist))

    return app


app = create_app()
