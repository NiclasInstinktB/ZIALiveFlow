#!/usr/bin/env python3
"""ZIA Live-Flow: administration CLI (for the Linux server).

Uses the backend code directly (account store, config). Live metrics of a
running server (buffer, throughput) come from the admin backend in the web UI.
This CLI works off **disk plus a port probe**, so it runs whether or not the
server is up.

    python manage.py status                 # detailed status
    python manage.py status --json          # machine-readable
    python manage.py users                  # list accounts
    python manage.py useradd -u max --admin              # create + full access
    python manage.py useradd -u max --perms logs,overview
    python manage.py passwd max
    python manage.py perms max --admin                   # full access (break-glass route)
    python manage.py perms max --perms logs,audit        # partial permissions
    python manage.py perms m.mustermann --ad --admin     # AD account
    python manage.py groups                              # groups + members
    python manage.py group Administrators --admin       # grant a group full access
    python manage.py enable|disable|delete max

Permissions are attached to **groups** only; ``perms`` creates the matching
group or adds the account to it. Available permissions: logs, logs_obf,
overview, settings, accounts, ldap, audit, update. This is the way in when
nobody can reach the web UI any more: there you may only grant permissions you
hold yourself (escalation brake), while on the server that limit does not apply.

Short form via ./manage.sh (activates the venv automatically).
"""
from __future__ import annotations

import argparse
import getpass
import json
import socket
import sys
import time

from backend import __version__ as APP_VERSION
from backend import settings_store
from backend.auth.models import (
    ALL_PERMISSIONS,
    MEMBER_AD_USER,
    MEMBER_LOCAL,
    PERMISSIONS,
    VIEWER_PERMISSIONS,
)
from backend.auth.store import LastAdminError, get_admin_store
from backend.config import settings


# ── Helpers ────────────────────────────────────────────────────────
def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    if port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_host() -> str:
    # 0.0.0.0 is not a connectable target address, so probe locally via loopback.
    h = settings.ingest_bind_host
    return "127.0.0.1" if h in ("0.0.0.0", "", "::") else h


def _ask_password(confirm: bool = True) -> str:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Repeat password: ")
        if pw != pw2:
            sys.exit("Passwords do not match.")
    if len(pw) < 8:
        sys.exit("Password must be at least 8 characters long.")
    return pw


def _resolve_perms(args) -> set[str]:
    """``--admin`` grants every permission, ``--perms a,b,c`` is validated, otherwise the baseline set."""
    if getattr(args, "admin", False):
        return set(ALL_PERMISSIONS)
    raw = (getattr(args, "perms", "") or "").strip()
    if not raw:
        return set(VIEWER_PERMISSIONS)
    perms = {p.strip() for p in raw.split(",") if p.strip()}
    unknown = perms - set(PERMISSIONS)
    if unknown:
        sys.exit(f"Unknown permissions: {', '.join(sorted(unknown))}. Allowed: {', '.join(PERMISSIONS)}")
    return perms


def _perm_label(u: dict) -> str:
    return "admin (all)" if u["is_admin"] else (", ".join(u["permissions"]) or "(none)")


# ── Commands ───────────────────────────────────────────────────────
def cmd_status(args: argparse.Namespace) -> int:
    settings_store.load_and_apply()  # include persisted overrides
    store = get_admin_store()
    host = _probe_host()
    data = {
        "version": APP_VERSION,
        "app_env": settings.app_env,
        "is_production": settings.is_production,
        "web_ui": {
            "host": settings.app_host,
            "port": settings.app_port,
            "reachable": _port_open("127.0.0.1", settings.app_port),
        },
        "ingest": {
            "enabled": settings.ingest_enabled,
            "bind_host": settings.ingest_bind_host,
            "web_port": settings.ingest_web_port,
            "fw_port": settings.ingest_fw_port,
            "web_listening": _port_open(host, settings.ingest_web_port),
            "fw_listening": _port_open(host, settings.ingest_fw_port),
        },
        "retention_minutes": settings.retention_minutes,
        "buffer_max_records": settings.buffer_max_records,
        "session": {
            "idle_minutes": settings.session_idle_minutes,
            "ttl_minutes": settings.session_ttl_minutes,
            "cookie_secure": settings.session_cookie_secure,
        },
        "accounts": store.counts(),
        "data": {
            "admin_store": str(settings.admin_store_file),
            "runtime_settings": str(settings_store._PATH),
        },
        "security": {
            "jwt_secret_is_default": settings.jwt_secret_is_default,
        },
    }
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    def yn(b: bool) -> str:
        return "yes" if b else "NO"

    c = data["accounts"]
    print(f"ZIA Live-Flow {data['version']}  ({data['app_env']})")
    print("─" * 52)
    print(f"Web UI       {settings.app_host}:{settings.app_port}   reachable: {yn(data['web_ui']['reachable'])}")
    ing = data["ingest"]
    print(f"Ingest       enabled: {yn(ing['enabled'])}   bind: {ing['bind_host']}")
    print(f"  Web feed   port {ing['web_port']}   listening: {yn(ing['web_listening'])}")
    print(f"  FW feed    port {ing['fw_port']}   listening: {yn(ing['fw_listening'])}")
    print(f"Retention    {data['retention_minutes']} min   buffer cap {data['buffer_max_records']:,}")
    print(f"Session      idle {data['session']['idle_minutes']} min, ttl {data['session']['ttl_minutes']} min, "
          f"cookie-secure {yn(data['session']['cookie_secure'])}")
    print(f"Accounts     {c['total']} total, {c['admins']} admin, {c['viewers']} non-admin, "
          f"{c['enabled']} enabled, {c['disabled']} disabled")
    print(f"Store        {data['data']['admin_store']}")
    if data["security"]["jwt_secret_is_default"]:
        print("WARNING      JWT_SECRET is still the placeholder. Set a real one before production!")
    if data["is_production"] and not data["session"]["cookie_secure"]:
        print("WARNING      Production without SESSION_COOKIE_SECURE. Set it to true behind TLS.")
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    users = get_admin_store().list()
    if args.json:
        print(json.dumps(users, indent=2))
        return 0
    if not users:
        print("(no accounts)")
        return 0
    print(f"{'USER':<18} {'SOURCE':<6} {'STATUS':<12} PERMISSIONS")
    print("─" * 72)
    for u in users:
        st = "enabled" if u["enabled"] else "disabled"
        src = "AD" if u.get("source") == "ad" else "local"
        print(f"{u['username']:<18} {src:<6} {st:<12} {_perm_label(u)}")
    return 0


def cmd_useradd(args: argparse.Namespace) -> int:
    """Create an account. It does NOT get permissions here; those come from groups
    (``manage.py perms <user> --admin``)."""
    pw = args.password or _ask_password()
    if len(pw) < 8:
        sys.exit("Password must be at least 8 characters long.")
    try:
        u = get_admin_store().create(args.username, pw, args.display or "")
    except ValueError as e:
        sys.exit(str(e))
    print(f"Account created: {u['username']} (no permissions yet).")
    if getattr(args, "admin", False) or (getattr(args, "perms", "") or "").strip():
        return cmd_perms(args)
    print(f"Grant permissions with: manage.py perms {u['username']} --admin")
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    pw = _ask_password()
    try:
        get_admin_store().update(args.username, password=pw)
    except KeyError:
        sys.exit("User not found.")
    print(f"Password for {args.username} changed.")
    return 0


def cmd_perms(args: argparse.Namespace) -> int:
    """Grant permissions through a group, because that is the only place they live.

    This is the break-glass route for when nobody can reach the web UI any more.
    Permissions are attached to groups only, and in the UI nobody can hand out a
    permission they do not hold themselves (escalation brake), not even to their
    own account. On the server that brake does not apply.
    """
    store = get_admin_store()
    username = args.username.strip()
    ad = getattr(args, "ad", False)
    mtype = MEMBER_AD_USER if ad else MEMBER_LOCAL

    if not ad and not store.account_exists(username):
        sys.exit(f"Account '{username}' not found. Create it with: manage.py useradd -u {username}")

    full = getattr(args, "admin", False)
    if not full and not (args.perms or "").strip():
        sys.exit("Please pass --perms a,b,c or --admin.")

    # Pick the target group: --admin uses the full-access group, otherwise a named
    # one. Full access is stored as a FLAG so the group picks up future permissions
    # automatically instead of freezing today's list.
    name = (getattr(args, "group", "") or "").strip() or ("Administrators" if full else f"CLI {username}")
    existing = next((g for g in store.list_groups() if g["name"].lower() == name.lower()), None)
    perms = _resolve_perms(args) if not full else set(ALL_PERMISSIONS)

    try:
        if existing is None:
            store.create_group(name, perms, all_permissions=full)
            print(f"Group '{name}' created.")
        else:
            name = existing["name"]
            store.set_group_permissions(name, perms, all_permissions=True if full else None)
        store.add_member(name, mtype, username)
    except (ValueError, KeyError) as e:
        sys.exit(str(e))

    if ad:
        print(f"{username} (AD) is a member of '{name}'. Permissions take effect at the NEXT sign-in.")
        return 0
    u = store.get_active(username) or {}
    print(f"{username} → group '{name}' → permissions: {_perm_label(u) if u else '(none)'}")
    return 0


def cmd_group(args: argparse.Namespace) -> int:
    """Set the permissions of ONE group without touching memberships.

    The case this exists for: you are authorized through a group that lacks
    exactly the permissions you now need. The UI is a dead end there, because
    only someone who already holds everything may grant full access, and the
    missing permissions are precisely why you do not.
    """
    store = get_admin_store()
    name = args.name.strip()
    existing = next((g for g in store.list_groups() if g["name"].lower() == name.lower()), None)
    if existing is None:
        known = ", ".join(g["name"] for g in store.list_groups()) or "none"
        sys.exit(f"Group '{name}' not found. Available: {known}")
    name = existing["name"]

    if args.no_admin:
        # Touch only the flag: with the flag set, the public view already reports
        # ALL permissions. Writing those back would freeze full access as a fixed
        # list instead of switching it off.
        store.set_group_permissions(name, None, all_permissions=False)
    elif args.admin:
        store.set_group_permissions(name, ALL_PERMISSIONS, all_permissions=True)
    elif (args.perms or "").strip():
        store.set_group_permissions(name, _resolve_perms(args), all_permissions=False)
    else:
        sys.exit("Please pass --admin, --no-admin or --perms a,b,c.")

    g = next(x for x in store.list_groups() if x["name"] == name)
    rights = "ALL (including future ones)" if g["all_permissions"] else (", ".join(g["permissions"]) or "(none)")
    print(f"Group '{name}' → permissions: {rights}")
    members = [m for m in g["members"] if m["type"] == MEMBER_LOCAL]
    if members:
        print("Members do NOT have to sign in again (local accounts read their permissions per request).")
    if any(m["type"] != MEMBER_LOCAL for m in g["members"]):
        print("AD members have to sign in again ONCE, because their permissions sit in the session token.")
    return 0


def cmd_groups(args: argparse.Namespace) -> int:
    """List groups with their permissions and members."""
    groups = get_admin_store().list_groups()
    if not groups:
        print("No groups.")
        return 0
    for g in groups:
        rights = "ALL (including future ones)" if g.get("all_permissions") else (", ".join(g["permissions"]) or "(none)")
        members = ", ".join(f"{m['type']}:{m['ref']}" for m in g["members"]) or "none"
        print(g["name"])
        print(f"  Permissions: {rights}")
        print(f"  Members    : {members}")
    return 0


def _set_enabled(username: str, enabled: bool) -> int:
    try:
        u = get_admin_store().update(username, enabled=enabled)
    except KeyError:
        sys.exit("User not found.")
    except LastAdminError as e:
        sys.exit(str(e))
    print(f"{u['username']} → {'enabled' if u['enabled'] else 'disabled'}")
    return 0


def cmd_enable(args: argparse.Namespace) -> int:
    return _set_enabled(args.username, True)


def cmd_disable(args: argparse.Namespace) -> int:
    return _set_enabled(args.username, False)


def cmd_delete(args: argparse.Namespace) -> int:
    if not args.yes:
        ans = input(f"Really delete account '{args.username}'? [y/N] ").strip().lower()
        if ans not in ("j", "ja", "y", "yes"):
            print("aborted.")
            return 1
    try:
        get_admin_store().delete(args.username)
    except KeyError:
        sys.exit("User not found.")
    except LastAdminError as e:
        sys.exit(str(e))
    print(f"Account {args.username} deleted.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="manage.py", description="ZIA Live-Flow administration")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="Detailed server and account status")
    s.add_argument("--json", action="store_true", help="machine-readable")
    s.set_defaults(func=cmd_status)

    lu = sub.add_parser("users", help="List accounts")
    lu.add_argument("--json", action="store_true")
    lu.set_defaults(func=cmd_users)

    ua = sub.add_parser("useradd", help="Create an account")
    ua.add_argument("-u", "--username", required=True)
    ua.add_argument("--admin", action="store_true", help="all permissions")
    ua.add_argument("--perms", default="", help=f"permissions, comma-separated ({', '.join(PERMISSIONS)})")
    ua.add_argument("-d", "--display", default="", help="display name")
    ua.add_argument("-p", "--password", default="", help="password (otherwise asked interactively)")
    ua.set_defaults(func=cmd_useradd)

    pw = sub.add_parser("passwd", help="Set a password (interactive)")
    pw.add_argument("username")
    pw.set_defaults(func=cmd_passwd)

    pe = sub.add_parser("perms", help="Grant permissions (through a group)")
    pe.add_argument("username")
    pe.add_argument("--perms", default="", help=f"permissions, comma-separated ({', '.join(PERMISSIONS)})")
    pe.add_argument("--admin", action="store_true", help="full access (all permissions, including future ones)")
    pe.add_argument("--group", default="", help="target group (default: 'Administrators' or 'CLI <user>')")
    pe.add_argument("--ad", action="store_true", help="AD account (member by sAMAccountName)")
    pe.set_defaults(func=cmd_perms)

    gr = sub.add_parser("groups", help="List groups with their permissions and members")
    gr.set_defaults(func=cmd_groups)

    gp = sub.add_parser("group", help="Set the permissions of a group (without changing members)")
    gp.add_argument("name", help="group name, e.g. Administrators")
    gp.add_argument("--admin", action="store_true", help="full access (all permissions, including future ones)")
    gp.add_argument("--no-admin", action="store_true", dest="no_admin", help="turn off full access")
    gp.add_argument("--perms", default="", help=f"permissions, comma-separated ({', '.join(PERMISSIONS)})")
    gp.set_defaults(func=cmd_group)

    en = sub.add_parser("enable", help="Enable an account")
    en.add_argument("username")
    en.set_defaults(func=cmd_enable)

    di = sub.add_parser("disable", help="Disable an account")
    di.add_argument("username")
    di.set_defaults(func=cmd_disable)

    de = sub.add_parser("delete", help="Delete an account")
    de.add_argument("username")
    de.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    de.set_defaults(func=cmd_delete)

    return p


def main() -> None:
    # Keep the Windows console (cp1252) from choking on box-drawing and special
    # characters; Linux is UTF-8 anyway.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
