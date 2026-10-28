"""Auth data model: the authenticated user for the duration of one request.

Authorization runs on **granular permissions**, no longer on a single role. An account
holds a set of permissions; ``admin`` means all of them. A new permission is added to
``PERMISSIONS`` (plus a gate on the route in question).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ── Permissions ────────────────────────────────────────────────────
# Order = display order in the UI. To extend: add an entry here, give it a label in
# PERMISSION_LABELS and set ``require_permission`` on the route. No role rework needed.
PERM_LOGS = "logs"          # see live flow and view: clear text, all fields
PERM_LOGS_OBF = "logs_obf"  # live flow, but personal fields masked (see below)
PERM_OVERVIEW = "overview"  # overview / live status
PERM_SETTINGS = "settings"  # settings (retention/buffer/session) plus global chips
PERM_ACCOUNTS = "accounts"  # manage accounts
PERM_LDAP = "ldap"          # configure AD/LDAP
PERM_AUDIT = "audit"        # view the audit log
PERM_UPDATE = "update"      # trigger a self-update

PERMISSIONS: tuple[str, ...] = (
    PERM_LOGS, PERM_LOGS_OBF, PERM_OVERVIEW, PERM_SETTINGS, PERM_ACCOUNTS,
    PERM_LDAP, PERM_AUDIT, PERM_UPDATE,
)

PERMISSION_LABELS: dict[str, str] = {
    PERM_LOGS: "Logs (live flow)",
    PERM_LOGS_OBF: "Logs anonymized (no personal data)",
    PERM_OVERVIEW: "Overview",
    PERM_SETTINGS: "Settings",
    PERM_ACCOUNTS: "Accounts",
    PERM_LDAP: "AD/LDAP",
    PERM_AUDIT: "Audit log",
    PERM_UPDATE: "Update",
}

ALL_PERMISSIONS: frozenset[str] = frozenset(PERMISSIONS)
# Baseline permissions of a "normal" user (formerly the ``viewer`` role).
VIEWER_PERMISSIONS: frozenset[str] = frozenset({PERM_LOGS, PERM_OVERVIEW})

# Permissions that each grant access to the live flow on their own. ``logs`` beats
# ``logs_obf``: whoever holds both sees clear text.
LOG_PERMISSIONS: frozenset[str] = frozenset({PERM_LOGS, PERM_LOGS_OBF})

# ── Legacy roles (only still used to migrate existing accounts/tokens) ──
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"


def normalize_permissions(values) -> frozenset[str]:
    """Arbitrary input → a valid permission set (unknown entries are discarded)."""
    if not values:
        return frozenset()
    return frozenset(v for v in values if v in PERMISSIONS)


def permissions_for_role(role: str | None) -> frozenset[str]:
    """Legacy role → permission set (migration). admin or unknown → all, viewer → baseline."""
    if (role or "").strip().lower() == ROLE_VIEWER:
        return VIEWER_PERMISSIONS
    return ALL_PERMISSIONS  # admin OR missing (legacy accounts were admins)


@dataclass
class Principal:
    """Signed-in user (session): a local or AD account, together with its permissions."""

    username: str
    display_name: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    source: str = "local"

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def can_read_logs(self) -> bool:
        """May see the live flow at all, either in clear text OR anonymized."""
        return bool(LOG_PERMISSIONS & self.permissions)

    @property
    def logs_obfuscated(self) -> bool:
        """Only the anonymized permission? Then personal fields are masked and the user
        filter is blocked (see ``ingest/redact.py``). ``logs`` (clear text) wins: whoever
        holds both sees everything."""
        return not self.has(PERM_LOGS) and self.has(PERM_LOGS_OBF)

    @property
    def is_admin(self) -> bool:
        """Full admin = holds ALL permissions (only for display and shortcuts)."""
        return ALL_PERMISSIONS <= self.permissions

    @property
    def is_ad(self) -> bool:
        """AD account? Then no local password change (the password lives in AD)."""
        return self.source == SOURCE_AD


# ── Account source ─────────────────────────────────────────────────
# local → account in admins.json (local password, break glass; also works while AD is
#         down).
# ad    → signed in via AD/LDAP and mirrored into the store just in time (NO local
#         password; permissions and display name come from AD on every sign-in).
SOURCE_LOCAL = "local"
SOURCE_AD = "ad"
SOURCES = (SOURCE_LOCAL, SOURCE_AD)


def normalize_source(value: str | None) -> str:
    """Unknown or empty source → local (safe default, backwards compatible)."""
    v = (value or "").strip().lower()
    return v if v in SOURCES else SOURCE_LOCAL


# ── Group members ───────────────────────────────────────────────────
# A group (a local app container) carries a permission set and a member list. Every
# member is a typed reference:
#   local    → a local account (by username)
#   ad_user  → an AD person (by sAMAccountName)
#   ad_group → an AD group (by CN); everyone AD says is in it counts as a member
# A person's effective permissions = the union of the permissions of ALL groups they are
# a member of (directly or through one of their AD groups). There are NO direct account
# permissions any more: permissions only ever arrive through groups.
MEMBER_LOCAL = "local"
MEMBER_AD_USER = "ad_user"
MEMBER_AD_GROUP = "ad_group"
MEMBER_TYPES = (MEMBER_LOCAL, MEMBER_AD_USER, MEMBER_AD_GROUP)


def normalize_member_type(value: str | None) -> str | None:
    """A valid member type, or ``None`` if unknown."""
    v = (value or "").strip().lower()
    return v if v in MEMBER_TYPES else None
