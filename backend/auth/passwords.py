"""Password hashing for local admin accounts.

Deliberately **standard library only** (PBKDF2-HMAC-SHA256), so no extra dependency (no
passlib, no bcrypt). The stored value is a self-describing string
``pbkdf2_sha256$<iterations>$<salt>$<hash>`` (salt and hash base64url, no padding), so the
iteration count and the salt travel with the hash.

Comparison is constant time (``hmac.compare_digest``). Clear-text passwords are never
stored or logged.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_ALGO = "pbkdf2_sha256"
# OWASP recommendation (2023) for PBKDF2-HMAC-SHA256.
_DEFAULT_ITERATIONS = 600_000
_SALT_BYTES = 16


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str, *, iterations: int = _DEFAULT_ITERATIONS) -> str:
    """Produces a PHC-like hash string for ``password``."""
    if not password:
        raise ValueError("Password must not be empty.")
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Checks ``password`` against a string produced by :func:`hash_password`.

    Returns ``False`` for an empty or malformed hash or a wrong password; never raises.
    """
    if not password or not stored:
        return False
    try:
        algo, iter_str, salt_b64, hash_b64 = stored.split("$")
        if algo != _ALGO:
            return False
        iterations = int(iter_str)
        salt = _unb64(salt_b64)
        expected = _unb64(hash_b64)
    except (ValueError, AttributeError):
        return False
    if iterations <= 0:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(dk, expected)
