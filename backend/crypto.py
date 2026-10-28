"""Symmetric encryption for stored secrets (Fernet/AES).

Used for the LDAP **bind password** that is entered in the admin backend. It is stored
encrypted (``backend/data/ldap_config.json``) and can never be read back in clear text:
the API only ever returns ``ldap_bind_password_set: true``.

Key: ``APP_ENCRYPTION_KEY`` (a Fernet key, base64 over 32 bytes). If it is missing, one is
derived deterministically from ``JWT_SECRET``. Note that rotating ``JWT_SECRET`` without a
dedicated key set makes previously encrypted secrets undecryptable, so they have to be
entered again.

"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from backend.config import settings
from backend.logging_config import get_logger

log = get_logger("crypto")


def _derive_key() -> bytes:
    raw = settings.app_encryption_key.strip()
    if raw:
        # Expects a valid Fernet key (base64, 32 bytes). Otherwise fall back to derivation.
        try:
            Fernet(raw.encode())
            return raw.encode()
        except (ValueError, TypeError):
            log.warning(
                "crypto.invalid_app_key",
                hint="APP_ENCRYPTION_KEY is not a valid Fernet key; deriving one from JWT_SECRET.",
            )
    digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


_fernet: Fernet | None = None


def _cipher() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_derive_key())
    return _fernet


def reset_cipher() -> None:
    """For tests and key changes: forces re-derivation on the next access."""
    global _fernet
    _fernet = None


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    return _cipher().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _cipher().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        log.error("crypto.decrypt_failed", hint="Secret could not be decrypted (key changed?).")
        return ""
