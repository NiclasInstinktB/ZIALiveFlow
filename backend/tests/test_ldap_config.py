"""Runtime LDAP config in the admin backend: persistence, Fernet bind password, .env
fallback. The AD-group-to-permission mapping now lives in the account store; all that is
left here is the one-off migration (:func:`take_legacy_group_permissions`)."""
from __future__ import annotations

import json

import pytest

from backend import crypto, ldap_config
from backend.config import settings


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    p = tmp_path / "ldap_config.json"
    monkeypatch.setattr(ldap_config, "_PATH", p)
    for name, val in (
        ("ldap_server", ""), ("ldap_domain", ""), ("ldap_base_dn", ""),
        ("ldap_bind_user", ""), ("ldap_bind_password", ""), ("ldap_port", 0),
        ("ldap_use_ssl", True),
    ):
        monkeypatch.setattr(settings, name, val)
    monkeypatch.setattr(settings, "app_encryption_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "unit-test-secret-key-1234567890")
    crypto.reset_cipher()
    yield p
    crypto.reset_cipher()


# ── Connection config plus the encrypted bind password ─────────────
def test_update_persists_and_applies(cfg):
    ldap_config.update({
        "ldap_server": "gc://dc01.example.com",
        "ldap_domain": "example.com",
        "ldap_base_dn": "DC=example,DC=com",
    })
    assert settings.ldap_server == "gc://dc01.example.com" and settings.ldap_configured is True
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["ldap_server"] == "gc://dc01.example.com"


def test_bind_password_encrypted_and_never_public(cfg):
    ldap_config.update({"ldap_bind_user": "svc", "ldap_bind_password": "s3cr3t!"})
    assert settings.ldap_bind_password == "s3cr3t!"
    blob = json.dumps(json.loads(cfg.read_text(encoding="utf-8")))
    assert "s3cr3t!" not in blob and "ldap_bind_password_enc" in blob
    pub = ldap_config.current_public()
    assert "ldap_bind_password" not in pub and pub["ldap_bind_password_set"] is True


def test_password_kept_when_omitted(cfg):
    ldap_config.update({"ldap_bind_password": "keepme"})
    ldap_config.update({"ldap_bind_user": "svc"})  # no password in this update
    assert settings.ldap_bind_password == "keepme"


def test_password_cleared_with_empty_string(cfg):
    ldap_config.update({"ldap_bind_password": "gone"})
    ldap_config.update({"ldap_bind_password": ""})
    assert settings.ldap_bind_password == ""
    assert "ldap_bind_password_enc" not in json.loads(cfg.read_text(encoding="utf-8"))


def test_load_and_apply_roundtrip_decrypts(cfg, monkeypatch):
    ldap_config.update({
        "ldap_server": "dc01", "ldap_domain": "d", "ldap_base_dn": "DC=d",
        "ldap_bind_password": "pw", "ldap_port": 3269, "ldap_use_ssl": True,
    })
    monkeypatch.setattr(settings, "ldap_server", "")
    monkeypatch.setattr(settings, "ldap_bind_password", "")
    monkeypatch.setattr(settings, "ldap_port", 0)
    ldap_config.load_and_apply()
    assert settings.ldap_server == "dc01" and settings.ldap_port == 3269
    assert settings.ldap_bind_password == "pw"  # decrypted


def test_port_is_clamped(cfg):
    ldap_config.update({"ldap_port": 999999})
    assert settings.ldap_port == 65535


def test_env_fallback_when_no_file(cfg, monkeypatch):
    monkeypatch.setattr(settings, "ldap_server", "env-dc.example.com")
    ldap_config.load_and_apply()  # no file present, so nothing is overwritten
    assert settings.ldap_server == "env-dc.example.com"


# ── One-off migration of the legacy group mapping ───────────────────
def test_take_legacy_group_permissions_extracts_and_clears(cfg):
    ldap_config.update({"ldap_server": "dc", "ldap_domain": "d", "ldap_base_dn": "DC=d"})
    # Write the legacy data straight into the file (the update path no longer knows these fields).
    raw = json.loads(cfg.read_text(encoding="utf-8"))
    raw["group_permissions"] = [{"group": "G", "permissions": ["logs", "bogus"]}]
    raw["default_permissions"] = ["overview"]
    cfg.write_text(json.dumps(raw), encoding="utf-8")

    extracted = ldap_config.take_legacy_group_permissions()
    assert extracted == [{"group": "G", "permissions": ["logs"]}]  # unknown permissions filtered out
    after = json.loads(cfg.read_text(encoding="utf-8"))
    assert "group_permissions" not in after and "default_permissions" not in after  # removed
    assert after["ldap_server"] == "dc"  # the connection fields stay
    assert ldap_config.take_legacy_group_permissions() == []  # idempotent


def test_take_legacy_returns_empty_without_legacy_keys(cfg):
    ldap_config.update({"ldap_server": "dc"})
    assert ldap_config.take_legacy_group_permissions() == []
