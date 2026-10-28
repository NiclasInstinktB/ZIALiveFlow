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


# ── Only what the operator actually changed reaches the file ───────
# The admin form posts the whole draft, so every connection field arrives on every
# save, including the ones that are still on their .env value and were never touched.
def test_save_stores_only_the_changed_field(cfg, monkeypatch):
    monkeypatch.setattr(settings, "ldap_server", "env-dc.example.com")
    monkeypatch.setattr(settings, "ldap_domain", "env.example.com")
    ldap_config.update({
        "ldap_server": "env-dc.example.com",
        "ldap_domain": "env.example.com",
        "ldap_base_dn": "",
        "ldap_bind_user": "",
        "ldap_group_attr": "memberOf",
        "ldap_use_ssl": True,
        "ldap_port": 0,
        "ldap_connect_timeout_seconds": 11,  # the only edit
    })
    assert json.loads(cfg.read_text(encoding="utf-8")) == {"ldap_connect_timeout_seconds": 11}


def test_save_without_a_single_change_writes_nothing(cfg):
    ldap_config.update({
        "ldap_server": "", "ldap_domain": "", "ldap_base_dn": "", "ldap_bind_user": "",
        "ldap_group_attr": "memberOf", "ldap_use_ssl": True, "ldap_port": 0,
        "ldap_connect_timeout_seconds": 5,
    })
    assert not cfg.exists()


def test_env_value_stays_changeable_after_a_save(cfg, monkeypatch):
    """An untouched field must not be frozen into the file by an unrelated save."""
    monkeypatch.setattr(settings, "ldap_server", "env-dc.example.com")
    ldap_config.update({"ldap_server": "env-dc.example.com", "ldap_bind_user": "svc"})
    assert "ldap_server" not in json.loads(cfg.read_text(encoding="utf-8"))

    # The operator edits LDAP_SERVER in the env file and restarts.
    monkeypatch.setattr(settings, "ldap_server", "new-dc.example.com")
    ldap_config.load_and_apply()
    assert settings.ldap_server == "new-dc.example.com"


# ── A rejected batch must apply nothing ────────────────────────────
def test_invalid_port_applies_nothing_and_writes_nothing(cfg):
    with pytest.raises(ValueError):
        ldap_config.update({
            "ldap_server": "dc01.example.com",
            "ldap_domain": "example.com",
            "ldap_use_ssl": False,
            "ldap_port": "not-a-number",
        })
    assert settings.ldap_server == ""
    assert settings.ldap_domain == ""
    assert settings.ldap_use_ssl is True
    assert not cfg.exists()


def test_invalid_port_leaves_an_earlier_save_intact(cfg):
    ldap_config.update({"ldap_server": "dc01.example.com"})
    with pytest.raises(ValueError):
        ldap_config.update({"ldap_domain": "example.com", "ldap_port": "nope"})
    assert json.loads(cfg.read_text(encoding="utf-8")) == {"ldap_server": "dc01.example.com"}
    assert settings.ldap_domain == ""


def test_rejected_batch_does_not_touch_the_bind_password(cfg):
    ldap_config.update({"ldap_bind_password": "keepme"})
    with pytest.raises(ValueError):
        ldap_config.update({"ldap_bind_password": "newpw", "ldap_port": "nope"})
    assert settings.ldap_bind_password == "keepme"
    ldap_config.load_and_apply()
    assert settings.ldap_bind_password == "keepme"
    assert "ldap_bind_password" not in ldap_config.current_public()


# ── A damaged file must not stop the app from starting ─────────────
def test_load_survives_a_file_that_is_not_an_object(cfg):
    cfg.write_text("[1, 2, 3]", encoding="utf-8")
    ldap_config.load_and_apply()  # must not raise


def test_update_survives_a_file_that_is_not_an_object(cfg):
    cfg.write_text('"junk"', encoding="utf-8")
    ldap_config.update({"ldap_server": "dc01.example.com"})
    assert json.loads(cfg.read_text(encoding="utf-8"))["ldap_server"] == "dc01.example.com"


def test_take_legacy_survives_a_file_that_is_not_an_object(cfg):
    cfg.write_text("[1, 2, 3]", encoding="utf-8")
    assert ldap_config.take_legacy_group_permissions() == []


def test_load_survives_a_non_string_secret(cfg):
    cfg.write_text(json.dumps({"ldap_bind_password_enc": 12345}), encoding="utf-8")
    ldap_config.load_and_apply()  # must not raise


# ── A secret that cannot be decrypted must not wipe the .env fallback ──
def test_undecryptable_secret_keeps_the_env_password(cfg, monkeypatch):
    """After a JWT_SECRET rotation the stored secret is lost, but .env is the fallback."""
    ldap_config.update({"ldap_bind_password": "stored-pw"})
    monkeypatch.setattr(settings, "jwt_secret", "a-completely-different-secret-9876")
    crypto.reset_cipher()
    monkeypatch.setattr(settings, "ldap_bind_password", "env-pw")
    ldap_config.load_and_apply()
    assert settings.ldap_bind_password == "env-pw"
