"""Runtime OIDC/SSO config in the admin backend: persistence, Fernet client secret,
.env fallback, write-only secret, and the enabled/configured flag."""
from __future__ import annotations

import json

import pytest

from backend import crypto, oidc_config
from backend.config import settings


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    p = tmp_path / "oidc_config.json"
    monkeypatch.setattr(oidc_config, "_PATH", p)
    for name, val in (
        ("oidc_enabled", False),
        ("oidc_issuer", ""),
        ("oidc_client_id", ""),
        ("oidc_client_secret", ""),
        ("oidc_redirect_url", ""),
        ("oidc_scopes", "openid profile email"),
    ):
        monkeypatch.setattr(settings, name, val)
    monkeypatch.setattr(settings, "app_encryption_key", "")
    monkeypatch.setattr(settings, "jwt_secret", "unit-test-secret-key-1234567890")
    crypto.reset_cipher()
    yield p
    crypto.reset_cipher()


def test_update_persists_and_applies(cfg):
    oidc_config.update({
        "oidc_enabled": True,
        "oidc_issuer": "https://login.microsoftonline.com/tid/v2.0",
        "oidc_client_id": "client-123",
        "oidc_client_secret": "s3cr3t!",
    })
    assert settings.oidc_enabled is True
    assert settings.oidc_issuer == "https://login.microsoftonline.com/tid/v2.0"
    assert settings.oidc_configured is True
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["oidc_client_id"] == "client-123"


def test_configured_needs_enabled_and_secret(cfg):
    # Complete, but NOT enabled, so not configured.
    oidc_config.update({"oidc_issuer": "iss", "oidc_client_id": "cid", "oidc_client_secret": "sec"})
    assert settings.oidc_configured is False
    oidc_config.update({"oidc_enabled": True})
    assert settings.oidc_configured is True
    # Remove the secret and it is no longer configured.
    oidc_config.update({"oidc_client_secret": ""})
    assert settings.oidc_configured is False


def test_client_secret_encrypted_and_never_public(cfg):
    oidc_config.update({"oidc_client_id": "cid", "oidc_client_secret": "top-secret"})
    assert settings.oidc_client_secret == "top-secret"
    blob = json.dumps(json.loads(cfg.read_text(encoding="utf-8")))
    assert "top-secret" not in blob and "oidc_client_secret_enc" in blob
    pub = oidc_config.current_public()
    assert "oidc_client_secret" not in pub and pub["oidc_client_secret_set"] is True


def test_secret_kept_when_omitted(cfg):
    oidc_config.update({"oidc_client_secret": "keepme"})
    oidc_config.update({"oidc_client_id": "cid"})  # no secret in this update
    assert settings.oidc_client_secret == "keepme"


def test_secret_cleared_with_empty_string(cfg):
    oidc_config.update({"oidc_client_secret": "gone"})
    oidc_config.update({"oidc_client_secret": ""})
    assert settings.oidc_client_secret == ""
    assert "oidc_client_secret_enc" not in json.loads(cfg.read_text(encoding="utf-8"))


def test_load_and_apply_roundtrip_decrypts(cfg, monkeypatch):
    oidc_config.update({
        "oidc_enabled": True, "oidc_issuer": "iss", "oidc_client_id": "cid",
        "oidc_client_secret": "pw", "oidc_scopes": "openid",
    })
    monkeypatch.setattr(settings, "oidc_issuer", "")
    monkeypatch.setattr(settings, "oidc_client_secret", "")
    monkeypatch.setattr(settings, "oidc_enabled", False)
    oidc_config.load_and_apply()
    assert settings.oidc_issuer == "iss" and settings.oidc_enabled is True
    assert settings.oidc_client_secret == "pw"  # decrypted


def test_env_fallback_when_no_file(cfg, monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "env-issuer")
    oidc_config.load_and_apply()  # no file present, so nothing is overwritten
    assert settings.oidc_issuer == "env-issuer"


def test_test_connection_without_issuer(cfg):
    assert oidc_config.test_connection() == {"ok": False, "detail": "Issuer URL is missing."}


# ── Only what the operator actually changed reaches the file ───────
# The SSO form posts the whole draft, so every field arrives on every save, including
# the ones that are still on their .env value and were never touched.
def test_save_stores_only_the_changed_field(cfg, monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "https://env-issuer.example.com")
    oidc_config.update({
        "oidc_enabled": False,
        "oidc_issuer": "https://env-issuer.example.com",
        "oidc_client_id": "",
        "oidc_redirect_url": "https://app.example.com/callback",  # the only edit
        "oidc_scopes": "openid profile email",
    })
    assert json.loads(cfg.read_text(encoding="utf-8")) == {
        "oidc_redirect_url": "https://app.example.com/callback"
    }


def test_save_without_a_single_change_writes_nothing(cfg):
    oidc_config.update({
        "oidc_enabled": False, "oidc_issuer": "", "oidc_client_id": "",
        "oidc_redirect_url": "", "oidc_scopes": "openid profile email",
    })
    assert not cfg.exists()


def test_env_value_stays_changeable_after_a_save(cfg, monkeypatch):
    """An untouched field must not be frozen into the file by an unrelated save."""
    monkeypatch.setattr(settings, "oidc_issuer", "https://env-issuer.example.com")
    oidc_config.update({
        "oidc_issuer": "https://env-issuer.example.com", "oidc_client_id": "cid",
    })
    assert "oidc_issuer" not in json.loads(cfg.read_text(encoding="utf-8"))

    # The operator edits OIDC_ISSUER in the env file and restarts.
    monkeypatch.setattr(settings, "oidc_issuer", "https://new-issuer.example.com")
    oidc_config.load_and_apply()
    assert settings.oidc_issuer == "https://new-issuer.example.com"


# ── A damaged file must not stop the app from starting ─────────────
def test_load_survives_a_file_that_is_not_an_object(cfg):
    cfg.write_text("[1, 2, 3]", encoding="utf-8")
    oidc_config.load_and_apply()  # must not raise


def test_update_survives_a_file_that_is_not_an_object(cfg):
    cfg.write_text('"junk"', encoding="utf-8")
    oidc_config.update({"oidc_client_id": "cid"})
    assert json.loads(cfg.read_text(encoding="utf-8"))["oidc_client_id"] == "cid"


def test_load_survives_a_non_string_secret(cfg):
    cfg.write_text(json.dumps({"oidc_client_secret_enc": 12345}), encoding="utf-8")
    oidc_config.load_and_apply()  # must not raise


# ── A secret that cannot be decrypted must not wipe the .env fallback ──
def test_undecryptable_secret_keeps_the_env_secret(cfg, monkeypatch):
    """After a JWT_SECRET rotation the stored secret is lost, but .env is the fallback."""
    oidc_config.update({"oidc_client_secret": "stored-secret"})
    monkeypatch.setattr(settings, "jwt_secret", "a-completely-different-secret-9876")
    crypto.reset_cipher()
    monkeypatch.setattr(settings, "oidc_client_secret", "env-secret")
    oidc_config.load_and_apply()
    assert settings.oidc_client_secret == "env-secret"
    assert "oidc_client_secret" not in oidc_config.current_public()
