"""Unit tests for config.toml parsing and validation helpers."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

import snc_cribl_mcp.config as config_module
from snc_cribl_mcp.config import CriblConfig


def _write_config(path: Path, content: str) -> None:
    """Write config content to the given path."""
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def test_expand_env_placeholders_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """Placeholders should expand using environment variables."""
    monkeypatch.setenv("TEST_VAR", "value")
    assert config_module._expand_env_placeholders("x-${TEST_VAR}") == "x-value"


def test_expand_env_placeholders_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing placeholder variables should raise an error."""
    monkeypatch.delenv("MISSING_VAR", raising=False)
    with pytest.raises(RuntimeError, match="Missing environment variable"):
        config_module._expand_env_placeholders("${MISSING_VAR}")


def test_expand_config_values_nested(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nested structures should expand placeholders in all strings."""
    monkeypatch.setenv("TEST_PASS", "secret")
    value = {
        "password": "${TEST_PASS}",
        "list": ["${TEST_PASS}", 1, True],
        "nested": {"flag": False},
    }
    expanded = config_module._expand_config_values(cast("config_module.TomlValue", value))
    assert expanded == {
        "password": "secret",
        "list": ["secret", 1, True],
        "nested": {"flag": False},
    }


def test_normalize_base_url_errors() -> None:
    """Invalid URLs should raise ValueError."""
    with pytest.raises(ValueError, match="Server url is required"):
        config_module._normalize_base_url("   ")
    with pytest.raises(ValueError, match="Invalid server url"):
        config_module._normalize_base_url("cribl.example.com")


def test_normalize_base_url_appends() -> None:
    """Base URLs should normalize to /api/v1."""
    assert config_module._normalize_base_url("https://cribl.example.com") == "https://cribl.example.com/api/v1"
    assert config_module._normalize_base_url("https://cribl.example.com/api/v1/") == "https://cribl.example.com/api/v1"


def test_is_cloud_url() -> None:
    """Cribl.Cloud URLs should be detected by hostname."""
    assert config_module._is_cloud_url("https://tenant.cribl.cloud/api/v1") is True
    assert config_module._is_cloud_url("https://cribl.example.com/api/v1") is False


def test_is_server_table() -> None:
    """Server tables should be detected by scalar values."""
    assert config_module._is_server_table({"url": "https://cribl.example.com"}) is True
    assert config_module._is_server_table({"oak": {"url": "https://cribl.example.com"}}) is False


def test_collect_server_tables() -> None:
    """Nested tables should flatten into dotted server names."""
    tables = {
        "golden": {"oak": {"url": "https://cribl.example.com"}},
        "alpha": {"url": "https://cribl.example.com"},
        "note": "skip",
    }
    servers = config_module._collect_server_tables(cast("config_module.TomlTable", tables))
    assert servers == {
        "golden.oak": {"url": "https://cribl.example.com"},
        "alpha": {"url": "https://cribl.example.com"},
    }


def test_load_config_data_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing config.toml should raise an error."""
    monkeypatch.setattr(config_module, "CONFIG_PATH", tmp_path / "missing.toml")
    with pytest.raises(RuntimeError, match="Config file not found"):
        config_module._load_config_data()


def test_load_config_data_invalid_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid TOML should raise an error."""
    config_path = tmp_path / "config.toml"
    config_path.write_text("invalid = [", encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    with pytest.raises(RuntimeError, match="Invalid TOML"):
        config_module._load_config_data()


def test_load_config_data_non_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-table config roots should raise a TypeError."""
    config_path = tmp_path / "config.toml"
    config_path.write_text("key = 'value'", encoding="utf-8")
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    def _bad_expand(_value: config_module.TomlValue) -> config_module.TomlValue:
        return "oops"

    monkeypatch.setattr(config_module, "_expand_config_values", _bad_expand)
    with pytest.raises(TypeError, match="top-level table"):
        config_module._load_config_data()


def test_load_configs_invalid_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-table defaults should raise a TypeError."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        defaults = "bad"

        [alpha]
        url = "https://cribl.example.com"
        username = "user"
        password = "pass"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    config_module.clear_config_cache()
    with pytest.raises(TypeError, match="defaults"):
        config_module._load_configs()


def test_load_configs_no_servers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing server sections should raise a RuntimeError."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [defaults]
        timeout_ms = 10000
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    config_module.clear_config_cache()
    with pytest.raises(RuntimeError, match="No server configurations"):
        config_module._load_configs()


def test_load_configs_invalid_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid server sections should raise a RuntimeError."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [alpha]
        username = "user"
        password = "pass"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    config_module.clear_config_cache()
    with pytest.raises(RuntimeError, match="Invalid Cribl configuration"):
        config_module._load_configs()


def test_resolve_case_insensitive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server resolution should be case-insensitive."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [Alpha]
        url = "https://cribl.example.com"
        username = "user"
        password = "pass"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    config_module.clear_config_cache()
    config = CriblConfig.resolve("alpha")
    assert config.server_name == "Alpha"


def test_load_configs_defaults_on_prem_username_to_local_user_and_keyring_password(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On-prem configs without credentials should use the local user and keyring password first."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [golden.oak]
        url = "https://cribl.example.com"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)
    monkeypatch.setattr(config_module, "_get_local_username", lambda: "scott")

    lookups: list[tuple[str, str]] = []

    def _fake_keyring_password(service_name: str, username: str) -> str | None:
        lookups.append((service_name, username))
        return "keychain-pass"

    monkeypatch.setattr(config_module, "_get_keyring_password", _fake_keyring_password)
    config_module.clear_config_cache()

    config = CriblConfig.resolve("golden.oak")

    assert config.username == "scott"
    assert config.password == "keychain-pass"
    assert lookups == [("snc-cribl-mcp:golden.oak", "scott")]


def test_load_configs_falls_back_to_env_password_when_keyring_has_no_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On-prem configs should fall back to per-server environment password names after keyring."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [golden.oak]
        url = "https://cribl.example.com"
        username = "admin"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    def _missing_keyring_password(_service_name: str, _username: str) -> str | None:
        return None

    monkeypatch.setattr(config_module, "_get_keyring_password", _missing_keyring_password)
    monkeypatch.setenv("GOLDEN_OAK_PASS", "env-pass")
    config_module.clear_config_cache()

    config = CriblConfig.resolve("golden.oak")

    assert config.username == "admin"
    assert config.password == "env-pass"


def test_load_configs_missing_on_prem_password_error_names_lookup_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing on-prem passwords should explain the keyring and env fallback paths that were tried."""
    config_path = tmp_path / "config.toml"
    _write_config(
        config_path,
        """
        [golden.oak]
        url = "https://cribl.example.com"
        username = "admin"
        """,
    )
    monkeypatch.setattr(config_module, "CONFIG_PATH", config_path)

    def _missing_keyring_password(_service_name: str, _username: str) -> str | None:
        return None

    monkeypatch.setattr(config_module, "_get_keyring_password", _missing_keyring_password)
    for env_name in (
        "SNC_CRIBL_MCP_GOLDEN_OAK_PASSWORD",
        "CRIBL_GOLDEN_OAK_PASSWORD",
        "GOLDEN_OAK_PASSWORD",
        "GOLDEN_OAK_PASS",
    ):
        monkeypatch.delenv(env_name, raising=False)
    config_module.clear_config_cache()

    with pytest.raises(RuntimeError) as exc_info:
        CriblConfig.resolve("golden.oak")

    message = str(exc_info.value)
    assert "snc-cribl-mcp:golden.oak" in message
    assert "admin" in message
    assert "GOLDEN_OAK_PASS" in message


def test_base_url_str_property() -> None:
    """base_url_str should return the normalized string URL."""
    config = CriblConfig(url="https://cribl.example.com", username="user", password="pass")
    assert config.base_url_str == "https://cribl.example.com/api/v1"


def test_validate_credentials_mismatched_username() -> None:
    """Missing password should fail validation."""
    with pytest.raises(ValidationError, match="username and password"):
        CriblConfig(url="https://cribl.example.com", username="user")


def test_validate_credentials_mismatched_client_secret() -> None:
    """Missing client secret should fail validation."""
    with pytest.raises(ValidationError, match="client_id and client_secret"):
        CriblConfig(url="https://tenant.cribl.cloud", client_id="id")


def test_validate_credentials_cloud_with_user_pass() -> None:
    """Cribl.Cloud should reject username/password auth."""
    with pytest.raises(ValidationError, match=r"Cribl\.Cloud servers do not use username/password"):
        CriblConfig(
            url="https://tenant.cribl.cloud",
            username="user",
            password="pass",
            client_id="id",
            client_secret="secret",
        )


def test_validate_credentials_on_prem_with_client_creds() -> None:
    """On-prem should reject client credentials auth."""
    with pytest.raises(ValidationError, match="On-prem servers do not use client_id"):
        CriblConfig(
            url="https://cribl.example.com",
            username="user",
            password="pass",
            client_id="id",
            client_secret="secret",
        )
