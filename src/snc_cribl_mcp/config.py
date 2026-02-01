"""Configuration management for the SNC Cribl MCP server.

This module defines the ``CriblConfig`` model and helpers to load configuration
from ``config.toml``. Server sections (for example, ``[golden.oak]``) are merged
with ``[defaults]`` and selected by name at runtime.
"""

from __future__ import annotations

import os
import re
import tomllib
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

# Load variables from a local .env file for development convenience
load_dotenv()

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.toml"
_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")

type TomlPrimitive = str | int | float | bool | None
type TomlValue = TomlPrimitive | list[TomlValue] | dict[str, TomlValue]
type TomlTable = dict[str, TomlValue]


def _expand_env_placeholders(value: str) -> str:
    """Expand ${VAR} placeholders using environment variables.

    Args:
        value: String containing ${VAR} placeholders.

    Returns:
        String with placeholders replaced by environment values.

    Raises:
        RuntimeError: If a referenced environment variable is missing.

    """

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        resolved = os.getenv(key)
        if resolved is None:
            msg = f"Missing environment variable '{key}' referenced in config.toml."
            raise RuntimeError(msg)
        return resolved

    return _ENV_PATTERN.sub(_replace, value)


def _expand_config_values(value: TomlValue) -> TomlValue:
    """Recursively expand environment placeholders in config values.

    Args:
        value: Config value (dict, list, or scalar).

    Returns:
        Value with ${VAR} placeholders expanded in all strings.

    """
    if isinstance(value, str):
        return _expand_env_placeholders(value)
    if isinstance(value, list):
        return [_expand_config_values(item) for item in value]
    if isinstance(value, dict):
        expanded: TomlTable = {}
        for key, val in value.items():
            expanded[str(key)] = _expand_config_values(val)
        return expanded
    return value


def _normalize_base_url(raw_url: str) -> str:
    """Normalize a server URL into a base API URL.

    Args:
        raw_url: URL from the config file.

    Returns:
        Normalized base URL that ends with /api/v1.

    Raises:
        ValueError: If the URL is missing or invalid.

    """
    cleaned = raw_url.strip()
    if not cleaned:
        msg = "Server url is required."
        raise ValueError(msg)

    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        msg = f"Invalid server url '{raw_url}'."
        raise ValueError(msg)

    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v1"):
        path = f"{path}/api/v1" if path else "/api/v1"

    normalized = parsed._replace(path=path, params="", query="", fragment="")
    return urlunparse(normalized)


def _is_cloud_url(url: str) -> bool:
    """Return True if the URL points to Cribl.Cloud.

    Args:
        url: Base API URL.

    Returns:
        True when the host ends with .cribl.cloud.

    """
    hostname = urlparse(url).hostname or ""
    return hostname.endswith(".cribl.cloud")


def _is_server_table(value: TomlTable) -> bool:
    """Return True if a table appears to be a server configuration.

    Args:
        value: TOML table to inspect.

    Returns:
        True when the table contains non-table values (e.g., url, username).

    """
    return any(not isinstance(item, dict) for item in value.values())


def _collect_server_tables(source: TomlTable, *, prefix: str = "") -> dict[str, TomlTable]:
    """Collect server tables, flattening dotted table names.

    Args:
        source: TOML table to scan.
        prefix: Current dotted prefix.

    Returns:
        Mapping of dotted server names to table values.

    """
    servers: dict[str, TomlTable] = {}
    for key, value in source.items():
        if not isinstance(value, dict):
            continue
        name = f"{prefix}.{key}" if prefix else key
        if _is_server_table(value):
            servers[name] = value
        else:
            servers.update(_collect_server_tables(value, prefix=name))
    return servers


def _load_config_data() -> TomlTable:
    """Load and expand the config.toml file.

    Returns:
        Parsed and expanded config data.

    Raises:
        RuntimeError: If the config.toml file is missing or invalid.

    """
    if not CONFIG_PATH.exists():
        msg = f"Config file not found at {CONFIG_PATH}."
        raise RuntimeError(msg)

    try:
        with CONFIG_PATH.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        msg = f"Invalid TOML in {CONFIG_PATH}: {exc}."
        raise RuntimeError(msg) from exc

    expanded = _expand_config_values(data)
    if not isinstance(expanded, dict):
        msg = "config.toml must contain a top-level table."
        raise TypeError(msg)
    return expanded


@lru_cache(maxsize=1)
def _load_configs() -> dict[str, CriblConfig]:
    """Load all server configurations from config.toml.

    Returns:
        Mapping of server name to CriblConfig.

    Raises:
        RuntimeError: If no servers are configured or configs are invalid.

    """
    data = _load_config_data()
    defaults_value = data.get("defaults")
    if defaults_value is None:
        defaults: TomlTable = {}
    elif isinstance(defaults_value, dict):
        defaults = defaults_value
    else:
        msg = "The [defaults] section must be a table in config.toml."
        raise TypeError(msg)

    nested_servers: TomlTable = {key: value for key, value in data.items() if key != "defaults"}
    servers = _collect_server_tables(nested_servers)
    if not servers:
        msg = "No server configurations found in config.toml."
        raise RuntimeError(msg)

    configs: dict[str, CriblConfig] = {}
    for server_name, server_values in servers.items():
        merged: TomlTable = {**defaults, **server_values, "server_name": server_name}
        try:
            configs[server_name] = CriblConfig.model_validate(merged)
        except ValidationError as exc:
            messages = "; ".join(err["msg"] for err in exc.errors())
            msg = f"Invalid Cribl configuration for '{server_name}': {messages}"
            raise RuntimeError(msg) from exc

    return configs


def clear_config_cache() -> None:
    """Clear cached config.toml parsing results."""
    _load_configs.cache_clear()


class CriblConfig(BaseModel):
    """Configuration values required to interact with a Cribl deployment."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    base_url: str = Field(alias="url")
    username: str | None = None
    password: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    oauth_token_url: str | None = None
    oauth_audience: str | None = None
    verify_ssl: bool = True
    timeout_ms: int = Field(default=10000, ge=1000, le=600000)
    server_name: str | None = None

    @field_validator("base_url", mode="before")
    @classmethod
    def _normalize_url(cls, value: str) -> str:
        """Normalize the base URL and ensure /api/v1 is present."""
        return _normalize_base_url(value)

    @model_validator(mode="after")
    def _validate_credentials(self) -> CriblConfig:
        if (self.username is None) != (self.password is None):
            msg = "Set both username and password."
            raise ValueError(msg)

        if (self.client_id is None) != (self.client_secret is None):
            msg = "Set both client_id and client_secret."
            raise ValueError(msg)

        is_cloud = _is_cloud_url(self.base_url)
        has_user_pass = bool(self.username and self.password)
        has_client_creds = bool(self.client_id and self.client_secret)

        if is_cloud:
            if not has_client_creds:
                msg = "Cribl.Cloud servers require client_id and client_secret."
                raise ValueError(msg)
            if has_user_pass:
                msg = "Cribl.Cloud servers do not use username/password credentials."
                raise ValueError(msg)
        else:
            if not has_user_pass:
                msg = "On-prem servers require username and password."
                raise ValueError(msg)
            if has_client_creds:
                msg = "On-prem servers do not use client_id/client_secret credentials."
                raise ValueError(msg)

        return self

    @property
    def base_url_str(self) -> str:
        """Return the resolved base URL as a plain string."""
        return str(self.base_url)

    @classmethod
    def resolve(cls, server: str | None = None) -> CriblConfig:
        """Resolve server config by name or default (first server section).

        Args:
            server: Optional server name from the tool parameter.

        Returns:
            Resolved CriblConfig instance.

        Raises:
            RuntimeError: When no valid configuration is found.

        """
        configs = _load_configs()

        if server:
            if server in configs:
                return configs[server]
            lowered = {name.lower(): name for name in configs}
            match = lowered.get(server.lower())
            if match:
                return configs[match]
            available = ", ".join(configs.keys())
            msg = f"Server '{server}' not configured. Available servers: {available}."
            raise RuntimeError(msg)

        default_name = next(iter(configs))
        return configs[default_name]


__all__ = ["CONFIG_PATH", "CriblConfig", "clear_config_cache"]
