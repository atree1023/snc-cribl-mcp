"""Configuration management for the SNC Cribl MCP server.

This module defines the ``CriblConfig`` model and helpers to load configuration
from ``config.toml``. Server sections (for example, ``[golden.oak]``) are merged
with ``[defaults]`` and selected by name at runtime.
"""

from __future__ import annotations

import getpass
import logging
import os
import re
import tomllib
from collections.abc import Mapping
from functools import cache, lru_cache
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import keyring
from dotenv import load_dotenv
from keyring.errors import KeyringError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

# Load variables from a local .env file for development convenience
load_dotenv()

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.toml"
_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")
_KEYRING_SERVICE_PREFIX = "snc-cribl-mcp"

logger = logging.getLogger("snc_cribl_mcp.config")

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

    TOML dotted-table nesting can represent both a parent server and a child
    server, such as ``[golden.oak]`` and ``[golden.oak.new]``. When both tables
    include server settings, both names are registered intentionally.

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
        nested_values: TomlTable = {}
        for nested_key, nested_value in value.items():
            if isinstance(nested_value, dict):
                nested_values[nested_key] = nested_value
        servers.update(_collect_server_tables(nested_values, prefix=name))
    return servers


def _non_empty_string(value: object) -> str | None:
    """Return a stripped string when the value is a non-empty string."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _get_local_username() -> str | None:
    """Return the current local login username, if available."""
    try:
        return _non_empty_string(getpass.getuser())
    except KeyError, OSError, RuntimeError:
        logger.debug("Could not resolve the local username.", exc_info=True)
        return None


def _keyring_service_name(server_name: str | None, base_url: str, keychain_name: str | None = None) -> str:
    """Return the keyring service name for a Cribl server."""
    configured_name = _non_empty_string(keychain_name)
    if configured_name is not None:
        return configured_name

    identifier = _non_empty_string(server_name) or _non_empty_string(urlparse(base_url).hostname) or base_url
    return f"{_KEYRING_SERVICE_PREFIX}:{identifier}"


def _get_keyring_password(service_name: str, username: str) -> str | None:
    """Return a stored password from the active keyring backend, if available."""
    try:
        password = keyring.get_password(service_name, username)
    except KeyringError, OSError, RuntimeError:
        logger.debug(
            "Could not read password from keyring service '%s' for username '%s'.",
            service_name,
            username,
            exc_info=True,
        )
        return None

    return password or None


def _server_env_fragment(server_name: str) -> str:
    """Return the environment-variable fragment for a server name."""
    return re.sub(r"[^A-Z0-9]+", "_", server_name.upper()).strip("_")


def _password_env_names(server_name: str) -> tuple[str, ...]:
    """Return per-server environment variable names for password fallback."""
    fragment = _server_env_fragment(server_name)
    if not fragment:
        return ()

    candidates = (
        f"SNC_CRIBL_MCP_{fragment}_PASSWORD",
        f"CRIBL_{fragment}_PASSWORD",
        f"{fragment}_PASSWORD",
        f"{fragment}_PASS",
    )
    return tuple(dict.fromkeys(candidates))


def _get_env_password(server_name: str) -> str | None:
    """Return the first configured per-server environment password."""
    for env_name in _password_env_names(server_name):
        password = os.getenv(env_name)
        if password:
            return password
    return None


def _on_prem_base_url_for_password_resolution(values: TomlTable) -> str | None:
    """Return a base URL when the server should use on-prem password fallback."""
    raw_url = _non_empty_string(values.get("url"))
    if raw_url is None:
        return None

    try:
        base_url = _normalize_base_url(raw_url)
    except ValueError:
        return None

    if _is_cloud_url(base_url) or _non_empty_string(values.get("client_id")) or _non_empty_string(values.get("client_secret")):
        return None

    return base_url


def _missing_on_prem_password_message(server_name: str, service_name: str, username: str | None) -> str:
    """Return a clear missing password message for on-prem credential lookup."""
    username_description = username or "<unavailable local user>"
    env_names = ", ".join(_password_env_names(server_name))
    msg = (
        f"On-prem server '{server_name}' is missing a password. Tried macOS keychain service "
        f"'{service_name}' for username '{username_description}'"
    )
    return f"{msg} and environment variables: {env_names}." if env_names else f"{msg}."


def _resolve_on_prem_credentials(server_name: str, values: TomlTable) -> TomlTable:
    """Resolve local-user, keyring, and environment credentials for on-prem servers."""
    base_url = _on_prem_base_url_for_password_resolution(values)
    if base_url is None:
        return values

    resolved: TomlTable = dict(values)
    username = _non_empty_string(resolved.get("username")) or _get_local_username()
    if username is not None:
        resolved["username"] = username

    password = _non_empty_string(resolved.get("password"))
    service_name = _keyring_service_name(server_name, base_url, _non_empty_string(resolved.get("keychain_name")))

    if password is None and username is not None:
        password = _get_keyring_password(service_name, username)
        if password:
            resolved["password"] = password

    if password is None:
        password = _get_env_password(server_name)
        if password:
            resolved["password"] = password

    if _non_empty_string(resolved.get("password")) is None:
        raise RuntimeError(_missing_on_prem_password_message(server_name, service_name, username))

    return resolved


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
def _load_config_sections() -> tuple[TomlTable, dict[str, TomlTable]]:
    """Load defaults and raw server sections from config.toml."""
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

    return defaults, servers


def _build_config(server_name: str, defaults: TomlTable, server_values: TomlTable) -> CriblConfig:
    """Merge, resolve credentials, and validate one server config."""
    merged: TomlTable = {**defaults, **server_values, "server_name": server_name}
    merged = _resolve_on_prem_credentials(server_name, merged)
    try:
        return CriblConfig.model_validate(merged)
    except ValidationError as exc:
        messages = "; ".join(err["msg"] for err in exc.errors())
        msg = f"Invalid Cribl configuration for '{server_name}': {messages}"
        raise RuntimeError(msg) from exc


def _match_server_name(server: str, servers: Mapping[str, TomlTable]) -> str:
    """Return the configured server name matching a user-supplied selector."""
    if server in servers:
        return server

    lowered = {name.lower(): name for name in servers}
    match = lowered.get(server.lower())
    if match is not None:
        return match

    available = ", ".join(servers.keys())
    msg = f"Server '{server}' not configured. Available servers: {available}."
    raise RuntimeError(msg)


@cache
def _load_config(server_name: str) -> CriblConfig:
    """Load and validate one canonical server config."""
    defaults, servers = _load_config_sections()
    return _build_config(server_name, defaults, servers[server_name])


@lru_cache(maxsize=1)
def _load_configs() -> dict[str, CriblConfig]:
    """Load all server configurations from config.toml.

    Returns:
        Mapping of server name to CriblConfig.

    Raises:
        RuntimeError: If no servers are configured or configs are invalid.

    """
    _, servers = _load_config_sections()
    return {server_name: _load_config(server_name) for server_name in servers}


def clear_config_cache() -> None:
    """Clear cached config.toml parsing results."""
    _load_config.cache_clear()
    _load_config_sections.cache_clear()
    _load_configs.cache_clear()


class CriblConfig(BaseModel):
    """Configuration values required to interact with a Cribl deployment."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    base_url: str = Field(alias="url")
    username: str | None = None
    password: str | None = None
    keychain_name: str | None = None
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
        _, servers = _load_config_sections()

        if server:
            server_name = _match_server_name(server, servers)
            return _load_config(server_name)

        default_name = next(iter(servers))
        return _load_config(default_name)


__all__ = ["CONFIG_PATH", "CriblConfig", "clear_config_cache"]
