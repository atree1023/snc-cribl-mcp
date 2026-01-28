"""Configuration management for the SNC Cribl MCP server.

This module defines the ``CriblConfig`` model and helpers to load configuration
from environment variables. It mirrors the behavior previously embedded in
``server.py`` to keep a single source of truth for configuration.
"""

import os
from collections.abc import Iterable
from typing import Any

from dotenv import load_dotenv
from pydantic import AnyUrl, BaseModel, Field, ValidationError, model_validator

# Load variables from a local .env file for development convenience
load_dotenv()


class CriblConfig(BaseModel):
    """Configuration values required to interact with a Cribl deployment."""

    server_url: str | AnyUrl
    base_url: str | AnyUrl
    username: str | None = None
    password: str | None = None
    bearer_token: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    oauth_token_url: str | None = None
    oauth_audience: str | None = None
    verify_ssl: bool = True
    timeout_ms: int = Field(default=10000, ge=1000, le=600000)

    @model_validator(mode="after")
    def _validate_credentials(self) -> CriblConfig:
        has_bearer = bool(self.bearer_token)
        has_user_pass = bool(self.username and self.password)
        has_client_creds = bool(self.client_id and self.client_secret)

        if (self.username is None) != (self.password is None):
            msg = "Set both CRIBL_USERNAME and CRIBL_PASSWORD."
            raise ValueError(msg)

        if (self.client_id is None) != (self.client_secret is None):
            msg = "Set both CRIBL_CLIENT_ID and CRIBL_CLIENT_SECRET."
            raise ValueError(msg)

        if not (has_bearer or has_user_pass or has_client_creds):
            msg = "Set CRIBL_BEARER_TOKEN, CRIBL_USERNAME/CRIBL_PASSWORD, or CRIBL_CLIENT_ID/CRIBL_CLIENT_SECRET."
            raise ValueError(msg)
        return self

    @property
    def base_url_str(self) -> str:
        """Return the resolved base URL as a plain string."""
        return str(self.base_url)

    @staticmethod
    def _first_env_value(keys: Iterable[str]) -> str | None:
        """Return the first non-empty environment value from a list of keys.

        Args:
            keys: Environment variable names to check in order.

        Returns:
            First non-empty environment value, or None if not found.

        """
        for key in keys:
            value = os.getenv(key)
            if value:
                return value
        return None

    @classmethod
    def _resolve_env_value(
        cls,
        *,
        instance_prefix: str | None,
        var_name: str,
        aliases: tuple[str, ...] = (),
        include_legacy: bool = True,
    ) -> str | None:
        """Resolve an environment value with instance and default fallbacks.

        Args:
            instance_prefix: Prefix for instance-scoped variables (e.g., "CRIBL_DEV_").
            var_name: Variable name suffix (e.g., "SERVER_URL").
            aliases: Alternate suffixes to check (e.g., ("URL",)).
            include_legacy: Whether to check legacy CRIBL_* variables.

        Returns:
            Resolved environment value if present.

        """
        keys: list[str] = []
        if instance_prefix:
            keys.append(f"{instance_prefix}{var_name}")
            keys.extend(f"{instance_prefix}{alias}" for alias in aliases)
        keys.append(f"CRIBL_DEFAULT_{var_name}")
        keys.extend(f"CRIBL_DEFAULT_{alias}" for alias in aliases)
        if include_legacy:
            keys.append(f"CRIBL_{var_name}")
            keys.extend(f"CRIBL_{alias}" for alias in aliases)
        return cls._first_env_value(keys)

    @classmethod
    def from_env(cls) -> CriblConfig:
        """Build a configuration object from environment variables."""
        server_url = cls._first_env_value(["CRIBL_SERVER_URL", "CRIBL_URL"])
        if not server_url:
            msg = "CRIBL_SERVER_URL is required to reach the Cribl API."
            raise RuntimeError(msg)
        base_url = os.getenv("CRIBL_BASE_URL")
        if not base_url:
            base_url = f"{server_url.rstrip('/')}/api/v1"
        verify_ssl = os.getenv("CRIBL_VERIFY_SSL")
        timeout_ms = os.getenv("CRIBL_TIMEOUT_MS")
        raw_config: dict[str, Any] = {
            "server_url": server_url,
            "base_url": base_url,
            "username": os.getenv("CRIBL_USERNAME"),
            "password": os.getenv("CRIBL_PASSWORD"),
            "bearer_token": os.getenv("CRIBL_BEARER_TOKEN"),
            "client_id": os.getenv("CRIBL_CLIENT_ID"),
            "client_secret": os.getenv("CRIBL_CLIENT_SECRET"),
            "oauth_token_url": os.getenv("CRIBL_OAUTH_TOKEN_URL"),
            "oauth_audience": os.getenv("CRIBL_OAUTH_AUDIENCE"),
        }
        if verify_ssl is not None:
            raw_config["verify_ssl"] = verify_ssl
        if timeout_ms is not None:
            raw_config["timeout_ms"] = timeout_ms
        try:
            return cls(**raw_config)
        except ValidationError as exc:
            messages = "; ".join(err["msg"] for err in exc.errors())
            msg = f"Invalid Cribl configuration: {messages}"
            raise RuntimeError(msg) from exc

    @classmethod
    def from_env_default(cls) -> CriblConfig:
        """Build a configuration object using CRIBL_DEFAULT_* variables.

        Returns:
            Resolved CriblConfig instance.

        Raises:
            RuntimeError: If no default server URL is configured.

        """
        server_url = cls._resolve_env_value(instance_prefix=None, var_name="SERVER_URL", aliases=("URL",))
        if not server_url or not server_url.startswith("http"):
            msg = "CRIBL_DEFAULT_SERVER_URL is required to reach the Cribl API."
            raise RuntimeError(msg)
        base_url = cls._resolve_env_value(instance_prefix=None, var_name="BASE_URL")
        if not base_url:
            base_url = f"{server_url.rstrip('/')}/api/v1"

        raw_config: dict[str, Any] = {
            "server_url": server_url,
            "base_url": base_url,
            "username": cls._resolve_env_value(instance_prefix=None, var_name="USERNAME", include_legacy=False),
            "password": cls._resolve_env_value(instance_prefix=None, var_name="PASSWORD", include_legacy=False),
            "bearer_token": cls._resolve_env_value(instance_prefix=None, var_name="BEARER_TOKEN", include_legacy=False),
            "client_id": cls._resolve_env_value(instance_prefix=None, var_name="CLIENT_ID", include_legacy=False),
            "client_secret": cls._resolve_env_value(instance_prefix=None, var_name="CLIENT_SECRET", include_legacy=False),
            "oauth_token_url": cls._resolve_env_value(
                instance_prefix=None,
                var_name="OAUTH_TOKEN_URL",
                include_legacy=False,
            ),
            "oauth_audience": cls._resolve_env_value(
                instance_prefix=None,
                var_name="OAUTH_AUDIENCE",
                include_legacy=False,
            ),
        }
        verify_ssl = cls._resolve_env_value(instance_prefix=None, var_name="VERIFY_SSL", include_legacy=False)
        timeout_ms = cls._resolve_env_value(instance_prefix=None, var_name="TIMEOUT_MS", include_legacy=False)
        if verify_ssl is not None:
            raw_config["verify_ssl"] = verify_ssl
        if timeout_ms is not None:
            raw_config["timeout_ms"] = timeout_ms

        try:
            return cls(**raw_config)
        except ValidationError as exc:
            messages = "; ".join(err["msg"] for err in exc.errors())
            msg = f"Invalid Cribl configuration: {messages}"
            raise RuntimeError(msg) from exc

    @classmethod
    def from_env_named(cls, server_name: str) -> CriblConfig:
        """Build config from named server environment variables.

        Args:
            server_name: Logical server name used in environment variable prefixes.

        Returns:
            Resolved CriblConfig for the named server.

        Raises:
            RuntimeError: If the named server is not configured or invalid.

        """
        prefix = f"CRIBL_{server_name.upper()}_"
        server_url = cls._resolve_env_value(instance_prefix=prefix, var_name="SERVER_URL", aliases=("URL",))
        if not server_url:
            msg = f"Server '{server_name}' not configured. Set {prefix}SERVER_URL."
            raise RuntimeError(msg)

        base_url = cls._resolve_env_value(instance_prefix=prefix, var_name="BASE_URL") or f"{server_url.rstrip('/')}/api/v1"
        verify_ssl = cls._resolve_env_value(instance_prefix=prefix, var_name="VERIFY_SSL")
        timeout_ms = cls._resolve_env_value(instance_prefix=prefix, var_name="TIMEOUT_MS")
        raw_config: dict[str, Any] = {
            "server_url": server_url,
            "base_url": base_url,
            "username": cls._resolve_env_value(instance_prefix=prefix, var_name="USERNAME"),
            "password": cls._resolve_env_value(instance_prefix=prefix, var_name="PASSWORD"),
            "bearer_token": cls._resolve_env_value(instance_prefix=prefix, var_name="BEARER_TOKEN"),
            "client_id": cls._resolve_env_value(instance_prefix=prefix, var_name="CLIENT_ID"),
            "client_secret": cls._resolve_env_value(instance_prefix=prefix, var_name="CLIENT_SECRET"),
            "oauth_token_url": cls._resolve_env_value(instance_prefix=prefix, var_name="OAUTH_TOKEN_URL"),
            "oauth_audience": cls._resolve_env_value(instance_prefix=prefix, var_name="OAUTH_AUDIENCE"),
        }
        if verify_ssl is not None:
            raw_config["verify_ssl"] = verify_ssl
        if timeout_ms is not None:
            raw_config["timeout_ms"] = timeout_ms
        try:
            return cls(**raw_config)
        except ValidationError as exc:
            messages = "; ".join(err["msg"] for err in exc.errors())
            msg = f"Invalid Cribl configuration: {messages}"
            raise RuntimeError(msg) from exc

    @classmethod
    def resolve(cls, server: str | None = None) -> CriblConfig:
        """Resolve server config by name, default, or legacy format.

        Args:
            server: Optional server name from the tool parameter.

        Returns:
            Resolved CriblConfig instance.

        Raises:
            RuntimeError: When no valid configuration is found.

        """
        if server:
            return cls.from_env_named(server)

        default_server = os.getenv("CRIBL_DEFAULT_SERVER")
        if default_server:
            return cls.from_env_named(default_server)

        if cls._first_env_value(["CRIBL_DEFAULT_SERVER_URL", "CRIBL_DEFAULT_URL"]):
            return cls.from_env_default()

        if cls._first_env_value(["CRIBL_SERVER_URL", "CRIBL_URL"]):
            return cls.from_env()

        msg = "No server configured. Set CRIBL_DEFAULT_SERVER or CRIBL_SERVER_URL."
        raise RuntimeError(msg)


__all__ = ["CriblConfig"]
