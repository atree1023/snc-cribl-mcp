"""Configuration management for the SNC Cribl MCP server.

This module defines the ``CriblConfig`` model and helpers to load configuration
from environment variables. It mirrors the behavior previously embedded in
``server.py`` to keep a single source of truth for configuration.
"""

import os
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
    verify_ssl: bool = True
    timeout_ms: int = Field(default=10000, ge=1000, le=600000)

    @model_validator(mode="after")
    def _validate_credentials(self) -> CriblConfig:
        if not self.bearer_token and not (self.username and self.password):
            msg = "Set CRIBL_BEARER_TOKEN or both CRIBL_USERNAME and CRIBL_PASSWORD."
            raise ValueError(msg)
        return self

    @property
    def base_url_str(self) -> str:
        """Return the resolved base URL as a plain string."""
        return str(self.base_url)

    @classmethod
    def from_env(cls) -> CriblConfig:
        """Build a configuration object from environment variables."""
        server_url = os.getenv("CRIBL_SERVER_URL")
        if not server_url:
            msg = "CRIBL_SERVER_URL is required to reach the Cribl API."
            raise RuntimeError(msg)
        base_url = os.getenv("CRIBL_BASE_URL")
        if not base_url:
            base_url = f"{server_url.rstrip('/')}/api/v1"
        raw_config: dict[str, Any] = {
            "server_url": server_url,
            "base_url": base_url,
            "username": os.getenv("CRIBL_USERNAME"),
            "password": os.getenv("CRIBL_PASSWORD"),
            "bearer_token": os.getenv("CRIBL_BEARER_TOKEN"),
            "verify_ssl": os.getenv("CRIBL_VERIFY_SSL"),
            "timeout_ms": os.getenv("CRIBL_TIMEOUT_MS"),
        }
        try:
            return cls(**raw_config)
        except ValidationError as exc:
            messages = "; ".join(err["msg"] for err in exc.errors())
            msg = f"Invalid Cribl configuration: {messages}"
            raise RuntimeError(msg) from exc


__all__ = ["CriblConfig"]
