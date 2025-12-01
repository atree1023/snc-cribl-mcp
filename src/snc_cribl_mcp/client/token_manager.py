"""Token management utilities for the Cribl Control Plane API."""

import asyncio
import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Self

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models import Security

from ..config import CriblConfig

logger = logging.getLogger("snc_cribl_mcp.token_manager")


class TokenManager:
    """Manage bearer tokens for the Cribl API, refreshing when necessary."""

    def __init__(self, config: CriblConfig) -> None:
        """Initialize the token manager.

        Args:
            config: The resolved Cribl configuration to use for authentication.

        """
        self._config = config
        self._cached_token: str | None = config.bearer_token
        self._token_expires_at: datetime | None = None
        self._lock: asyncio.Lock | None = None
        self._lock_loop: asyncio.AbstractEventLoop | None = None

    def __enter__(self) -> Self:
        """Return the token manager for context manager usage."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close resources when leaving a context manager block."""
        self.close()

    def close(self) -> None:
        """Clean up resources (no-op; retained for interface compatibility)."""

    def _ensure_lock(self) -> asyncio.Lock:
        """Return an asyncio lock bound to the current event loop.

        Creates a new lock if one does not exist or if the event loop has changed.
        """
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def _get_jwt_exp(self, token: str) -> datetime:
        """Decode the exp claim from trusted Cribl-issued JWTs.

        Tokens are retrieved directly from the Cribl Control Plane via mutual
        authentication, so we only read the expiration claim here. Do not reuse
        this helper for untrusted tokens because it does not validate JWT
        signatures.
        """
        parts = token.split(".")
        if len(parts) != 3:  # noqa: PLR2004
            msg = "Invalid JWT format"
            raise ValueError(msg)
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))
        exp = payload.get("exp")
        if exp is None:
            msg = "Token missing 'exp' field"
            raise ValueError(msg)
        return datetime.fromtimestamp(exp, tz=UTC)

    async def get_security(self) -> Security:
        """Return a Security object with a valid bearer token, refreshing if needed."""
        lock = self._ensure_lock()
        async with lock:
            now = datetime.now(UTC)
            if self._cached_token and self._token_expires_at and (now + timedelta(seconds=3)) < self._token_expires_at:
                return Security(bearer_auth=self._cached_token)

            if self._cached_token and not (self._config.username and self._config.password):
                # Token exists but may be expired and we cannot refresh - log warning and return anyway
                logger.warning("Cached token may be expired but no credentials available to refresh")
                return Security(bearer_auth=self._cached_token)

            token = await self._fetch_and_cache_token()
            return Security(bearer_auth=token)

    async def _fetch_and_cache_token(self) -> str:
        """Authenticate with Cribl and cache the returned bearer token.

        Returns:
            The newly fetched bearer token.

        Raises:
            RuntimeError: If credentials are missing or authentication fails.

        """
        username = self._config.username
        password = self._config.password
        if not (username and password):
            msg = "CRIBL_USERNAME and CRIBL_PASSWORD must be set to retrieve a token."
            raise RuntimeError(msg)

        try:
            token = await self._request_token(username=username, password=password)
        except Exception:
            logger.exception("Failed to authenticate with Cribl")
            raise

        if not token:
            msg = "Cribl authentication succeeded but returned an empty token."
            raise RuntimeError(msg)

        try:
            expires_at = self._get_jwt_exp(token)
            if expires_at <= datetime.now(UTC):
                msg = "Cribl authentication returned an expired token."
                raise RuntimeError(msg)
            self._token_expires_at = expires_at
        except (ValueError, IndexError, json.JSONDecodeError):
            logger.warning("Could not parse token expiration, token refresh might not work as expected.")
            self._token_expires_at = datetime.now(UTC) + timedelta(hours=1)

        self._cached_token = token

        logger.debug("Fetched new bearer token from Cribl API.")
        return token

    async def _request_token(self, *, username: str, password: str) -> str:
        """Request a bearer token from the Cribl API.

        Args:
            username: Cribl API username.
            password: Cribl API password.

        Returns:
            Bearer token string from the authentication response.

        """
        timeout = httpx.Timeout(self._config.timeout_ms / 1000)
        async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=timeout) as http_client:
            control_plane = CriblControlPlane(
                server_url=self._config.base_url_str,
                async_client=http_client,
            )
            async with control_plane:
                response = await control_plane.auth.tokens.get_async(
                    username=username,
                    password=password,
                )
        return response.token


__all__ = ["TokenManager"]
