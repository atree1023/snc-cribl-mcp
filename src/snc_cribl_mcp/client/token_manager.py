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

DEFAULT_OAUTH_TOKEN_URL = "https://login.cribl.cloud/oauth/token"  # noqa: S105
DEFAULT_OAUTH_AUDIENCE = "https://api.cribl.cloud"


class TokenManager:
    """Manage bearer tokens for the Cribl API, refreshing when necessary."""

    def __init__(self, config: CriblConfig) -> None:
        """Initialize the token manager.

        Args:
            config: The resolved Cribl configuration to use for authentication.

        """
        self._config = config
        self._cached_token: str | None = None
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

            if self._cached_token and not self._can_refresh():
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
        client_id = self._config.client_id
        client_secret = self._config.client_secret

        if client_id and client_secret:
            token, expires_in = await self._request_oauth_token_with_logging(
                client_id=client_id,
                client_secret=client_secret,
            )
            if not token:
                msg = "Cribl authentication succeeded but returned an empty token."
                raise RuntimeError(msg)
            self._token_expires_at = self._resolve_oauth_expiration(token, expires_in)
        elif username and password:
            token = await self._request_token_with_logging(username=username, password=password)
            if not token:
                msg = "Cribl authentication succeeded but returned an empty token."
                raise RuntimeError(msg)
            self._token_expires_at = self._resolve_token_expiration(token)
        else:
            msg = "Username/password or client_id/client_secret must be set to retrieve a token."
            raise RuntimeError(msg)

        self._cached_token = token

        logger.debug("Fetched new bearer token from Cribl API.")
        return token

    def _resolve_oauth_expiration(self, token: str, expires_in: int | None) -> datetime:
        """Resolve token expiration for OAuth flows.

        Args:
            token: Access token string.
            expires_in: Optional expires_in duration (seconds).

        Returns:
            Datetime when the token should be considered expired.

        """
        if expires_in:
            return datetime.now(UTC) + timedelta(seconds=expires_in)
        return self._resolve_token_expiration(token)

    def _resolve_token_expiration(self, token: str) -> datetime:
        """Resolve token expiration by decoding JWT or falling back to a default.

        Args:
            token: Access token string.

        Returns:
            Datetime when the token should be considered expired.

        """
        try:
            expires_at = self._get_jwt_exp(token)
            if expires_at <= datetime.now(UTC):
                msg = "Cribl authentication returned an expired token."
                raise RuntimeError(msg)
        except (ValueError, IndexError, json.JSONDecodeError):
            logger.warning("Could not parse token expiration, token refresh might not work as expected.")
            return datetime.now(UTC) + timedelta(hours=1)
        else:
            return expires_at

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

        token: str | None = None
        result = getattr(response, "result", None)
        candidate = getattr(result, "token", None)
        if isinstance(candidate, str) and candidate:
            token = candidate
        else:
            candidate = getattr(response, "token", None)
            if isinstance(candidate, str) and candidate:
                token = candidate

        if token is None:
            msg = "Cribl authentication succeeded but returned an empty token."
            raise RuntimeError(msg)
        return token

    async def _request_oauth_token(self, *, client_id: str, client_secret: str) -> tuple[str, int | None]:
        """Request an OAuth access token via client credentials.

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.

        Returns:
            Tuple of access token and optional expires_in (seconds).

        """
        token_url = self._config.oauth_token_url or DEFAULT_OAUTH_TOKEN_URL
        audience = self._config.oauth_audience or DEFAULT_OAUTH_AUDIENCE
        timeout = httpx.Timeout(self._config.timeout_ms / 1000)
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": audience,
        }

        async with httpx.AsyncClient(verify=self._config.verify_ssl, timeout=timeout) as http_client:
            response = await http_client.post(token_url, data=payload)
            response.raise_for_status()
            data = response.json()

        token = data.get("access_token")
        expires_in_raw = data.get("expires_in")
        expires_in: int | None
        if expires_in_raw is None:
            expires_in = None
        else:
            try:
                expires_in = int(expires_in_raw)
            except (TypeError, ValueError):
                logger.warning("Invalid expires_in value in OAuth response; ignoring expiration override.")
                expires_in = None
        return token, expires_in

    async def _request_oauth_token_with_logging(
        self,
        *,
        client_id: str,
        client_secret: str,
    ) -> tuple[str, int | None]:
        """Request an OAuth token and log failures.

        Args:
            client_id: OAuth client ID.
            client_secret: OAuth client secret.

        Returns:
            Tuple of access token and optional expires_in (seconds).

        """
        try:
            return await self._request_oauth_token(client_id=client_id, client_secret=client_secret)
        except Exception:
            logger.exception("Failed to authenticate with Cribl")
            raise

    async def _request_token_with_logging(self, *, username: str, password: str) -> str:
        """Request a bearer token and log failures.

        Args:
            username: Cribl API username.
            password: Cribl API password.

        Returns:
            Bearer token string from the authentication response.

        """
        try:
            return await self._request_token(username=username, password=password)
        except Exception:
            logger.exception("Failed to authenticate with Cribl")
            raise

    def _can_refresh(self) -> bool:
        """Return True if credentials are available to refresh tokens."""
        has_user_pass = bool(self._config.username and self._config.password)
        has_client_creds = bool(self._config.client_id and self._config.client_secret)
        return has_user_pass or has_client_creds


_TOKEN_MANAGERS: dict[str, TokenManager] = {}


def get_token_manager(config: CriblConfig) -> TokenManager:
    """Return a cached TokenManager for the given configuration.

    Args:
        config: Resolved Cribl configuration.

    Returns:
        TokenManager instance scoped to the configuration's base URL.

    """
    key = str(config.base_url)
    manager = _TOKEN_MANAGERS.get(key)
    if manager is None:
        manager = TokenManager(config)
        _TOKEN_MANAGERS[key] = manager
    return manager


__all__ = ["TokenManager", "get_token_manager"]
