"""Additional unit tests for TokenManager covering edge cases.

These tests supplement the base tests in test_token_manager_base.py, focusing on
JWT parsing, edge cases around expiration, and the _request_token method.
"""

# pyright: reportPrivateUsage=false

import base64
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from snc_cribl_mcp.client.token_manager import TokenManager
from snc_cribl_mcp.config import CriblConfig


def _config_with_credentials() -> CriblConfig:
    """Create a config with username/password authentication."""
    return CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
    )


def _make_jwt(exp: datetime | None = None, *, missing_exp: bool = False) -> str:
    """Create a test JWT token with the given expiration."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_dict: dict[str, int] = {}
    if exp and not missing_exp:
        payload_dict["exp"] = int(exp.timestamp())
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"fake-signature").decode().rstrip("=")
    return f"{header}.{payload}.{signature}"


class TestTokenManagerJWTParsing:
    """Tests for JWT expiration parsing."""

    def test_get_jwt_exp_valid_token(self) -> None:
        """Valid JWT should have its exp claim parsed correctly."""
        manager = TokenManager(_config_with_credentials())
        future = datetime.now(UTC) + timedelta(hours=2)
        token = _make_jwt(exp=future)

        result = manager._get_jwt_exp(token)

        # Allow a small tolerance for test execution time
        assert abs((result - future).total_seconds()) < 2

    def test_get_jwt_exp_missing_exp_raises(self) -> None:
        """JWT without exp claim should raise ValueError."""
        manager = TokenManager(_config_with_credentials())
        token = _make_jwt(missing_exp=True)

        with pytest.raises(ValueError, match="missing 'exp' field"):
            manager._get_jwt_exp(token)

    def test_get_jwt_exp_invalid_format_raises(self) -> None:
        """Non-JWT string should raise ValueError."""
        manager = TokenManager(_config_with_credentials())

        with pytest.raises(ValueError, match="Invalid JWT format"):
            manager._get_jwt_exp("not.a.valid.jwt.token")

    def test_get_jwt_exp_two_parts_raises(self) -> None:
        """JWT with only two parts should raise ValueError."""
        manager = TokenManager(_config_with_credentials())

        with pytest.raises(ValueError, match="Invalid JWT format"):
            manager._get_jwt_exp("header.payload")


class TestTokenManagerCaching:
    """Tests for token caching behavior."""

    @pytest.mark.asyncio
    async def test_cached_token_returned_when_not_expired(self) -> None:
        """Cached token should be returned without network call when still valid."""
        manager = TokenManager(_config_with_credentials())
        manager._cached_token = "preexisting-token"  # type: ignore[reportPrivateUsage]
        # Set expiration to 1 hour from now
        manager._token_expires_at = datetime.now(UTC) + timedelta(hours=1)

        security = await manager.get_security()

        assert security.bearer_auth == "preexisting-token"

    @pytest.mark.asyncio
    async def test_cached_token_near_expiration_still_used(self) -> None:
        """Token near expiration (> 3 seconds) should still be used."""
        manager = TokenManager(_config_with_credentials())
        manager._cached_token = "preexisting-token"  # type: ignore[reportPrivateUsage]
        # Set expiration to 5 seconds from now (> 3 second buffer)
        manager._token_expires_at = datetime.now(UTC) + timedelta(seconds=5)

        security = await manager.get_security()

        assert security.bearer_auth == "preexisting-token"

    @pytest.mark.asyncio
    async def test_expired_token_logs_warning_no_credentials(self) -> None:
        """Expired token without credentials should log warning and return cached token."""
        manager = TokenManager(_config_with_credentials())
        manager._cached_token = "preexisting-token"  # type: ignore[reportPrivateUsage]
        manager._config.username = None  # type: ignore[reportPrivateUsage]
        manager._config.password = None  # type: ignore[reportPrivateUsage]
        # Set expiration to past
        manager._token_expires_at = datetime.now(UTC) - timedelta(hours=1)

        with patch("snc_cribl_mcp.client.token_manager.logger") as mock_logger:
            security = await manager.get_security()
            mock_logger.warning.assert_called()

        assert security.bearer_auth == "preexisting-token"


class TestTokenManagerLocking:
    """Tests for async lock behavior."""

    @pytest.mark.asyncio
    async def test_ensure_lock_creates_new_lock_on_new_loop(self) -> None:
        """A new lock should be created when called from a different event loop."""
        manager = TokenManager(_config_with_credentials())

        # First call to _ensure_lock
        lock1 = manager._ensure_lock()
        assert lock1 is not None

        # Simulate same loop - should return same lock
        lock2 = manager._ensure_lock()
        assert lock1 is lock2


class TestTokenManagerRequestToken:
    """Tests for the _request_token method."""

    @pytest.mark.asyncio
    async def test_request_token_success(self) -> None:
        """Successful token request should return the token."""
        manager = TokenManager(_config_with_credentials())

        with patch("snc_cribl_mcp.client.token_manager.httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client

            mock_control_plane = MagicMock()
            mock_control_plane.__aenter__ = AsyncMock(return_value=mock_control_plane)
            mock_control_plane.__aexit__ = AsyncMock(return_value=None)
            mock_response = MagicMock()
            mock_response.token = "new-token"
            mock_control_plane.auth.tokens.get_async = AsyncMock(return_value=mock_response)

            with patch("snc_cribl_mcp.client.token_manager.CriblControlPlane", return_value=mock_control_plane):
                token = await manager._request_token(username="user", password="pass")

            assert token == "new-token"

    @pytest.mark.asyncio
    async def test_fetch_and_cache_token_handles_unparseable_jwt(self) -> None:
        """If JWT parsing fails, token should still be cached with default expiration."""
        manager = TokenManager(_config_with_credentials())

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="opaque-token"),
            patch.object(manager, "_get_jwt_exp", side_effect=ValueError("Invalid JWT")),
            patch("snc_cribl_mcp.client.token_manager.logger") as mock_logger,
        ):
            security = await manager.get_security()

            assert security.bearer_auth == "opaque-token"
            assert manager._cached_token == "opaque-token"
            assert manager._token_expires_at is not None
            # Should log warning about unparseable token
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_fetch_and_cache_token_handles_json_decode_error(self) -> None:
        """If JWT payload is not valid JSON, token should still be cached."""
        manager = TokenManager(_config_with_credentials())

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="bad-json-token"),
            patch.object(manager, "_get_jwt_exp", side_effect=json.JSONDecodeError("msg", "doc", 0)),
            patch("snc_cribl_mcp.client.token_manager.logger") as mock_logger,
        ):
            security = await manager.get_security()

            assert security.bearer_auth == "bad-json-token"
            mock_logger.warning.assert_called()

    @pytest.mark.asyncio
    async def test_fetch_token_exception_logged_and_raised(self) -> None:
        """Authentication failures should be logged and re-raised."""
        manager = TokenManager(_config_with_credentials())

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, side_effect=Exception("Auth failed")),
            patch("snc_cribl_mcp.client.token_manager.logger") as mock_logger,
            pytest.raises(Exception, match="Auth failed"),
        ):
            await manager.get_security()

        mock_logger.exception.assert_called()


class TestTokenManagerRefresh:
    """Tests for token refresh logic."""

    @pytest.mark.asyncio
    async def test_token_refresh_when_near_expiration(self) -> None:
        """Token should be refreshed when within 3 seconds of expiration."""
        manager = TokenManager(_config_with_credentials())
        manager._cached_token = "old-token"
        # Set expiration to 2 seconds from now (< 3 second buffer)
        manager._token_expires_at = datetime.now(UTC) + timedelta(seconds=2)

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="new-token"),
            patch.object(manager, "_get_jwt_exp", return_value=datetime.now(UTC) + timedelta(hours=1)),
        ):
            security = await manager.get_security()

        assert security.bearer_auth == "new-token"
