"""Unit tests for the base TokenManager in client.token_manager.

Covers caching behavior and error handling independent of server subclassing.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from snc_cribl_mcp.client.token_manager import TokenManager
from snc_cribl_mcp.config import CriblConfig


def _config_with_token() -> CriblConfig:
    return CriblConfig(
        server_url="https://cribl.example.com",
        base_url="https://cribl.example.com/api/v1",
        bearer_token="tok",
    )


def _config_with_credentials() -> CriblConfig:
    return CriblConfig(
        server_url="https://cribl.example.com",
        base_url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
    )


@pytest.mark.asyncio
async def test_get_security_returns_existing() -> None:
    """It should return the existing bearer token from config without network calls."""
    manager = TokenManager(_config_with_token())
    security = await manager.get_security()
    assert security.bearer_auth == "tok"


@pytest.mark.asyncio
async def test_fetch_new_token_success() -> None:
    """It should fetch a new token when none exists and then cache it."""
    manager = TokenManager(_config_with_credentials())

    with (
        patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="newtok") as mock_request,
        patch.object(manager, "_get_jwt_exp", return_value=datetime.now(UTC) + timedelta(hours=1)),
    ):
        security = await manager.get_security()
        assert security.bearer_auth == "newtok"

        security2 = await manager.get_security()
        assert security2.bearer_auth == "newtok"

    mock_request.assert_awaited_once()


@pytest.mark.asyncio
async def test_fetch_new_token_missing_credentials_raises() -> None:
    """Missing credentials at fetch time should raise a RuntimeError."""
    manager = TokenManager(_config_with_credentials())
    manager._config.username = None  # type: ignore[reportPrivateUsage]
    manager._cached_token = None  # type: ignore[reportPrivateUsage]

    with pytest.raises(RuntimeError, match="CRIBL_USERNAME and CRIBL_PASSWORD"):
        await manager.get_security()


@pytest.mark.asyncio
async def test_fetch_new_token_empty_response_raises() -> None:
    """An empty token in the auth response should raise a RuntimeError."""
    manager = TokenManager(_config_with_credentials())

    with (
        patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value=""),
        pytest.raises(RuntimeError, match="empty token"),
    ):
        await manager.get_security()


@pytest.mark.asyncio
async def test_fetch_new_token_expired_response_raises() -> None:
    """Tokens that are already expired should be rejected immediately."""
    manager = TokenManager(_config_with_credentials())

    with (
        patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="newtok"),
        patch.object(manager, "_get_jwt_exp", return_value=datetime.now(UTC) - timedelta(minutes=1)),
        pytest.raises(RuntimeError, match="expired token"),
    ):
        await manager.get_security()


def test_close_is_idempotent() -> None:
    """TokenManager.close should be safe to call multiple times."""
    manager = TokenManager(_config_with_credentials())
    manager.close()
    manager.close()


def test_context_manager_calls_close() -> None:
    """Using TokenManager as a context manager should still call close()."""
    manager = TokenManager(_config_with_credentials())
    with patch.object(manager, "close") as mock_close, manager:
        pass

    mock_close.assert_called_once()
