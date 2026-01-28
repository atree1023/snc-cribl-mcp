"""Unit tests for the base TokenManager in client.token_manager.

Covers caching behavior and error handling independent of server subclassing.
"""

# pyright: reportPrivateUsage=false

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from snc_cribl_mcp.client.token_manager import TokenManager, get_token_manager
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


def _config_with_oauth() -> CriblConfig:
    return CriblConfig(
        server_url="https://cribl.example.com",
        base_url="https://cribl.example.com/api/v1",
        client_id="client-id",
        client_secret="client-secret",
    )


def _config_with_unique_base_url() -> CriblConfig:
    return CriblConfig(
        server_url="https://cribl-unique.example.com",
        base_url="https://cribl-unique.example.com/api/v1",
        bearer_token="tok",
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

    with pytest.raises(RuntimeError, match="CRIBL_USERNAME/CRIBL_PASSWORD"):
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


@pytest.mark.asyncio
async def test_fetch_oauth_token_success() -> None:
    """OAuth client credentials should fetch and cache tokens."""
    manager = TokenManager(_config_with_oauth())

    with patch.object(TokenManager, "_request_oauth_token", new_callable=AsyncMock, return_value=("oauth-token", 3600)):
        security = await manager.get_security()
        assert security.bearer_auth == "oauth-token"

        security2 = await manager.get_security()
        assert security2.bearer_auth == "oauth-token"


@pytest.mark.asyncio
async def test_fetch_oauth_token_empty_response_raises() -> None:
    """Empty OAuth token responses should raise a RuntimeError."""
    manager = TokenManager(_config_with_oauth())

    with (
        patch.object(
            TokenManager,
            "_request_oauth_token_with_logging",
            new_callable=AsyncMock,
            return_value=("", None),
        ),
        pytest.raises(RuntimeError, match="empty token"),
    ):
        await manager.get_security()


def test_resolve_oauth_expiration_falls_back_to_jwt() -> None:
    """OAuth expiration should fall back to JWT parsing when expires_in missing."""
    manager = TokenManager(_config_with_oauth())
    future = datetime.now(UTC) + timedelta(hours=1)

    with patch.object(manager, "_get_jwt_exp", return_value=future):
        result = manager._resolve_oauth_expiration("token", None)

    assert result == future


@pytest.mark.asyncio
async def test_request_oauth_token_parses_expires_in() -> None:
    """OAuth token request should parse numeric expires_in values."""
    manager = TokenManager(_config_with_oauth())

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"access_token": "tok", "expires_in": "3600"}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client
    mock_cm.__aexit__.return_value = None

    with patch("snc_cribl_mcp.client.token_manager.httpx.AsyncClient", return_value=mock_cm):
        token, expires_in = await manager._request_oauth_token(client_id="id", client_secret="secret")

    assert token == "tok"
    assert expires_in == 3600


@pytest.mark.asyncio
async def test_request_oauth_token_invalid_expires_in_logs() -> None:
    """Invalid expires_in values should log a warning and return None."""
    manager = TokenManager(_config_with_oauth())

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"access_token": "tok", "expires_in": "bad"}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client
    mock_cm.__aexit__.return_value = None

    with (
        patch("snc_cribl_mcp.client.token_manager.httpx.AsyncClient", return_value=mock_cm),
        patch("snc_cribl_mcp.client.token_manager.logger.warning") as mock_warning,
    ):
        token, expires_in = await manager._request_oauth_token(client_id="id", client_secret="secret")
        mock_warning.assert_called_once()

    assert token == "tok"
    assert expires_in is None


@pytest.mark.asyncio
async def test_request_oauth_token_without_expires_in() -> None:
    """Missing expires_in should return None for expiration."""
    manager = TokenManager(_config_with_oauth())

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"access_token": "tok"}

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    mock_cm = AsyncMock()
    mock_cm.__aenter__.return_value = mock_client
    mock_cm.__aexit__.return_value = None

    with patch("snc_cribl_mcp.client.token_manager.httpx.AsyncClient", return_value=mock_cm):
        token, expires_in = await manager._request_oauth_token(client_id="id", client_secret="secret")

    assert token == "tok"
    assert expires_in is None


@pytest.mark.asyncio
async def test_request_oauth_token_with_logging_logs_exception() -> None:
    """OAuth token logging wrapper should log and re-raise exceptions."""
    manager = TokenManager(_config_with_oauth())

    with (
        patch.object(TokenManager, "_request_oauth_token", side_effect=RuntimeError("boom")),
        patch("snc_cribl_mcp.client.token_manager.logger.exception") as mock_logger,
        pytest.raises(RuntimeError, match="boom"),
    ):
        await manager._request_oauth_token_with_logging(client_id="id", client_secret="secret")

    mock_logger.assert_called_once()


def test_get_token_manager_returns_cached() -> None:
    """Token manager factory should reuse instances per base URL."""
    config = _config_with_unique_base_url()
    first = get_token_manager(config)
    second = get_token_manager(config)

    assert first is second
