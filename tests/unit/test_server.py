"""Unit tests for the SNC Cribl MCP server.

Tests cover:
- Configuration loading and validation
- Token management and refresh logic
- Control plane client creation
- Group collection for products
- MCP tool execution
"""

import signal
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models import Security
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context
from pydantic import BaseModel, ValidationError

from snc_cribl_mcp.server import (
    CONFIG,
    PRODUCTS,
    CriblConfig,
    TokenManager,
    collect_product_groups,
    create_control_plane,
    handle_interrupt,
    list_groups_impl,
    main,
    serialize_config_group,
)


# Test helper model for validation error tests
class _DummyValidationModel(BaseModel):
    """Model for testing validation errors with required field."""

    required_field: str


@pytest.fixture
def mock_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set up environment variables for testing."""
    env_vars = {
        "CRIBL_SERVER_URL": "https://cribl.example.com",
        "CRIBL_BASE_URL": "https://cribl.example.com/api/v1",
        "CRIBL_BEARER_TOKEN": "test-token-123",
        "CRIBL_VERIFY_SSL": "true",
        "CRIBL_TIMEOUT_MS": "15000",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    # Ensure credentials are unset
    monkeypatch.delenv("CRIBL_USERNAME", raising=False)
    monkeypatch.delenv("CRIBL_PASSWORD", raising=False)

    return env_vars


@pytest.fixture
def mock_env_with_credentials(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Set up environment variables with username/password instead of token."""
    env_vars = {
        "CRIBL_SERVER_URL": "https://cribl.example.com",
        "CRIBL_BASE_URL": "https://cribl.example.com/api/v1",
        "CRIBL_USERNAME": "testuser",
        "CRIBL_PASSWORD": "testpass",
        "CRIBL_VERIFY_SSL": "true",
        "CRIBL_TIMEOUT_MS": "15000",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    # Clear token if set
    monkeypatch.delenv("CRIBL_BEARER_TOKEN", raising=False)
    return env_vars


@pytest.fixture
def sample_config_group() -> dict[str, Any]:
    """Sample ConfigGroup data for testing."""
    return {
        "id": "default",
        "description": "Default worker group",
        "tags": ["production"],
        "workerCount": 5,
        "isManaged": True,
    }


@pytest.fixture
def sample_list_response(sample_config_group: dict[str, Any]) -> dict[str, Any]:
    """Sample ListConfigGroupByProductResponse data."""
    return {
        "count": 1,
        "items": [sample_config_group],
    }


class TestCriblConfig:
    """Tests for CriblConfig validation and loading."""

    def test_from_env_with_token(self, mock_env: dict[str, str]) -> None:
        """Test loading configuration from environment with bearer token."""
        config = CriblConfig.from_env()
        # Pydantic AnyUrl normalizes URLs (adds trailing slash)
        assert str(config.server_url).rstrip("/") == mock_env["CRIBL_SERVER_URL"].rstrip("/")
        assert str(config.base_url).rstrip("/") == mock_env["CRIBL_BASE_URL"].rstrip("/")
        assert config.bearer_token == mock_env["CRIBL_BEARER_TOKEN"]
        assert config.verify_ssl is True
        assert config.timeout_ms == 15000

    def test_from_env_with_credentials(
        self,
        mock_env_with_credentials: dict[str, str],
    ) -> None:
        """Test loading configuration with username and password."""
        config = CriblConfig.from_env()
        assert config.username == mock_env_with_credentials["CRIBL_USERNAME"]
        assert config.password == mock_env_with_credentials["CRIBL_PASSWORD"]
        assert config.bearer_token is None

    def test_from_env_missing_server_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that missing CRIBL_SERVER_URL raises an error."""
        monkeypatch.delenv("CRIBL_SERVER_URL", raising=False)
        with pytest.raises(RuntimeError, match="CRIBL_SERVER_URL is required"):
            CriblConfig.from_env()

    def test_from_env_missing_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that missing both token and username/password raises an error."""
        monkeypatch.setenv("CRIBL_SERVER_URL", "https://cribl.example.com")
        monkeypatch.delenv("CRIBL_BEARER_TOKEN", raising=False)
        monkeypatch.delenv("CRIBL_USERNAME", raising=False)
        monkeypatch.delenv("CRIBL_PASSWORD", raising=False)
        with pytest.raises(RuntimeError, match="Invalid Cribl configuration"):
            CriblConfig.from_env()

    def test_from_env_generates_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that base URL is generated from server URL if not provided."""
        monkeypatch.setenv("CRIBL_SERVER_URL", "https://cribl.example.com/")
        monkeypatch.setenv("CRIBL_BEARER_TOKEN", "token")
        monkeypatch.delenv("CRIBL_BASE_URL", raising=False)
        config = CriblConfig.from_env()
        assert config.base_url_str == "https://cribl.example.com/api/v1"

    def test_base_url_str_property(self, mock_env: dict[str, str]) -> None:
        """Test the base_url_str property returns a string."""
        config = CriblConfig.from_env()
        assert isinstance(config.base_url_str, str)
        assert config.base_url_str == mock_env["CRIBL_BASE_URL"]

    def test_validation_error_invalid_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that invalid timeout values are rejected."""
        monkeypatch.setenv("CRIBL_SERVER_URL", "https://cribl.example.com")
        monkeypatch.setenv("CRIBL_BEARER_TOKEN", "token")
        monkeypatch.setenv("CRIBL_TIMEOUT_MS", "500")  # Too low
        with pytest.raises(RuntimeError, match="Invalid Cribl configuration"):
            CriblConfig.from_env()

    def test_direct_instantiation_with_token(self) -> None:
        """Test direct instantiation with bearer token."""
        config = CriblConfig(
            server_url="https://cribl.example.com",
            base_url="https://cribl.example.com/api/v1",
            bearer_token="test-token",
        )
        assert config.bearer_token == "test-token"
        assert config.username is None
        assert config.password is None

    def test_direct_instantiation_with_credentials(self) -> None:
        """Test direct instantiation with username and password."""
        config = CriblConfig(
            server_url="https://cribl.example.com",
            base_url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )
        assert config.username == "user"
        assert config.password == "pass"
        assert config.bearer_token is None

    def test_direct_instantiation_no_auth(self) -> None:
        """Test that instantiation without credentials raises an error."""
        with pytest.raises(ValidationError):
            CriblConfig(
                server_url="https://cribl.example.com",
                base_url="https://cribl.example.com/api/v1",
            )


class TestTokenManager:
    """Tests for TokenManager token handling and refresh logic."""

    @pytest.mark.asyncio
    async def test_get_security_with_existing_token(self, mock_env: dict[str, str]) -> None:
        """Test getting a token when one is already configured."""
        config = CriblConfig.from_env()
        manager = TokenManager(config)
        security = await manager.get_security()
        assert security.bearer_auth == mock_env["CRIBL_BEARER_TOKEN"]

    @pytest.mark.asyncio
    async def test_get_security_fetches_new_token(
        self,
        mock_env_with_credentials: dict[str, str],
    ) -> None:
        """Test fetching a new token when none exists."""
        config = CriblConfig.from_env()
        manager = TokenManager(config)

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="new-token-456") as mock_request,
            patch.object(manager, "_get_jwt_exp", return_value=datetime.now(UTC) + timedelta(hours=1)),
        ):
            security = await manager.get_security()
            assert security.bearer_auth == "new-token-456"
            assert manager._cached_token == "new-token-456"  # type: ignore[reportPrivateUsage]

        mock_request.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_security_caches_fetched_token(
        self,
        mock_env_with_credentials: dict[str, str],
    ) -> None:
        """Test that fetched tokens are cached for subsequent calls."""
        config = CriblConfig.from_env()
        manager = TokenManager(config)

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value="cached-token") as mock_request,
            patch.object(manager, "_get_jwt_exp", return_value=datetime.now(UTC) + timedelta(hours=1)),
        ):
            security1 = await manager.get_security()
            security2 = await manager.get_security()

        assert security1.bearer_auth == security2.bearer_auth == "cached-token"
        mock_request.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fetch_new_token_missing_credentials(self, mock_env: dict[str, str]) -> None:
        """Test that fetching a new token without credentials raises an error."""
        config = CriblConfig(
            server_url="https://cribl.example.com",
            base_url="https://cribl.example.com/api/v1",
            username="testuser",
            password="testpass",
        )
        manager = TokenManager(config)
        manager._config.username = None  # type: ignore[reportPrivateUsage]
        manager._cached_token = None  # type: ignore[reportPrivateUsage]

        with pytest.raises(RuntimeError, match="CRIBL_USERNAME and CRIBL_PASSWORD"):
            await manager.get_security()

    @pytest.mark.asyncio
    async def test_fetch_new_token_empty_response(
        self,
        mock_env_with_credentials: dict[str, str],
    ) -> None:
        """Test handling of empty token in authentication response."""
        config = CriblConfig.from_env()
        manager = TokenManager(config)

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value=""),
            pytest.raises(RuntimeError, match="returned an empty token"),
        ):
            await manager.get_security()


class TestCreateControlPlane:
    """Tests for the create_control_plane context manager."""

    @pytest.mark.asyncio
    async def test_creates_client_with_token(self, mock_env: dict[str, str]) -> None:
        """Test creating a control plane client with bearer token."""
        config = CriblConfig.from_env()
        security = Security(bearer_auth="test-token")
        async with create_control_plane(config, security=security) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_creates_client_without_token(self, mock_env: dict[str, str]) -> None:
        """Test creating a control plane client without bearer token."""
        config = CriblConfig.from_env()
        async with create_control_plane(config, security=None) as client:
            assert client is not None


class TestSerializeConfigGroup:
    """Tests for serialize_config_group function."""

    def test_serialize_config_group(self, sample_config_group: dict[str, Any]) -> None:
        """Test serializing a ConfigGroup object."""
        mock_group = MagicMock()
        mock_group.model_dump.return_value = sample_config_group

        result = serialize_config_group(mock_group)
        assert result == sample_config_group
        mock_group.model_dump.assert_called_once_with(mode="json", exclude_none=True)


class TestCollectProductGroups:
    """Tests for collect_product_groups function."""

    @pytest.mark.asyncio
    async def test_collect_groups_success(
        self,
        sample_config_group: dict[str, Any],
    ) -> None:
        """Test successfully collecting groups for a product."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = [MagicMock()]
        mock_response.items[0].model_dump.return_value = sample_config_group
        mock_response.count = 1
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        result = await collect_product_groups(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )

        assert result["status"] == "ok"
        assert result["count"] == 1
        assert result["reported_count"] == 1
        assert len(result["items"]) == 1

    @pytest.mark.asyncio
    async def test_collect_groups_empty_items(self) -> None:
        """Test collecting groups when items list is None."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = None
        mock_response.count = 0
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        result = await collect_product_groups(
            mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=10000,
            ctx=mock_ctx,
        )

        assert result["status"] == "ok"
        assert result["count"] == 0
        assert result["items"] == []

    @pytest.mark.asyncio
    async def test_collect_groups_count_none(self) -> None:
        """Test collecting groups when response.count is None (omits reported_count)."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = []
        mock_response.count = None
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        result = await collect_product_groups(
            mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=10000,
            ctx=mock_ctx,
        )

        assert result["status"] == "ok"
        assert result["count"] == 0
        assert result["items"] == []
        assert "reported_count" not in result

    @pytest.mark.asyncio
    async def test_collect_groups_404_not_found(self) -> None:
        """Test handling of HTTP 404 for unavailable product."""
        mock_client = MagicMock()
        api_error = CriblControlPlaneError(
            message="Not found",
            body=None,
            raw_response=MagicMock(status_code=404),
        )
        mock_client.groups.list_async = AsyncMock(side_effect=api_error)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        result = await collect_product_groups(
            mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=10000,
            ctx=mock_ctx,
        )

        assert result["status"] == "unavailable"
        assert result["count"] == 0
        assert result["items"] == []
        assert "404" in result["message"]
        mock_ctx.warning.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_groups_api_error_non_404(self) -> None:
        """Test handling of non-404 API errors."""
        mock_client = MagicMock()
        api_error = CriblControlPlaneError(
            message="Internal server error",
            body=None,
            raw_response=MagicMock(status_code=500),
        )
        mock_client.groups.list_async = AsyncMock(side_effect=api_error)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        with pytest.raises(RuntimeError, match="Cribl API error"):
            await collect_product_groups(
                mock_client,
                product=ProductsCore.STREAM,
                timeout_ms=10000,
                ctx=mock_ctx,
            )

    @pytest.mark.asyncio
    async def test_collect_groups_network_error(self) -> None:
        """Test handling of network errors."""
        mock_client = MagicMock()
        mock_client.groups.list_async = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused"),
        )

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        with pytest.raises(RuntimeError, match="Network error while listing stream groups"):
            await collect_product_groups(
                mock_client,
                product=ProductsCore.STREAM,
                timeout_ms=10000,
                ctx=mock_ctx,
            )

    @pytest.mark.asyncio
    async def test_collect_groups_cribl_error(self) -> None:
        """Test handling of generic Cribl SDK errors."""
        mock_client = MagicMock()
        sdk_error = CriblControlPlaneError(
            message="SDK error",
            raw_response=MagicMock(),
        )
        mock_client.groups.list_async = AsyncMock(side_effect=sdk_error)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        with pytest.raises(RuntimeError, match="Cribl API error"):
            await collect_product_groups(
                mock_client,
                product=ProductsCore.STREAM,
                timeout_ms=10000,
                ctx=mock_ctx,
            )

    @pytest.mark.asyncio
    async def test_collect_groups_validation_error_returns_structured_error(self) -> None:
        """Test that SDK validation errors return a structured error response."""
        mock_client = MagicMock()

        # Create a mock HTTP response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({})
        raw_body = '{"items": [{"id": "g1"}], "count": 1}'
        mock_response.text = raw_body

        # Create a Pydantic ValidationError
        pydantic_error: ValidationError
        try:
            _DummyValidationModel.model_validate({})
        except ValidationError as ve:
            pydantic_error = ve
        else:
            pytest.fail("Expected ValidationError")

        # Wrap it in ResponseValidationError
        validation_exc = ResponseValidationError(
            "Response validation failed",
            mock_response,
            pydantic_error,
            raw_body,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=validation_exc)

        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()
        mock_ctx.error = AsyncMock()

        result = await collect_product_groups(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )

        # Should return error response, not raise
        assert result["status"] == "validation_error"
        assert result["product"] == "stream"
        assert "errors" in result
        assert "resolution" in result
        # Error should have been logged
        assert mock_ctx.error.await_count >= 1


class TestListGroupsTool:
    """Tests for the list_groups MCP tool."""

    @pytest.mark.asyncio
    async def test_list_groups_success(
        self,
        sample_config_group: dict[str, Any],
    ) -> None:
        """Test successful execution of list_groups tool."""
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = [MagicMock()]
        mock_response.items[0].model_dump.return_value = sample_config_group
        mock_response.count = 1
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_client
        mock_context_manager.__aexit__.return_value = None

        with (
            patch("snc_cribl_mcp.server.TOKEN_MANAGER.get_security") as mock_get_security,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_security.return_value = Security(bearer_auth="test-token")
            data = await list_groups_impl(mock_ctx)

            assert isinstance(data, dict)
            assert "retrieved_at" in data
            assert "base_url" in data
            assert "groups" in data
            assert "stream" in data["groups"]
            assert "edge" in data["groups"]
            assert data["groups"]["stream"]["status"] == "ok"
            assert data["groups"]["edge"]["status"] == "ok"

    @pytest.mark.asyncio
    async def test_list_groups_with_unavailable_product(
        self,
        sample_config_group: dict[str, Any],
    ) -> None:
        """Test list_groups when one product is unavailable."""
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        mock_client = MagicMock()

        async def mock_list_async(product: ProductsCore, timeout_ms: int) -> MagicMock:
            if product == ProductsCore.STREAM:
                mock_response = MagicMock()
                mock_response.items = [MagicMock()]
                mock_response.items[0].model_dump.return_value = sample_config_group
                mock_response.count = 1
                return mock_response
            raise CriblControlPlaneError(
                message="Not found",
                body=None,
                raw_response=MagicMock(status_code=404),
            )

        mock_client.groups.list_async = mock_list_async

        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_client
        mock_context_manager.__aexit__.return_value = None

        with (
            patch("snc_cribl_mcp.server.TOKEN_MANAGER.get_security") as mock_get_security,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_security.return_value = Security(bearer_auth="test-token")
            data = await list_groups_impl(mock_ctx)

            assert data["groups"]["stream"]["status"] == "ok"
            assert data["groups"]["edge"]["status"] == "unavailable"

    @pytest.mark.asyncio
    async def test_list_groups_json_format(
        self,
        sample_config_group: dict[str, Any],
    ) -> None:
        """Test that list_groups returns properly formatted JSON."""
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.info = AsyncMock()
        mock_ctx.warning = AsyncMock()

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = []
        mock_response.count = 0
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        mock_context_manager = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_client
        mock_context_manager.__aexit__.return_value = None

        with (
            patch("snc_cribl_mcp.server.TOKEN_MANAGER.get_security") as mock_get_security,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_security.return_value = Security(bearer_auth="test-token")
            data = await list_groups_impl(mock_ctx)

            # Should be a dict
            assert isinstance(data, dict)
            assert "groups" in data


class TestModuleConstants:
    """Tests for module-level constants and configuration."""

    def test_products_tuple(self) -> None:
        """Test that PRODUCTS contains expected product types."""
        assert len(PRODUCTS) == 2
        assert ProductsCore.STREAM in PRODUCTS
        assert ProductsCore.EDGE in PRODUCTS

    def test_config_loaded(self, mock_env: dict[str, str]) -> None:
        """Test that CONFIG is properly loaded at module level."""
        # CONFIG is loaded at module import, so we verify it's accessible
        assert CONFIG is not None
        assert hasattr(CONFIG, "base_url")


class TestSignalHandler:
    """Tests for signal handler function."""

    def test_handle_interrupt_calls_sys_exit(self) -> None:
        """Test that handle_interrupt logs and exits cleanly."""
        with (
            patch("snc_cribl_mcp.server.logger") as mock_logger,
            pytest.raises(SystemExit) as exc_info,
        ):
            handle_interrupt(2, None)  # SIGINT = 2

        mock_logger.info.assert_called_once_with("Received interrupt signal, shutting down...")
        assert exc_info.value.code == 0

    def test_handle_interrupt_sigterm(self) -> None:
        """Test that handle_interrupt works with SIGTERM."""
        with (
            patch("snc_cribl_mcp.server.logger") as mock_logger,
            pytest.raises(SystemExit) as exc_info,
        ):
            handle_interrupt(15, MagicMock())  # SIGTERM = 15, frame is ignored

        mock_logger.info.assert_called_once()
        assert exc_info.value.code == 0


class TestMainFunction:
    """Tests for the main() entry point function."""

    def test_main_registers_signal_handlers_and_runs_app(self) -> None:
        """Test that main() registers signal handlers and starts the app."""
        with (
            patch("snc_cribl_mcp.server.signal.signal") as mock_signal,
            patch("snc_cribl_mcp.server.app.run") as mock_run,
        ):
            main()

            # Verify signal handlers were registered
            assert mock_signal.call_count == 2
            mock_signal.assert_any_call(signal.SIGINT, handle_interrupt)
            mock_signal.assert_any_call(signal.SIGTERM, handle_interrupt)

            # Verify app.run() was called
            mock_run.assert_called_once()
