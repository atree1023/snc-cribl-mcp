"""Unit tests for the SNC Cribl MCP server.

Tests cover:
- Configuration loading and validation
- Token management and refresh logic
- Control plane client creation
- Group collection for products
- MCP tool execution
"""

import signal
import textwrap
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models import Security
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context
from pydantic import BaseModel, ValidationError

import snc_cribl_mcp.config as config_module
from snc_cribl_mcp.server import (
    PRODUCTS,
    CriblConfig,
    TokenManager,
    collect_product_groups,
    create_control_plane,
    get_token_manager,
    handle_interrupt,
    list_groups_impl,
    main,
    serialize_config_group,
)


# Test helper model for validation error tests
class _DummyValidationModel(BaseModel):
    """Model for testing validation errors with required field."""

    required_field: str


def _write_config(path: Path, content: str) -> None:
    """Write a config.toml file and clear the config cache."""
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
    config_module.clear_config_cache()


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Provide a temporary config.toml path and clear cached config state."""
    path = tmp_path / "config.toml"
    monkeypatch.setattr(config_module, "CONFIG_PATH", path)
    config_module.clear_config_cache()
    yield path
    config_module.clear_config_cache()


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

    def test_resolve_default_first_section(self, config_path: Path) -> None:
        """Default should resolve to the first non-default section."""
        _write_config(
            config_path,
            """
            [defaults]
            verify_ssl = true
            timeout_ms = 15000

            [alpha]
            url = "https://cribl.example.com"
            username = "testuser"
            password = "testpass"

            [beta]
            url = "https://example.cribl.cloud"
            client_id = "client-id"
            client_secret = "client-secret"
            """,
        )

        config = CriblConfig.resolve()

        assert config.server_name == "alpha"
        assert config.base_url_str == "https://cribl.example.com/api/v1"
        assert config.verify_ssl is True
        assert config.timeout_ms == 15000

    def test_resolve_named_server(self, config_path: Path) -> None:
        """Named servers should resolve from config.toml."""
        _write_config(
            config_path,
            """
            [defaults]
            timeout_ms = 12000

            [golden.oak]
            url = "https://cribl.example.com"
            username = "user"
            password = "pass"

            [cribl.cloud]
            url = "https://tenant.cribl.cloud"
            client_id = "client-id"
            client_secret = "client-secret"
            """,
        )

        config = CriblConfig.resolve("cribl.cloud")

        assert config.server_name == "cribl.cloud"
        assert config.base_url_str == "https://tenant.cribl.cloud/api/v1"
        assert config.timeout_ms == 12000

    def test_resolve_missing_server(self, config_path: Path) -> None:
        """Unknown server names should raise a runtime error."""
        _write_config(
            config_path,
            """
            [alpha]
            url = "https://cribl.example.com"
            username = "user"
            password = "pass"
            """,
        )

        with pytest.raises(RuntimeError, match="not configured"):
            CriblConfig.resolve("missing")

    def test_cloud_requires_client_credentials(self, config_path: Path) -> None:
        """Cribl.Cloud servers must use client credentials."""
        _write_config(
            config_path,
            """
            [cribl.cloud]
            url = "https://tenant.cribl.cloud"
            username = "user"
            password = "pass"
            """,
        )

        with pytest.raises(RuntimeError, match="client_id and client_secret"):
            CriblConfig.resolve("cribl.cloud")

    def test_on_prem_requires_username_password(self, config_path: Path) -> None:
        """On-prem servers must use username and password."""
        _write_config(
            config_path,
            """
            [golden.oak]
            url = "https://cribl.example.com"
            client_id = "client-id"
            client_secret = "client-secret"
            """,
        )

        with pytest.raises(RuntimeError, match="username and password"):
            CriblConfig.resolve("golden.oak")

    def test_expands_env_placeholders(self, config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment placeholders should expand using .env/env values."""
        monkeypatch.setenv("TEST_PASS", "secret")
        _write_config(
            config_path,
            """
            [golden.oak]
            url = "https://cribl.example.com"
            username = "user"
            password = "${TEST_PASS}"
            """,
        )

        config = CriblConfig.resolve("golden.oak")
        assert config.password == "secret"

    def test_base_url_auto_append(self, config_path: Path) -> None:
        """URLs missing /api/v1 should be normalized."""
        _write_config(
            config_path,
            """
            [alpha]
            url = "https://cribl.example.com/"
            username = "user"
            password = "pass"
            """,
        )

        config = CriblConfig.resolve("alpha")
        assert config.base_url_str == "https://cribl.example.com/api/v1"

    def test_invalid_timeout_raises(self, config_path: Path) -> None:
        """Invalid timeout values should raise errors."""
        _write_config(
            config_path,
            """
            [defaults]
            timeout_ms = 500

            [alpha]
            url = "https://cribl.example.com"
            username = "user"
            password = "pass"
            """,
        )

        with pytest.raises(RuntimeError, match="Invalid Cribl configuration"):
            CriblConfig.resolve("alpha")


class TestTokenManager:
    """Tests for TokenManager token handling and refresh logic."""

    @pytest.mark.asyncio
    async def test_get_security_with_existing_token(self) -> None:
        """Test getting a token when one is already cached."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )
        manager = TokenManager(config)
        manager._cached_token = "cached-token"  # type: ignore[reportPrivateUsage]
        manager._token_expires_at = datetime.now(UTC) + timedelta(hours=1)  # type: ignore[reportPrivateUsage]
        security = await manager.get_security()
        assert security.bearer_auth == "cached-token"

    @pytest.mark.asyncio
    async def test_get_security_fetches_new_token(
        self,
    ) -> None:
        """Test fetching a new token when none exists."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="testuser",
            password="testpass",
        )
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
    ) -> None:
        """Test that fetched tokens are cached for subsequent calls."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="testuser",
            password="testpass",
        )
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
    async def test_fetch_new_token_missing_credentials(self) -> None:
        """Test that fetching a new token without credentials raises an error."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="testuser",
            password="testpass",
        )
        manager = TokenManager(config)
        manager._config.username = None  # type: ignore[reportPrivateUsage]
        manager._config.password = None  # type: ignore[reportPrivateUsage]
        manager._cached_token = None  # type: ignore[reportPrivateUsage]

        with pytest.raises(RuntimeError, match="Username/password or client_id/client_secret"):
            await manager.get_security()

    @pytest.mark.asyncio
    async def test_fetch_new_token_empty_response(
        self,
    ) -> None:
        """Test handling of empty token in authentication response."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="testuser",
            password="testpass",
        )
        manager = TokenManager(config)

        with (
            patch.object(TokenManager, "_request_token", new_callable=AsyncMock, return_value=""),
            pytest.raises(RuntimeError, match="returned an empty token"),
        ):
            await manager.get_security()


class TestCreateControlPlane:
    """Tests for the create_control_plane context manager."""

    @pytest.mark.asyncio
    async def test_creates_client_with_token(self) -> None:
        """Test creating a control plane client with bearer token."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )
        security = Security(bearer_auth="test-token")
        async with create_control_plane(config, security=security) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_creates_client_without_token(self) -> None:
        """Test creating a control plane client without bearer token."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )
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

        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )

        with (
            patch("snc_cribl_mcp.server.CriblConfig.resolve", return_value=config),
            patch("snc_cribl_mcp.server.get_token_manager") as mock_get_token_manager,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_token_manager.return_value = SimpleNamespace(
                get_security=AsyncMock(return_value=Security(bearer_auth="test-token"))
            )
            data = await list_groups_impl(mock_ctx, server="dev")

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

        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )

        with (
            patch("snc_cribl_mcp.server.CriblConfig.resolve", return_value=config),
            patch("snc_cribl_mcp.server.get_token_manager") as mock_get_token_manager,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_token_manager.return_value = SimpleNamespace(
                get_security=AsyncMock(return_value=Security(bearer_auth="test-token"))
            )
            data = await list_groups_impl(mock_ctx, server=None)

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

        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )

        with (
            patch("snc_cribl_mcp.server.CriblConfig.resolve", return_value=config),
            patch("snc_cribl_mcp.server.get_token_manager") as mock_get_token_manager,
            patch("snc_cribl_mcp.server.create_control_plane", return_value=mock_context_manager),
        ):
            mock_get_token_manager.return_value = SimpleNamespace(
                get_security=AsyncMock(return_value=Security(bearer_auth="test-token"))
            )
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

    def test_token_manager_factory(self) -> None:
        """Token managers should be created via the factory for a config."""
        config = CriblConfig(
            url="https://cribl.example.com/api/v1",
            username="user",
            password="pass",
        )
        manager = get_token_manager(config)
        assert isinstance(manager, TokenManager)


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
