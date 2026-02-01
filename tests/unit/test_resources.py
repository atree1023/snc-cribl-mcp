"""Unit tests for MCP resources."""

# pyright: reportPrivateUsage=false

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Context, FastMCP

from snc_cribl_mcp import resources


@pytest.fixture
def mock_deps() -> SimpleNamespace:
    """Create a mock dependencies object."""
    deps = SimpleNamespace()
    deps.config = MagicMock()
    deps.config.timeout_ms = 1000
    deps.config.base_url_str = "http://test.local"

    deps.resolve_config = MagicMock(return_value=deps.config)

    deps.products = [MagicMock()]
    deps.products[0].value = "stream"

    deps.token_manager = MagicMock()
    deps.token_manager.get_security = AsyncMock(return_value="token")
    deps.get_token_manager = MagicMock(return_value=deps.token_manager)

    deps.create_cp = MagicMock()
    deps.create_cp.return_value.__aenter__ = AsyncMock()
    deps.create_cp.return_value.__aexit__ = AsyncMock()

    deps.collect_product_groups = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_sources = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_destinations = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_pipelines = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_routes = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_breakers = AsyncMock(return_value={"status": "ok"})
    deps.collect_product_lookups = AsyncMock(return_value={"status": "ok"})

    return deps


@pytest.mark.asyncio
async def test_register_resources(mock_deps: SimpleNamespace) -> None:
    """Test that resources are registered and callable."""
    app = FastMCP("test")

    # Register resources
    resources.register(app, deps=mock_deps)

    # Verify resources are registered
    # FastMCP stores resources in _resource_manager
    assert "cribl://groups" in app._resource_manager._resources
    assert "cribl://sources" in app._resource_manager._resources
    assert "cribl://destinations" in app._resource_manager._resources
    assert "cribl://pipelines" in app._resource_manager._resources
    assert "cribl://routes" in app._resource_manager._resources
    assert "cribl://breakers" in app._resource_manager._resources
    assert "cribl://lookups" in app._resource_manager._resources

    # Test calling the groups resource
    resource = app._resource_manager._resources["cribl://groups"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    # Verify result
    data = cast("dict[str, Any]", result)
    assert data["base_url"] == "http://test.local"
    assert "groups" in data
    assert data["groups"]["stream"]["status"] == "ok"

    # Verify dependencies were called
    mock_deps.create_cp.assert_called_once()
    call_args = mock_deps.create_cp.call_args
    assert call_args.kwargs["security"] == "token"
    mock_deps.token_manager.get_security.assert_awaited_once()
    mock_deps.collect_product_groups.assert_called_once()


@pytest.mark.asyncio
async def test_get_sources_resource(mock_deps: SimpleNamespace) -> None:
    """Test the sources resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://sources"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "sources" in data
    mock_deps.collect_product_sources.assert_called_once()


@pytest.mark.asyncio
async def test_get_destinations_resource(mock_deps: SimpleNamespace) -> None:
    """Test the destinations resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://destinations"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "destinations" in data
    mock_deps.collect_product_destinations.assert_called_once()


@pytest.mark.asyncio
async def test_get_pipelines_resource(mock_deps: SimpleNamespace) -> None:
    """Test the pipelines resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://pipelines"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "pipelines" in data
    mock_deps.collect_product_pipelines.assert_called_once()
    # Verify security was passed
    call_args = mock_deps.collect_product_pipelines.call_args
    assert call_args.kwargs["security"] == "token"


@pytest.mark.asyncio
async def test_get_routes_resource(mock_deps: SimpleNamespace) -> None:
    """Test the routes resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://routes"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "routes" in data
    mock_deps.collect_product_routes.assert_called_once()


@pytest.mark.asyncio
async def test_get_breakers_resource(mock_deps: SimpleNamespace) -> None:
    """Test the breakers resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://breakers"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "breakers" in data
    mock_deps.collect_product_breakers.assert_called_once()
    # Verify security was passed
    call_args = mock_deps.collect_product_breakers.call_args
    assert call_args.kwargs["security"] == "token"


@pytest.mark.asyncio
async def test_get_lookups_resource(mock_deps: SimpleNamespace) -> None:
    """Test the lookups resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://lookups"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "lookups" in data
    mock_deps.collect_product_lookups.assert_called_once()
    # Verify security was passed
    call_args = mock_deps.collect_product_lookups.call_args
    assert call_args.kwargs["security"] == "token"


@pytest.mark.asyncio
async def test_groups_resource_handles_collector_error(mock_deps: SimpleNamespace) -> None:
    """Ensure groups resource degrades gracefully when collectors fail."""
    mock_deps.collect_product_groups.side_effect = RuntimeError("boom")

    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = app._resource_manager._resources["cribl://groups"]
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    data = cast("dict[str, Any]", result)

    product_result = data["groups"]["stream"]
    assert product_result["status"] == "error"
    assert product_result["error"] == "boom"
    assert product_result["error_type"] == "RuntimeError"
