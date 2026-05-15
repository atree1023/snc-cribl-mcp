"""Unit tests for MCP resources."""

# pyright: reportPrivateUsage=false

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Context, FastMCP

from snc_cribl_mcp import resources
from snc_cribl_mcp.operations.packs import collect_packs


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
    deps.collect_packs = AsyncMock(return_value={"status": "ok"})

    return deps


@pytest.mark.asyncio
async def test_register_resources(mock_deps: SimpleNamespace) -> None:
    """Test that resources are registered and callable."""
    app = FastMCP("test")

    resources.register(app, deps=mock_deps)

    registered_resources = {str(resource.uri) for resource in await app.list_resources()}
    assert "cribl://groups" in registered_resources
    assert "cribl://sources" in registered_resources
    assert "cribl://destinations" in registered_resources
    assert "cribl://pipelines" in registered_resources
    assert "cribl://routes" in registered_resources
    assert "cribl://breakers" in registered_resources
    assert "cribl://lookups" in registered_resources
    assert "cribl://packs" in registered_resources

    resource = await app.get_resource("cribl://groups")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert data["base_url"] == "http://test.local"
    assert "groups" in data
    assert data["groups"]["stream"]["status"] == "ok"

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

    resource = await app.get_resource("cribl://sources")
    assert resource is not None
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

    resource = await app.get_resource("cribl://destinations")
    assert resource is not None
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

    resource = await app.get_resource("cribl://pipelines")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "pipelines" in data
    mock_deps.collect_product_pipelines.assert_called_once()


@pytest.mark.asyncio
async def test_get_routes_resource(mock_deps: SimpleNamespace) -> None:
    """Test the routes resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://routes")
    assert resource is not None
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

    resource = await app.get_resource("cribl://breakers")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "breakers" in data
    mock_deps.collect_product_breakers.assert_called_once()
    call_args = mock_deps.collect_product_breakers.call_args
    assert call_args.kwargs["security"] == "token"


@pytest.mark.asyncio
async def test_get_lookups_resource(mock_deps: SimpleNamespace) -> None:
    """Test the lookups resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://lookups")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "lookups" in data
    mock_deps.collect_product_lookups.assert_called_once()
    call_args = mock_deps.collect_product_lookups.call_args
    assert call_args.kwargs["security"] == "token"


@pytest.mark.asyncio
async def test_get_packs_resource(mock_deps: SimpleNamespace) -> None:
    """Test the top-level Packs resource."""
    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://packs")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    assert isinstance(result, dict)

    data = cast("dict[str, Any]", result)
    assert "packs" in data
    assert data["packs"]["status"] == "ok"
    mock_deps.collect_packs.assert_awaited_once()
    assert mock_deps.collect_packs.await_args.kwargs == {"timeout_ms": 1000}


@pytest.mark.asyncio
async def test_get_packs_resource_uses_top_level_collect_signature(mock_deps: SimpleNamespace) -> None:
    """The Packs resource should call collect_packs once at leader scope."""
    pack_model = MagicMock()
    pack_model.model_dump.return_value = {"id": "cribl-okta", "source": "git+repo"}
    sdk_response = MagicMock(items=[pack_model], count=1)
    client = MagicMock()
    client.packs.list_async = AsyncMock(return_value=sdk_response)
    mock_deps.create_cp.return_value.__aenter__.return_value = client
    mock_deps.collect_packs = collect_packs

    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://packs")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    data = cast("dict[str, Any]", result)

    client.packs.list_async.assert_awaited_once_with(with_=None, timeout_ms=1000)
    assert data["packs"]["items"] == [{"id": "cribl-okta", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_packs_resource_handles_collector_error(mock_deps: SimpleNamespace) -> None:
    """Ensure packs resource degrades gracefully when the leader-level collector fails."""
    mock_deps.collect_packs.side_effect = RuntimeError("boom")

    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://packs")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    data = cast("dict[str, Any]", result)

    assert data["packs"]["status"] == "error"
    assert data["packs"]["error"] == "boom"
    assert data["packs"]["error_type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_groups_resource_handles_collector_error(mock_deps: SimpleNamespace) -> None:
    """Ensure groups resource degrades gracefully when collectors fail."""
    mock_deps.collect_product_groups.side_effect = RuntimeError("boom")

    app = FastMCP("test")
    resources.register(app, deps=mock_deps)

    resource = await app.get_resource("cribl://groups")
    assert resource is not None
    async with Context(app):
        result = await resource.fn()  # type: ignore[reportUnknownMemberType]
    data = cast("dict[str, Any]", result)

    product_result = data["groups"]["stream"]
    assert product_result["status"] == "error"
    assert product_result["error"] == "boom"
    assert product_result["error_type"] == "RuntimeError"
