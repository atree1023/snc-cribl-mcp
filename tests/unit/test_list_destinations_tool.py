"""Unit tests for the list_destinations MCP tool wrapper.

Validates JSON shape, dependency injection, and error handling through the
tool registration layer (without requiring a running FastMCP app).
"""

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.operations.destinations import collect_product_destinations as _collect_product_destinations
from snc_cribl_mcp.tools.list_destinations import register as register_list_destinations


class _FakeApp:
    """Minimal stand-in for FastMCP app to capture registered tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}

    def tool(
        self,
        *,
        name: str,
        description: str,
        annotations: dict[str, Any] | None = None,
    ) -> Callable[[Callable[[Context], Awaitable[dict[str, Any]]]], Callable[[Context], Awaitable[dict[str, Any]]]]:
        """Register a tool by name and return a decorator that captures the function."""

        def _decorator(
            func: Callable[[Context], Awaitable[dict[str, Any]]],
        ) -> Callable[[Context], Awaitable[dict[str, Any]]]:
            # Use parameters to avoid unused-argument warnings in strict linters
            _ = (description, annotations)
            self.tools[name] = func
            return func

        return _decorator


@pytest.fixture
def deps_base() -> SimpleNamespace:
    """Return base dependencies object with config and products set."""
    config = CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
    )
    products = (ProductsCore.STREAM, ProductsCore.EDGE)
    return SimpleNamespace(config=config, products=products)


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_list_destinations_tool_success(deps_base: SimpleNamespace, mock_ctx: Context) -> None:
    """The tool should aggregate destinations across products and return formatted JSON."""
    # Set up token manager
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=object()))

    # Mock client and SDK calls via context manager
    mock_client = MagicMock()
    # STREAM groups
    groups_resp_stream = MagicMock(items=[MagicMock()])
    groups_resp_stream.items[0].model_dump.return_value = {"id": "g1"}
    # EDGE groups
    groups_resp_edge = MagicMock(items=[MagicMock()])
    groups_resp_edge.items[0].model_dump.return_value = {"id": "e1"}

    async def groups_list_async(product: ProductsCore, timeout_ms: int) -> MagicMock:
        return groups_resp_stream if product == ProductsCore.STREAM else groups_resp_edge

    mock_client.groups.list_async = AsyncMock(side_effect=groups_list_async)
    mock_client.sdk_configuration = MagicMock(server_url=deps_base.config.base_url_str)

    # Destinations per-group
    resp_g1 = MagicMock(items=[MagicMock()], count=1)
    resp_g1.items[0].model_dump.return_value = {"name": "d1"}
    resp_e1 = MagicMock(items=[MagicMock(), MagicMock()], count=2)
    resp_e1.items[0].model_dump.return_value = {"name": "d2"}
    resp_e1.items[1].model_dump.return_value = {"name": "d3"}

    async def destinations_list_async(*_args: object, **kwargs: dict[str, object]) -> MagicMock:
        srv_url = str(kwargs.get("server_url", ""))
        assert srv_url.endswith(("/m/g1", "/m/e1"))  # ensure group scoping
        return resp_g1 if srv_url.endswith("/m/g1") else resp_e1

    mock_client.destinations = MagicMock(list_async=AsyncMock(side_effect=destinations_list_async))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        resolve_config=MagicMock(return_value=deps_base.config),
        get_token_manager=MagicMock(return_value=token_manager),
        products=deps_base.products,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_destinations=_collect_product_destinations,
    )

    app = _FakeApp()
    register_list_destinations(app, deps=deps)  # type: ignore[arg-type]
    assert "list_destinations" in app.tools

    raw = await app.tools["list_destinations"](mock_ctx)
    data = raw

    destinations = cast("dict[str, Any]", data["destinations"])

    assert data["base_url"] == deps_base.config.base_url_str
    assert "stream" in destinations
    assert "edge" in destinations
    stream = cast("dict[str, Any]", destinations["stream"])
    edge = cast("dict[str, Any]", destinations["edge"])
    assert stream["total_count"] == 1
    assert edge["total_count"] == 2


@pytest.mark.asyncio
async def test_list_destinations_tool_handles_unavailable_product(
    deps_base: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """If groups listing is 404 for a product, it should mark that product unavailable."""
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=object()))

    mock_client = MagicMock()
    # STREAM OK, EDGE 404
    groups_resp_stream = MagicMock(items=[MagicMock()])
    groups_resp_stream.items[0].model_dump.return_value = {"id": "g1"}
    api_error_404 = CriblControlPlaneError(message="Not found", body=None, raw_response=MagicMock(status_code=404))

    async def groups_list_async(product: ProductsCore, timeout_ms: int) -> MagicMock:
        if product == ProductsCore.STREAM:
            return groups_resp_stream
        raise api_error_404

    mock_client.groups.list_async = AsyncMock(side_effect=groups_list_async)
    mock_client.sdk_configuration = MagicMock(server_url=deps_base.config.base_url_str)
    empty_resp = MagicMock(items=[])
    empty_resp.count = None
    mock_client.destinations = MagicMock(list_async=AsyncMock(return_value=empty_resp))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        resolve_config=MagicMock(return_value=deps_base.config),
        get_token_manager=MagicMock(return_value=token_manager),
        products=deps_base.products,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_destinations=_collect_product_destinations,
    )

    app = _FakeApp()
    register_list_destinations(app, deps=deps)  # type: ignore[arg-type]

    raw = await app.tools["list_destinations"](mock_ctx)
    data = raw

    destinations = cast("dict[str, Any]", data["destinations"])

    stream = cast("dict[str, Any]", destinations["stream"])
    edge = cast("dict[str, Any]", destinations["edge"])
    assert stream["status"] == "ok"
    assert edge["status"] == "unavailable"
