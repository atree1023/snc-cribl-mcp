"""Unit tests for the list_lookups MCP tool wrapper.

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
from cribl_control_plane.models.security import Security
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.operations.lookups import collect_product_lookups as _collect_product_lookups
from snc_cribl_mcp.tools.list_lookups import register as register_list_lookups


class _FakeApp:
    """Minimal stand-in for FastMCP app to capture registered tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[[Context], Awaitable[dict[str, Any]]]] = {}

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
        server_url="https://cribl.example.com",
        base_url="https://cribl.example.com/api/v1",
        bearer_token=None,
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
async def test_list_lookups_tool_success(deps_base: SimpleNamespace, mock_ctx: Context) -> None:
    """The tool should aggregate lookups across products and return formatted JSON."""
    # Set up token manager
    security = Security(bearer_auth="fake-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))

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

    # Mock async_client for lookups
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url=deps_base.config.base_url_str,
        async_client=mock_http_client,
    )

    # Lookups per-group
    # g1 response
    resp_g1 = MagicMock()
    resp_g1.status_code = 200
    resp_g1.json.return_value = {"items": [{"id": "l1"}], "count": 1}

    # e1 response
    resp_e1 = MagicMock()
    resp_e1.status_code = 200
    resp_e1.json.return_value = {"items": [{"id": "l2"}, {"id": "l3"}], "count": 2}

    async def http_get(url: str, **_kwargs: object) -> MagicMock:
        if "/m/g1/system/lookups" in url:
            return resp_g1
        if "/m/e1/system/lookups" in url:
            return resp_e1
        return MagicMock(status_code=404)

    mock_http_client.get = AsyncMock(side_effect=http_get)

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_lookups=_collect_product_lookups,
    )

    app = _FakeApp()
    register_list_lookups(app, deps=deps)  # type: ignore[arg-type]
    assert "list_lookups" in app.tools

    raw = await app.tools["list_lookups"](mock_ctx)
    data = raw

    lookups = cast("dict[str, Any]", data["lookups"])

    assert data["base_url"] == deps_base.config.base_url_str
    assert "stream" in lookups
    assert "edge" in lookups
    stream = cast("dict[str, Any]", lookups["stream"])
    edge = cast("dict[str, Any]", lookups["edge"])
    assert stream["total_count"] == 1
    assert edge["total_count"] == 2

    # Verify headers were passed
    calls = mock_http_client.get.call_args_list
    for call in calls:
        assert call.kwargs["headers"]["Authorization"] == "Bearer fake-token"


@pytest.mark.asyncio
async def test_list_lookups_tool_handles_unavailable_product(
    deps_base: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """If groups listing is 404 for a product, it should mark that product unavailable."""
    security = Security(bearer_auth="fake-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))

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

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url=deps_base.config.base_url_str,
        async_client=mock_http_client,
    )

    # Stream lookups empty
    resp_g1 = MagicMock()
    resp_g1.status_code = 200
    resp_g1.json.return_value = {"items": [], "count": 0}
    mock_http_client.get.return_value = resp_g1

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_lookups=_collect_product_lookups,
    )

    app = _FakeApp()
    register_list_lookups(app, deps=deps)  # type: ignore[arg-type]

    raw = await app.tools["list_lookups"](mock_ctx)
    data = raw

    lookups = cast("dict[str, Any]", data["lookups"])

    stream = cast("dict[str, Any]", lookups["stream"])
    edge = cast("dict[str, Any]", lookups["edge"])
    assert stream["status"] == "ok"
    assert edge["status"] == "unavailable"
