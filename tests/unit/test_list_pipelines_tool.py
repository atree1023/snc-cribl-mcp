"""Unit tests for the list_pipelines MCP tool wrapper.

Validates JSON shape, dependency injection, and error handling through the
tool registration layer (without requiring a running FastMCP app).
Uses HTTP collection to preserve function configurations.
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
from snc_cribl_mcp.operations.pipelines import collect_product_pipelines as _collect_product_pipelines
from snc_cribl_mcp.tools.list_pipelines import register as register_list_pipelines


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
    ) -> Callable[
        [Callable[[Context], Awaitable[dict[str, Any]]]],
        Callable[[Context], Awaitable[dict[str, Any]]],
    ]:
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


@pytest.fixture
def mock_security() -> Security:
    """Return a mock Security object with bearer token."""
    return Security(bearer_auth="test-token")


@pytest.mark.asyncio
async def test_list_pipelines_tool_success(
    deps_base: SimpleNamespace,
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """The tool should aggregate pipelines across products and return formatted JSON."""
    # Set up token manager to return our mock security
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=mock_security))

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

    # Mock HTTP client for pipelines
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    g1_response = MagicMock()
    g1_response.status_code = 200
    g1_response.json.return_value = {
        "items": [{"id": "p1", "conf": {"functions": []}}],
        "count": 1,
    }
    g1_response.raise_for_status = MagicMock()

    e1_response = MagicMock()
    e1_response.status_code = 200
    e1_response.json.return_value = {
        "items": [
            {"id": "p2", "conf": {"functions": []}},
            {"id": "p3", "conf": {"functions": []}},
        ],
        "count": 2,
    }
    e1_response.raise_for_status = MagicMock()

    async def mock_get(url: str, **kwargs: object) -> MagicMock:
        if "/m/g1/pipelines" in url:
            return g1_response
        return e1_response

    mock_http_client.get = AsyncMock(side_effect=mock_get)

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_pipelines=_collect_product_pipelines,
    )

    app = _FakeApp()
    register_list_pipelines(app, deps=deps)  # type: ignore[arg-type]
    assert "list_pipelines" in app.tools

    # Tool function takes only ctx; security is obtained via token_manager internally
    raw = await app.tools["list_pipelines"](mock_ctx)
    data = raw

    pipelines = cast("dict[str, Any]", data["pipelines"])

    assert data["base_url"] == deps_base.config.base_url_str
    assert "stream" in pipelines
    assert "edge" in pipelines
    stream = cast("dict[str, Any]", pipelines["stream"])
    edge = cast("dict[str, Any]", pipelines["edge"])
    assert stream["total_count"] == 1
    assert edge["total_count"] == 2


@pytest.mark.asyncio
async def test_list_pipelines_tool_handles_unavailable_product(
    deps_base: SimpleNamespace,
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """If groups listing is 404 for a product, it should mark that product unavailable."""
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=mock_security))

    mock_client = MagicMock()
    # STREAM OK, EDGE 404
    groups_resp_stream = MagicMock(items=[MagicMock()])
    groups_resp_stream.items[0].model_dump.return_value = {"id": "g1"}
    api_error_404 = CriblControlPlaneError(
        message="Not found",
        body=None,
        raw_response=MagicMock(status_code=404),
    )

    async def groups_list_async(product: ProductsCore, timeout_ms: int) -> MagicMock:
        if product == ProductsCore.STREAM:
            return groups_resp_stream
        raise api_error_404

    mock_client.groups.list_async = AsyncMock(side_effect=groups_list_async)
    mock_client.sdk_configuration = MagicMock(server_url=deps_base.config.base_url_str)

    # Mock HTTP client for pipelines
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    empty_response = MagicMock()
    empty_response.status_code = 200
    empty_response.json.return_value = {"items": [], "count": 0}
    empty_response.raise_for_status = MagicMock()
    mock_http_client.get = AsyncMock(return_value=empty_response)

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_pipelines=_collect_product_pipelines,
    )

    app = _FakeApp()
    register_list_pipelines(app, deps=deps)  # type: ignore[arg-type]

    # Tool function takes only ctx; security is obtained via token_manager internally
    raw = await app.tools["list_pipelines"](mock_ctx)
    data = raw

    pipelines = cast("dict[str, Any]", data["pipelines"])

    stream = cast("dict[str, Any]", pipelines["stream"])
    edge = cast("dict[str, Any]", pipelines["edge"])
    assert stream["status"] == "ok"
    assert edge["status"] == "unavailable"
