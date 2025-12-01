"""Unit tests for the list_sources MCP tool wrapper.

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
from snc_cribl_mcp.operations.sources import collect_product_sources as _collect_product_sources
from snc_cribl_mcp.tools.list_sources import register as register_list_sources


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
async def test_list_sources_tool_success(deps_base: SimpleNamespace, mock_ctx: Context) -> None:
    """The tool should aggregate sources across products and return formatted JSON."""
    # Set up token manager with proper Security mock
    security = Security(bearer_auth="test-token")
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

    # Mock async_client for collector HTTP calls
    mock_http_client = AsyncMock()

    # Mock HTTP responses for collector sources (/lib/jobs endpoint)
    # Return empty collectors for both groups
    resp_empty_jobs = MagicMock()
    resp_empty_jobs.status_code = 200
    resp_empty_jobs.json.return_value = {"items": []}

    async def http_get(url: str, **_kwargs: object) -> MagicMock:
        if "/lib/jobs" in url:
            return resp_empty_jobs
        return MagicMock(status_code=404)

    mock_http_client.get = AsyncMock(side_effect=http_get)

    mock_client.sdk_configuration = MagicMock(
        server_url=deps_base.config.base_url_str,
        async_client=mock_http_client,
    )

    # Sources per-group
    resp_g1 = MagicMock(items=[MagicMock()], count=1)
    resp_g1.items[0].model_dump.return_value = {"name": "s1"}
    resp_e1 = MagicMock(items=[MagicMock(), MagicMock()], count=2)
    resp_e1.items[0].model_dump.return_value = {"name": "s2"}
    resp_e1.items[1].model_dump.return_value = {"name": "s3"}

    async def sources_list_async(*_args: object, **kwargs: dict[str, object]) -> MagicMock:
        srv_url = str(kwargs.get("server_url", ""))
        assert srv_url.endswith(("/m/g1", "/m/e1"))  # ensure group scoping
        return resp_g1 if srv_url.endswith("/m/g1") else resp_e1

    mock_client.sources = MagicMock(list_async=AsyncMock(side_effect=sources_list_async))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_sources=_collect_product_sources,
    )

    app = _FakeApp()
    register_list_sources(app, deps=deps)  # type: ignore[arg-type]
    assert "list_sources" in app.tools

    raw = await app.tools["list_sources"](mock_ctx)
    data = raw

    sources = cast("dict[str, Any]", data["sources"])

    assert data["base_url"] == deps_base.config.base_url_str
    assert "stream" in sources
    assert "edge" in sources
    stream = cast("dict[str, Any]", sources["stream"])
    edge = cast("dict[str, Any]", sources["edge"])
    assert stream["total_count"] == 1
    assert edge["total_count"] == 2


@pytest.mark.asyncio
async def test_list_sources_tool_handles_unavailable_product(
    deps_base: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """If groups listing is 404 for a product, it should mark that product unavailable."""
    security = Security(bearer_auth="test-token")
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

    # Mock async_client for collector HTTP calls
    mock_http_client = AsyncMock()

    # Mock HTTP responses for collector sources (/lib/jobs endpoint)
    resp_empty_jobs = MagicMock()
    resp_empty_jobs.status_code = 200
    resp_empty_jobs.json.return_value = {"items": []}

    async def http_get(url: str, **_kwargs: object) -> MagicMock:
        if "/lib/jobs" in url:
            return resp_empty_jobs
        return MagicMock(status_code=404)

    mock_http_client.get = AsyncMock(side_effect=http_get)

    mock_client.sdk_configuration = MagicMock(
        server_url=deps_base.config.base_url_str,
        async_client=mock_http_client,
    )

    empty_resp = MagicMock(items=[])
    empty_resp.count = None
    mock_client.sources = MagicMock(list_async=AsyncMock(return_value=empty_resp))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    deps = SimpleNamespace(
        **deps_base.__dict__,
        token_manager=token_manager,
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_sources=_collect_product_sources,
    )

    app = _FakeApp()
    register_list_sources(app, deps=deps)  # type: ignore[arg-type]

    raw = await app.tools["list_sources"](mock_ctx)
    data = raw

    sources = cast("dict[str, Any]", data["sources"])

    stream = cast("dict[str, Any]", sources["stream"])
    edge = cast("dict[str, Any]", sources["edge"])
    assert stream["status"] == "ok"
    assert edge["status"] == "unavailable"
