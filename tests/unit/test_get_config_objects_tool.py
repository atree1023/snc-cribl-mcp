"""Unit tests for the consolidated get_config_objects MCP tool."""

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.tools.get_config_objects import register as register_get_config_objects


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
    ) -> Callable[
        [Callable[..., Awaitable[dict[str, Any]]]],
        Callable[..., Awaitable[dict[str, Any]]],
    ]:
        def _decorator(
            func: Callable[..., Awaitable[dict[str, Any]]],
        ) -> Callable[..., Awaitable[dict[str, Any]]]:
            _ = (description, annotations)
            self.tools[name] = func
            return func

        return _decorator


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    return ctx


@pytest.fixture
def deps() -> SimpleNamespace:
    """Return injected dependencies for a compact get_config_objects tool run."""
    config = CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
    )
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=object()))
    mock_client = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    async def collect_product_pipelines(
        _client: object,
        *,
        product: ProductsCore,
        timeout_ms: int,
        ctx: Context,
    ) -> dict[str, Any]:
        _ = (timeout_ms, ctx)
        if product == ProductsCore.STREAM:
            return {
                "status": "ok",
                "total_count": 1,
                "groups": [
                    {
                        "group_id": "default",
                        "items": [{"id": "parse_firewall", "conf": {"functions": []}}],
                    }
                ],
            }
        return {"status": "ok", "total_count": 0, "groups": []}

    return SimpleNamespace(
        resolve_config=MagicMock(return_value=config),
        get_token_manager=MagicMock(return_value=token_manager),
        products=(ProductsCore.STREAM, ProductsCore.EDGE),
        create_cp=MagicMock(return_value=mock_cm),
        collect_product_pipelines=collect_product_pipelines,
    )


@pytest.mark.asyncio
async def test_get_config_objects_tool_returns_shaped_pipelines(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """The tool should collect and shape config objects for the requested product."""
    app = _FakeApp()
    register_get_config_objects(app, deps=deps)  # type: ignore[arg-type]

    data = await app.tools["get_config_objects"](
        mock_ctx,
        kind="pipelines",
        product="stream",
        include_dependencies=True,
    )

    assert data["base_url"] == "https://cribl.example.com/api/v1"
    assert data["kind"] == "pipelines"
    assert data["returned_count"] == 1
    assert data["objects"][0]["id"] == "parse_firewall"


@pytest.mark.asyncio
async def test_get_config_objects_tool_rejects_unknown_kind(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """Unknown object kinds should fail before any collector is invoked."""
    app = _FakeApp()
    register_get_config_objects(app, deps=deps)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Unsupported config object kind"):
        await app.tools["get_config_objects"](
            mock_ctx,
            kind="widgets",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_get_config_objects_tool_rejects_unregistered_kind(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """Supported kinds should fail clearly when their collector is not registered."""
    app = _FakeApp()
    register_get_config_objects(app, deps=deps)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="not registered"):
        await app.tools["get_config_objects"](
            mock_ctx,
            kind="routes",
        )


@pytest.mark.asyncio
async def test_get_config_objects_tool_passes_security_to_direct_http_collectors(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """Breakers and lookups should receive the security object for HTTP fallback collectors."""
    collector = AsyncMock(return_value={"status": "ok", "total_count": 0, "groups": []})
    deps.collect_product_breakers = collector

    app = _FakeApp()
    register_get_config_objects(app, deps=deps)  # type: ignore[arg-type]

    data = await app.tools["get_config_objects"](
        mock_ctx,
        kind="breakers",
        product="edge",
    )

    assert data["kind"] == "breakers"
    assert data["returned_count"] == 0
    collector.assert_awaited_once()
    assert collector.await_args is not None
    assert len(collector.await_args.args) == 2
    assert collector.await_args.kwargs["product"] == ProductsCore.EDGE
