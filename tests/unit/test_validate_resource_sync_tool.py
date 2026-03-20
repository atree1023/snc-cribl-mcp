"""Unit tests for the validate_resource_sync MCP tool wrapper."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.tools.validate_resource_sync import register as register_validate_resource_sync


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
        """Register a tool by name and return a decorator that captures the function."""

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


@pytest.mark.asyncio
async def test_validate_resource_sync_tool_forwards_group_resource_arguments(mock_ctx: Context) -> None:
    """Group validation should not require source_group and should parse product values."""
    impl = AsyncMock(return_value={"in_sync": True})

    app = _FakeApp()
    register_validate_resource_sync(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["validate_resource_sync"](
        mock_ctx,
        resource_kind="groups",
        source_server="golden.oak",
        target_server="cribl.cloud",
        item_id="default",
        product="edge",
    )

    assert result["in_sync"] is True
    impl.assert_awaited_once_with(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.EDGE,
        group_id=None,
        target_group_id=None,
        item_id="default",
    )


@pytest.mark.asyncio
async def test_validate_resource_sync_tool_rejects_group_selectors_for_groups(mock_ctx: Context) -> None:
    """Group validation should reject source_group and target_group parameters."""
    impl = AsyncMock(return_value={})

    app = _FakeApp()
    register_validate_resource_sync(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="only apply to sources, destinations, pipelines, and routes"):
        await app.tools["validate_resource_sync"](
            mock_ctx,
            resource_kind="groups",
            source_server="golden.oak",
            target_server="cribl.cloud",
            source_group="default",
        )
