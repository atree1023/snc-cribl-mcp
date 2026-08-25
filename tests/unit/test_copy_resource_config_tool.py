"""Unit tests for the copy_resource_config MCP tool wrapper."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.tools.copy_resource_config import register as register_copy_resource_config


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
async def test_copy_resource_config_tool_forwards_arguments(mock_ctx: Context) -> None:
    """The tool should validate inputs and forward normalized arguments to the implementation."""
    impl = AsyncMock(return_value={"copied_count": 1})

    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["copy_resource_config"](
        mock_ctx,
        resource_kind="pipelines",
        source_server="golden.oak",
        target_server="cribl.cloud",
        source_group="sandbox_appnode",
        target_group="default",
        item_id="cisco_asa",
    )

    assert result["copied_count"] == 1
    impl.assert_awaited_once_with(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        group_id="sandbox_appnode",
        target_group_id="default",
        item_id="cisco_asa",
        item_pattern=None,
        item_regex=None,
        exclude_item_pattern=None,
        exclude_item_regex=None,
        case_sensitive=False,
        overwrite=True,
        validate_after=True,
        append_routes=False,
        dry_run=True,
        expected_plan_sha256=None,
    )


@pytest.mark.asyncio
async def test_copy_resource_config_tool_requires_source_group_for_group_scoped_resources(
    mock_ctx: Context,
) -> None:
    """Group-scoped resource copies should reject missing source_group selectors."""
    impl = AsyncMock(return_value={})

    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="source_group is required"):
        await app.tools["copy_resource_config"](
            mock_ctx,
            resource_kind="pipelines",
            source_server="golden.oak",
            target_server="cribl.cloud",
        )


@pytest.mark.asyncio
async def test_copy_resource_config_tool_rejects_group_selectors_for_groups(
    mock_ctx: Context,
) -> None:
    """Product-scoped group copies should reject source_group and target_group."""
    impl = AsyncMock(return_value={})

    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="only apply to sources, destinations, pipelines, and routes"):
        await app.tools["copy_resource_config"](
            mock_ctx,
            resource_kind="groups",
            source_server="golden.oak",
            target_server="cribl.cloud",
            source_group="default",
        )


@pytest.mark.asyncio
async def test_copy_resource_config_tool_forwards_product_scoped_groups(mock_ctx: Context) -> None:
    """Group copies without selectors should be forwarded as product-scoped operations."""
    impl = AsyncMock(return_value={"updated_count": 1})

    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["copy_resource_config"](
        mock_ctx,
        resource_kind="groups",
        source_server="golden.oak",
        target_server="cribl.cloud",
        item_id="default",
    )

    assert result == {"updated_count": 1}
    impl.assert_awaited_once_with(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        group_id=None,
        target_group_id=None,
        item_id="default",
        item_pattern=None,
        item_regex=None,
        exclude_item_pattern=None,
        exclude_item_regex=None,
        case_sensitive=False,
        overwrite=True,
        validate_after=True,
        append_routes=False,
        dry_run=True,
        expected_plan_sha256=None,
    )


@pytest.mark.asyncio
async def test_copy_resource_config_tool_forwards_filters_and_dry_run(mock_ctx: Context) -> None:
    """The tool should forward item filters and dry-run controls to the implementation."""
    impl = AsyncMock(return_value={"dry_run": True, "planned_count": 2})

    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["copy_resource_config"](
        mock_ctx,
        resource_kind="sources",
        source_server="dev-dvb",
        target_server="dev-dva",
        source_group="default",
        item_pattern="sdpe-rest-* but not sdpe-rest-test-*",
        item_regex=r"^sdpe-rest-",
        exclude_item_regex=r"-tmp$",
        dry_run=True,
    )

    assert result["dry_run"] is True
    impl.assert_awaited_once_with(
        "sources",
        "dev-dvb",
        "dev-dva",
        product=ProductsCore.STREAM,
        group_id="default",
        target_group_id=None,
        item_id=None,
        item_pattern="sdpe-rest-* but not sdpe-rest-test-*",
        item_regex=r"^sdpe-rest-",
        exclude_item_pattern=None,
        exclude_item_regex=r"-tmp$",
        case_sensitive=False,
        overwrite=True,
        validate_after=True,
        append_routes=False,
        dry_run=True,
        expected_plan_sha256=None,
    )


@pytest.mark.asyncio
async def test_copy_resource_config_tool_requires_and_forwards_reviewed_plan(mock_ctx: Context) -> None:
    """Execution should require and forward the exact dry-run plan digest."""
    impl = AsyncMock(return_value={"copied_count": 1})
    app = _FakeApp()
    register_copy_resource_config(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="expected_plan_sha256 is required"):
        await app.tools["copy_resource_config"](
            mock_ctx,
            resource_kind="pipelines",
            source_server="source",
            target_server="target",
            source_group="default",
            dry_run=False,
        )
    impl.assert_not_awaited()

    await app.tools["copy_resource_config"](
        mock_ctx,
        resource_kind="pipelines",
        source_server="source",
        target_server="target",
        source_group="default",
        dry_run=False,
        expected_plan_sha256="reviewed-plan",
    )
    assert impl.await_args is not None
    assert impl.await_args.kwargs["dry_run"] is False
    assert impl.await_args.kwargs["expected_plan_sha256"] == "reviewed-plan"
