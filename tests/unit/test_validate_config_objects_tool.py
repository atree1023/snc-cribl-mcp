"""Unit tests for semantic config validation tool wiring."""

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.tools.validate_config_objects import register as register_validate_config_objects


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


@pytest.mark.asyncio
async def test_validate_config_objects_tool_returns_semantic_results(mock_ctx: Context) -> None:
    """The tool should force payload validation and classify semantic differences."""
    impl = AsyncMock(
        return_value={
            "resource_kind": "destinations",
            "scope": "group",
            "items": [
                {
                    "item_id": "splunk:hec",
                    "status": "different",
                    "source": {"id": "splunk:hec", "type": "splunk_hec", "servers": ["phx"]},
                    "target": {"id": "splunk:hec-aus", "type": "splunk_hec", "servers": ["aus"]},
                }
            ],
        }
    )

    app = _FakeApp()
    register_validate_config_objects(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["validate_config_objects"](
        mock_ctx,
        resource_kind="destinations",
        source_server="phx",
        target_server="aus",
        source_group="default",
        product="stream",
    )

    assert result["semantic_in_sync"] is True
    assert result["items"][0]["semantic_status"] == "functionally_equivalent"
    assert result["items"][0]["identity_differences"] == [
        {
            "path": "id",
            "reason": "object identity",
        },
        {
            "path": "servers[0]",
            "reason": "environment endpoint list",
        },
    ]
    impl.assert_awaited_once_with(
        "destinations",
        "phx",
        "aus",
        product=ProductsCore.STREAM,
        group_id="default",
        target_group_id=None,
        item_id=None,
        item_pattern=None,
        item_regex=None,
        exclude_item_pattern=None,
        exclude_item_regex=None,
        case_sensitive=False,
        include_payloads=True,
    )


@pytest.mark.asyncio
async def test_validate_config_objects_tool_rejects_missing_group(mock_ctx: Context) -> None:
    """Group-scoped semantic validation should require a source group."""
    impl = AsyncMock(return_value={})

    app = _FakeApp()
    register_validate_config_objects(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="source_group is required"):
        await app.tools["validate_config_objects"](
            mock_ctx,
            resource_kind="sources",
            source_server="phx",
            target_server="aus",
        )


@pytest.mark.asyncio
async def test_validate_config_objects_tool_rejects_group_selectors_for_groups(mock_ctx: Context) -> None:
    """Semantic group validation should reject group selector arguments."""
    impl = AsyncMock(return_value={})

    app = _FakeApp()
    register_validate_config_objects(app, impl=impl)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="only apply to sources, destinations, pipelines, and routes"):
        await app.tools["validate_config_objects"](
            mock_ctx,
            resource_kind="groups",
            source_server="phx",
            target_server="aus",
            target_group="default",
        )


@pytest.mark.asyncio
async def test_validate_config_objects_tool_forwards_product_scoped_groups(mock_ctx: Context) -> None:
    """Group semantic validation should be forwarded when no group selectors are provided."""
    impl = AsyncMock(return_value={"items": [{"item_id": "default", "status": "in_sync"}]})

    app = _FakeApp()
    register_validate_config_objects(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["validate_config_objects"](
        mock_ctx,
        resource_kind="groups",
        source_server="phx",
        target_server="aus",
        item_id="default",
    )

    assert result["semantic_in_sync"] is True
    impl.assert_awaited_once_with(
        "groups",
        "phx",
        "aus",
        product=ProductsCore.STREAM,
        group_id=None,
        target_group_id=None,
        item_id="default",
        item_pattern=None,
        item_regex=None,
        exclude_item_pattern=None,
        exclude_item_regex=None,
        case_sensitive=False,
        include_payloads=True,
    )


@pytest.mark.asyncio
async def test_validate_config_objects_tool_forwards_item_filters(mock_ctx: Context) -> None:
    """Semantic validation should forward item filters to sync validation."""
    impl = AsyncMock(return_value={"items": []})

    app = _FakeApp()
    register_validate_config_objects(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["validate_config_objects"](
        mock_ctx,
        resource_kind="sources",
        source_server="dev-dvb",
        target_server="dev-dva",
        source_group="default",
        item_pattern="sdpe-rest-* but not sdpe-rest-test-*",
        item_regex=r"^sdpe-rest-",
        exclude_item_pattern="*-tmp",
        case_sensitive=True,
    )

    assert result["semantic_in_sync"] is True
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
        exclude_item_pattern="*-tmp",
        exclude_item_regex=None,
        case_sensitive=True,
        include_payloads=True,
    )
