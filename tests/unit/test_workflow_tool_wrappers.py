"""Unit tests for workflow-style MCP tool wrappers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.tools.group_sync import register as register_group_sync
from snc_cribl_mcp.tools.system_settings import register as register_system_settings
from snc_cribl_mcp.tools.users import register as register_users


class _FakeApp:
    """Minimal FastMCP stand-in that captures registered tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}
        self.annotations: dict[str, dict[str, Any] | None] = {}

    def tool(
        self,
        *,
        name: str,
        description: str,
        annotations: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Callable[..., Awaitable[dict[str, Any]]]]:
        """Register a tool by name and return the original function."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
            _ = description
            self.tools[name] = func
            self.annotations[name] = annotations
            return func

        return _decorator


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_group_sync_tools_forward_replicate_and_validate_arguments(mock_ctx: Context) -> None:
    """Group workflow tools should parse products and forward all workflow options."""
    replicate_impl = AsyncMock(return_value={"copied_count": 2})
    validate_impl = AsyncMock(return_value={"in_sync": True})
    app = _FakeApp()

    register_group_sync(app, replicate_impl=replicate_impl, validate_impl=validate_impl)  # type: ignore[arg-type]

    replicate_result = await app.tools["replicate_group_config"](
        mock_ctx,
        source_server="source",
        target_server="target",
        source_group="Main Workers",
        target_group="Target Workers",
        product="edge",
        content_kinds=["sources"],
        include_group_settings=False,
        overwrite=False,
        validate_after=False,
        append_routes=True,
    )
    validate_result = await app.tools["validate_group_config"](
        mock_ctx,
        source_server="source",
        target_server="target",
        source_group="Main Workers",
        product="stream",
        content_kinds=["variables"],
        include_payloads=True,
    )

    assert replicate_result == {"copied_count": 2}
    assert validate_result == {"in_sync": True}
    replicate_impl.assert_awaited_once_with(
        "source",
        "target",
        product=ProductsCore.EDGE,
        source_group="Main Workers",
        target_group="Target Workers",
        content_kinds=["sources"],
        include_group_settings=False,
        overwrite=False,
        validate_after=False,
        append_routes=True,
    )
    validate_impl.assert_awaited_once_with(
        "source",
        "target",
        product=ProductsCore.STREAM,
        source_group="Main Workers",
        target_group=None,
        content_kinds=["variables"],
        include_group_settings=True,
        include_payloads=True,
    )
    assert app.annotations["validate_group_config"] == {"title": "Validate group or fleet sync", "readOnlyHint": True}


@pytest.mark.asyncio
async def test_system_settings_tools_forward_arguments(mock_ctx: Context) -> None:
    """System settings workflow tools should forward mutation and validation options."""
    replicate_impl = AsyncMock(return_value={"action": "updated"})
    validate_impl = AsyncMock(return_value={"in_sync": False})
    app = _FakeApp()

    register_system_settings(app, replicate_impl=replicate_impl, validate_impl=validate_impl)  # type: ignore[arg-type]

    replicate_result = await app.tools["replicate_system_settings"](
        mock_ctx,
        source_server="source",
        target_server="target",
        overwrite=False,
        validate_after=False,
    )
    validate_result = await app.tools["validate_system_settings"](
        mock_ctx,
        source_server="source",
        target_server="target",
        include_payloads=True,
    )

    assert replicate_result == {"action": "updated"}
    assert validate_result == {"in_sync": False}
    replicate_impl.assert_awaited_once_with("source", "target", overwrite=False, validate_after=False)
    validate_impl.assert_awaited_once_with("source", "target", include_payloads=True)


@pytest.mark.asyncio
async def test_sync_user_tool_forwards_arguments(mock_ctx: Context) -> None:
    """The sync_user tool should forward profile fields and write options by keyword."""
    impl = AsyncMock(return_value={"action": "created"})
    app = _FakeApp()

    register_users(app, impl=impl)  # type: ignore[arg-type]

    result = await app.tools["sync_user"](
        mock_ctx,
        target_server="target",
        username="test-user",
        source_server="source",
        password_env="TEST_USER_PASSWORD",
        first="Test",
        last="User",
        email="test.user@example.invalid",
        roles=["admin"],
        disabled=True,
        overwrite=False,
        validate_after=False,
    )

    assert result == {"action": "created"}
    impl.assert_awaited_once_with(
        target_server="target",
        username="test-user",
        source_server="source",
        password=None,
        password_env="TEST_USER_PASSWORD",
        first="Test",
        last="User",
        email="test.user@example.invalid",
        roles=["admin"],
        disabled=True,
        overwrite=False,
        validate_after=False,
    )
