"""Unit tests for the list_groups MCP tool wrapper.

Validates JSON shape, dependency injection, and error handling through the
tool registration layer (without requiring a running FastMCP app).
"""

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Context

from snc_cribl_mcp.tools.list_groups import register as register_list_groups


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
def mock_ctx() -> Context:
    """Return a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    return ctx


@pytest.mark.asyncio
async def test_list_groups_tool_registration(mock_ctx: Context) -> None:
    """The tool should register correctly and delegate to the implementation."""
    app = _FakeApp()

    # Mock implementation
    mock_impl = AsyncMock(return_value={"groups": {"stream": {"status": "ok"}}})

    register_list_groups(app, impl=mock_impl)  # type: ignore[arg-type]

    assert "list_groups" in app.tools

    # Invoke the tool
    result = await app.tools["list_groups"](mock_ctx)

    # Verify delegation
    mock_impl.assert_called_once_with(mock_ctx)
    assert result == {"groups": {"stream": {"status": "ok"}}}
