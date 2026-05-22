"""Unit tests for the list_variables MCP tool wrapper."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.operations.variables import collect_product_variables
from snc_cribl_mcp.tools.list_variables import register as register_list_variables


class _FakeApp:
    """Minimal FastMCP stand-in that captures registered tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = {}

    def tool(
        self,
        *,
        name: str,
        description: str,
        annotations: dict[str, Any] | None = None,
    ) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], Callable[..., Awaitable[dict[str, Any]]]]:
        """Register a tool by name and return the original function."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
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
async def test_list_variables_tool_aggregates_direct_http_results(mock_ctx: Context) -> None:
    """The variables tool should use direct HTTP collection with bearer auth."""
    config = CriblConfig(url="https://cribl.example.com/api/v1", username="user", password="pass")
    security = Security(bearer_auth="test-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))

    group_model = MagicMock()
    group_model.model_dump.return_value = {"id": "worker-main"}
    client = MagicMock()
    client.groups.list_async = AsyncMock(return_value=MagicMock(items=[group_model]))
    http_client = AsyncMock()
    client.sdk_configuration = MagicMock(server_url=config.base_url_str, async_client=http_client)

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"count": 1, "items": [{"id": "site", "value": "phx"}]}
    response.raise_for_status = MagicMock()
    http_client.get = AsyncMock(return_value=response)

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=None)
    deps = SimpleNamespace(
        resolve_config=MagicMock(return_value=config),
        get_token_manager=MagicMock(return_value=token_manager),
        products=(ProductsCore.STREAM,),
        create_cp=MagicMock(return_value=cm),
        collect_product_variables=collect_product_variables,
    )

    app = _FakeApp()
    register_list_variables(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["list_variables"](mock_ctx, server="prod")
    variables = cast("dict[str, Any]", result["variables"])
    stream = cast("dict[str, Any]", variables["stream"])

    assert result["base_url"] == "https://cribl.example.com/api/v1"
    assert stream["total_count"] == 1
    assert stream["groups"][0]["items"] == [{"id": "site", "value": "phx"}]
    assert http_client.get.await_args is not None
    assert http_client.get.await_args.kwargs["headers"] == {"Authorization": "Bearer test-token"}
    deps.resolve_config.assert_called_once_with("prod")
