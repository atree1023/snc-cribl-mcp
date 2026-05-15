"""Unit tests for Pack MCP tool wrappers."""

from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.tools.packs import register as register_pack_tools


class _FakeApp:
    """Minimal stand-in for FastMCP app to capture registered tools."""

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
        """Register a tool by name and return a decorator that captures the function."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
            _ = description
            self.tools[name] = func
            self.annotations[name] = annotations
            return func

        return _decorator


def _counted_response(*items: dict[str, Any], count: int | None = None) -> MagicMock:
    """Build a fake SDK counted response with serializable model items."""
    models: list[MagicMock] = []
    for item in items:
        model = MagicMock()
        model.model_dump.return_value = item
        models.append(model)

    response = MagicMock()
    response.items = models
    response.count = len(items) if count is None else count
    return response


def _single_response(payload: dict[str, Any]) -> MagicMock:
    """Build a fake SDK single-object response."""
    response = MagicMock()
    response.model_dump.return_value = payload
    return response


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    return ctx


@pytest.fixture
def deps() -> SimpleNamespace:
    """Return dependencies with a fake Pack-capable client."""
    config = CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
    )
    security = Security(bearer_auth="test-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))

    client = MagicMock()
    client.packs.list_async = AsyncMock(return_value=_counted_response({"id": "cribl-okta", "source": "git+repo"}))
    client.packs.get_async = AsyncMock(return_value=_counted_response({"id": "cribl-okta", "source": "git+repo"}))
    client.packs.sources.list_async = AsyncMock(return_value=_counted_response())
    client.packs.sources.get_async = AsyncMock(return_value=_counted_response({"id": "in_http", "type": "http"}))
    client.packs.destinations.list_async = AsyncMock(return_value=_counted_response())
    client.packs.destinations.get_async = AsyncMock(return_value=_counted_response({"id": "devnull", "type": "devnull"}))
    client.packs.pipelines.list_async = AsyncMock(return_value=_counted_response())
    client.packs.pipelines.get_async = AsyncMock(return_value=_counted_response({"id": "main"}))
    client.packs.routes.list_async = AsyncMock(return_value=_counted_response())
    client.packs.routes.get_async = AsyncMock(return_value=_counted_response({"id": "default"}))
    client.packs.install_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    client.packs.upload_async = AsyncMock(return_value=_single_response({"source": "uploaded.crbl"}))
    client.packs.update_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    client.packs.delete_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    async_client = MagicMock(spec=httpx.AsyncClient)
    async_client.get = AsyncMock(
        return_value=httpx.Response(
            200,
            json={"count": 0, "items": []},
            request=httpx.Request("GET", "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta/system/lookups"),
        )
    )
    client.sdk_configuration = MagicMock(server_url=config.base_url_str, async_client=async_client)
    group_model = MagicMock()
    group_model.model_dump.return_value = {"id": "worker-main", "name": "Main Workers"}
    client.groups.list_async = AsyncMock(return_value=MagicMock(items=[group_model]))

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=None)

    return SimpleNamespace(
        resolve_config=MagicMock(return_value=config),
        get_token_manager=MagicMock(return_value=token_manager),
        create_cp=MagicMock(return_value=cm),
        client=client,
        token_manager=token_manager,
        config=config,
    )


@pytest.mark.asyncio
async def test_pack_tools_register_with_expected_annotations(deps: SimpleNamespace) -> None:
    """All Pack tools should be registered with read-only hints matching behavior."""
    app = _FakeApp()

    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    assert set(app.tools) == {
        "list_packs",
        "get_pack",
        "install_pack",
        "upload_pack",
        "update_pack",
        "delete_pack",
    }
    assert app.annotations["list_packs"] == {"title": "List Packs", "readOnlyHint": True, "idempotentHint": True}
    assert app.annotations["get_pack"] == {"title": "Get Pack", "readOnlyHint": True, "idempotentHint": True}
    assert app.annotations["install_pack"] == {
        "title": "Install Pack",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
    }
    assert app.annotations["upload_pack"] == {
        "title": "Upload Pack",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
    }
    assert app.annotations["update_pack"] == {
        "title": "Upgrade Pack",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
    }
    assert app.annotations["delete_pack"] == {
        "title": "Uninstall Pack",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
    }


@pytest.mark.asyncio
async def test_list_packs_tool_resolves_server_and_wraps_response(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """list_packs should resolve per-request config and return standard metadata."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["list_packs"](mock_ctx, server="prod", with_="inputs")

    deps.resolve_config.assert_called_once_with("prod")
    deps.get_token_manager.assert_called_once_with(deps.config)
    deps.token_manager.get_security.assert_awaited_once()
    deps.create_cp.assert_called_once_with(deps.config, security=Security(bearer_auth="test-token"))
    deps.client.packs.list_async.assert_awaited_once_with(with_="inputs", timeout_ms=10000)
    assert result["base_url"] == "https://cribl.example.com/api/v1"
    assert result["packs"]["items"] == [{"id": "cribl-okta", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_list_packs_tool_supports_distributed_group_scope(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """list_packs should resolve product and group selectors into a group-scoped SDK server_url."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["list_packs"](
        mock_ctx,
        product="stream",
        group="Main Workers",
    )

    deps.client.groups.list_async.assert_awaited_once_with(product=ProductsCore.STREAM, timeout_ms=10000)
    deps.client.packs.list_async.assert_awaited_once_with(
        with_=None,
        timeout_ms=10000,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )
    assert result["scope"] == {
        "product": "stream",
        "group_selector": "Main Workers",
        "group_id": "worker-main",
        "matched_by": "name",
        "group_name": "Main Workers",
        "group_description": None,
    }


@pytest.mark.asyncio
async def test_pack_mutation_tools_forward_arguments(
    deps: SimpleNamespace,
    mock_ctx: Context,
    tmp_path: Path,
) -> None:
    """Mutating Pack tools should forward tool arguments to the SDK operations."""
    pack_file = tmp_path / "uploaded.crbl"
    pack_file.write_bytes(b"pack")
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    install_result = await app.tools["install_pack"](mock_ctx, request={"source": "git+repo"})
    upload_result = await app.tools["upload_pack"](mock_ctx, file_path=str(pack_file))
    update_result = await app.tools["update_pack"](
        mock_ctx,
        pack_id="cribl-duo",
        source="https://example.com/cribl-duo.crbl",
        allow_custom_functions=True,
    )
    delete_result = await app.tools["delete_pack"](mock_ctx, pack_id="cribl-duo")

    deps.client.packs.install_async.assert_awaited_once_with(request={"source": "git+repo"}, timeout_ms=10000)
    deps.client.packs.upload_async.assert_awaited_once()
    deps.client.packs.update_async.assert_awaited_once_with(
        id="cribl-duo",
        source="https://example.com/cribl-duo.crbl",
        allow_custom_functions=True,
        timeout_ms=10000,
    )
    deps.client.packs.delete_async.assert_awaited_once_with(id="cribl-duo", timeout_ms=10000)
    assert install_result["install"]["items"] == [{"id": "cribl-duo", "source": "git+repo"}]
    assert upload_result["upload"] == {"status": "ok", "source": "uploaded.crbl"}
    assert update_result["update"]["items"] == [{"id": "cribl-duo", "source": "git+repo"}]
    assert delete_result["delete"]["items"] == [{"id": "cribl-duo", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_get_pack_tool_returns_singular_section(deps: SimpleNamespace, mock_ctx: Context) -> None:
    """get_pack should wrap the new Pack content summary under a singular section."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["get_pack"](mock_ctx, pack_id="cribl-okta")

    deps.client.packs.get_async.assert_awaited_once_with(id="cribl-okta", timeout_ms=10000)
    assert result["pack"]["metadata"]["items"] == [{"id": "cribl-okta", "source": "git+repo"}]
    assert result["pack"]["sections"]["sources"]["total_count"] == 0


@pytest.mark.asyncio
async def test_get_pack_tool_forwards_detail_arguments(deps: SimpleNamespace, mock_ctx: Context) -> None:
    """get_pack should forward kind, object_id, and detail to the operation layer."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["get_pack"](
        mock_ctx,
        pack_id="cribl-okta",
        kind="pipelines",
        object_id="main",
        detail="full",
    )

    deps.client.packs.pipelines.get_async.assert_awaited_once_with(id="main", pack="cribl-okta", timeout_ms=10000)
    assert result["pack"]["objects"]["items"][0]["payload"]["id"] == "main"


@pytest.mark.asyncio
async def test_get_pack_tool_reports_validation_error_for_aggregate_cursor(
    deps: SimpleNamespace,
    mock_ctx: Context,
) -> None:
    """get_pack should surface operation validation errors in the standard tool envelope."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["get_pack"](mock_ctx, pack_id="cribl-okta", cursor="1")

    assert result["pack"]["status"] == "validation_error"
    assert "cursor and limit" in result["pack"]["message"]


@pytest.mark.asyncio
async def test_pack_tool_rejects_product_without_group(deps: SimpleNamespace, mock_ctx: Context) -> None:
    """Pack tools should fail fast when product is supplied without distributed group scope."""
    app = _FakeApp()
    register_pack_tools(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["list_packs"](mock_ctx, product="edge")

    assert result["packs"]["status"] == "validation_error"
    assert "product is only used when group is provided" in result["packs"]["message"]
    deps.client.packs.list_async.assert_not_awaited()
