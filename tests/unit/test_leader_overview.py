"""Unit tests for leader overview operation and MCP tool wrapper."""

from collections.abc import Awaitable, Callable, Sequence
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.operations.leader_overview import collect_leader_overview
from snc_cribl_mcp.tools.leader_overview import register as register_leader_overview


class _Model:
    """Tiny SDK-model stand-in with Pydantic-like serialization."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, mode: str = "json", *, exclude_none: bool = True) -> dict[str, Any]:
        return self.payload


class _Counted:
    """Tiny counted response payload."""

    def __init__(self, items: Sequence[object], count: int | None = None) -> None:
        self.items = list(items)
        self.count = len(self.items) if count is None else count


class _Page:
    """Tiny SDK paginated response wrapper."""

    def __init__(self, items: Sequence[object], count: int | None = None, next_page: object | None = None) -> None:
        self.result = _Counted(items, count=count)
        self._next_page = next_page

    async def next(self) -> object | None:
        return self._next_page


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
        """Register a tool by name."""

        def _decorator(func: Callable[..., Awaitable[dict[str, Any]]]) -> Callable[..., Awaitable[dict[str, Any]]]:
            _ = (description, annotations)
            self.tools[name] = func
            return func

        return _decorator


@pytest.fixture
def config() -> CriblConfig:
    """Return a test Cribl config."""
    return CriblConfig(
        url="https://cribl.example.com/api/v1",
        username="user",
        password="pass",
        server_name="prod",
    )


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like mock."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    return ctx


async def _system_info_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.path == "/api/v1/system/info"
    assert request.headers["authorization"] == "Bearer test-token"
    return httpx.Response(
        200,
        json={
            "items": [
                {
                    "BUILD": {"VERSION": "4.18.1-37206a7f", "BRANCH": "v4.18.1"},
                    "distMode": "master",
                    "hostname": "cribl-leader",
                    "guid": "leader-guid",
                }
            ]
        },
    )


def _build_overview_client(config: CriblConfig, async_client: httpx.AsyncClient) -> MagicMock:
    """Build a mocked Cribl SDK client for leader overview tests."""
    client = MagicMock()
    client.sdk_configuration = SimpleNamespace(server_url=config.base_url_str, async_client=async_client)
    client.health.get_async = AsyncMock(
        return_value=_Model({"status": "healthy", "startTime": 1700000000000, "role": "primary"})
    )

    stream_groups = _Counted(
        [
            _Model({"id": "default", "name": "Default", "workerCount": 2, "configVersion": "abc123"}),
            _Model({"id": "empty", "name": "Empty", "workerCount": 0}),
        ],
        count=2,
    )
    edge_groups = _Counted([_Model({"id": "fleet-a", "name": "Fleet A", "workerCount": 3})], count=1)

    async def groups_list_async(product: ProductsCore, timeout_ms: int) -> _Counted:
        return stream_groups if product == ProductsCore.STREAM else edge_groups

    client.groups.list_async = AsyncMock(side_effect=groups_list_async)

    async def summary_async(product: object, timeout_ms: int) -> _Model:
        product_value = getattr(product, "value", product)
        summary = (
            {
                "groups": {"count": 2, "sources": 2, "destinations": 1},
                "workers": {"count": 3, "disconnectedCount": 1, "alive": 2},
            }
            if product_value == "stream"
            else {
                "groups": {"count": 1, "sources": 1, "destinations": 2},
                "workers": {"count": 3, "disconnectedCount": 0, "alive": 3},
            }
        )
        return _Model({"count": 1, "items": [summary]})

    client.nodes.summaries.get_async = AsyncMock(side_effect=summary_async)

    async def nodes_list_async(product: ProductsCore, limit: int, offset: int, timeout_ms: int) -> _Page:
        assert limit == 500
        assert offset == 0
        assert timeout_ms == config.timeout_ms
        if product == ProductsCore.STREAM:
            nodes = [
                _Model({"id": "s1", "group": "default", "status": "healthy", "info": {"cribl": {"version": "4.18.1"}}}),
                _Model({"id": "s2", "group": "default", "status": "healthy", "info": {"cribl": {"version": "4.18.1"}}}),
            ]
        else:
            nodes = [
                _Model({"id": "e1", "group": "fleet-a", "status": "healthy", "info": {"cribl": {"version": "4.18.1"}}}),
                _Model({"id": "e2", "group": "fleet-a", "status": "healthy", "info": {"cribl": {"version": "4.18.1"}}}),
                _Model({"id": "e3", "group": "fleet-a", "status": "healthy", "info": {"cribl": {"version": "4.18.1"}}}),
            ]
        return _Page(nodes, count=len(nodes))

    client.nodes.list_async = AsyncMock(side_effect=nodes_list_async)

    async def source_status_async(**kwargs: object) -> _Page:
        assert kwargs["limit"] == 500
        assert kwargs["offset"] == 0
        server_url = str(kwargs["server_url"])
        if server_url.endswith("/m/default"):
            return _Page(
                [
                    _Model({"id": "in_http", "status": {"health": "green", "healthCounts": {"green": 2}, "timestamp": 1}}),
                    _Model({"id": "in_syslog", "status": {"health": "red", "healthCounts": {"red": 1}, "timestamp": 1}}),
                ]
            )
        return _Page([_Model({"id": "edge_agent", "status": {"health": "green", "healthCounts": {"green": 3}}})])

    async def destination_status_async(**kwargs: object) -> _Page:
        assert kwargs["limit"] == 500
        assert kwargs["offset"] == 0
        server_url = str(kwargs["server_url"])
        if server_url.endswith("/m/default"):
            return _Page([_Model({"id": "devnull", "status": {"health": "green", "healthCounts": {"green": 2}}})])
        return _Page([_Model({"id": "s3", "status": {"health": "yellow", "healthCounts": {"yellow": 1}}})])

    client.sources.statuses.list_async = AsyncMock(side_effect=source_status_async)
    client.destinations.statuses.list_async = AsyncMock(side_effect=destination_status_async)
    return client


@pytest.mark.asyncio
async def test_collect_leader_overview_success(config: CriblConfig, mock_ctx: Context) -> None:
    """Leader overview should combine health, version, node counts, groups, and runtime statuses."""
    async_client = httpx.AsyncClient(transport=httpx.MockTransport(_system_info_handler))
    try:
        client = _build_overview_client(config, async_client)
        result = await collect_leader_overview(
            client,
            config=config,
            security=Security(bearer_auth="test-token"),
            products=(ProductsCore.STREAM, ProductsCore.EDGE),
            ctx=mock_ctx,
        )
    finally:
        await async_client.aclose()

    assert result["server"] == "prod"
    assert result["cribl_version"] == "4.18.1-37206a7f"
    assert result["system_info"]["build"]["VERSION"] == "4.18.1-37206a7f"
    assert result["system_info"]["version_source"] == "BUILD.VERSION"
    assert result["health"]["details"]["status"] == "healthy"

    stream = result["products"]["stream"]
    assert stream["node_counts"]["total"] == 3
    assert stream["node_counts"]["connected"] == 2
    assert stream["omitted_empty_group_count"] == 1
    assert stream["groups_with_nodes"][0]["id"] == "default"
    assert stream["groups_with_nodes"][0]["sources"]["health_counts"] == {"green": 1, "red": 1}

    edge = result["products"]["edge"]
    assert edge["groups_with_nodes"][0]["id"] == "fleet-a"
    assert edge["groups_with_nodes"][0]["destinations"]["health_counts"] == {"yellow": 1}


@pytest.mark.asyncio
async def test_collect_leader_overview_marks_unavailable_product(config: CriblConfig, mock_ctx: Context) -> None:
    """If a product's groups endpoint is unavailable, the overview should keep that product visible."""
    async_client = httpx.AsyncClient(transport=httpx.MockTransport(_system_info_handler))
    try:
        client = _build_overview_client(config, async_client)
        api_error_404 = CriblControlPlaneError(message="Not found", body=None, raw_response=MagicMock(status_code=404))

        async def groups_list_async(product: ProductsCore, timeout_ms: int) -> _Counted:
            if product == ProductsCore.EDGE:
                raise api_error_404
            return _Counted([_Model({"id": "default", "name": "Default", "workerCount": 0})], count=1)

        client.groups.list_async = AsyncMock(side_effect=groups_list_async)

        result = await collect_leader_overview(
            client,
            config=config,
            security=Security(bearer_auth="test-token"),
            products=(ProductsCore.STREAM, ProductsCore.EDGE),
            ctx=mock_ctx,
        )
    finally:
        await async_client.aclose()

    assert result["products"]["edge"]["status"] == "unavailable"
    assert result["products"]["edge"]["count"] == 0


@pytest.mark.asyncio
async def test_leader_overview_tool_registers_and_invokes_dependencies(config: CriblConfig, mock_ctx: Context) -> None:
    """The tool wrapper should resolve config, open the SDK client, and delegate to the operation."""
    security = Security(bearer_auth="test-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))
    sdk_client = MagicMock()

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=sdk_client)
    cm.__aexit__ = AsyncMock(return_value=None)

    collect_impl = AsyncMock(return_value={"status": "ok"})
    deps = SimpleNamespace(
        resolve_config=MagicMock(return_value=config),
        get_token_manager=MagicMock(return_value=token_manager),
        create_cp=MagicMock(return_value=cm),
        products=(ProductsCore.STREAM, ProductsCore.EDGE),
        collect_leader_overview=collect_impl,
    )

    app = _FakeApp()
    register_leader_overview(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["get_leader_overview"](mock_ctx, server="prod")

    assert result == {"status": "ok"}
    deps.resolve_config.assert_called_once_with("prod")
    deps.create_cp.assert_called_once_with(config, security=security)
    collect_impl.assert_awaited_once_with(
        sdk_client,
        config=config,
        security=security,
        products=(ProductsCore.STREAM, ProductsCore.EDGE),
        ctx=mock_ctx,
    )
