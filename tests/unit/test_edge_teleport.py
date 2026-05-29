"""Unit tests for Edge teleport operations and tool wrapper."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Sequence
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.security import Security
from fastmcp import Context

import snc_cribl_mcp.operations.edge_teleport as edge_teleport_module
from snc_cribl_mcp.config import CriblConfig
from snc_cribl_mcp.operations.edge_teleport import (
    collect_edge_info,
    extract_datacenter_from_edge_host,
    normalize_edge_hostname,
    resolve_edge_node,
)
from snc_cribl_mcp.tools.edge_info import register as register_edge_info


class _Model:
    """Tiny SDK-model stand-in with Pydantic-like serialization."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def model_dump(self, mode: str = "json", *, exclude_none: bool = True) -> dict[str, Any]:
        _ = (mode, exclude_none)
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
        url="https://cribl-edge.fra0.service-now.com:9000/api/v1",
        username="user",
        password="pass",
        server_name="edge.fra0",
    )


@pytest.fixture
def mock_ctx() -> Context:
    """Return a Context-like mock."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    return ctx


def _build_client(config: CriblConfig, async_client: httpx.AsyncClient) -> MagicMock:
    """Build a mocked SDK client with one Edge node."""
    client = MagicMock()
    client.sdk_configuration = SimpleNamespace(server_url=config.base_url_str, async_client=async_client)
    client.nodes.list_async = AsyncMock(
        return_value=_Page(
            [
                _Model(
                    {
                        "id": "007d7afb-74f4-4836-ac78-1020cfb44ceb",
                        "status": "healthy",
                        "group": "default_fleet",
                        "info": {"hostname": "cribl01.fra0.service-now.com"},
                    }
                )
            ],
            count=1,
        )
    )
    return client


def test_hostname_normalization_and_datacenter_extraction() -> None:
    """Edge host helpers should append the standard domain and extract datacenter labels."""
    assert normalize_edge_hostname("Cribl01.FRA0") == "cribl01.fra0.service-now.com"
    assert normalize_edge_hostname("cribl01", datacenter="fra0") == "cribl01.fra0.service-now.com"
    assert extract_datacenter_from_edge_host("cribl01.fra0") == "fra"
    assert extract_datacenter_from_edge_host("cribl01", datacenter="fra0") == "fra"


@pytest.mark.asyncio
async def test_resolve_edge_node_matches_short_hostname(config: CriblConfig) -> None:
    """Node lookup should match the short user-provided hostname."""
    async_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        client = _build_client(config, async_client)

        node = await resolve_edge_node(
            cast("CriblControlPlane", client),
            edge_host="cribl01.fra0",
            timeout_ms=config.timeout_ms,
        )
    finally:
        await async_client.aclose()

    assert node["id"] == "007d7afb-74f4-4836-ac78-1020cfb44ceb"


@pytest.mark.asyncio
async def test_collect_edge_info_searches_file(
    config: CriblConfig,
    mock_ctx: Context,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """File search should post the HAR-derived payload to the teleport endpoint."""
    monkeypatch.setattr(edge_teleport_module, "time", lambda: 1780077228)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/w/007d7afb-74f4-4836-ac78-1020cfb44ceb/edge/search/file"
        assert request.headers["authorization"] == "Bearer test-token"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["file"] == "/var/log/messages"
        assert "file_path" not in payload
        assert payload["offset"] == 0
        assert payload["limit"] == 50
        assert payload["et"] == 1780073628
        assert payload["query"] == "login"
        assert payload["rulesets"] == []
        return httpx.Response(
            200,
            json={
                "items": [{"offset": 12345, "count": 1, "items": [{"_raw": "login accepted"}]}],
                "count": 1,
            },
        )

    async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        client = _build_client(config, async_client)

        result = await collect_edge_info(
            cast("CriblControlPlane", client),
            config=config,
            security=Security(bearer_auth="test-token"),
            edge_host="cribl01.fra0",
            info_type="file",
            file_path="/var/log/messages",
            query="login",
            offset=0,
            limit=50,
            ctx=mock_ctx,
        )
    finally:
        await async_client.aclose()

    assert result["status"] == "ok"
    assert result["operation"] == "search_file"
    assert result["datacenter"] == "fra"
    assert result["edge_host"] == "cribl01.fra0.service-now.com"
    assert result["next_offset"] == 12345
    assert result["node"]["hostname"] == "cribl01.fra0.service-now.com"
    assert result["request"]["file"] == "/var/log/messages"
    assert "file_path" not in result["request"]
    assert result["request"]["et"] == 1780073628
    assert result["request"]["rulesets"] == []


@pytest.mark.asyncio
async def test_collect_edge_info_quotes_punctuation_search_terms(config: CriblConfig) -> None:
    """Search terms containing punctuation should be wrapped in double quotes."""

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["file"] == "/var/log/secure"
        assert payload["query"] == '"scott.burger"'
        assert payload["rulesets"] == ["Cribl"]
        return httpx.Response(200, json={"items": [{"offset": 0, "count": 0, "items": []}], "count": 1})

    async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        client = _build_client(config, async_client)

        result = await collect_edge_info(
            cast("CriblControlPlane", client),
            config=config,
            security=Security(bearer_auth="test-token"),
            edge_host="cribl01.fra0",
            info_type="file",
            file_path="/var/log/secure",
            query="scott.burger",
            earliest_time=1780071931,
            rulesets=["Cribl"],
        )
    finally:
        await async_client.aclose()

    assert result["request"]["query"] == '"scott.burger"'
    assert result["request"]["et"] == 1780071931
    assert result["request"]["rulesets"] == ["Cribl"]


@pytest.mark.asyncio
async def test_collect_edge_info_rejects_relative_file_path(config: CriblConfig) -> None:
    """File reads/searches should require absolute Edge paths."""
    async_client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _request: httpx.Response(500)))
    try:
        client = _build_client(config, async_client)

        with pytest.raises(ValueError, match="absolute path"):
            await collect_edge_info(
                cast("CriblControlPlane", client),
                config=config,
                security=Security(bearer_auth="test-token"),
                edge_host="cribl01.fra0",
                info_type="file",
                file_path="var/log/messages",
                query=None,
            )
    finally:
        await async_client.aclose()


@pytest.mark.asyncio
async def test_get_edge_info_tool_resolves_leader_from_datacenter(config: CriblConfig, mock_ctx: Context) -> None:
    """Tool wrapper should pick the leader from the host datacenter when server is omitted."""
    security = Security(bearer_auth="test-token")
    token_manager = SimpleNamespace(get_security=AsyncMock(return_value=security))

    mock_client = MagicMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    collect = AsyncMock(return_value={"status": "ok"})

    deps = SimpleNamespace(
        resolve_config=MagicMock(return_value=config),
        resolve_config_for_datacenter=MagicMock(return_value=config),
        get_token_manager=MagicMock(return_value=token_manager),
        create_cp=MagicMock(return_value=mock_cm),
        collect_edge_info=collect,
    )

    app = _FakeApp()
    register_edge_info(app, deps=deps)  # type: ignore[arg-type]

    result = await app.tools["get_edge_info"](
        mock_ctx,
        edge_host="cribl01.fra0",
        file="/var/log/messages",
        query="login",
    )

    assert result == {"status": "ok"}
    deps.resolve_config_for_datacenter.assert_called_once_with("fra")
    deps.resolve_config.assert_not_called()
    collect.assert_awaited_once()
    await_args = collect.await_args
    assert await_args is not None
    kwargs = cast("dict[str, Any]", await_args.kwargs)
    assert kwargs["edge_host"] == "cribl01.fra0.service-now.com"
    assert kwargs["datacenter"] == "fra"
