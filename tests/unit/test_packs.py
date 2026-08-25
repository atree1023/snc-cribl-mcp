"""Unit tests for top-level Pack operations."""

# pyright: reportPrivateUsage=false

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security

from snc_cribl_mcp.operations import packs


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


class _Page:
    """Small paginated SDK wrapper for multi-page Pack tests."""

    def __init__(self, *items: dict[str, Any], next_page: object | None = None) -> None:
        self.result = SimpleNamespace(
            items=[_single_response(item) for item in items],
            count=len(items),
        )
        self._next_page = next_page

    async def next(self) -> object | None:
        """Return the configured next page."""
        return self._next_page


def _json_response(url: str, payload: dict[str, Any], status_code: int = 200) -> httpx.Response:
    """Build an httpx JSON response with an attached request."""
    return httpx.Response(
        status_code,
        json=payload,
        request=httpx.Request("GET", url),
    )


def _text_response(url: str, text: str, status_code: int = 200) -> httpx.Response:
    """Build an httpx text response with an attached request."""
    return httpx.Response(
        status_code,
        text=text,
        request=httpx.Request("GET", url),
    )


def test_pack_serializers_and_summary_helpers_cover_edge_shapes() -> None:
    """Small Pack helpers should normalize odd but valid SDK and HTTP response shapes."""
    model = MagicMock()
    model.model_dump.return_value = {"id": "tuple-item"}

    assert packs._serialize_counted_response(SimpleNamespace(items=(model,), count=None)) == {
        "status": "ok",
        "count": 1,
        "items": [{"id": "tuple-item"}],
    }
    assert packs._serialize_http_counted_payload([{"id": "one"}, "skip"]) == {
        "status": "ok",
        "count": 2,
        "items": [{"id": "one"}],
    }
    assert packs._serialize_http_counted_payload("not-json-object") == {
        "status": "error",
        "error": "Unexpected non-JSON-object Pack response.",
        "error_type": "str",
    }
    assert packs._pack_scope_label(None) == "top-level"
    assert packs._coerce_cursor("not-an-int") == 0
    assert packs._pack_item_id({"display": "none"}) is None
    assert packs._enabled_state({"enabled": True}) is True
    assert packs._enabled_state({"disabled": True}) is False

    summary = packs._summarize_pack_item("pipelines", {"id": "pipe", "conf": {"functions": "bad"}}, detail="summary")
    assert summary == {"id": "pipe", "refs": {}}


def test_group_pack_categories_reports_error_and_partial_unavailable_states() -> None:
    """Grouped Pack category status should preserve partial errors and unavailable categories."""
    assert (
        packs._group_pack_categories(
            {
                "ok-without-count": {"status": "ok", "total_count": "unknown"},
                "broken": {"status": "error"},
            },
            detail="summary",
        )["status"]
        == "partial_error"
    )

    partial = packs._group_pack_categories(
        {
            "ok": {"status": "ok", "total_count": 2},
            "missing": {"status": "unavailable"},
        },
        detail="refs",
    )
    assert partial["status"] == "partial_unavailable"
    assert partial["total_count"] == 2
    assert partial["unavailable_count"] == 1


def test_pack_api_error_payload_formats_validation_and_server_errors() -> None:
    """Pack SDK errors should become structured MCP payloads."""
    validation_error = ResponseValidationError(
        "invalid response",
        httpx.Response(200, text="{}"),
        cause=RuntimeError("schema mismatch"),
        body="{}",
    )
    validation_payload = packs._pack_api_error_payload(
        validation_error,
        resource_type="packs.sources",
        server_url="https://cribl.example.com/api/v1/m/default",
    )
    assert validation_payload["status"] == "validation_error"
    assert validation_payload["group_id"] == "group-scoped"

    server_error = CriblControlPlaneError("boom", httpx.Response(500, text="boom"))
    error_payload = packs._pack_api_error_payload(server_error, resource_type="packs", server_url=None)
    assert error_payload["status"] == "error"
    assert error_payload["status_code"] == 500


@pytest.mark.asyncio
async def test_run_pack_api_call_reports_network_errors() -> None:
    """Pack SDK network failures should be returned as structured errors."""

    async def _call() -> object:
        msg = "offline"
        raise httpx.ConnectError(msg)

    result = await packs._run_pack_api_call(
        _call,
        serializer=lambda _response: {"status": "ok"},
        resource_type="packs",
        server_url=None,
    )

    assert result["status"] == "error"
    assert result["error_type"] == "ConnectError"


def test_pack_base_url_requires_configured_server_url(mock_client: MagicMock) -> None:
    """Direct Pack URLs should fail clearly when neither explicit nor client URL exists."""
    mock_client.sdk_configuration.server_url = ""

    with pytest.raises(ValueError, match="server_url is not configured"):
        packs._pack_base_url(mock_client, None)


@pytest.fixture
def mock_client() -> MagicMock:
    """Return a fake Cribl client with Pack SDK methods."""
    client = MagicMock()
    client.packs.list_async = AsyncMock(return_value=_counted_response({"id": "cribl-okta", "source": "git+repo"}))
    client.packs.get_async = AsyncMock(return_value=_counted_response({"id": "cribl-okta", "source": "git+repo"}))
    client.packs.sources.list_async = AsyncMock(return_value=_counted_response({"id": "in_http", "type": "http"}))
    client.packs.sources.get_async = AsyncMock(return_value=_counted_response({"id": "in_http", "type": "http"}))
    client.packs.destinations.list_async = AsyncMock(return_value=_counted_response({"id": "devnull", "type": "devnull"}))
    client.packs.destinations.get_async = AsyncMock(return_value=_counted_response({"id": "devnull", "type": "devnull"}))
    client.packs.pipelines.list_async = AsyncMock(
        return_value=_counted_response(
            {
                "id": "main",
                "conf": {
                    "functions": [
                        {"id": "lookup", "conf": {"file": "http_status.csv"}},
                    ],
                },
            }
        )
    )
    client.packs.pipelines.get_async = AsyncMock(
        return_value=_counted_response(
            {
                "id": "main",
                "conf": {
                    "functions": [
                        {"id": "lookup", "conf": {"file": "http_status.csv"}},
                    ],
                },
            }
        )
    )
    client.packs.routes.list_async = AsyncMock(
        return_value=_counted_response(
            {
                "id": "default",
                "routes": [
                    {"name": "main", "pipeline": "main", "output": "devnull"},
                ],
            }
        )
    )
    client.packs.routes.get_async = AsyncMock(
        return_value=_counted_response(
            {
                "id": "default",
                "routes": [
                    {"name": "main", "pipeline": "main", "output": "devnull"},
                ],
            }
        )
    )
    client.packs.install_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    client.packs.upload_async = AsyncMock(return_value=_single_response({"source": "cribl-duo-1.0.0.crbl"}))
    client.packs.update_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    client.packs.delete_async = AsyncMock(return_value=_counted_response({"id": "cribl-duo", "source": "git+repo"}))
    client.sdk_configuration = MagicMock(
        server_url="https://cribl.example.com/api/v1",
        async_client=MagicMock(spec=httpx.AsyncClient),
    )
    return client


def _install_pack_http_responder(mock_client: MagicMock) -> dict[str, dict[str, Any]]:
    """Install a fake direct-HTTP responder for Pack knowledge/settings sections."""
    base = "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta"
    payloads: dict[str, dict[str, Any]] = {
        f"{base}/system/lookups": {"count": 1, "items": [{"id": "http_status.csv", "size": 817}]},
        f"{base}/lib/breakers": {"count": 1, "items": [{"id": "Apache Ruleset", "rules": []}]},
        f"{base}/lib/parsers": {"count": 0, "items": []},
        f"{base}/lib/vars": {"count": 1, "items": [{"id": "theAnswer", "value": 42}]},
        f"{base}/system/samples": {"count": 1, "items": [{"id": "apache_common"}]},
        f"{base}/lib/regex": {"count": 0, "items": []},
        f"{base}/lib/grok": {"count": 0, "items": []},
        f"{base}/lib/schemas": {"count": 0, "items": []},
        f"{base}/functions": {"count": 1, "items": [{"id": "eval"}]},
        f"{base}/lib/hmac-functions": {"count": 0, "items": []},
        f"{base}/lib/appscope-configs": {"count": 0, "items": []},
        f"{base}/lib/database-connections": {"count": 0, "items": []},
        f"{base}/system/settings": {"count": 1, "items": [{"id": "settings", "api": {"protocol": "http1.1"}}]},
        f"{base}/system/settings/cribl": {"count": 1, "items": [{"id": "cribl", "intercom": True}]},
        f"{base}/system/settings/conf": {"count": 1, "items": [{"id": "conf", "api": {"retryCount": 120}}]},
        f"{base}/system/settings/auth": {"count": 1, "items": [{"id": "auth", "type": "local"}]},
        f"{base}/system/settings/git-settings": {"count": 0, "items": []},
    }

    async def get(url: str, **_: object) -> httpx.Response:
        payload = payloads.get(url)
        if payload is None:
            return _json_response(url, {"message": "missing"}, status_code=404)
        return _json_response(url, payload)

    mock_client.sdk_configuration.async_client.get = AsyncMock(side_effect=get)
    return payloads


@pytest.mark.asyncio
async def test_collect_packs_forwards_with_parameter(mock_client: MagicMock) -> None:
    """Pack listing should forward optional count expansion and serialize items."""
    result = await packs.collect_packs(mock_client, timeout_ms=1234, with_="inputs,outputs")

    mock_client.packs.list_async.assert_awaited_once_with(with_="inputs,outputs", timeout_ms=1234)
    assert result == {
        "status": "ok",
        "count": 1,
        "items": [{"id": "cribl-okta", "source": "git+repo"}],
        "reported_count": 1,
    }


@pytest.mark.asyncio
async def test_collect_packs_exhausts_sdk_pages_and_supports_collector_counts(mock_client: MagicMock) -> None:
    """SDK 0.11 Pack wrappers should be exhausted and forward the collector expansion."""
    second = _Page({"id": "second", "collectors": 2})
    mock_client.packs.list_async = AsyncMock(return_value=_Page({"id": "first", "collectors": 1}, next_page=second))

    result = await packs.collect_packs(mock_client, timeout_ms=1234, with_="collectors")

    mock_client.packs.list_async.assert_awaited_once_with(with_="collectors", timeout_ms=1234)
    assert result["count"] == 2
    assert [item["id"] for item in result["items"]] == ["first", "second"]


@pytest.mark.asyncio
async def test_get_pack_sdk_section_exhausts_all_pages(mock_client: MagicMock) -> None:
    """SDK-backed Pack sections should not truncate after their first page."""
    second = _Page({"id": "second", "type": "http"})
    mock_client.packs.sources.list_async = AsyncMock(
        return_value=_Page({"id": "first", "type": "system_metrics"}, next_page=second)
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        kind="sources",
        security=Security(bearer_auth="test-token"),
    )

    assert result["objects"]["total_count"] == 2
    assert [item["id"] for item in result["objects"]["items"]] == ["first", "second"]


@pytest.mark.asyncio
async def test_resolve_pack_group_scope_matches_group_name(mock_client: MagicMock) -> None:
    """Pack tools should resolve friendly group names before building group-scoped URLs."""
    mock_client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")
    group_model = MagicMock()
    group_model.model_dump.return_value = {"id": "worker-main", "name": "Main Workers"}
    mock_client.groups.list_async = AsyncMock(return_value=MagicMock(items=[group_model]))

    scope = await packs.resolve_pack_group_scope(
        mock_client,
        product=ProductsCore.STREAM,
        group=" main workers ",
        timeout_ms=1234,
    )

    mock_client.groups.list_async.assert_awaited_once_with(product=ProductsCore.STREAM, timeout_ms=1234)
    assert scope.server_url == "https://cribl.example.com/api/v1/m/worker-main"
    assert scope.as_dict() == {
        "product": "stream",
        "group_selector": "main workers",
        "group_id": "worker-main",
        "matched_by": "name",
        "group_name": "Main Workers",
        "group_description": None,
    }


@pytest.mark.asyncio
async def test_collect_packs_forwards_group_server_url(mock_client: MagicMock) -> None:
    """Pack listing should pass group-scoped server_url when provided."""
    result = await packs.collect_packs(
        mock_client,
        timeout_ms=1234,
        with_=None,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )

    mock_client.packs.list_async.assert_awaited_once_with(
        with_=None,
        timeout_ms=1234,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )
    assert result["items"] == [{"id": "cribl-okta", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_collect_packs_returns_unavailable_for_404(mock_client: MagicMock) -> None:
    """Pack listing should return a structured unavailable payload for missing Pack APIs."""
    mock_client.packs.list_async = AsyncMock(
        side_effect=CriblControlPlaneError(
            "Not found",
            httpx.Response(404, text="missing"),
        )
    )

    result = await packs.collect_packs(mock_client, timeout_ms=1234)

    assert result == {
        "status": "unavailable",
        "message": "Endpoint returned HTTP 404 (Not Found).",
        "count": 0,
        "items": [],
    }


@pytest.mark.asyncio
async def test_get_pack_returns_pack_contents_summary(mock_client: MagicMock) -> None:
    """Pack lookup should summarize the config content inside the Pack."""
    payloads = _install_pack_http_responder(mock_client)

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
    )

    mock_client.packs.get_async.assert_awaited_once_with(
        id="cribl-okta",
        timeout_ms=1234,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )
    mock_client.packs.sources.list_async.assert_awaited_once_with(
        pack="cribl-okta",
        timeout_ms=1234,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )
    assert result["status"] == "ok"
    assert result["pack_id"] == "cribl-okta"
    assert result["metadata"]["items"] == [{"id": "cribl-okta", "source": "git+repo"}]
    assert result["sections"]["sources"]["total_count"] == 1
    assert result["sections"]["destinations"]["items"][0]["id"] == "devnull"
    assert result["sections"]["pipelines"]["items"][0]["refs"] == {"lookups": ["http_status.csv"]}
    assert result["sections"]["routes"]["items"][0]["refs"] == {"destinations": ["devnull"], "pipelines": ["main"]}
    assert result["sections"]["knowledge"]["categories"]["lookups"]["items"][0]["id"] == "http_status.csv"
    assert result["sections"]["knowledge"]["total_count"] == 5
    assert result["sections"]["settings"]["categories"]["conf"]["items"][0]["keys"] == ["api", "id"]
    assert mock_client.sdk_configuration.async_client.get.await_count == len(payloads)


@pytest.mark.asyncio
async def test_get_pack_rejects_aggregate_pagination(mock_client: MagicMock) -> None:
    """Cursor and limit should only be accepted for a concrete Pack section."""
    with pytest.raises(ValueError, match="cursor and limit"):
        await packs.get_pack(
            mock_client,
            timeout_ms=1234,
            pack_id="cribl-okta",
            security=Security(bearer_auth="test-token"),
            cursor="50",
        )

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_rejects_aggregate_full_detail(mock_client: MagicMock) -> None:
    """Raw payload detail should require selecting one Pack section or category."""
    with pytest.raises(ValueError, match="detail='full'"):
        await packs.get_pack(
            mock_client,
            timeout_ms=1234,
            pack_id="cribl-okta",
            kind="knowledge",
            detail="full",
            security=Security(bearer_auth="test-token"),
        )

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_requires_security_for_http_backed_summary(mock_client: MagicMock) -> None:
    """Default Pack summaries should fail clearly when direct HTTP auth is unavailable."""
    with pytest.raises(ValueError, match="security is required"):
        await packs.get_pack(mock_client, timeout_ms=1234, pack_id="cribl-okta")

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_preserves_missing_metadata_status(mock_client: MagicMock) -> None:
    """A missing Pack metadata lookup should not be reported as a successful content summary."""
    mock_client.packs.get_async = AsyncMock(
        side_effect=CriblControlPlaneError(
            "Not found",
            httpx.Response(404, text="missing"),
        )
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="missing-pack",
        security=Security(bearer_auth="test-token"),
    )

    assert result["status"] == "unavailable"
    assert result["metadata"]["status"] == "unavailable"
    assert result["sections"] == {}
    mock_client.sdk_configuration.async_client.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_returns_single_full_sdk_backed_object(mock_client: MagicMock) -> None:
    """Pack lookup should drill into one object when kind and object_id are provided."""
    mock_client.packs.pipelines.get_async = AsyncMock(
        return_value=_single_response(
            {
                "id": "main",
                "conf": {
                    "functions": [
                        {"id": "lookup", "conf": {"file": "http_status.csv"}},
                    ],
                },
            }
        )
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        kind="pipelines",
        object_id="main",
        detail="full",
    )

    mock_client.packs.pipelines.get_async.assert_awaited_once_with(id="main", pack="cribl-okta", timeout_ms=1234)
    assert result["kind"] == "pipelines"
    assert result["object_id"] == "main"
    assert result["objects"]["items"][0]["payload"]["id"] == "main"
    assert result["objects"]["items"][0]["payload"]["conf"]["functions"][0]["id"] == "lookup"


@pytest.mark.asyncio
async def test_get_pack_returns_single_full_http_backed_object(mock_client: MagicMock) -> None:
    """HTTP-backed object drill-down should preserve single-object JSON payloads."""
    base = "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta/system/lookups/http_status.csv"

    async def get(url: str, **_: object) -> httpx.Response:
        assert url == base
        return _json_response(url, {"id": "http_status.csv", "size": 817})

    mock_client.sdk_configuration.async_client.get = AsyncMock(side_effect=get)

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="knowledge.lookups",
        object_id="http_status.csv",
        detail="full",
    )

    assert result["status"] == "ok"
    assert result["objects"]["total_count"] == 1
    assert result["objects"]["items"][0]["id"] == "http_status.csv"
    assert result["objects"]["items"][0]["payload"]["size"] == 817


@pytest.mark.asyncio
async def test_get_pack_reports_http_error_for_direct_endpoint(mock_client: MagicMock) -> None:
    """Direct HTTP Pack reads should surface non-404 status failures."""
    url = "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta/system/lookups"
    mock_client.sdk_configuration.async_client.get = AsyncMock(
        return_value=_json_response(url, {"message": "boom"}, status_code=500)
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="knowledge.lookups",
    )

    assert result["status"] == "error"
    assert result["objects"]["status_code"] == 500


@pytest.mark.asyncio
async def test_get_pack_reports_invalid_json_for_direct_endpoint(mock_client: MagicMock) -> None:
    """Direct HTTP Pack reads should surface invalid JSON responses."""
    url = "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta/system/lookups"
    mock_client.sdk_configuration.async_client.get = AsyncMock(return_value=_text_response(url, "not-json"))

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="knowledge.lookups",
    )

    assert result["status"] == "error"
    assert result["objects"]["error_type"] == "JSONDecodeError"


@pytest.mark.asyncio
async def test_get_pack_marks_all_unavailable_categories(mock_client: MagicMock) -> None:
    """Aggregate category groups should distinguish all-404 categories from empty categories."""

    async def get(url: str, **_: object) -> httpx.Response:
        return _json_response(url, {"message": "missing"}, status_code=404)

    mock_client.sdk_configuration.async_client.get = AsyncMock(side_effect=get)

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="knowledge",
    )

    assert result["status"] == "unavailable"
    assert result["objects"]["status"] == "unavailable"
    assert result["objects"]["total_count"] == 0
    assert result["objects"]["unavailable_count"] == len(result["objects"]["categories"])


@pytest.mark.asyncio
async def test_get_pack_preserves_missing_metadata_for_aggregate_kind(mock_client: MagicMock) -> None:
    """Aggregate Pack lookups should include object metadata when metadata lookup fails."""
    mock_client.packs.get_async = AsyncMock(
        side_effect=CriblControlPlaneError(
            "Not found",
            httpx.Response(404, text="missing"),
        )
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="missing-pack",
        kind="knowledge",
        security=Security(bearer_auth="test-token"),
    )

    assert result["status"] == "unavailable"
    assert result["kind"] == "knowledge"
    assert result["objects"] == packs._group_pack_categories({}, detail="summary")


@pytest.mark.asyncio
async def test_get_pack_reports_network_error_for_direct_endpoint(mock_client: MagicMock) -> None:
    """Direct Pack reads should translate transport errors into MCP error payloads."""
    mock_client.sdk_configuration.async_client.get = AsyncMock(side_effect=httpx.ConnectError("offline"))

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="knowledge.lookups",
    )

    assert result["status"] == "error"
    assert result["objects"]["error_type"] == "ConnectError"


@pytest.mark.asyncio
async def test_get_pack_paginates_concrete_sdk_section(mock_client: MagicMock) -> None:
    """Concrete sections should return cursor metadata when the result is truncated."""
    mock_client.packs.sources.list_async = AsyncMock(return_value=_counted_response({"id": "a"}, {"id": "b"}, {"id": "c"}))

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        kind="sources",
        cursor="1",
        limit=1,
    )

    assert result["objects"]["items"] == [{"id": "b", "refs": {}}]
    assert result["objects"]["truncated"] is True
    assert result["objects"]["next_cursor"] == "2"


@pytest.mark.asyncio
async def test_get_pack_reads_concrete_settings_category(mock_client: MagicMock) -> None:
    """Settings categories should use direct Pack HTTP endpoints."""
    url = "https://cribl.example.com/api/v1/m/worker-main/p/cribl-okta/system/settings/conf"
    mock_client.sdk_configuration.async_client.get = AsyncMock(
        return_value=_json_response(url, {"count": 1, "items": [{"id": "conf", "api": {"retryCount": 120}}]})
    )

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="settings.conf",
    )

    assert result["status"] == "ok"
    assert result["objects"]["items"] == [{"id": "conf", "refs": {}, "keys": ["api", "id"]}]


@pytest.mark.asyncio
async def test_get_pack_reads_settings_aggregate(mock_client: MagicMock) -> None:
    """The settings aggregate should group all direct settings categories."""
    _install_pack_http_responder(mock_client)

    result = await packs.get_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-okta",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        security=Security(bearer_auth="test-token"),
        kind="settings",
    )

    assert result["status"] == "ok"
    assert result["objects"]["categories"]["conf"]["items"][0]["id"] == "conf"


@pytest.mark.asyncio
async def test_get_pack_requires_concrete_knowledge_kind_for_object_id(mock_client: MagicMock) -> None:
    """Object drill-down under knowledge should require an explicit knowledge category."""
    with pytest.raises(ValueError, match="Use a concrete knowledge kind"):
        await packs.get_pack(
            mock_client,
            timeout_ms=1234,
            pack_id="cribl-okta",
            kind="knowledge",
            object_id="http_status.csv",
        )

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_requires_concrete_settings_kind_for_object_id(mock_client: MagicMock) -> None:
    """Object drill-down under settings should require an explicit settings category."""
    with pytest.raises(ValueError, match="Use a concrete settings kind"):
        await packs.get_pack(
            mock_client,
            timeout_ms=1234,
            pack_id="cribl-okta",
            kind="settings",
            object_id="conf",
        )

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_pack_rejects_unsupported_kind(mock_client: MagicMock) -> None:
    """Unsupported Pack object kinds should fail before any API calls."""
    with pytest.raises(ValueError, match="Unsupported Pack object kind"):
        await packs.get_pack(
            mock_client,
            timeout_ms=1234,
            pack_id="cribl-okta",
            kind=cast("Any", "widgets"),
        )

    mock_client.packs.get_async.assert_not_awaited()


@pytest.mark.asyncio
async def test_install_pack_forwards_request_body(mock_client: MagicMock) -> None:
    """Pack install should pass the caller's request mapping through to the SDK."""
    request = {"source": "git+https://github.com/criblpacks/cribl-duo-rest-io", "allow_custom_functions": False}

    result = await packs.install_pack(mock_client, timeout_ms=1234, request=request)

    mock_client.packs.install_async.assert_awaited_once_with(request=request, timeout_ms=1234)
    assert result["items"] == [{"id": "cribl-duo", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_install_pack_rejects_unknown_request_fields(mock_client: MagicMock) -> None:
    """Pack install should fail fast for typoed top-level request fields."""
    with pytest.raises(ValueError, match="Unsupported Pack install request field"):
        await packs.install_pack(mock_client, timeout_ms=1234, request={"sourse": "git+repo"})

    mock_client.packs.install_async.assert_not_called()


@pytest.mark.asyncio
async def test_upload_pack_reads_file_and_forwards_filename(mock_client: MagicMock, tmp_path: Path) -> None:
    """Pack upload should stream the selected local file to the SDK."""
    pack_file = tmp_path / "cribl-duo-1.0.0.crbl"
    pack_file.write_bytes(b"pack-bytes")

    async def upload_async(*, filename: str, request_body: bytes, timeout_ms: int) -> MagicMock:
        assert filename == "cribl-duo-1.0.0.crbl"
        assert request_body == b"pack-bytes"
        assert timeout_ms == 1234
        return _single_response({"source": "cribl-duo-1.0.0.crbl"})

    mock_client.packs.upload_async = AsyncMock(side_effect=upload_async)

    result = await packs.upload_pack(mock_client, timeout_ms=1234, file_path=pack_file)

    assert result == {"status": "ok", "source": "cribl-duo-1.0.0.crbl"}


@pytest.mark.asyncio
async def test_upload_pack_rejects_missing_file(mock_client: MagicMock, tmp_path: Path) -> None:
    """Pack upload should fail clearly before calling the SDK for missing files."""
    missing = tmp_path / "missing.crbl"

    with pytest.raises(ValueError, match="Pack file not found"):
        await packs.upload_pack(mock_client, timeout_ms=1234, file_path=missing)

    mock_client.packs.upload_async.assert_not_called()


@pytest.mark.asyncio
async def test_upload_pack_rejects_non_crbl_file(mock_client: MagicMock, tmp_path: Path) -> None:
    """Pack upload should reject existing files that are not Pack archives."""
    not_a_pack = tmp_path / "notes.txt"
    not_a_pack.write_text("not a pack")

    with pytest.raises(ValueError, match="Invalid Pack file extension"):
        await packs.upload_pack(mock_client, timeout_ms=1234, file_path=not_a_pack)

    mock_client.packs.upload_async.assert_not_called()


@pytest.mark.asyncio
async def test_update_pack_forwards_upgrade_options(mock_client: MagicMock) -> None:
    """Pack upgrade should forward optional SDK upgrade flags."""
    result = await packs.update_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-duo",
        server_url="https://cribl.example.com/api/v1/m/worker-main",
        request=packs.PackUpdateRequest(
            source="https://example.com/cribl-duo.crbl",
            options=packs.PackUpgradeOptions(
                allow_custom_functions=True,
                minor="1",
                spec="2.0.0",
            ),
        ),
    )

    mock_client.packs.update_async.assert_awaited_once_with(
        id="cribl-duo",
        source="https://example.com/cribl-duo.crbl",
        allow_custom_functions=True,
        minor="1",
        spec="2.0.0",
        timeout_ms=1234,
        server_url="https://cribl.example.com/api/v1/m/worker-main",
    )
    assert result["items"] == [{"id": "cribl-duo", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_update_pack_omits_unset_upgrade_options(mock_client: MagicMock) -> None:
    """Pack upgrade should avoid forwarding optional fields that callers did not set."""
    result = await packs.update_pack(
        mock_client,
        timeout_ms=1234,
        pack_id="cribl-duo",
        request=packs.PackUpdateRequest(source="https://example.com/cribl-duo.crbl"),
    )

    mock_client.packs.update_async.assert_awaited_once_with(
        id="cribl-duo",
        source="https://example.com/cribl-duo.crbl",
        timeout_ms=1234,
    )
    assert result["items"] == [{"id": "cribl-duo", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_delete_pack_forwards_pack_id(mock_client: MagicMock) -> None:
    """Pack uninstall should forward the SDK id parameter."""
    result = await packs.delete_pack(mock_client, timeout_ms=1234, pack_id="cribl-duo")

    mock_client.packs.delete_async.assert_awaited_once_with(id="cribl-duo", timeout_ms=1234)
    assert result["items"] == [{"id": "cribl-duo", "source": "git+repo"}]


@pytest.mark.asyncio
async def test_resolve_pack_group_scope_rejects_ambiguous_group_selector(mock_client: MagicMock) -> None:
    """Pack group resolution should fail clearly when a selector matches multiple groups."""
    first = MagicMock()
    first.model_dump.return_value = {"id": "worker-a", "name": "Main Workers"}
    second = MagicMock()
    second.model_dump.return_value = {"id": "worker-b", "name": "Main Workers"}
    mock_client.groups.list_async = AsyncMock(return_value=MagicMock(items=[first, second]))

    with pytest.raises(ValueError, match="matched multiple stream groups by name"):
        await packs.resolve_pack_group_scope(
            mock_client,
            product=ProductsCore.STREAM,
            group="Main Workers",
            timeout_ms=1234,
        )


@pytest.mark.asyncio
async def test_resolve_pack_group_scope_rejects_blank_missing_and_idless_matches(mock_client: MagicMock) -> None:
    """Pack group resolution should fail clearly for invalid selectors and malformed group payloads."""
    with pytest.raises(ValueError, match="must not be blank"):
        await packs.resolve_pack_group_scope(mock_client, product=ProductsCore.STREAM, group="  ", timeout_ms=1234)

    mock_client.groups.list_async = AsyncMock(return_value=MagicMock(items=[]))
    with pytest.raises(ValueError, match="Could not resolve group selector"):
        await packs.resolve_pack_group_scope(mock_client, product=ProductsCore.STREAM, group="missing", timeout_ms=1234)

    group_model = MagicMock()
    group_model.model_dump.return_value = {"name": "Nameless"}
    mock_client.groups.list_async = AsyncMock(return_value=MagicMock(items=[group_model]))
    with pytest.raises(ValueError, match="did not include an id"):
        await packs.resolve_pack_group_scope(mock_client, product=ProductsCore.STREAM, group="Nameless", timeout_ms=1234)
