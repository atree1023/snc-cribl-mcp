"""Unit tests for lookups collection helpers.

Covers success paths, 404 handling per-group, error propagation, and HTTP client errors.
"""

# pyright: reportPrivateUsage=false

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from snc_cribl_mcp.operations.common import serialize_model
from snc_cribl_mcp.operations.lookups import collect_product_lookups


@pytest.fixture
def mock_ctx() -> Context:
    """Provide a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    return ctx


@pytest.fixture
def security() -> Security:
    """Provide a mock Security object with bearer auth."""
    return Security(bearer_auth="test-token")


class TestSerializeModel:
    """Tests for the serialize_model helper function."""

    def test_serialize_model_with_pydantic_model(self) -> None:
        """Objects with model_dump should be serialized correctly."""
        mock_obj = MagicMock()
        mock_obj.model_dump.return_value = {"id": "test", "name": "lookup1"}

        result = serialize_model(mock_obj)

        assert result == {"id": "test", "name": "lookup1"}
        mock_obj.model_dump.assert_called_once_with(mode="json", exclude_none=True)

    def test_serialize_model_without_model_dump(self) -> None:
        """Objects without model_dump should return empty dict."""
        obj = object()

        result = serialize_model(obj)

        assert result == {}

    def test_serialize_model_raises_type_error(self) -> None:
        """Objects where model_dump raises TypeError should return empty dict."""
        mock_obj = MagicMock()
        mock_obj.model_dump.side_effect = TypeError("Invalid type")

        result = serialize_model(mock_obj)

        assert result == {}

    def test_serialize_model_raises_value_error(self) -> None:
        """Objects where model_dump raises ValueError should return empty dict."""
        mock_obj = MagicMock()
        mock_obj.model_dump.side_effect = ValueError("Invalid value")

        result = serialize_model(mock_obj)

        assert result == {}


@pytest.mark.asyncio
async def test_collect_product_lookups_success(mock_ctx: Context, security: Security) -> None:
    """It should list lookups for each group via HTTP requests and aggregate results."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    groups_response.items[1].model_dump.return_value = {"id": "g2"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    # First group returns 2 items, second returns 1
    resp_g1 = MagicMock()
    resp_g1.status_code = 200
    resp_g1.json.return_value = {"items": [{"id": "l1"}, {"id": "l2"}], "count": 2}

    resp_g2 = MagicMock()
    resp_g2.status_code = 200
    resp_g2.json.return_value = {"items": [{"id": "l3"}], "count": 1}

    async def http_get(url: str, **_kwargs: object) -> MagicMock:
        if "/m/g1/system/lookups" in url:
            return resp_g1
        if "/m/g2/system/lookups" in url:
            return resp_g2
        return MagicMock(status_code=404)

    mock_http_client.get = AsyncMock(side_effect=http_get)

    result = await collect_product_lookups(
        mock_client,
        security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    assert result["total_count"] == 3
    assert len(result["groups"]) == 2
    assert result["groups"][0]["group_id"] == "g1"
    assert result["groups"][0]["count"] == 2
    assert result["groups"][0]["reported_count"] == 2


@pytest.mark.asyncio
async def test_collect_product_lookups_404_per_group(mock_ctx: Context, security: Security) -> None:
    """404 on a group's lookups should be treated as empty for that group."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g404"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    resp_404 = MagicMock()
    resp_404.status_code = 404
    mock_http_client.get.return_value = resp_404

    result = await collect_product_lookups(
        mock_client,
        security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    assert result["total_count"] == 0
    assert result["groups"][0]["group_id"] == "g404"
    assert result["groups"][0]["count"] == 0
    # warning should have been awaited at least once
    assert getattr(mock_ctx.warning, "await_count", 0) >= 1


@pytest.mark.asyncio
async def test_collect_product_lookups_http_error_per_group(mock_ctx: Context, security: Security) -> None:
    """HTTP errors on a group's lookups should raise RuntimeError."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    mock_http_client.get.side_effect = httpx.ConnectError("Connection failed")

    with pytest.raises(RuntimeError, match="Network error while listing lookups"):
        await collect_product_lookups(
            mock_client,
            security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_lookups_unavailable_product(mock_ctx: Context, security: Security) -> None:
    """If listing groups returns 404, the function should return an 'unavailable' status."""
    mock_client = MagicMock()
    api_error_404 = CriblControlPlaneError(
        message="Not found",
        body=None,
        raw_response=MagicMock(status_code=404),
    )
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_404)

    result = await collect_product_lookups(
        mock_client,
        security,
        product=ProductsCore.EDGE,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "unavailable"
    assert result["total_count"] == 0
    assert result["groups"] == []


@pytest.mark.asyncio
async def test_collect_product_lookups_api_error_non_404(mock_ctx: Context, security: Security) -> None:
    """Non-404 API errors on groups listing should raise RuntimeError."""
    mock_client = MagicMock()
    api_error_500 = CriblControlPlaneError(
        message="Server error",
        body=None,
        raw_response=MagicMock(status_code=500),
    )
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_500)

    with pytest.raises(RuntimeError, match="Cribl API error while listing"):
        await collect_product_lookups(
            mock_client,
            security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_lookups_network_error_on_groups(mock_ctx: Context, security: Security) -> None:
    """Network errors while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("fail"))

    with pytest.raises(RuntimeError, match="Network error while listing"):
        await collect_product_lookups(
            mock_client,
            security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_lookups_skips_groups_without_id(mock_ctx: Context, security: Security) -> None:
    """Groups without an id or groupId should be skipped."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    # First group has no id, second has id
    groups_response.items[0].model_dump.return_value = {"name": "no_id_group"}
    groups_response.items[1].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    resp_g1 = MagicMock()
    resp_g1.status_code = 200
    resp_g1.json.return_value = {"items": [{"id": "l1"}], "count": 1}
    mock_http_client.get.return_value = resp_g1

    result = await collect_product_lookups(
        mock_client,
        security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    # Only one group should be processed
    assert len(result["groups"]) == 1
    assert result["groups"][0]["group_id"] == "g1"


@pytest.mark.asyncio
async def test_collect_product_lookups_with_groupid_field(mock_ctx: Context, security: Security) -> None:
    """Groups with groupId field instead of id should work."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"groupId": "fleet1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"items": [{"id": "l1"}]}
    mock_http_client.get.return_value = resp

    result = await collect_product_lookups(
        mock_client,
        security,
        product=ProductsCore.EDGE,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["groups"][0]["group_id"] == "fleet1"


@pytest.mark.asyncio
async def test_collect_product_lookups_without_bearer_auth(mock_ctx: Context) -> None:
    """Test that lookups can be collected even without bearer auth in Security."""
    security_no_auth = Security()

    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration = MagicMock(
        server_url="https://example/api/v1",
        async_client=mock_http_client,
    )

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"items": []}
    mock_http_client.get.return_value = resp

    result = await collect_product_lookups(
        mock_client,
        security_no_auth,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    # Verify no Authorization header was passed
    call_kwargs = mock_http_client.get.call_args.kwargs
    assert "Authorization" not in call_kwargs.get("headers", {})
