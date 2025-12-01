"""Unit tests for destination collection helpers.

Covers success paths, 404 handling per-group, and error propagation.
"""

# pyright: reportPrivateUsage=false

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from snc_cribl_mcp.operations.common import serialize_model
from snc_cribl_mcp.operations.destinations import collect_product_destinations


@pytest.fixture
def mock_ctx() -> Context:
    """Provide a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    return ctx


class TestSerializeModel:
    """Tests for the serialize_model helper function."""

    def test_serialize_model_with_pydantic_model(self) -> None:
        """Objects with model_dump should be serialized correctly."""
        mock_obj = MagicMock()
        mock_obj.model_dump.return_value = {"id": "test", "name": "dest1"}

        result = serialize_model(mock_obj)

        assert result == {"id": "test", "name": "dest1"}
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
async def test_collect_product_destinations_success(mock_ctx: Context) -> None:
    """It should list destinations for each group via the product-scoped client and aggregate results."""
    # Mock groups list
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    groups_response.items[1].model_dump.return_value = {"id": "g2"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    # Mock top-level destinations client and sdk_configuration for base URL
    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    stream_destinations = MagicMock()
    mock_client.destinations = stream_destinations

    # First group returns 2 items, second returns 1
    resp_g1 = MagicMock(items=[MagicMock(), MagicMock()], count=2)
    resp_g1.items[0].model_dump.return_value = {"name": "d1"}
    resp_g1.items[1].model_dump.return_value = {"name": "d2"}

    resp_g2 = MagicMock(items=[MagicMock()], count=1)
    resp_g2.items[0].model_dump.return_value = {"name": "d3"}

    async def list_async_side_effect(*_args: object, **kwargs: object) -> MagicMock:
        # Ensure correct kwargs are used
        assert "server_url" in kwargs
        assert kwargs["server_url"].endswith("/m/g1") or kwargs["server_url"].endswith("/m/g2")  # type: ignore[index]
        assert "timeout_ms" in kwargs
        if kwargs["server_url"].endswith("/m/g1"):  # type: ignore[index]
            return resp_g1
        return resp_g2

    stream_destinations.list_async = AsyncMock(side_effect=list_async_side_effect)

    result = await collect_product_destinations(
        mock_client,
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
async def test_collect_product_destinations_404_per_group(mock_ctx: Context) -> None:
    """404 on a group's destinations should be treated as empty for that group."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g404"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    stream_destinations = MagicMock()
    mock_client.destinations = stream_destinations

    api_error_404 = CriblControlPlaneError(message="Not found", body=None, raw_response=MagicMock(status_code=404))
    stream_destinations.list_async = AsyncMock(side_effect=api_error_404)

    result = await collect_product_destinations(
        mock_client,
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
async def test_collect_product_destinations_api_error_non_404(mock_ctx: Context) -> None:
    """Non-404 API errors should be raised as RuntimeError."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    edge_destinations = MagicMock()
    mock_client.destinations = edge_destinations

    api_error_500 = CriblControlPlaneError(message="Boom", body=None, raw_response=MagicMock(status_code=500))
    edge_destinations.list_async = AsyncMock(side_effect=api_error_500)

    with pytest.raises(RuntimeError, match="Cribl API error while listing destinations"):
        await collect_product_destinations(
            mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_destinations_network_error(mock_ctx: Context) -> None:
    """Network failures should be raised as RuntimeError."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    stream_destinations = MagicMock()
    mock_client.destinations = stream_destinations

    stream_destinations.list_async = AsyncMock(side_effect=httpx.ConnectError("fail"))

    with pytest.raises(RuntimeError, match="Network error while listing destinations"):
        await collect_product_destinations(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_destinations_unavailable_product_returns_unavailable(mock_ctx: Context) -> None:
    """If listing groups returns 404, the function should return an 'unavailable' status."""
    mock_client = MagicMock()
    api_error_404 = CriblControlPlaneError(message="Not found", body=None, raw_response=MagicMock(status_code=404))
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_404)

    result = await collect_product_destinations(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "unavailable"
    assert result["total_count"] == 0
    assert result["groups"] == []


@pytest.mark.asyncio
async def test_collect_product_destinations_network_error_on_groups(mock_ctx: Context) -> None:
    """Network error while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("Network failure"))

    with pytest.raises(RuntimeError, match="Network error while listing stream groups"):
        await collect_product_destinations(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_destinations_api_error_non_404_on_groups(mock_ctx: Context) -> None:
    """Non-404 API error while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    api_error_500 = CriblControlPlaneError(message="Server error", body=None, raw_response=MagicMock(status_code=500))
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_500)

    with pytest.raises(RuntimeError, match="Cribl API error while listing stream groups for destinations"):
        await collect_product_destinations(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_destinations_skips_groups_without_id(mock_ctx: Context) -> None:
    """Groups without id or groupId should be skipped."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    # First group has no id, second has id
    groups_response.items[0].model_dump.return_value = {"name": "no_id_group"}
    groups_response.items[1].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    stream_destinations = MagicMock()
    mock_client.destinations = stream_destinations

    resp_g1 = MagicMock(items=[MagicMock()], count=1)
    resp_g1.items[0].model_dump.return_value = {"name": "d1"}
    stream_destinations.list_async = AsyncMock(return_value=resp_g1)

    result = await collect_product_destinations(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    # Only one group should be processed (the one with id)
    assert len(result["groups"]) == 1
    assert result["groups"][0]["group_id"] == "g1"
    assert result["total_count"] == 1
