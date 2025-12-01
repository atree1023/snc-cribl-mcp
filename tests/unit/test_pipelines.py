"""Unit tests for pipeline collection helpers.

Covers success paths, 404 handling per-group, and error propagation.
Uses HTTP collection (like breakers/lookups) to preserve function configs.
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
from snc_cribl_mcp.operations.pipelines import collect_product_pipelines


@pytest.fixture
def mock_ctx() -> Context:
    """Provide a Context-like AsyncMock for tool logging."""
    ctx = MagicMock(spec=Context)
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    return ctx


@pytest.fixture
def mock_security() -> Security:
    """Provide a mock Security object with bearer token."""
    return Security(bearer_auth="test-token")


class TestSerializeModel:
    """Tests for the serialize_model helper function."""

    def test_serialize_model_with_pydantic_model(self) -> None:
        """Objects with model_dump should be serialized correctly."""
        mock_obj = MagicMock()
        mock_obj.model_dump.return_value = {"id": "test", "name": "pipeline1"}

        result = serialize_model(mock_obj)

        assert result == {"id": "test", "name": "pipeline1"}
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


@pytest.mark.asyncio
async def test_collect_product_pipelines_success(mock_ctx: Context, mock_security: Security) -> None:
    """It should list pipelines for each group via HTTP and aggregate results."""
    # Mock groups list
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    groups_response.items[1].model_dump.return_value = {"id": "g2"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    # Mock sdk_configuration for base URL and async_client
    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")

    # Mock HTTP responses for pipelines endpoint
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    # Create mock responses with function conf data preserved
    g1_response = MagicMock()
    g1_response.status_code = 200
    g1_response.json.return_value = {
        "items": [
            {
                "id": "p1",
                "conf": {
                    "functions": [
                        {
                            "id": "eval",
                            "filter": "true",
                            "conf": {"add": [{"name": "test", "value": "'value'"}]},
                        }
                    ]
                },
            },
            {"id": "p2", "conf": {"functions": []}},
        ],
        "count": 2,
    }
    g1_response.raise_for_status = MagicMock()

    g2_response = MagicMock()
    g2_response.status_code = 200
    g2_response.json.return_value = {
        "items": [{"id": "p3", "conf": {"functions": []}}],
        "count": 1,
    }
    g2_response.raise_for_status = MagicMock()

    async def mock_get(url: str, **kwargs: object) -> MagicMock:
        if "/m/g1/pipelines" in url:
            return g1_response
        return g2_response

    mock_http_client.get = AsyncMock(side_effect=mock_get)

    result = await collect_product_pipelines(
        mock_client,
        mock_security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    assert result["total_count"] == 3
    assert len(result["groups"]) == 2
    assert result["groups"][0]["group_id"] == "g1"
    assert result["groups"][0]["count"] == 2
    # Verify function conf data is preserved
    p1 = result["groups"][0]["items"][0]
    assert p1["conf"]["functions"][0]["conf"]["add"][0]["name"] == "test"


@pytest.mark.asyncio
async def test_collect_product_pipelines_preserves_function_conf(
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """The HTTP collection should preserve all function conf data."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)
    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")

    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    # Pipeline with complex function configurations
    pipeline_data = {
        "items": [
            {
                "id": "test_pipeline",
                "conf": {
                    "output": "default",
                    "functions": [
                        {
                            "id": "regex_extract",
                            "filter": "true",
                            "conf": {
                                "regex": "/ASA-\\d+-(?<__code>\\d+)/",
                                "source": "_raw",
                            },
                            "description": "Extract ASA Code",
                        },
                        {
                            "id": "sampling",
                            "filter": "true",
                            "conf": {"rules": [{"filter": "__action=='permitted'", "rate": 10}]},
                        },
                        {
                            "id": "mask",
                            "filter": "true",
                            "conf": {
                                "rules": [
                                    {
                                        "matchRegex": "/password=[^&]+/",
                                        "replaceExpr": "'password=***'",
                                    }
                                ],
                                "fields": ["_raw"],
                            },
                        },
                    ],
                },
            }
        ],
        "count": 1,
    }

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = pipeline_data
    response.raise_for_status = MagicMock()
    mock_http_client.get = AsyncMock(return_value=response)

    result = await collect_product_pipelines(
        mock_client,
        mock_security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    pipeline = result["groups"][0]["items"][0]

    # Verify regex_extract conf is preserved
    regex_func = pipeline["conf"]["functions"][0]
    assert regex_func["id"] == "regex_extract"
    assert regex_func["conf"]["regex"] == "/ASA-\\d+-(?<__code>\\d+)/"
    assert regex_func["conf"]["source"] == "_raw"

    # Verify sampling conf is preserved
    sampling_func = pipeline["conf"]["functions"][1]
    assert sampling_func["id"] == "sampling"
    assert sampling_func["conf"]["rules"][0]["filter"] == "__action=='permitted'"
    assert sampling_func["conf"]["rules"][0]["rate"] == 10

    # Verify mask conf is preserved
    mask_func = pipeline["conf"]["functions"][2]
    assert mask_func["id"] == "mask"
    assert mask_func["conf"]["rules"][0]["matchRegex"] == "/password=[^&]+/"


@pytest.mark.asyncio
async def test_collect_product_pipelines_404_per_group(mock_ctx: Context, mock_security: Security) -> None:
    """404 on a group's pipelines should be treated as empty for that group."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g404"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    response = MagicMock()
    response.status_code = 404
    mock_http_client.get = AsyncMock(return_value=response)

    result = await collect_product_pipelines(
        mock_client,
        mock_security,
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
async def test_collect_product_pipelines_network_error(mock_ctx: Context, mock_security: Security) -> None:
    """Network failures should be raised as RuntimeError."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    mock_http_client.get = AsyncMock(side_effect=httpx.ConnectError("fail"))

    with pytest.raises(RuntimeError, match="Network error while listing pipelines"):
        await collect_product_pipelines(
            mock_client,
            mock_security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_unavailable_product_returns_unavailable(
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """If listing groups returns 404, the function should return an 'unavailable' status."""
    mock_client = MagicMock()
    api_error_404 = CriblControlPlaneError(
        message="Not found",
        body=None,
        raw_response=MagicMock(status_code=404),
    )
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_404)

    result = await collect_product_pipelines(
        mock_client,
        mock_security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "unavailable"
    assert result["total_count"] == 0
    assert result["groups"] == []


@pytest.mark.asyncio
async def test_collect_product_pipelines_network_error_on_groups(
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """Network error while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("Network failure"))

    with pytest.raises(RuntimeError, match="Network error while listing stream groups"):
        await collect_product_pipelines(
            mock_client,
            mock_security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_api_error_non_404_on_groups(
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """Non-404 API error while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    api_error_500 = CriblControlPlaneError(
        message="Server error",
        body=None,
        raw_response=MagicMock(status_code=500),
    )
    mock_client.groups.list_async = AsyncMock(side_effect=api_error_500)

    with pytest.raises(RuntimeError, match="Cribl API error while listing stream groups for pipelines"):
        await collect_product_pipelines(
            mock_client,
            mock_security,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_skips_groups_without_id(
    mock_ctx: Context,
    mock_security: Security,
) -> None:
    """Groups without id or groupId should be skipped."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    # First group has no id, second has id
    groups_response.items[0].model_dump.return_value = {"name": "no_id_group"}
    groups_response.items[1].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_http_client = AsyncMock()
    mock_client.sdk_configuration.async_client = mock_http_client

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "items": [{"id": "p1", "conf": {"functions": []}}],
        "count": 1,
    }
    response.raise_for_status = MagicMock()
    mock_http_client.get = AsyncMock(return_value=response)

    result = await collect_product_pipelines(
        mock_client,
        mock_security,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    # Only one group should be processed (the one with id)
    assert len(result["groups"]) == 1
    assert result["groups"][0]["group_id"] == "g1"
    assert result["total_count"] == 1
