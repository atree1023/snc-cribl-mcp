"""Unit tests for pipeline collection helpers.

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
from snc_cribl_mcp.operations.pipelines import collect_product_pipelines


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
async def test_collect_product_pipelines_success(mock_ctx: Context) -> None:
    """It should list pipelines for each group via the SDK and aggregate results."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    groups_response.items[1].model_dump.return_value = {"id": "g2"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()

    resp_g1 = MagicMock(items=[MagicMock(), MagicMock()], count=2)
    resp_g1.items[0].model_dump.return_value = {"id": "p1", "conf": {"functions": []}}
    resp_g1.items[1].model_dump.return_value = {"id": "p2", "conf": {"functions": []}}

    resp_g2 = MagicMock(items=[MagicMock()], count=1)
    resp_g2.items[0].model_dump.return_value = {"id": "p3", "conf": {"functions": []}}

    async def list_async_side_effect(*_args: object, **kwargs: object) -> MagicMock:
        srv_url = str(kwargs.get("server_url", ""))
        assert srv_url.endswith(("/m/g1", "/m/g2"))
        return resp_g1 if srv_url.endswith("/m/g1") else resp_g2

    mock_client.pipelines.list_async = AsyncMock(side_effect=list_async_side_effect)

    result = await collect_product_pipelines(
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


@pytest.mark.asyncio
async def test_collect_product_pipelines_with_pipeline_id(mock_ctx: Context) -> None:
    """It should fetch a single pipeline per group and skip 404s gracefully."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    groups_response.items[1].model_dump.return_value = {"id": "g2"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()

    resp_g1 = MagicMock(items=[MagicMock()], count=1)
    resp_g1.items[0].model_dump.return_value = {"id": "p1", "conf": {"functions": []}}

    api_error_404 = CriblControlPlaneError(
        message="Not found",
        body=None,
        raw_response=MagicMock(status_code=404),
    )

    async def get_async_side_effect(*_args: object, **kwargs: object) -> MagicMock:
        assert kwargs["id"] == "p1"
        srv_url = str(kwargs.get("server_url", ""))
        if srv_url.endswith("/m/g1"):
            return resp_g1
        assert srv_url.endswith("/m/g2")
        raise api_error_404

    mock_client.pipelines.get_async = AsyncMock(side_effect=get_async_side_effect)
    mock_client.pipelines.list_async = AsyncMock(side_effect=AssertionError("list_async should not be called"))

    result = await collect_product_pipelines(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
        pipeline_id="p1",
    )

    assert result["status"] == "ok"
    assert result["total_count"] == 1
    assert len(result["groups"]) == 2
    assert result["groups"][0]["count"] == 1
    assert result["groups"][1]["count"] == 0
    assert getattr(mock_ctx.warning, "await_count", 0) >= 1


@pytest.mark.asyncio
async def test_collect_product_pipelines_serializes_function_conf(mock_ctx: Context) -> None:
    """Function configuration data should be preserved in serialized output."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)
    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()

    pipeline_data = {
        "id": "test_pipeline",
        "conf": {
            "output": "default",
            "functions": [
                {
                    "id": "regex_extract",
                    "filter": "true",
                    "conf": {"regex": "/ASA-\\d+-(?<__code>\\d+)/", "source": "_raw"},
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
                        "rules": [{"matchRegex": "/password=[^&]+/", "replaceExpr": "'password=***'"}],
                        "fields": ["_raw"],
                    },
                },
            ],
        },
    }

    response = MagicMock(items=[MagicMock()], count=1)
    response.items[0].model_dump.return_value = pipeline_data
    mock_client.pipelines.list_async = AsyncMock(return_value=response)

    result = await collect_product_pipelines(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    pipeline = result["groups"][0]["items"][0]

    regex_func = pipeline["conf"]["functions"][0]
    assert regex_func["id"] == "regex_extract"
    assert regex_func["conf"]["regex"] == "/ASA-\\d+-(?<__code>\\d+)/"
    assert regex_func["conf"]["source"] == "_raw"

    sampling_func = pipeline["conf"]["functions"][1]
    assert sampling_func["id"] == "sampling"
    assert sampling_func["conf"]["rules"][0]["filter"] == "__action=='permitted'"
    assert sampling_func["conf"]["rules"][0]["rate"] == 10

    mask_func = pipeline["conf"]["functions"][2]
    assert mask_func["id"] == "mask"
    assert mask_func["conf"]["rules"][0]["matchRegex"] == "/password=[^&]+/"


@pytest.mark.asyncio
async def test_collect_product_pipelines_404_per_group(mock_ctx: Context) -> None:
    """404 on a group's pipelines should be treated as empty for that group."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g404"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()

    api_error_404 = CriblControlPlaneError(message="Not found", body=None, raw_response=MagicMock(status_code=404))
    mock_client.pipelines.list_async = AsyncMock(side_effect=api_error_404)

    result = await collect_product_pipelines(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "ok"
    assert result["total_count"] == 0
    assert result["groups"][0]["group_id"] == "g404"
    assert result["groups"][0]["count"] == 0
    assert getattr(mock_ctx.warning, "await_count", 0) >= 1


@pytest.mark.asyncio
async def test_collect_product_pipelines_network_error(mock_ctx: Context) -> None:
    """Network failures should be raised as RuntimeError."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock()])
    groups_response.items[0].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()
    mock_client.pipelines.list_async = AsyncMock(side_effect=httpx.ConnectError("fail"))

    with pytest.raises(RuntimeError, match="Network error while listing pipelines"):
        await collect_product_pipelines(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_unavailable_product_returns_unavailable(mock_ctx: Context) -> None:
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
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert result["status"] == "unavailable"
    assert result["total_count"] == 0
    assert result["groups"] == []


@pytest.mark.asyncio
async def test_collect_product_pipelines_network_error_on_groups(mock_ctx: Context) -> None:
    """Network error while listing groups should raise RuntimeError."""
    mock_client = MagicMock()
    mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("Network failure"))

    with pytest.raises(RuntimeError, match="Network error while listing stream groups"):
        await collect_product_pipelines(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_api_error_non_404_on_groups(mock_ctx: Context) -> None:
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
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
        )


@pytest.mark.asyncio
async def test_collect_product_pipelines_skips_groups_without_id(mock_ctx: Context) -> None:
    """Groups without id or groupId should be skipped."""
    mock_client = MagicMock()
    groups_response = MagicMock(items=[MagicMock(), MagicMock()])
    groups_response.items[0].model_dump.return_value = {"name": "no_id_group"}
    groups_response.items[1].model_dump.return_value = {"id": "g1"}
    mock_client.groups.list_async = AsyncMock(return_value=groups_response)

    mock_client.sdk_configuration = MagicMock(server_url="https://example/api/v1")
    mock_client.pipelines = MagicMock()

    response = MagicMock(items=[MagicMock()], count=1)
    response.items[0].model_dump.return_value = {"id": "p1", "conf": {"functions": []}}
    mock_client.pipelines.list_async = AsyncMock(return_value=response)

    result = await collect_product_pipelines(
        mock_client,
        product=ProductsCore.STREAM,
        timeout_ms=10000,
        ctx=mock_ctx,
    )

    assert len(result["groups"]) == 1
    assert result["groups"][0]["group_id"] == "g1"
    assert result["total_count"] == 1
