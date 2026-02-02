"""Unit tests for operations.common module.

Covers utility functions for building API responses, serialization helpers,
and shared HTTP/SDK collection logic.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models import Security
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context
from pydantic import ValidationError

from snc_cribl_mcp.operations.common import (
    HTTP_NOT_FOUND,
    CollectionContext,
    HttpCollectionContext,
    build_group_entry,
    build_success_result,
    build_unavailable_result,
    collect_items_via_http,
    collect_items_via_sdk,
    extract_group_id,
    get_auth_headers,
    get_group_url,
    handle_product_unavailable,
    list_groups_minimal,
    serialize_model,
)


class TestSerializeModel:
    """Tests for the serialize_model helper function."""

    def test_serialize_pydantic_model(self) -> None:
        """Pydantic-like objects should serialize via model_dump."""
        mock_obj = MagicMock()
        mock_obj.model_dump.return_value = {"id": "test", "value": 42}

        result = serialize_model(mock_obj)

        assert result == {"id": "test", "value": 42}
        mock_obj.model_dump.assert_called_once_with(mode="json", exclude_none=True)

    def test_serialize_plain_object(self) -> None:
        """Objects without model_dump return empty dict."""
        obj = object()
        result = serialize_model(obj)
        assert result == {}

    def test_serialize_model_dump_raises_type_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """model_dump raising TypeError returns empty dict and logs warning."""
        mock_obj = MagicMock()
        mock_obj.model_dump.side_effect = TypeError("Invalid type")

        result = serialize_model(mock_obj)

        assert result == {}
        assert "Failed to serialize model" in caplog.text
        assert "Invalid type" in caplog.text

    def test_serialize_model_dump_raises_value_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """model_dump raising ValueError returns empty dict and logs warning."""
        mock_obj = MagicMock()
        mock_obj.model_dump.side_effect = ValueError("Invalid value")

        result = serialize_model(mock_obj)

        assert result == {}
        assert "Failed to serialize model" in caplog.text
        assert "Invalid value" in caplog.text


class TestBuildUnavailableResult:
    """Tests for build_unavailable_result helper."""

    def test_unavailable_grouped(self) -> None:
        """Default (is_grouped=True) returns total_count and groups."""
        result = build_unavailable_result()

        assert result["status"] == "unavailable"
        assert result["message"] == "Endpoint returned HTTP 404 (Not Found)."
        assert result["total_count"] == 0
        assert result["groups"] == []
        assert "count" not in result
        assert "items" not in result

    def test_unavailable_non_grouped(self) -> None:
        """is_grouped=False returns count and items."""
        result = build_unavailable_result(is_grouped=False)

        assert result["status"] == "unavailable"
        assert result["message"] == "Endpoint returned HTTP 404 (Not Found)."
        assert result["count"] == 0
        assert result["items"] == []
        assert "total_count" not in result
        assert "groups" not in result


class TestBuildSuccessResult:
    """Tests for build_success_result helper."""

    def test_success_grouped_with_groups(self) -> None:
        """is_grouped=True with groups aggregates counts."""
        groups: list[dict[str, Any]] = [
            {"group_id": "g1", "count": 3, "items": []},
            {"group_id": "g2", "count": 2, "items": []},
        ]
        result = build_success_result([], is_grouped=True, groups=groups)

        assert result["status"] == "ok"
        assert result["total_count"] == 5
        assert result["groups"] == groups
        assert "count" not in result
        assert "items" not in result

    def test_success_grouped_no_groups(self) -> None:
        """is_grouped=True without groups falls through to non-grouped path."""
        items = [{"id": "i1"}, {"id": "i2"}]
        result = build_success_result(items, is_grouped=True, groups=None)

        # Falls through to non-grouped branch since groups is None
        assert result["status"] == "ok"
        assert result["count"] == 2
        assert result["items"] == items

    def test_success_non_grouped(self) -> None:
        """is_grouped=False returns count and items."""
        items = [{"id": "i1"}, {"id": "i2"}, {"id": "i3"}]
        result = build_success_result(items, is_grouped=False)

        assert result["status"] == "ok"
        assert result["count"] == 3
        assert result["items"] == items
        assert "total_count" not in result
        assert "groups" not in result

    def test_success_non_grouped_with_reported_count(self) -> None:
        """is_grouped=False includes reported_count when provided."""
        items = [{"id": "i1"}]
        result = build_success_result(items, reported_count=10, is_grouped=False)

        assert result["status"] == "ok"
        assert result["count"] == 1
        assert result["items"] == items
        assert result["reported_count"] == 10

    def test_success_non_grouped_no_reported_count(self) -> None:
        """is_grouped=False omits reported_count when None."""
        items = [{"id": "i1"}]
        result = build_success_result(items, reported_count=None, is_grouped=False)

        assert result["status"] == "ok"
        assert result["count"] == 1
        assert result["items"] == items
        assert "reported_count" not in result


class TestBuildGroupEntry:
    """Tests for build_group_entry helper."""

    def test_group_entry_basic(self) -> None:
        """Basic group entry with items."""
        items = [{"name": "s1"}, {"name": "s2"}]
        entry = build_group_entry("g1", items)

        assert entry["group_id"] == "g1"
        assert entry["count"] == 2
        assert entry["items"] == items
        assert "reported_count" not in entry

    def test_group_entry_with_reported_count(self) -> None:
        """Group entry includes reported_count when provided."""
        items = [{"name": "s1"}]
        entry = build_group_entry("g1", items, reported_count=5)

        assert entry["group_id"] == "g1"
        assert entry["count"] == 1
        assert entry["items"] == items
        assert entry["reported_count"] == 5

    def test_group_entry_empty_items(self) -> None:
        """Group entry with no items."""
        entry = build_group_entry("empty_group", [])

        assert entry["group_id"] == "empty_group"
        assert entry["count"] == 0
        assert entry["items"] == []


class TestExtractGroupId:
    """Tests for extract_group_id helper."""

    def test_extract_id_field(self) -> None:
        """Extracts id when present."""
        group = {"id": "my-group", "name": "My Group"}
        assert extract_group_id(group) == "my-group"

    def test_extract_groupid_field(self) -> None:
        """Extracts groupId when id is not present."""
        group = {"groupId": "alt-group", "name": "Alt Group"}
        assert extract_group_id(group) == "alt-group"

    def test_extract_prefers_id_over_groupid(self) -> None:
        """The id field takes precedence over groupId."""
        group = {"id": "primary", "groupId": "secondary"}
        assert extract_group_id(group) == "primary"

    def test_extract_missing_id(self) -> None:
        """Returns None when neither id nor groupId present."""
        group = {"name": "No ID"}
        assert extract_group_id(group) is None

    def test_extract_empty_id(self) -> None:
        """Returns groupId when id is empty string."""
        group = {"id": "", "groupId": "fallback"}
        assert extract_group_id(group) == "fallback"


class TestGetGroupUrl:
    """Tests for get_group_url helper."""

    def test_build_group_url(self) -> None:
        """Builds correct group-scoped URL."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")

        url = get_group_url(mock_client, "my-group")

        assert url == "https://cribl.example.com/api/v1/m/my-group"

    def test_build_group_url_trailing_slash(self) -> None:
        """Strips trailing slash from base URL to avoid double slashes."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1/")

        url = get_group_url(mock_client, "workers")

        assert url == "https://cribl.example.com/api/v1/m/workers"

    def test_build_group_url_raises_on_none_server_url(self) -> None:
        """Raises ValueError when server_url is None."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_client.sdk_configuration = MagicMock(server_url=None)

        with pytest.raises(ValueError, match="server_url is not configured"):
            get_group_url(mock_client, "my-group")

    def test_build_group_url_raises_on_empty_server_url(self) -> None:
        """Raises ValueError when server_url is empty string."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_client.sdk_configuration = MagicMock(server_url="")

        with pytest.raises(ValueError, match="server_url is not configured"):
            get_group_url(mock_client, "my-group")


class TestGetAuthHeaders:
    """Tests for get_auth_headers helper."""

    def test_with_bearer_token(self) -> None:
        """Returns Authorization header when token present."""
        security = Security(bearer_auth="test-token-123")

        headers = get_auth_headers(security)

        assert headers == {"Authorization": "Bearer test-token-123"}

    def test_without_bearer_token(self) -> None:
        """Returns empty dict when no token."""
        security = Security()

        headers = get_auth_headers(security)

        assert headers == {}


class TestCollectionContext:
    """Tests for CollectionContext dataclass."""

    def test_collection_context_creation(self) -> None:
        """CollectionContext is created with correct attributes."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_ctx = MagicMock(spec=Context)

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
            resource_type="sources",
        )

        assert coll_ctx.client is mock_client
        assert coll_ctx.product == ProductsCore.STREAM
        assert coll_ctx.timeout_ms == 10000
        assert coll_ctx.ctx is mock_ctx
        assert coll_ctx.resource_type == "sources"

    def test_collection_context_immutable(self) -> None:
        """CollectionContext is frozen/immutable."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_ctx = MagicMock(spec=Context)

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=5000,
            ctx=mock_ctx,
            resource_type="destinations",
        )

        with pytest.raises(AttributeError):
            coll_ctx.timeout_ms = 20000  # type: ignore[misc]


class TestHttpCollectionContext:
    """Tests for HttpCollectionContext dataclass."""

    def test_http_context_creation(self) -> None:
        """HttpCollectionContext wraps CollectionContext with HTTP params."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_ctx = MagicMock(spec=Context)
        security = Security(bearer_auth="token")

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
            resource_type="breakers",
        )

        http_ctx = HttpCollectionContext(
            coll_ctx=coll_ctx,
            security=security,
            endpoint_path="lib/breakers",
        )

        assert http_ctx.coll_ctx is coll_ctx
        assert http_ctx.security is security
        assert http_ctx.endpoint_path == "lib/breakers"

    def test_http_context_immutable(self) -> None:
        """HttpCollectionContext is frozen/immutable."""
        mock_client = MagicMock(spec=CriblControlPlane)
        mock_ctx = MagicMock(spec=Context)
        security = Security()

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=5000,
            ctx=mock_ctx,
            resource_type="lookups",
        )

        http_ctx = HttpCollectionContext(
            coll_ctx=coll_ctx,
            security=security,
            endpoint_path="system/lookups",
        )

        with pytest.raises(AttributeError):
            http_ctx.endpoint_path = "new/path"  # type: ignore[misc]


class TestListGroupsMinimal:
    """Tests for list_groups_minimal async function."""

    async def test_returns_serialized_groups(self) -> None:
        """Returns list of serialized group dictionaries."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_item1 = MagicMock()
        mock_item1.model_dump.return_value = {"id": "group1", "name": "Group 1"}
        mock_item2 = MagicMock()
        mock_item2.model_dump.return_value = {"id": "group2", "name": "Group 2"}
        mock_response.items = [mock_item1, mock_item2]
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        result = await list_groups_minimal(
            mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
        )

        assert len(result) == 2
        assert result[0] == {"id": "group1", "name": "Group 1"}
        assert result[1] == {"id": "group2", "name": "Group 2"}
        mock_client.groups.list_async.assert_called_once_with(
            product=ProductsCore.STREAM,
            timeout_ms=10000,
        )

    async def test_handles_none_items(self) -> None:
        """Returns empty list when items is None."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.items = None
        mock_client.groups.list_async = AsyncMock(return_value=mock_response)

        result = await list_groups_minimal(
            mock_client,
            product=ProductsCore.EDGE,
            timeout_ms=5000,
        )

        assert result == []


class TestHandleProductUnavailable:
    """Tests for handle_product_unavailable async function."""

    async def test_logs_warning_and_returns_unavailable(self) -> None:
        """Logs warning and returns unavailable result."""
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.warning = AsyncMock()

        result = await handle_product_unavailable(
            mock_ctx,
            ProductsCore.STREAM,
            "sources",
        )

        assert result["status"] == "unavailable"
        assert result["total_count"] == 0
        assert result["groups"] == []
        mock_ctx.warning.assert_called_once()
        call_args = mock_ctx.warning.call_args[0][0]
        assert "stream" in call_args
        assert "sources" in call_args


class TestCollectItemsViaSdk:
    """Tests for collect_items_via_sdk async function."""

    def _create_collection_context(self) -> tuple[CollectionContext, MagicMock, MagicMock]:
        """Helper to create a CollectionContext with mocks."""
        mock_client = MagicMock()
        mock_client.sdk_configuration = MagicMock(server_url="https://cribl.example.com")
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.warning = AsyncMock()

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
            resource_type="sources",
        )
        return coll_ctx, mock_client, mock_ctx

    async def test_collects_items_from_multiple_groups(self) -> None:
        """Collects items from multiple groups in parallel."""
        coll_ctx, mock_client, _ = self._create_collection_context()

        # Mock list_groups_minimal
        mock_group_response = MagicMock()
        mock_group1 = MagicMock()
        mock_group1.model_dump.return_value = {"id": "group1"}
        mock_group2 = MagicMock()
        mock_group2.model_dump.return_value = {"id": "group2"}
        mock_group_response.items = [mock_group1, mock_group2]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Mock list_method for each group
        mock_item1 = MagicMock()
        mock_item1.model_dump.return_value = {"id": "src1", "type": "http"}
        mock_item2 = MagicMock()
        mock_item2.model_dump.return_value = {"id": "src2", "type": "syslog"}

        mock_list_method = AsyncMock()
        mock_response1 = MagicMock()
        mock_response1.items = [mock_item1]
        mock_response1.count = 1
        mock_response2 = MagicMock()
        mock_response2.items = [mock_item2]
        mock_response2.count = 1
        mock_list_method.side_effect = [mock_response1, mock_response2]

        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "ok"
        assert result["total_count"] == 2
        assert len(result["groups"]) == 2

    async def test_handles_404_from_groups_endpoint(self) -> None:
        """Returns unavailable when groups endpoint returns 404."""
        coll_ctx, mock_client, mock_ctx = self._create_collection_context()

        exc = CriblControlPlaneError(
            message="Not Found",
            raw_response=MagicMock(status_code=HTTP_NOT_FOUND),
            body=None,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        mock_list_method = AsyncMock()
        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "unavailable"
        mock_ctx.warning.assert_called_once()

    async def test_raises_runtime_error_on_api_error(self) -> None:
        """Raises RuntimeError on non-404 API errors."""
        coll_ctx, mock_client, _ = self._create_collection_context()

        exc = CriblControlPlaneError(
            message="Server Error",
            raw_response=MagicMock(status_code=500),
            body=None,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        mock_list_method = AsyncMock()
        with pytest.raises(RuntimeError, match="Cribl API error"):
            await collect_items_via_sdk(coll_ctx, mock_list_method)

    async def test_raises_runtime_error_on_network_error(self) -> None:
        """Raises RuntimeError on network errors."""
        coll_ctx, mock_client, _ = self._create_collection_context()

        mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        mock_list_method = AsyncMock()
        with pytest.raises(RuntimeError, match="Network error"):
            await collect_items_via_sdk(coll_ctx, mock_list_method)

    async def test_returns_empty_when_no_valid_groups(self) -> None:
        """Returns empty result when all groups have invalid IDs."""
        coll_ctx, mock_client, _ = self._create_collection_context()

        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"name": "no-id-group"}  # No id field
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        mock_list_method = AsyncMock()
        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "ok"
        assert result["total_count"] == 0
        assert result["groups"] == []
        mock_list_method.assert_not_called()

    async def test_handles_response_validation_error_on_groups(self) -> None:
        """Returns validation error response when listing groups fails validation."""
        coll_ctx, mock_client, mock_ctx = self._create_collection_context()
        mock_ctx.error = AsyncMock()

        # Create a mock ValidationError as the cause
        mock_validation_error = MagicMock(spec=ValidationError)
        mock_validation_error.errors.return_value = [
            {
                "loc": ("body", "items", 0, "id"),
                "msg": "Field required",
                "type": "missing",
                "input": None,
            }
        ]

        exc = ResponseValidationError(
            message="Validation failed",
            raw_response=MagicMock(status_code=200),
            cause=mock_validation_error,
            body='{"items": [{}]}',
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        mock_list_method = AsyncMock()
        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "validation_error"
        assert "groups" in result["resource_type"]
        mock_ctx.error.assert_called_once()
        mock_list_method.assert_not_called()

    async def test_handles_response_validation_error_on_items(self) -> None:
        """Returns validation error when fetching group items fails validation."""
        coll_ctx, mock_client, mock_ctx = self._create_collection_context()
        mock_ctx.error = AsyncMock()

        # Mock successful group listing
        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Create a mock ValidationError for the list_method
        mock_validation_error = MagicMock(spec=ValidationError)
        mock_validation_error.errors.return_value = [
            {
                "loc": ("body", "items", 0, "tcpjson", "connections"),
                "msg": "Field required",
                "type": "missing",
                "input": None,
            }
        ]

        exc = ResponseValidationError(
            message="Validation failed",
            raw_response=MagicMock(status_code=200),
            cause=mock_validation_error,
            body='{"items": [{"id": "src1"}]}',
        )

        mock_list_method = AsyncMock(side_effect=exc)
        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "validation_error"
        assert result["group_id"] == "group1"
        mock_ctx.error.assert_called_once()

    async def test_handles_response_validation_error_without_validation_cause(self) -> None:
        """Returns validation error even when cause is not ValidationError."""
        coll_ctx, mock_client, mock_ctx = self._create_collection_context()
        mock_ctx.error = AsyncMock()

        # ResponseValidationError with non-ValidationError cause
        exc = ResponseValidationError(
            message="Unexpected error",
            raw_response=MagicMock(status_code=200),
            cause=Exception("Some other error"),
            body='{"items": []}',
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        mock_list_method = AsyncMock()
        result = await collect_items_via_sdk(coll_ctx, mock_list_method)

        assert result["status"] == "validation_error"
        # When cause is not ValidationError, errors list should be empty
        assert result["errors"] == []


class TestCollectItemsViaHttp:
    """Tests for collect_items_via_http async function."""

    def _create_http_context(self) -> tuple[HttpCollectionContext, MagicMock, MagicMock]:
        """Helper to create an HttpCollectionContext with mocks."""
        mock_client = MagicMock()
        mock_client.sdk_configuration = MagicMock(
            server_url="https://cribl.example.com",
            async_client=MagicMock(spec=httpx.AsyncClient),
        )
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.warning = AsyncMock()
        security = Security(bearer_auth="test-token")

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
            resource_type="breakers",
        )

        http_ctx = HttpCollectionContext(
            coll_ctx=coll_ctx,
            security=security,
            endpoint_path="lib/breakers",
        )
        return http_ctx, mock_client, mock_ctx

    async def test_collects_items_from_multiple_groups(self) -> None:
        """Collects items from multiple groups via HTTP in parallel."""
        http_ctx, mock_client, _ = self._create_http_context()

        # Mock list_groups_minimal
        mock_group_response = MagicMock()
        mock_group1 = MagicMock()
        mock_group1.model_dump.return_value = {"id": "group1"}
        mock_group2 = MagicMock()
        mock_group2.model_dump.return_value = {"id": "group2"}
        mock_group_response.items = [mock_group1, mock_group2]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Mock HTTP responses
        mock_http_client = mock_client.sdk_configuration.async_client
        mock_resp1 = MagicMock()
        mock_resp1.status_code = 200
        mock_resp1.json.return_value = {"items": [{"id": "b1"}], "count": 1}
        mock_resp1.raise_for_status = MagicMock()

        mock_resp2 = MagicMock()
        mock_resp2.status_code = 200
        mock_resp2.json.return_value = {"items": [{"id": "b2"}], "count": 1}
        mock_resp2.raise_for_status = MagicMock()

        mock_http_client.get = AsyncMock(side_effect=[mock_resp1, mock_resp2])

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "ok"
        assert result["total_count"] == 2
        assert len(result["groups"]) == 2

    async def test_handles_404_from_groups_endpoint(self) -> None:
        """Returns unavailable when groups endpoint returns 404."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()

        exc = CriblControlPlaneError(
            message="Not Found",
            raw_response=MagicMock(status_code=HTTP_NOT_FOUND),
            body=None,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "unavailable"
        mock_ctx.warning.assert_called_once()

    async def test_raises_runtime_error_on_api_error(self) -> None:
        """Raises RuntimeError on non-404 API errors."""
        http_ctx, mock_client, _ = self._create_http_context()

        exc = CriblControlPlaneError(
            message="Server Error",
            raw_response=MagicMock(status_code=500),
            body=None,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        with pytest.raises(RuntimeError, match="Cribl API error"):
            await collect_items_via_http(http_ctx)

    async def test_raises_runtime_error_on_network_error(self) -> None:
        """Raises RuntimeError on network errors during group listing."""
        http_ctx, mock_client, _ = self._create_http_context()

        mock_client.groups.list_async = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with pytest.raises(RuntimeError, match="Network error"):
            await collect_items_via_http(http_ctx)

    async def test_returns_empty_when_no_valid_groups(self) -> None:
        """Returns empty result when all groups have invalid IDs."""
        http_ctx, mock_client, _ = self._create_http_context()

        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"name": "no-id-group"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "ok"
        assert result["total_count"] == 0
        assert result["groups"] == []

    async def test_handles_404_from_item_endpoint(self) -> None:
        """Handles 404 from individual group item endpoint gracefully."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()

        # Mock list_groups_minimal
        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Mock HTTP 404 response
        mock_http_client = mock_client.sdk_configuration.async_client
        mock_resp = MagicMock()
        mock_resp.status_code = HTTP_NOT_FOUND
        mock_http_client.get = AsyncMock(return_value=mock_resp)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "ok"
        assert result["total_count"] == 0
        assert len(result["groups"]) == 1
        assert result["groups"][0]["count"] == 0
        mock_ctx.warning.assert_called_once()

    async def test_handles_404_from_item_endpoint_with_item_id(self) -> None:
        """Handles 404 from an item-specific endpoint and logs item ID."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()
        http_ctx = HttpCollectionContext(
            coll_ctx=http_ctx.coll_ctx,
            security=http_ctx.security,
            endpoint_path=http_ctx.endpoint_path,
            item_id="breaker-1",
        )

        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        mock_http_client = mock_client.sdk_configuration.async_client
        mock_resp = MagicMock()
        mock_resp.status_code = HTTP_NOT_FOUND
        mock_http_client.get = AsyncMock(return_value=mock_resp)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "ok"
        assert result["total_count"] == 0
        assert len(result["groups"]) == 1
        assert result["groups"][0]["count"] == 0
        mock_ctx.warning.assert_called_once()

        warning_message = mock_ctx.warning.call_args[0][0]
        assert "breaker-1" in warning_message

        request_url = mock_http_client.get.call_args[0][0]
        assert request_url.endswith("/m/group1/lib/breakers/breaker-1")

    async def test_raises_on_http_error_during_item_fetch(self) -> None:
        """Raises RuntimeError on HTTP errors during item fetch."""
        http_ctx, mock_client, _ = self._create_http_context()

        # Mock list_groups_minimal
        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Mock HTTP error
        mock_http_client = mock_client.sdk_configuration.async_client
        mock_http_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with pytest.raises(RuntimeError, match="Network error"):
            await collect_items_via_http(http_ctx)

    async def test_raises_on_invalid_json_response(self) -> None:
        """Raises RuntimeError on invalid JSON response."""
        http_ctx, mock_client, _ = self._create_http_context()

        # Mock list_groups_minimal
        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        # Mock HTTP response with invalid JSON
        mock_http_client = mock_client.sdk_configuration.async_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.side_effect = ValueError("Invalid JSON")
        mock_http_client.get = AsyncMock(return_value=mock_resp)

        with pytest.raises(RuntimeError, match="Invalid JSON response"):
            await collect_items_via_http(http_ctx)

    async def test_raises_on_none_server_url(self) -> None:
        """Raises ValueError when server_url is None."""
        mock_client = MagicMock()
        mock_client.sdk_configuration = MagicMock(
            server_url=None,
            async_client=MagicMock(spec=httpx.AsyncClient),
        )
        mock_ctx = MagicMock(spec=Context)
        mock_ctx.warning = AsyncMock()
        security = Security(bearer_auth="test-token")

        coll_ctx = CollectionContext(
            client=mock_client,
            product=ProductsCore.STREAM,
            timeout_ms=10000,
            ctx=mock_ctx,
            resource_type="breakers",
        )

        http_ctx = HttpCollectionContext(
            coll_ctx=coll_ctx,
            security=security,
            endpoint_path="lib/breakers",
        )

        # Mock list_groups_minimal to return groups
        mock_group_response = MagicMock()
        mock_group = MagicMock()
        mock_group.model_dump.return_value = {"id": "group1"}
        mock_group_response.items = [mock_group]
        mock_client.groups.list_async = AsyncMock(return_value=mock_group_response)

        with pytest.raises(ValueError, match="server_url is not configured"):
            await collect_items_via_http(http_ctx)

    async def test_handles_response_validation_error_on_groups(self) -> None:
        """Returns validation error response when listing groups fails validation."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()
        mock_ctx.error = AsyncMock()

        # Create a mock ValidationError as the cause
        mock_validation_error = MagicMock(spec=ValidationError)
        mock_validation_error.errors.return_value = [
            {
                "loc": ("body", "items", 0, "id"),
                "msg": "Field required",
                "type": "missing",
                "input": None,
            }
        ]

        exc = ResponseValidationError(
            message="Validation failed",
            raw_response=MagicMock(status_code=200),
            cause=mock_validation_error,
            body='{"items": [{}]}',
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "validation_error"
        assert "groups" in result["resource_type"]
        mock_ctx.error.assert_called_once()

    async def test_handles_response_validation_error_without_body_attr(self) -> None:
        """Handles ResponseValidationError when body attribute is missing."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()
        mock_ctx.error = AsyncMock()

        # Create a mock ValidationError as the cause
        mock_validation_error = MagicMock(spec=ValidationError)
        mock_validation_error.errors.return_value = []

        # Create exception with body=None
        exc = ResponseValidationError(
            message="Validation failed",
            raw_response=MagicMock(status_code=200),
            cause=mock_validation_error,
            body=None,
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "validation_error"
        mock_ctx.error.assert_called_once()

    async def test_handles_response_validation_error_with_non_validation_cause(self) -> None:
        """Returns validation error even when cause is not ValidationError."""
        http_ctx, mock_client, mock_ctx = self._create_http_context()
        mock_ctx.error = AsyncMock()

        # ResponseValidationError with non-ValidationError cause
        exc = ResponseValidationError(
            message="Unexpected error",
            raw_response=MagicMock(status_code=200),
            cause=Exception("Some other error"),
            body='{"items": []}',
        )
        mock_client.groups.list_async = AsyncMock(side_effect=exc)

        result = await collect_items_via_http(http_ctx)

        assert result["status"] == "validation_error"
        # When cause is not ValidationError, errors list should be empty
        assert result["errors"] == []
