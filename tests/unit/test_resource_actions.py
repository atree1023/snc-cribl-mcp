"""Unit tests for context-free SDK CRUD helpers."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore

from snc_cribl_mcp.operations.resource_actions import (
    append_resource,
    build_sdk_capability_matrix,
    canonicalize_resource_item,
    create_resource,
    deploy_group,
    update_resource,
)


def _make_response(*items: dict[str, Any]) -> MagicMock:
    """Build a counted SDK-style response with serialized items."""
    response = MagicMock()
    response.items = []
    for item in items:
        model = MagicMock()
        model.model_dump.return_value = item
        response.items.append(model)
    return response


@pytest.mark.asyncio
async def test_create_resource_sources_uses_group_scope() -> None:
    """Source creates should send the raw request payload to the group-scoped SDK endpoint."""
    client = MagicMock()
    client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")
    client.sources.create_async = AsyncMock(return_value=_make_response({"id": "in_http"}))

    item: dict[str, Any] = {"id": "in_http", "type": "http", "port": 10080}
    await create_resource(
        client,
        "sources",
        item=item,
        timeout_ms=2000,
        group_id="default",
    )

    client.sources.create_async.assert_awaited_once()
    assert client.sources.create_async.await_args is not None
    kwargs = client.sources.create_async.await_args.kwargs
    assert kwargs["request"] == item
    assert kwargs["timeout_ms"] == 2000
    assert kwargs["server_url"] == "https://cribl.example.com/api/v1/m/default"


@pytest.mark.asyncio
async def test_update_resource_groups_normalizes_aliases() -> None:
    """Group updates should translate serialized camelCase fields into SDK kwargs."""
    client = MagicMock()
    client.groups.update_async = AsyncMock(return_value=_make_response({"id": "default"}))

    item: dict[str, Any] = {
        "id": "default",
        "configVersion": "abc1234",
        "description": "Default Worker Group",
        "lookupDeployments": [],
        "type": "stream",
        "workerRemoteAccess": True,
    }
    await update_resource(
        client,
        "groups",
        item_id="default",
        item=item,
        timeout_ms=3000,
        product=ProductsCore.STREAM,
    )

    client.groups.update_async.assert_awaited_once()
    assert client.groups.update_async.await_args is not None
    kwargs = client.groups.update_async.await_args.kwargs
    assert kwargs["product"] == ProductsCore.STREAM
    assert kwargs["id_param"] == "default"
    assert kwargs["id"] == "default"
    assert kwargs["config_version"] == "abc1234"
    assert kwargs["lookup_deployments"] == []
    assert kwargs["type_"] == "stream"
    assert kwargs["worker_remote_access"] is True


@pytest.mark.asyncio
async def test_append_resource_routes_uses_request_body() -> None:
    """Route appends should send only the route list as request_body."""
    client = MagicMock()
    client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")
    client.routes.append_async = AsyncMock(return_value=_make_response({"id": "default"}))

    item: dict[str, Any] = {
        "id": "default",
        "routes": [{"id": "r1", "name": "route 1", "filter": "true"}],
        "comments": [],
        "groups": {},
    }
    await append_resource(
        client,
        "routes",
        item_id="default",
        item=item,
        timeout_ms=1500,
        group_id="default",
    )

    client.routes.append_async.assert_awaited_once()
    assert client.routes.append_async.await_args is not None
    kwargs = client.routes.append_async.await_args.kwargs
    assert kwargs["id"] == "default"
    assert kwargs["request_body"] == item["routes"]
    assert kwargs["server_url"] == "https://cribl.example.com/api/v1/m/default"


@pytest.mark.asyncio
async def test_deploy_group_passes_version_and_lookups() -> None:
    """Group deploy should forward versioned deployment arguments unchanged."""
    client = MagicMock()
    client.groups.deploy_async = AsyncMock(return_value=_make_response({"id": "default"}))

    lookups = [{"filename": "sample.csv"}]
    await deploy_group(
        client,
        product=ProductsCore.STREAM,
        group_id="default",
        version="12345",
        timeout_ms=2500,
        lookups=lookups,
    )

    client.groups.deploy_async.assert_awaited_once()
    assert client.groups.deploy_async.await_args is not None
    kwargs = client.groups.deploy_async.await_args.kwargs
    assert kwargs["product"] == ProductsCore.STREAM
    assert kwargs["id"] == "default"
    assert kwargs["version"] == "12345"
    assert kwargs["lookups"] == lookups


def test_canonicalize_resource_item_routes_matches_update_shape() -> None:
    """Route canonicalization should preserve the update payload shape without id_param."""
    item: dict[str, Any] = {
        "id": "default",
        "routes": [{"id": "default", "name": "default", "filter": "true"}],
        "comments": [],
        "groups": {},
    }

    assert canonicalize_resource_item("routes", item) == item


def test_build_sdk_capability_matrix_reflects_route_and_group_special_cases() -> None:
    """The capability matrix should expose append/deploy support where the SDK provides it."""
    matrix = build_sdk_capability_matrix()

    assert matrix["groups"]["deploy"] is True
    assert matrix["groups"]["create"] is True
    assert matrix["routes"]["append"] is True
    assert matrix["routes"]["create"] is False
    assert matrix["routes"]["delete"] is False
