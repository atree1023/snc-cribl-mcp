"""Unit tests for context-free SDK CRUD helpers."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore

import snc_cribl_mcp.operations.resource_actions as resource_actions_module
from snc_cribl_mcp.operations.resource_actions import (
    append_resource,
    build_sdk_capability_matrix,
    canonicalize_resource_item,
    create_resource,
    delete_resource,
    deploy_group,
    get_resource,
    list_resource,
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


@pytest.mark.asyncio
async def test_list_resource_destinations_uses_group_scope() -> None:
    """List operations should pass group-scoped server URLs to SDK methods."""
    client = MagicMock()
    client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")
    client.destinations.list_async = AsyncMock(return_value=_make_response({"id": "splunk:hec"}))

    items = await list_resource(
        client,
        "destinations",
        timeout_ms=1200,
        group_id="default",
    )

    assert items == [{"id": "splunk:hec"}]
    client.destinations.list_async.assert_awaited_once()
    assert client.destinations.list_async.await_args is not None
    kwargs = client.destinations.list_async.await_args.kwargs
    assert kwargs["timeout_ms"] == 1200
    assert kwargs["server_url"] == "https://cribl.example.com/api/v1/m/default"


@pytest.mark.asyncio
async def test_list_resource_requires_scope_arguments() -> None:
    """Resource helpers should reject missing product or group scope arguments."""
    client = MagicMock()

    with pytest.raises(ValueError, match="requires a product"):
        await list_resource(client, "groups", timeout_ms=1000)

    with pytest.raises(ValueError, match="requires a group_id"):
        await list_resource(client, "sources", timeout_ms=1000)


@pytest.mark.asyncio
async def test_get_resource_raises_when_sdk_returns_no_items() -> None:
    """A get response with no items should surface a clear RuntimeError."""
    client = MagicMock()
    response = MagicMock()
    response.items = []
    client.groups.get_async = AsyncMock(return_value=response)

    with pytest.raises(RuntimeError, match="returned no items"):
        await get_resource(
            client,
            "groups",
            item_id="missing",
            timeout_ms=1000,
            product=ProductsCore.STREAM,
        )


@pytest.mark.asyncio
async def test_get_resource_returns_first_serialized_item() -> None:
    """A get response with items should return the first serialized resource."""
    client = MagicMock()
    client.groups.get_async = AsyncMock(return_value=_make_response({"id": "default"}))

    item = await get_resource(
        client,
        "groups",
        item_id="default",
        timeout_ms=1000,
        product=ProductsCore.STREAM,
    )

    assert item == {"id": "default"}


@pytest.mark.asyncio
async def test_update_resource_rejects_specs_without_update_support(monkeypatch: pytest.MonkeyPatch) -> None:
    """Update should fail before touching the SDK when a spec lacks update support."""
    fake_spec = resource_actions_module.ResourceSpec(
        kind="routes",
        client_attr="routes",
        scope="group",
        supported_actions=frozenset(),
    )

    def _get_resource_spec(_kind: resource_actions_module.ResourceKind) -> resource_actions_module.ResourceSpec:
        return fake_spec

    monkeypatch.setattr(resource_actions_module, "get_resource_spec", _get_resource_spec)

    with pytest.raises(ValueError, match="Update is not supported"):
        await update_resource(
            MagicMock(),
            "routes",
            item_id="default",
            item={"id": "default", "routes": []},
            timeout_ms=1000,
            group_id="default",
        )


@pytest.mark.asyncio
async def test_create_resource_rejects_routes() -> None:
    """Routes do not have an SDK create action."""
    with pytest.raises(ValueError, match="Create is not supported"):
        await create_resource(
            MagicMock(),
            "routes",
            item={"id": "default", "routes": []},
            timeout_ms=1000,
            group_id="default",
        )


@pytest.mark.asyncio
async def test_append_resource_rejects_non_route_resources() -> None:
    """Only routes support append semantics."""
    with pytest.raises(ValueError, match="Append is not supported"):
        await append_resource(
            MagicMock(),
            "sources",
            item_id="in_http",
            item={"id": "in_http"},
            timeout_ms=1000,
            group_id="default",
        )


@pytest.mark.asyncio
async def test_delete_resource_rejects_routes() -> None:
    """Routes cannot be deleted through the generic resource helper."""
    with pytest.raises(ValueError, match="Delete is not supported"):
        await delete_resource(
            MagicMock(),
            "routes",
            item_id="default",
            timeout_ms=1000,
            group_id="default",
        )


@pytest.mark.asyncio
async def test_delete_resource_groups_calls_sdk_delete() -> None:
    """Delete should forward product-scoped group deletion arguments."""
    client = MagicMock()
    client.groups.delete_async = AsyncMock(return_value=_make_response({"id": "default"}))

    items = await delete_resource(
        client,
        "groups",
        item_id="default",
        timeout_ms=1800,
        product=ProductsCore.STREAM,
    )

    assert items == [{"id": "default"}]
    client.groups.delete_async.assert_awaited_once()
    assert client.groups.delete_async.await_args is not None
    kwargs = client.groups.delete_async.await_args.kwargs
    assert kwargs["id"] == "default"
    assert kwargs["product"] == ProductsCore.STREAM
    assert kwargs["timeout_ms"] == 1800


@pytest.mark.asyncio
async def test_update_resource_sources_destinations_and_pipelines() -> None:
    """Update helpers should build SDK-specific payload names for each kind."""
    client = MagicMock()
    client.sdk_configuration = MagicMock(server_url="https://cribl.example.com/api/v1")
    client.sources.update_async = AsyncMock(return_value=_make_response({"id": "in_http"}))
    client.destinations.update_async = AsyncMock(return_value=_make_response({"id": "splunk:hec"}))
    client.pipelines.update_async = AsyncMock(return_value=_make_response({"id": "parse_firewall"}))

    source = {"id": "in_http", "type": "http", "port": 10080}
    destination = {"id": "splunk:hec", "type": "splunk_hec", "endpoint": "https://example.com"}
    pipeline: dict[str, Any] = {"id": "parse_firewall", "conf": {"functions": []}}

    await update_resource(client, "sources", item_id="in_http", item=source, timeout_ms=1000, group_id="default")
    await update_resource(
        client,
        "destinations",
        item_id="splunk:hec",
        item=destination,
        timeout_ms=1000,
        group_id="default",
    )
    await update_resource(
        client,
        "pipelines",
        item_id="parse_firewall",
        item=pipeline,
        timeout_ms=1000,
        group_id="default",
    )

    assert client.sources.update_async.await_args is not None
    assert client.destinations.update_async.await_args is not None
    assert client.pipelines.update_async.await_args is not None
    assert client.sources.update_async.await_args.kwargs["input_"] == source
    assert client.destinations.update_async.await_args.kwargs["output"] == destination
    assert client.pipelines.update_async.await_args.kwargs["id_param"] == "parse_firewall"
    assert client.pipelines.update_async.await_args.kwargs["conf"] == {"functions": []}


def test_canonicalize_resource_item_covers_all_supported_payload_shapes() -> None:
    """Canonicalization should normalize all resource kinds into comparable payloads."""
    source = {
        "id": "in_http",
        "type": "http",
        "pipeline": None,
        "nested": {"keep": [{"value": 1, "drop": None}]},
    }
    destination = {"id": "splunk:hec", "type": "splunk_hec", "url": None, "endpoint": "https://example.com"}
    pipeline: dict[str, Any] = {"id": "parse_firewall", "conf": {"functions": []}}
    group = {"id": "default", "description": "Default", "lookupDeployments": None, "type": "stream"}

    assert canonicalize_resource_item("sources", source) == {
        "id": "in_http",
        "type": "http",
        "nested": {"keep": [{"value": 1}]},
    }
    assert canonicalize_resource_item("destinations", destination) == {
        "id": "splunk:hec",
        "type": "splunk_hec",
        "endpoint": "https://example.com",
    }
    assert canonicalize_resource_item("pipelines", pipeline) == {
        "id": "parse_firewall",
        "conf": {"functions": []},
    }
    assert canonicalize_resource_item("groups", group)["description"] == "Default"

    with pytest.raises(ValueError, match="Unsupported resource kind"):
        canonicalize_resource_item(cast("Any", "lookups"), {"id": "lookup.csv"})


def test_payload_builders_reject_unsupported_shapes() -> None:
    """Private payload builders should still reject impossible action/kind pairs."""
    with pytest.raises(ValueError, match="Create is not supported"):
        resource_actions_module._build_create_kwargs("routes", {"id": "default"})

    with pytest.raises(ValueError, match="Update is not supported"):
        resource_actions_module._build_update_kwargs(cast("Any", "lookups"), "lookup.csv", {"id": "lookup.csv"})
