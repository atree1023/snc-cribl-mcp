"""Unit tests for cross-leader copy and sync validation helpers."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import snc_cribl_mcp.operations.sync as sync_module


def _resolved(name: str) -> SimpleNamespace:
    """Return a minimal resolved-server stand-in for sync tests."""
    return SimpleNamespace(
        server_name=name,
        config=SimpleNamespace(timeout_ms=1000),
        client=object(),
    )


@pytest.mark.asyncio
async def test_validate_resource_sync_collection_reports_differences(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collection validation should classify in-sync, missing, and changed items."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncIterator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    list_resource = AsyncMock(
        side_effect=[
            [
                {"id": "one", "type": "http"},
                {"id": "two", "type": "syslog"},
            ],
            [
                {"id": "one", "type": "syslog"},
                {"id": "three", "type": "http"},
            ],
        ]
    )
    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)

    result = await sync_module.validate_resource_sync(
        "sources",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
    )

    assert result["in_sync"] is False
    assert result["counts"] == {
        "source": 2,
        "target": 2,
        "in_sync": 0,
        "different": 1,
        "missing_on_source": 1,
        "missing_on_target": 1,
    }
    statuses = {item["item_id"]: item["status"] for item in result["items"]}
    assert statuses == {
        "one": "different",
        "three": "missing_on_source",
        "two": "missing_on_target",
    }


@pytest.mark.asyncio
async def test_copy_resource_config_creates_missing_target_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copy should create a missing target item and validate it afterward."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncIterator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_item = {"id": "in_http", "type": "http", "port": 10080}
    get_resource = AsyncMock(return_value=source_item)
    create_resource = AsyncMock(return_value=[source_item])
    maybe_get_item = AsyncMock(side_effect=[None, source_item])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "create_resource", create_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)

    result = await sync_module.copy_resource_config(
        "sources",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        item_id="in_http",
    )

    assert result["created_count"] == 1
    assert result["updated_count"] == 0
    assert result["copied_count"] == 1
    assert result["items"][0]["action"] == "created"
    assert result["items"][0]["validation"]["status"] == "in_sync"
    create_resource.assert_awaited_once()


@pytest.mark.asyncio
async def test_copy_resource_config_appends_routes_when_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route copies can use append mode instead of replace mode."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncIterator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    route_set: dict[str, object] = {
        "id": "default",
        "routes": [{"id": "r1", "name": "Route 1", "filter": "true"}],
        "comments": [],
        "groups": {},
    }
    get_resource = AsyncMock(return_value=route_set)
    maybe_get_item = AsyncMock(side_effect=[{"id": "default"}, route_set])
    append_resource = AsyncMock(return_value=[route_set])
    update_resource = AsyncMock()

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)
    monkeypatch.setattr(sync_module, "append_resource", append_resource)
    monkeypatch.setattr(sync_module, "update_resource", update_resource)

    result = await sync_module.copy_resource_config(
        "routes",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        item_id="default",
        append_routes=True,
    )

    assert result["appended_count"] == 1
    assert result["items"][0]["action"] == "appended"
    append_resource.assert_awaited_once()
    update_resource.assert_not_awaited()


@pytest.mark.asyncio
async def test_copy_resource_config_skips_existing_item_when_overwrite_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing targets should be skipped when overwrite is disabled."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncIterator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_item = {"id": "pipe1", "conf": {"output": "default"}}
    get_resource = AsyncMock(return_value=source_item)
    maybe_get_item = AsyncMock(return_value={"id": "pipe1", "conf": {"output": "other"}})
    update_resource = AsyncMock()

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)
    monkeypatch.setattr(sync_module, "update_resource", update_resource)

    result = await sync_module.copy_resource_config(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        item_id="pipe1",
        overwrite=False,
        validate_after=False,
    )

    assert result["skipped_count"] == 1
    assert result["items"][0]["action"] == "skipped"
    update_resource.assert_not_awaited()
