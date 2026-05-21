"""Unit tests for cross-leader copy and sync validation helpers."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore

import snc_cribl_mcp.operations.sync as sync_module


def _resolved(name: str) -> SimpleNamespace:
    """Return a minimal resolved-server stand-in for sync tests."""
    return SimpleNamespace(
        server_name=name,
        config=SimpleNamespace(timeout_ms=1000),
        client=object(),
    )


def test_sync_diff_and_group_text_helpers_cover_edge_cases() -> None:
    """Private sync helpers should handle root/list diffs and group text matching."""
    assert sync_module._diff_paths([1, 2], [1]) == ["length"]
    assert sync_module._diff_paths([1, 2], [1, 3]) == ["[1]"]
    assert len(sync_module._diff_paths(list(range(30)), list(range(30, 60)))) == 25
    assert sync_module._diff_paths("left", "right") == ["$"]
    assert len(sync_module._diff_paths({f"key_{index:03d}": index for index in range(30)}, {})) == 25
    assert len(sync_module._diff_paths({"nested": {f"key_{index:03d}": index for index in range(30)}}, {"nested": {}})) == 25

    assert sync_module._normalize_group_text(None) is None
    assert sync_module._normalize_group_text("  ") is None
    assert sync_module._normalize_group_text("  Default  ") == "Default"

    groups = [
        {"id": "one", "name": None},
        {"id": "two", "name": "Default"},
        {"id": "three", "name": "default"},
    ]
    assert sync_module._match_groups(groups, selector="DEFAULT", field="name", case_sensitive=False) == groups[1:]
    duplicate_groups = [
        {"id": "one", "description": "duplicate"},
        {"id": "two", "description": "duplicate"},
    ]
    with pytest.raises(ValueError, match="matched multiple groups"):
        sync_module._select_group_match(
            duplicate_groups,
            selector="duplicate",
            server_name="leader",
            product=ProductsCore.STREAM,
        )


@pytest.mark.asyncio
async def test_resolve_group_selector_handles_validation_errors_and_passthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Group selector resolution should validate selectors before API lookup."""
    resolved = cast("sync_module.ResolvedControlPlane", _resolved("source"))

    with pytest.raises(ValueError, match="selector is required"):
        await sync_module._resolve_group_selector(resolved, selector=None, product=ProductsCore.STREAM)

    with pytest.raises(ValueError, match="must not be blank"):
        await sync_module._resolve_group_selector(resolved, selector="  ", product=ProductsCore.STREAM)

    passthrough = await sync_module._resolve_group_selector(resolved, selector=" default ", product=None)
    assert passthrough.as_dict() == {
        "selector": " default ",
        "id": "default",
        "matched_by": "passthrough",
        "name": None,
        "description": None,
    }

    list_resource = AsyncMock(return_value=[{"id": "Default", "name": "Default Group"}])
    monkeypatch.setattr(sync_module, "list_resource", list_resource)

    case_insensitive = await sync_module._resolve_group_selector(
        resolved,
        selector="default",
        product=ProductsCore.STREAM,
    )

    assert case_insensitive.group_id == "Default"
    assert case_insensitive.matched_by == "id"
    assert case_insensitive.name == "Default Group"

    list_resource.return_value = []
    with pytest.raises(ValueError, match="Could not resolve group selector"):
        await sync_module._resolve_group_selector(resolved, selector="missing", product=ProductsCore.STREAM)

    list_resource.return_value = [{"name": "nameless"}]
    with pytest.raises(ValueError, match="did not include an id"):
        await sync_module._resolve_group_selector(resolved, selector="nameless", product=ProductsCore.STREAM)


def test_apply_validate_response_limit_handles_each_reduction_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    """Response limiting should strip payloads, summarize extras, then truncate items."""
    assert sync_module._apply_validate_response_limit({"items": []}) == {"items": []}

    monkeypatch.setattr(sync_module, "_MAX_VALIDATE_RESPONSE_BYTES", 250)
    payload_limited = sync_module._apply_validate_response_limit(
        {
            "items": [
                {
                    "item_id": "pipe1",
                    "status": "different",
                    "differing_paths": ["conf"],
                    "source": {"blob": "x" * 1000},
                    "target": {"blob": "y" * 1000},
                }
            ]
        }
    )

    assert "source" not in payload_limited["items"][0]
    assert "target" not in payload_limited["items"][0]
    assert payload_limited["warnings"] == ["Omitted per-item source and target payloads to stay within MCP response limits."]

    summarized = sync_module._apply_validate_response_limit(
        {
            "items": [
                {
                    "item_id": "pipe2",
                    "status": "different",
                    "differing_paths": ["conf"],
                    "extra": "x" * 1000,
                }
            ]
        }
    )

    assert summarized["items"] == [{"item_id": "pipe2", "status": "different", "differing_paths": ["conf"]}]
    assert summarized["warnings"] == ["Reduced validation item details to summary fields to stay within MCP response limits."]

    monkeypatch.setattr(sync_module, "_MAX_VALIDATE_RESPONSE_BYTES", 500)
    truncated = sync_module._apply_validate_response_limit(
        {"items": [{"item_id": f"item-{index}", "status": "different", "differing_paths": ["x" * 150]} for index in range(3)]}
    )

    assert truncated["response_truncated"] is True
    assert truncated["returned_item_count"] == 1
    assert truncated["omitted_item_count"] == 2
    assert truncated["warnings"] == ["Returned 1 of 3 validation item results to stay within MCP response limits."]

    monkeypatch.setattr(sync_module, "_MAX_VALIDATE_RESPONSE_BYTES", 1)
    fully_reduced = sync_module._apply_validate_response_limit(
        {
            "items": [
                {
                    "item_id": "pipe3",
                    "status": "different",
                    "differing_paths": ["conf"],
                    "source": {"blob": "x" * 1000},
                    "target": {"blob": "y" * 1000},
                    "extra": "z" * 1000,
                }
            ]
        }
    )

    assert fully_reduced["response_truncated"] is True
    assert fully_reduced["returned_item_count"] == 0
    assert fully_reduced["omitted_item_count"] == 1


def test_apply_validate_response_limit_can_exhaust_truncation_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The final truncation loop should also support keeping every summary item."""
    estimates = iter([2, 0, 0])
    monkeypatch.setattr(sync_module, "_MAX_VALIDATE_RESPONSE_BYTES", 1)

    def _estimate_json_size_bytes(_payload: dict[str, Any]) -> int:
        return next(estimates)

    monkeypatch.setattr(sync_module, "_estimate_json_size_bytes", _estimate_json_size_bytes)

    result = sync_module._apply_validate_response_limit(
        {
            "items": [
                {"item_id": "one", "status": "different", "differing_paths": []},
                {"item_id": "two", "status": "different", "differing_paths": []},
            ]
        }
    )

    assert result["response_truncated"] is False
    assert result["returned_item_count"] == 2
    assert result["omitted_item_count"] == 0
    assert result["warnings"] == []


def test_index_items_skips_entries_without_ids() -> None:
    """Indexing should ignore resources that do not include id or groupId."""
    assert sync_module._index_items([{"id": "one"}, {"name": "skip"}, {"groupId": "three"}]) == {
        "one": {"id": "one"},
        "three": {"groupId": "three"},
    }


@pytest.mark.asyncio
async def test_maybe_get_item_returns_none_only_for_http_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Single-item lookup should translate HTTP 404 to None and re-raise other errors."""
    not_found = CriblControlPlaneError("missing", httpx.Response(404, text="missing"))
    direct_not_found = httpx.HTTPStatusError(
        "missing",
        request=httpx.Request("GET", "https://cribl.example/api/v1/m/default/lib/vars/missing"),
        response=httpx.Response(404, text="missing"),
    )
    server_error = CriblControlPlaneError("boom", httpx.Response(500, text="boom"))
    direct_server_error = httpx.HTTPStatusError(
        "boom",
        request=httpx.Request("GET", "https://cribl.example/api/v1/m/default/lib/vars/broken"),
        response=httpx.Response(500, text="boom"),
    )
    get_resource = AsyncMock(side_effect=[not_found, direct_not_found, server_error, direct_server_error])
    monkeypatch.setattr(sync_module, "get_resource", get_resource)

    resolved = cast("sync_module.ResolvedControlPlane", _resolved("target"))

    assert await sync_module._maybe_get_item(resolved, "groups", item_id="missing") is None
    assert await sync_module._maybe_get_item(resolved, "variables", item_id="missing") is None

    with pytest.raises(CriblControlPlaneError, match="boom"):
        await sync_module._maybe_get_item(resolved, "groups", item_id="broken")
    with pytest.raises(httpx.HTTPStatusError, match="boom"):
        await sync_module._maybe_get_item(resolved, "variables", item_id="broken")


def test_copy_error_helpers_include_status_codes_and_validate_target_group() -> None:
    """Copy error serialization should preserve HTTP status details when available."""
    error = CriblControlPlaneError("missing", httpx.Response(404, text="missing"))

    assert sync_module._serialize_copy_error(error) == {
        "type": "CriblControlPlaneError",
        "message": "missing",
        "status_code": 404,
    }
    assert sync_module._require_resolved_target_group_id("default") == "default"
    with pytest.raises(ValueError, match="resolved target group id is missing"):
        sync_module._require_resolved_target_group_id(None)


@pytest.mark.asyncio
async def test_validate_resource_sync_collection_reports_differences(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collection validation should classify in-sync, missing, and changed items."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
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
    assert "source" not in result["items"][0]
    assert "target" not in result["items"][0]


@pytest.mark.asyncio
async def test_copy_resource_config_creates_missing_target_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copy should create a missing target item and validate it afterward."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
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
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
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
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
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


@pytest.mark.asyncio
async def test_copy_resource_config_continues_after_per_item_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed write for one item should not abort the rest of the copy batch."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_items = [
        {"id": "pipe1", "conf": {"output": "default"}},
        {"id": "pipe2", "conf": {"output": "default"}},
    ]
    list_resource = AsyncMock(return_value=source_items)
    maybe_get_item = AsyncMock(side_effect=[None, None])
    create_resource = AsyncMock(side_effect=[RuntimeError("target rejected pipe1"), [source_items[1]]])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)
    monkeypatch.setattr(sync_module, "create_resource", create_resource)

    result = await sync_module.copy_resource_config(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        validate_after=False,
    )

    assert result["copied_count"] == 1
    assert result["created_count"] == 1
    assert result["failed_count"] == 1
    assert result["items"] == [
        {
            "item_id": "pipe1",
            "action": "failed",
            "attempted_action": "create",
            "error": {
                "type": "RuntimeError",
                "message": "target rejected pipe1",
            },
        },
        {
            "item_id": "pipe2",
            "action": "created",
        },
    ]
    assert create_resource.await_count == 2


@pytest.mark.asyncio
async def test_copy_resource_config_preserves_success_when_validation_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation lookup failures should be reported per item without discarding a successful write."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_items = [
        {"id": "pipe1", "conf": {"output": "default"}},
        {"id": "pipe2", "conf": {"output": "default"}},
    ]
    list_resource = AsyncMock(return_value=source_items)
    create_resource = AsyncMock(side_effect=[[source_items[0]], [source_items[1]]])
    maybe_get_item = AsyncMock(
        side_effect=[
            None,
            RuntimeError("validation lookup failed"),
            None,
            source_items[1],
        ]
    )

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)
    monkeypatch.setattr(sync_module, "create_resource", create_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)

    result = await sync_module.copy_resource_config(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
    )

    assert result["copied_count"] == 2
    assert result["failed_count"] == 0
    assert result["items"][0] == {
        "item_id": "pipe1",
        "action": "created",
        "validation_error": {
            "type": "RuntimeError",
            "message": "validation lookup failed",
        },
    }
    assert result["items"][1]["action"] == "created"
    assert result["items"][1]["validation"]["status"] == "in_sync"


@pytest.mark.asyncio
async def test_validate_resource_sync_resolves_distinct_group_selectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation should resolve source and target group selectors independently."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    list_resource = AsyncMock(
        side_effect=[
            [{"id": "source-group-id", "description": "sandbox_appnode"}],
            [{"id": "default", "name": "default", "description": "Default Worker Group"}],
            [{"id": "cisco_asa", "conf": {"functions": []}}],
            [{"id": "cisco_asa", "conf": {"functions": []}}],
        ]
    )
    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)

    result = await sync_module.validate_resource_sync(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        group_id="sandbox_appnode",
        target_group_id="default",
    )

    assert result["in_sync"] is True
    assert result["group_id"] == "source-group-id"
    assert result["target_group_id"] == "default"
    assert result["source_group"] == {
        "selector": "sandbox_appnode",
        "id": "source-group-id",
        "matched_by": "description",
        "name": None,
        "description": "sandbox_appnode",
    }
    assert result["target_group"] == {
        "selector": "default",
        "id": "default",
        "matched_by": "id",
        "name": "default",
        "description": "Default Worker Group",
    }

    assert list_resource.await_args_list[2].kwargs["group_id"] == "source-group-id"
    assert list_resource.await_args_list[3].kwargs["group_id"] == "default"


@pytest.mark.asyncio
async def test_validate_resource_sync_single_item_reports_missing_on_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single-item validation should explicitly report when neither leader has the item."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    maybe_get_item = AsyncMock(side_effect=[None, None])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)

    result = await sync_module.validate_resource_sync(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        item_id="missing-group",
    )

    assert result["in_sync"] is False
    assert result["items"] == [
        {
            "item_id": "missing-group",
            "status": "missing_on_both",
            "differing_paths": [],
        }
    ]


@pytest.mark.asyncio
async def test_validate_resource_sync_single_item_can_include_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single-item validation can include canonicalized payloads when requested."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_item: dict[str, object] = {
        "id": "default",
        "description": "Source Group",
        "lookupDeployments": [],
        "type": "stream",
    }
    target_item: dict[str, object] = {
        "id": "default",
        "description": "Target Group",
        "lookupDeployments": [],
        "type": "stream",
    }
    maybe_get_item = AsyncMock(side_effect=[source_item, target_item])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)

    result = await sync_module.validate_resource_sync(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        item_id="default",
        include_payloads=True,
    )

    assert result["items"][0]["status"] == "different"
    assert result["items"][0]["source"]["description"] == "Source Group"
    assert result["items"][0]["target"]["description"] == "Target Group"


@pytest.mark.asyncio
async def test_validate_resource_sync_truncates_large_collection_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Collection validation should trim oversized responses and report the truncation."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    list_resource = AsyncMock(
        side_effect=[
            [
                {"id": "group1", "description": "left", "lookupDeployments": [], "type": "stream"},
                {"id": "group2", "description": "left", "lookupDeployments": [], "type": "stream"},
                {"id": "group3", "description": "left", "lookupDeployments": [], "type": "stream"},
            ],
            [
                {"id": "group1", "description": "right", "lookupDeployments": [], "type": "stream"},
                {"id": "group2", "description": "right", "lookupDeployments": [], "type": "stream"},
                {"id": "group3", "description": "right", "lookupDeployments": [], "type": "stream"},
            ],
        ]
    )

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)
    monkeypatch.setattr(sync_module, "_MAX_VALIDATE_RESPONSE_BYTES", 450)

    result = await sync_module.validate_resource_sync(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
    )

    assert result["response_truncated"] is True
    assert result["returned_item_count"] < 3
    assert result["omitted_item_count"] > 0
    assert result["warnings"]
    assert all("source" not in item and "target" not in item for item in result["items"])


@pytest.mark.asyncio
async def test_copy_resource_config_resolves_target_group_selector_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Copy should resolve group selectors before reading and writing resources."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_item = {"id": "cisco_asa", "conf": {"output": "default"}}
    list_resource = AsyncMock(
        side_effect=[
            [{"id": "source-group-id", "description": "sandbox_appnode"}],
            [{"id": "default", "description": "Default Worker Group"}],
        ]
    )
    get_resource = AsyncMock(return_value=source_item)
    maybe_get_item = AsyncMock(side_effect=[None, source_item])
    create_resource = AsyncMock(return_value=[source_item])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "list_resource", list_resource)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)
    monkeypatch.setattr(sync_module, "create_resource", create_resource)

    result = await sync_module.copy_resource_config(
        "pipelines",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        group_id="sandbox_appnode",
        target_group_id="default",
        item_id="cisco_asa",
    )

    assert result["created_count"] == 1
    assert result["group_id"] == "source-group-id"
    assert result["target_group_id"] == "default"
    assert get_resource.await_args is not None
    assert create_resource.await_args is not None
    assert get_resource.await_args.kwargs["group_id"] == "source-group-id"
    assert create_resource.await_args.kwargs["group_id"] == "default"


@pytest.mark.asyncio
async def test_copy_resource_config_updates_existing_target_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing targets should be updated when overwrite is enabled."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_item: dict[str, Any] = {"id": "pipe1", "conf": {"functions": []}}
    get_resource = AsyncMock(return_value=source_item)
    maybe_get_item = AsyncMock(return_value={"id": "pipe1", "conf": {"functions": [{"id": "eval"}]}})
    update_resource = AsyncMock(return_value=[source_item])

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
        validate_after=False,
    )

    assert result["updated_count"] == 1
    assert result["items"] == [{"item_id": "pipe1", "action": "updated"}]
    update_resource.assert_awaited_once()


@pytest.mark.asyncio
async def test_copy_resource_config_updates_product_scoped_group(monkeypatch: pytest.MonkeyPatch) -> None:
    """Product-scoped group copies should not attempt group selector resolution."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    source_group: dict[str, Any] = {"id": "default", "description": "Default", "lookupDeployments": [], "type": "stream"}
    get_resource = AsyncMock(return_value=source_group)
    maybe_get_item = AsyncMock(return_value={"id": "default", "description": "Old", "lookupDeployments": [], "type": "stream"})
    update_resource = AsyncMock(return_value=[source_group])

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)
    monkeypatch.setattr(sync_module, "update_resource", update_resource)

    result = await sync_module.copy_resource_config(
        "groups",
        "golden.oak",
        "cribl.cloud",
        product=ProductsCore.STREAM,
        item_id="default",
        validate_after=False,
    )

    assert result["updated_count"] == 1
    assert result["group_id"] is None
    assert result["target_group_id"] is None
    assert update_resource.await_args is not None
    assert update_resource.await_args.kwargs["product"] == ProductsCore.STREAM
    assert update_resource.await_args.kwargs["group_id"] is None


@pytest.mark.asyncio
async def test_copy_resource_config_reports_missing_route_target_as_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Routes require a target route set before copy can update or append them."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    route_set: dict[str, Any] = {"id": "default", "routes": [], "comments": [], "groups": {}}
    get_resource = AsyncMock(return_value=route_set)
    maybe_get_item = AsyncMock(return_value=None)

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource", get_resource)
    monkeypatch.setattr(sync_module, "_maybe_get_item", maybe_get_item)

    result = await sync_module.copy_resource_config(
        "routes",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        item_id="default",
        validate_after=False,
    )

    assert result["unsupported_count"] == 1
    assert result["items"] == [
        {
            "item_id": "default",
            "action": "unsupported",
            "reason": "Routes require an existing target route set before they can be updated or appended.",
        }
    ]


@pytest.mark.asyncio
async def test_copy_resource_config_reports_generic_unsupported_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generic unsupported-create path should remain stable for future specs."""

    @asynccontextmanager
    async def _pair(_source: str, _target: str) -> AsyncGenerator[tuple[SimpleNamespace, SimpleNamespace]]:
        yield _resolved("source"), _resolved("target")

    def _supports(_action: object) -> bool:
        return False

    fake_spec = SimpleNamespace(scope="group", supports=_supports)
    route_set: dict[str, Any] = {"id": "default", "routes": [], "comments": [], "groups": {}}

    def _get_resource_spec(_kind: object) -> SimpleNamespace:
        return fake_spec

    monkeypatch.setattr(sync_module, "connect_server_pair", _pair)
    monkeypatch.setattr(sync_module, "get_resource_spec", _get_resource_spec)
    monkeypatch.setattr(sync_module, "get_resource", AsyncMock(return_value=route_set))
    monkeypatch.setattr(sync_module, "_maybe_get_item", AsyncMock(return_value=None))

    result = await sync_module.copy_resource_config(
        "routes",
        "golden.oak",
        "cribl.cloud",
        group_id="default",
        item_id="default",
        validate_after=False,
    )

    assert result["unsupported_count"] == 1
    assert result["items"] == [
        {
            "item_id": "default",
            "action": "unsupported",
            "reason": "Create is not supported for resource kind 'routes'.",
        }
    ]
