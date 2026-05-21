"""Unit tests for whole group/fleet sync workflows."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cribl_control_plane.models.productscore import ProductsCore

import snc_cribl_mcp.operations.group_sync as group_sync_module


def test_coerce_content_kinds_validates_and_deduplicates() -> None:
    """Content kind parsing should preserve order and reject unknown values."""
    assert group_sync_module._coerce_content_kinds(["sources", "routes", "sources"]) == ("sources", "routes")
    with pytest.raises(ValueError, match="Unsupported group content kind"):
        group_sync_module._coerce_content_kinds(["nope"])


@pytest.mark.asyncio
async def test_replicate_group_config_copies_group_then_contents(monkeypatch: pytest.MonkeyPatch) -> None:
    """The group workflow should resolve the source and copy sections in requested order."""

    @asynccontextmanager
    async def _source(_server: str) -> AsyncGenerator[SimpleNamespace]:
        yield SimpleNamespace(server_name="source", config=SimpleNamespace(timeout_ms=1000), client=object())

    resolve_group = AsyncMock(return_value=SimpleNamespace(group_id="default"))

    async def _copy_resource(kind: str, _source: str, _target: str, **_kwargs: object) -> dict[str, object]:
        return {"resource_kind": kind, "copied_count": 1}

    copy_resource = AsyncMock(side_effect=_copy_resource)

    monkeypatch.setattr(group_sync_module, "connect_to_server", _source)
    monkeypatch.setattr(group_sync_module, "_resolve_group_selector", resolve_group)
    monkeypatch.setattr(group_sync_module, "copy_resource_config", copy_resource)

    result = await group_sync_module.replicate_group_config(
        "source",
        "target",
        product=ProductsCore.STREAM,
        source_group="Default Worker Group",
        content_kinds=["variables", "sources", "routes"],
    )

    assert result["copied_count"] == 4
    assert result["group_id"] == "default"
    assert list(result["content_results"]) == ["variables", "sources", "routes"]
    assert [call.args[0] for call in copy_resource.await_args_list] == ["groups", "variables", "sources", "routes"]
    assert copy_resource.await_args_list[1].kwargs["group_id"] == "default"
    assert copy_resource.await_args_list[1].kwargs["target_group_id"] == "default"


@pytest.mark.asyncio
async def test_replicate_group_config_rejects_group_level_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    """Group settings copy should reject target ids that differ from the source id."""

    @asynccontextmanager
    async def _source(_server: str) -> AsyncGenerator[SimpleNamespace]:
        yield SimpleNamespace(server_name="source", config=SimpleNamespace(timeout_ms=1000), client=object())

    monkeypatch.setattr(group_sync_module, "connect_to_server", _source)
    monkeypatch.setattr(
        group_sync_module, "_resolve_group_selector", AsyncMock(return_value=SimpleNamespace(group_id="default"))
    )

    with pytest.raises(ValueError, match="different target group id"):
        await group_sync_module.replicate_group_config(
            "source",
            "target",
            product=ProductsCore.STREAM,
            source_group="default",
            target_group="renamed",
        )


@pytest.mark.asyncio
async def test_validate_group_config_reports_per_section_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validation should preserve errors for one content section without hiding the rest."""

    @asynccontextmanager
    async def _source(_server: str) -> AsyncGenerator[SimpleNamespace]:
        yield SimpleNamespace(server_name="source", config=SimpleNamespace(timeout_ms=1000), client=object())

    async def _validate(kind: str, _source: str, _target: str, **_kwargs: object) -> dict[str, object]:
        if kind == "lookups":
            msg = "target lookup endpoint unavailable"
            raise RuntimeError(msg)
        return {"resource_kind": kind, "in_sync": True}

    monkeypatch.setattr(group_sync_module, "connect_to_server", _source)
    monkeypatch.setattr(
        group_sync_module, "_resolve_group_selector", AsyncMock(return_value=SimpleNamespace(group_id="default"))
    )
    monkeypatch.setattr(group_sync_module, "validate_resource_sync", _validate)

    result = await group_sync_module.validate_group_config_sync(
        "source",
        "target",
        product=ProductsCore.STREAM,
        source_group="default",
        content_kinds=["sources", "lookups"],
    )

    assert result["in_sync"] is False
    assert result["content_results"]["sources"]["in_sync"] is True
    assert result["content_results"]["lookups"]["error"]["message"] == "target lookup endpoint unavailable"
