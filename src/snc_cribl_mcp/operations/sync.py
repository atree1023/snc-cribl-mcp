"""Aggregate copy and sync-validation helpers for Cribl leaders."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore

from ..client.cribl_client import ResolvedControlPlane, connect_server_pair
from .common import HTTP_NOT_FOUND
from .resource_actions import (
    ResourceKind,
    append_resource,
    canonicalize_resource_item,
    create_resource,
    get_resource,
    get_resource_spec,
    list_resource,
    update_resource,
)

_MAX_DIFF_PATHS = 25
type JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None


def _resource_item_id(item: dict[str, Any]) -> str | None:
    """Return the canonical item id from a serialized resource."""
    item_id = item.get("id") or item.get("groupId")
    return str(item_id) if item_id is not None else None


def _join_path(prefix: str, suffix: str) -> str:
    """Join nested diff segments into a dotted path."""
    return suffix if not prefix else f"{prefix}.{suffix}"


def _diff_paths(source: JsonValue, target: JsonValue, *, prefix: str = "") -> list[str]:  # noqa: C901
    """Return a bounded list of differing paths between two payloads."""
    if source == target:
        return []

    if isinstance(source, dict) and isinstance(target, dict):
        source_dict = cast("dict[str, JsonValue]", source)
        target_dict = cast("dict[str, JsonValue]", target)
        diffs: list[str] = []
        for key in sorted(set(source_dict) | set(target_dict)):
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
            child = _join_path(prefix, str(key))
            if key not in source_dict or key not in target_dict:
                diffs.append(child)
                continue
            diffs.extend(_diff_paths(source_dict[key], target_dict[key], prefix=child))
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
        return diffs[:_MAX_DIFF_PATHS]

    if isinstance(source, list) and isinstance(target, list):
        source_list = cast("list[JsonValue]", source)
        target_list = cast("list[JsonValue]", target)
        if len(source_list) != len(target_list):
            return [_join_path(prefix, "length")]
        diffs: list[str] = []
        for index, (left, right) in enumerate(zip(source_list, target_list, strict=False)):
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
            diffs.extend(_diff_paths(left, right, prefix=f"{prefix}[{index}]"))
        return diffs[:_MAX_DIFF_PATHS]

    return [prefix or "$"]


def _compare_items(
    kind: ResourceKind,
    item_id: str,
    source_item: dict[str, Any] | None,
    target_item: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare source and target items and return a JSON-friendly diff summary."""
    if source_item is None and target_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_source",
            "differing_paths": [],
        }
    if source_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_source",
            "differing_paths": [],
        }
    if target_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_target",
            "differing_paths": [],
        }

    source_payload = canonicalize_resource_item(kind, source_item)
    target_payload = canonicalize_resource_item(kind, target_item)
    differing_paths = _diff_paths(source_payload, target_payload)
    return {
        "item_id": item_id,
        "status": "in_sync" if not differing_paths else "different",
        "differing_paths": differing_paths,
        "source": source_payload,
        "target": target_payload,
    }


async def _maybe_get_item(
    resolved: ResolvedControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    product: ProductsCore | None = None,
    group_id: str | None = None,
) -> dict[str, Any] | None:
    """Fetch one item and return ``None`` on HTTP 404."""
    try:
        return await get_resource(
            resolved.client,
            kind,
            item_id=item_id,
            timeout_ms=resolved.config.timeout_ms,
            product=product,
            group_id=group_id,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return None
        raise


def _index_items(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index serialized items by id, skipping entries without a stable identifier."""
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = _resource_item_id(item)
        if item_id:
            indexed[item_id] = item
    return indexed


async def validate_resource_sync(  # noqa: PLR0913
    kind: ResourceKind,
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    target_group_id: str | None = None,
    item_id: str | None = None,
) -> dict[str, Any]:
    """Validate whether two leaders are in sync for a resource scope."""
    spec = get_resource_spec(kind)
    effective_target_group = target_group_id or group_id

    async with connect_server_pair(source_server, target_server) as (source, target):
        if item_id is not None:
            source_item = await _maybe_get_item(source, kind, item_id=item_id, product=product, group_id=group_id)
            target_item = await _maybe_get_item(
                target,
                kind,
                item_id=item_id,
                product=product,
                group_id=effective_target_group,
            )
            item_result = _compare_items(kind, item_id, source_item, target_item)
            return {
                "resource_kind": kind,
                "scope": spec.scope,
                "source_server": source.server_name,
                "target_server": target.server_name,
                "product": product.value if product else None,
                "group_id": group_id,
                "target_group_id": effective_target_group,
                "in_sync": item_result["status"] == "in_sync",
                "items": [item_result],
            }

        source_items = await list_resource(
            source.client,
            kind,
            timeout_ms=source.config.timeout_ms,
            product=product,
            group_id=group_id,
        )
        target_items = await list_resource(
            target.client,
            kind,
            timeout_ms=target.config.timeout_ms,
            product=product,
            group_id=effective_target_group,
        )
        source_index = _index_items(source_items)
        target_index = _index_items(target_items)

        results = [
            _compare_items(
                kind,
                compared_id,
                source_index.get(compared_id),
                target_index.get(compared_id),
            )
            for compared_id in sorted(set(source_index) | set(target_index))
        ]

        return {
            "resource_kind": kind,
            "scope": spec.scope,
            "source_server": source.server_name,
            "target_server": target.server_name,
            "product": product.value if product else None,
            "group_id": group_id,
            "target_group_id": effective_target_group,
            "in_sync": all(result["status"] == "in_sync" for result in results),
            "counts": {
                "source": len(source_index),
                "target": len(target_index),
                "in_sync": sum(result["status"] == "in_sync" for result in results),
                "different": sum(result["status"] == "different" for result in results),
                "missing_on_source": sum(result["status"] == "missing_on_source" for result in results),
                "missing_on_target": sum(result["status"] == "missing_on_target" for result in results),
            },
            "items": results,
        }


async def copy_resource_config(  # noqa: PLR0913
    kind: ResourceKind,
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    target_group_id: str | None = None,
    item_id: str | None = None,
    overwrite: bool = True,
    validate_after: bool = True,
    append_routes: bool = False,
) -> dict[str, Any]:
    """Copy one or more configs from a source leader to a target leader."""
    spec = get_resource_spec(kind)
    effective_target_group = target_group_id or group_id

    async with connect_server_pair(source_server, target_server) as (source, target):
        if item_id is not None:
            source_items = {}
            source_item = await get_resource(
                source.client,
                kind,
                item_id=item_id,
                timeout_ms=source.config.timeout_ms,
                product=product,
                group_id=group_id,
            )
            source_items[item_id] = source_item
        else:
            source_items = _index_items(
                await list_resource(
                    source.client,
                    kind,
                    timeout_ms=source.config.timeout_ms,
                    product=product,
                    group_id=group_id,
                )
            )

        item_results: list[dict[str, Any]] = []
        for current_item_id, source_item in source_items.items():
            target_item = await _maybe_get_item(
                target,
                kind,
                item_id=current_item_id,
                product=product,
                group_id=effective_target_group,
            )

            if target_item is None:
                if spec.supports("create"):
                    await create_resource(
                        target.client,
                        kind,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        product=product,
                        group_id=effective_target_group,
                    )
                    action = "created"
                elif kind == "routes" and spec.supports("update"):
                    item_results.append(
                        {
                            "item_id": current_item_id,
                            "action": "unsupported",
                            "reason": "Routes require an existing target route set before they can be updated or appended.",
                        }
                    )
                    continue
                else:
                    item_results.append(
                        {
                            "item_id": current_item_id,
                            "action": "unsupported",
                            "reason": f"Create is not supported for resource kind '{kind}'.",
                        }
                    )
                    continue
            elif not overwrite:
                item_results.append(
                    {
                        "item_id": current_item_id,
                        "action": "skipped",
                        "reason": "Target item already exists and overwrite is disabled.",
                    }
                )
                continue
            elif kind == "routes" and append_routes:
                await append_resource(
                    target.client,
                    kind,
                    item_id=current_item_id,
                    item=source_item,
                    timeout_ms=target.config.timeout_ms,
                    group_id=effective_target_group or "",
                )
                action = "appended"
            else:
                await update_resource(
                    target.client,
                    kind,
                    item_id=current_item_id,
                    item=source_item,
                    timeout_ms=target.config.timeout_ms,
                    product=product,
                    group_id=effective_target_group,
                )
                action = "updated"

            result: dict[str, Any] = {
                "item_id": current_item_id,
                "action": action,
            }
            if validate_after:
                result["validation"] = _compare_items(
                    kind,
                    current_item_id,
                    source_item,
                    await _maybe_get_item(
                        target,
                        kind,
                        item_id=current_item_id,
                        product=product,
                        group_id=effective_target_group,
                    ),
                )
            item_results.append(result)

        return {
            "resource_kind": kind,
            "scope": spec.scope,
            "source_server": source.server_name,
            "target_server": target.server_name,
            "product": product.value if product else None,
            "group_id": group_id,
            "target_group_id": effective_target_group,
            "copied_count": sum(result.get("action") in {"appended", "created", "updated"} for result in item_results),
            "created_count": sum(result.get("action") == "created" for result in item_results),
            "updated_count": sum(result.get("action") == "updated" for result in item_results),
            "appended_count": sum(result.get("action") == "appended" for result in item_results),
            "skipped_count": sum(result.get("action") == "skipped" for result in item_results),
            "unsupported_count": sum(result.get("action") == "unsupported" for result in item_results),
            "items": item_results,
        }


__all__ = [
    "copy_resource_config",
    "validate_resource_sync",
]
