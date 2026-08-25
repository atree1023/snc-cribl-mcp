"""Workflow helpers for replicating whole worker groups and Edge fleets."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal, cast

from cribl_control_plane.models.productscore import ProductsCore

from ..client.cribl_client import connect_to_server
from .resource_actions import ResourceKind
from .sync import _resolve_group_selector, copy_resource_config, validate_resource_sync

type GroupContentKind = Literal[
    "breakers",
    "destinations",
    "lookups",
    "pipelines",
    "routes",
    "sources",
    "variables",
]

DEFAULT_GROUP_CONTENT_KINDS: tuple[GroupContentKind, ...] = (
    "variables",
    "breakers",
    "lookups",
    "destinations",
    "pipelines",
    "sources",
    "routes",
)


def _coerce_content_kinds(kinds: Iterable[str] | None) -> tuple[GroupContentKind, ...]:
    """Validate requested group content kinds."""
    if kinds is None:
        return DEFAULT_GROUP_CONTENT_KINDS
    supported = set(DEFAULT_GROUP_CONTENT_KINDS)
    coerced: list[GroupContentKind] = []
    for kind in kinds:
        normalized = kind.strip()
        if normalized not in supported:
            msg = f"Unsupported group content kind '{kind}'. Supported kinds: {', '.join(DEFAULT_GROUP_CONTENT_KINDS)}."
            raise ValueError(msg)
        coerced.append(normalized)
    return tuple(dict.fromkeys(coerced))


async def _resolve_group_id(server: str, selector: str, product: ProductsCore) -> str:
    """Resolve a group selector on one configured leader."""
    async with connect_to_server(server) as resolved_server:
        resolved = await _resolve_group_selector(resolved_server, selector=selector, product=product)
        return resolved.group_id


async def _resolve_target_group_id(
    target_server: str,
    *,
    target_group: str | None,
    source_group_id: str,
    product: ProductsCore,
) -> str:
    """Resolve the target group id used for group-level compatibility checks."""
    if target_group is None:
        return source_group_id
    return await _resolve_group_id(target_server, target_group, product)


def _group_level_target_supported(source_group_id: str, target_group_id: str) -> bool:
    """Return whether group-level copy can use the existing resource helper."""
    return target_group_id == source_group_id


async def replicate_group_config(
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore,
    source_group: str,
    target_group: str | None = None,
    content_kinds: Iterable[str] | None = None,
    include_group_settings: bool = True,
    overwrite: bool = True,
    validate_after: bool = True,
    append_routes: bool = False,
) -> dict[str, Any]:
    """Replicate a worker group or Edge fleet plus its group-scoped content."""
    source_group_id = await _resolve_group_id(source_server, source_group, product)
    effective_target_group = target_group or source_group_id
    resolved_target_group_id = (
        await _resolve_target_group_id(
            target_server,
            target_group=target_group,
            source_group_id=source_group_id,
            product=product,
        )
        if include_group_settings
        else effective_target_group
    )
    kinds = _coerce_content_kinds(content_kinds)

    group_result: dict[str, Any] | None = None
    if include_group_settings:
        if not _group_level_target_supported(source_group_id, resolved_target_group_id):
            msg = (
                "Copying group-level settings to a different target group id is not supported yet. "
                "Use the same group id or set include_group_settings=false."
            )
            raise ValueError(msg)
        group_result = await copy_resource_config(
            "groups",
            source_server,
            target_server,
            product=product,
            item_id=source_group_id,
            overwrite=overwrite,
            validate_after=validate_after,
        )

    content_results: dict[str, dict[str, Any]] = {}
    for kind in kinds:
        content_results[kind] = await copy_resource_config(
            cast("ResourceKind", kind),
            source_server,
            target_server,
            product=product,
            group_id=source_group_id,
            target_group_id=effective_target_group,
            overwrite=overwrite,
            validate_after=validate_after,
            append_routes=append_routes if kind == "routes" else False,
        )

    return {
        "resource_kind": "group_config",
        "source_server": source_server,
        "target_server": target_server,
        "product": product.value,
        "source_group_selector": source_group,
        "target_group_selector": effective_target_group,
        "group_id": source_group_id,
        "target_group_id": resolved_target_group_id,
        "include_group_settings": include_group_settings,
        "content_kinds": list(kinds),
        "group_result": group_result,
        "content_results": content_results,
        "copied_count": (group_result or {}).get("copied_count", 0)
        + sum(result.get("copied_count", 0) for result in content_results.values()),
        "failed_count": (group_result or {}).get("failed_count", 0)
        + sum(result.get("failed_count", 0) for result in content_results.values()),
        "skipped_count": (group_result or {}).get("skipped_count", 0)
        + sum(result.get("skipped_count", 0) for result in content_results.values()),
        "unsupported_count": (group_result or {}).get("unsupported_count", 0)
        + sum(result.get("unsupported_count", 0) for result in content_results.values()),
    }


async def validate_group_config_sync(
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore,
    source_group: str,
    target_group: str | None = None,
    content_kinds: Iterable[str] | None = None,
    include_group_settings: bool = True,
    include_payloads: bool = False,
) -> dict[str, Any]:
    """Validate a whole worker group or Edge fleet across leaders."""
    source_group_id = await _resolve_group_id(source_server, source_group, product)
    effective_target_group = target_group or source_group_id
    resolved_target_group_id = (
        await _resolve_target_group_id(
            target_server,
            target_group=target_group,
            source_group_id=source_group_id,
            product=product,
        )
        if include_group_settings
        else effective_target_group
    )
    kinds = _coerce_content_kinds(content_kinds)

    group_result: dict[str, Any] | None = None
    if include_group_settings:
        if not _group_level_target_supported(source_group_id, resolved_target_group_id):
            group_result = {
                "in_sync": False,
                "error": "Group-level validation to a different target group id is not supported yet.",
            }
        else:
            group_result = await validate_resource_sync(
                "groups",
                source_server,
                target_server,
                product=product,
                item_id=source_group_id,
                include_payloads=include_payloads,
            )

    content_results: dict[str, dict[str, Any]] = {}
    for kind in kinds:
        try:
            content_results[kind] = await validate_resource_sync(
                cast("ResourceKind", kind),
                source_server,
                target_server,
                product=product,
                group_id=source_group_id,
                target_group_id=effective_target_group,
                include_payloads=include_payloads,
            )
        except Exception as exc:  # noqa: BLE001 - report per-section validation failures
            content_results[kind] = {
                "resource_kind": kind,
                "scope": "group",
                "source_server": source_server,
                "target_server": target_server,
                "product": product.value,
                "group_id": source_group_id,
                "target_group_id": effective_target_group,
                "in_sync": False,
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            }

    sections = list(([group_result] if group_result is not None else []) + list(content_results.values()))
    return {
        "resource_kind": "group_config",
        "source_server": source_server,
        "target_server": target_server,
        "product": product.value,
        "source_group_selector": source_group,
        "target_group_selector": effective_target_group,
        "group_id": source_group_id,
        "target_group_id": resolved_target_group_id,
        "include_group_settings": include_group_settings,
        "content_kinds": list(kinds),
        "in_sync": all(result.get("in_sync") is True for result in sections),
        "group_result": group_result,
        "content_results": content_results,
    }


__all__ = [
    "DEFAULT_GROUP_CONTENT_KINDS",
    "GroupContentKind",
    "replicate_group_config",
    "validate_group_config_sync",
]
