"""Helpers for listing configured sources across products and groups.

This module handles two types of sources:
1. Regular sources from `/api/v1/m/{group_id}/system/inputs` (via SDK)
2. Collector sources from `/api/v1/m/{group_id}/lib/jobs` (via SDK 0.6.0+)

Collector sources are saved jobs of type ``collection`` that pull data from
external systems like S3, REST APIs, databases, and other upstreams.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Any, cast

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from ..models.collectors import filter_collector_jobs
from .common import (
    CollectionContext,
    ProductResult,
    build_group_entry,
    build_success_result,
    collect_items_via_sdk,
)

logger = logging.getLogger("snc_cribl_mcp.operations.sources")

type CollectorListMethod = Callable[..., Awaitable[Any]]


class UnsupportedCollectorsSdkError(RuntimeError):
    """Raised when the installed SDK lacks collector listing support."""


async def collect_product_sources(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> ProductResult:
    """Fetch all configured sources for all groups of a product.

    This function collects both regular sources (from /system/inputs) and
    collector sources (from /lib/jobs) and merges them into a single result.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.

    Returns:
        Standard result dictionary with grouped source items. Each group contains
        both regular sources and collector sources.

    """
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="sources",
    )

    # Collect regular sources via SDK
    regular_result = await collect_items_via_sdk(coll_ctx, client.sources.list_async)

    collector_list_method = _require_collectors_list_method(client)

    # Collect collector sources via SDK, gracefully handling failures
    try:
        collector_result = await _collect_collector_sources(
            coll_ctx,
            collector_list_method=collector_list_method,
        )
    except Exception as exc:  # noqa: BLE001 - graceful degradation on collector failure
        await ctx.warning(f"Failed to fetch collector sources: {exc}; returning regular sources only.")
        return regular_result

    # Merge results
    return _merge_source_results(regular_result, collector_result)


async def _collect_collector_sources(
    coll_ctx: CollectionContext,
    *,
    collector_list_method: CollectorListMethod,
) -> ProductResult:
    """Collect collector sources for all groups of a product via the SDK.

    Args:
        coll_ctx: Collection context with client, product, timeout, ctx.
        collector_list_method: Group-scoped SDK method used to list collector jobs.

    Returns:
        Standard result dictionary with grouped collector items.

    """
    collector_ctx = CollectionContext(
        client=coll_ctx.client,
        product=coll_ctx.product,
        timeout_ms=coll_ctx.timeout_ms,
        ctx=coll_ctx.ctx,
        resource_type="collector_sources",
    )

    result = await collect_items_via_sdk(collector_ctx, collector_list_method)

    # Keep only collector jobs in case the upstream endpoint includes non-collector saved jobs.
    if result.get("status") == "ok" and "groups" in result:
        filtered_groups: list[dict[str, Any]] = []
        for group in result["groups"]:
            items = group.get("items", [])
            collector_items = filter_collector_jobs(items)
            filtered_groups.append(
                build_group_entry(
                    group["group_id"],
                    collector_items,
                    reported_count=len(collector_items),
                )
            )
        result["groups"] = filtered_groups
        result["total_count"] = sum(g.get("count", 0) for g in filtered_groups)

    return result


def _require_collectors_list_method(client: CriblControlPlane) -> CollectorListMethod:
    """Return the collector list method or fail fast on unsupported SDK versions."""
    collectors = getattr(client, "collectors", None)
    list_async = getattr(collectors, "list_async", None)
    if not callable(list_async):
        msg = (
            "Installed cribl-control-plane SDK does not expose client.collectors.list_async. "
            "snc_cribl_mcp requires cribl-control-plane>=0.6.0."
        )
        raise UnsupportedCollectorsSdkError(msg)
    return cast("CollectorListMethod", list_async)


def _merge_source_results(
    regular_result: ProductResult,
    collector_result: ProductResult,
) -> ProductResult:
    """Merge regular sources and collector sources into a single result.

    Args:
        regular_result: Result from regular sources collection.
        collector_result: Result from collector sources collection.

    Returns:
        Merged result with both regular and collector sources per group.

    """
    # Handle edge cases where one result failed
    if regular_result.get("status") != "ok":
        # Regular source failures must remain visible; collectors are only supplementary.
        return regular_result

    if collector_result.get("status") != "ok":
        # If collectors failed, return regular sources only
        return regular_result

    # Build a map of group_id -> items for collector sources
    collector_by_group: dict[str, list[dict[str, Any]]] = {}
    for group in collector_result.get("groups", []):
        group_id = group.get("group_id")
        if group_id:
            collector_by_group[group_id] = group.get("items", [])

    # Merge collector sources into regular source groups
    merged_groups: list[dict[str, Any]] = []
    seen_group_ids: set[str] = set()

    for group in regular_result.get("groups", []):
        group_id = group.get("group_id")
        seen_group_ids.add(group_id)

        regular_items = group.get("items", [])
        collector_items = collector_by_group.get(group_id, [])

        # Combine items and update count
        combined_items = regular_items + collector_items
        merged_groups.append(
            build_group_entry(
                group_id,
                combined_items,
                reported_count=len(combined_items),
            )
        )

    # Add any groups that only have collector sources (shouldn't normally happen)
    for group_id, items in collector_by_group.items():
        if group_id not in seen_group_ids:
            merged_groups.append(build_group_entry(group_id, items, reported_count=len(items)))

    return build_success_result([], is_grouped=True, groups=merged_groups)


__all__ = ["collect_product_sources"]
