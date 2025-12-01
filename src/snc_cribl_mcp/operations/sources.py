"""Helpers for listing configured sources across products and groups.

This module handles two types of sources:
1. Regular sources from /api/v1/m/{group_id}/system/inputs (via SDK)
2. Collector sources (SavedJobs) from /api/v1/m/{group_id}/lib/jobs (via HTTP)

Collector sources are "Saved Jobs" of type "collection" that pull data from
external systems like S3, REST APIs, databases, etc.
"""

import logging
from typing import Any

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from ..models.collectors import filter_collector_jobs
from .common import (
    CollectionContext,
    HttpCollectionContext,
    ProductResult,
    build_group_entry,
    build_success_result,
    collect_items_via_http,
    collect_items_via_sdk,
)

logger = logging.getLogger("snc_cribl_mcp.operations.sources")

# Endpoint path for collector sources (Saved Jobs)
JOBS_ENDPOINT = "lib/jobs"


async def collect_product_sources(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
    security: Security | None = None,
) -> ProductResult:
    """Fetch all configured sources for all groups of a product.

    This function collects both regular sources (from /system/inputs) and
    collector sources (from /lib/jobs) and merges them into a single result.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.
        security: Security configuration with bearer token (required for collector sources).

    Returns:
        Standard result dictionary with grouped source items. Each group contains
        both regular sources and collector sources (filtered from SavedJobs).

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

    # If security is not provided, return only regular sources
    if security is None:
        await ctx.warning("No security context provided; skipping collector sources.")
        return regular_result

    # Collect collector sources via HTTP, gracefully handling failures
    try:
        collector_result = await _collect_collector_sources(coll_ctx, security)
    except Exception as exc:  # noqa: BLE001 - graceful degradation on collector failure
        await ctx.warning(f"Failed to fetch collector sources: {exc}; returning regular sources only.")
        return regular_result

    # Merge results
    return _merge_source_results(regular_result, collector_result)


async def _collect_collector_sources(
    coll_ctx: CollectionContext,
    security: Security,
) -> ProductResult:
    """Collect collector sources (SavedJobs) for all groups of a product.

    Args:
        coll_ctx: Collection context with client, product, timeout, ctx.
        security: Security configuration with bearer token.

    Returns:
        Standard result dictionary with grouped collector items.

    """
    http_ctx = HttpCollectionContext(
        coll_ctx=CollectionContext(
            client=coll_ctx.client,
            product=coll_ctx.product,
            timeout_ms=coll_ctx.timeout_ms,
            ctx=coll_ctx.ctx,
            resource_type="collector_sources",
        ),
        security=security,
        endpoint_path=JOBS_ENDPOINT,
    )

    result = await collect_items_via_http(http_ctx)

    # Filter jobs to only include collectors (type='collection')
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
        # If regular sources failed, return collector result with error context
        if collector_result.get("status") == "ok":
            return collector_result
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
