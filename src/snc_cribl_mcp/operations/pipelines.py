"""Helpers for listing configured pipelines across products and groups."""

import logging
from functools import partial

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from .common import (
    CollectionContext,
    ProductResult,
    collect_items_via_sdk,
)

logger = logging.getLogger("snc_cribl_mcp.operations.pipelines")


async def collect_product_pipelines(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
    pipeline_id: str | None = None,
) -> ProductResult:
    """Fetch pipelines for all groups of a product, optionally filtered by pipeline ID.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.
        pipeline_id: Optional pipeline identifier to fetch a single pipeline per group.

    Returns:
        Standard result dictionary with grouped pipeline items.

    """
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="pipelines",
    )
    if pipeline_id:
        list_method = partial(client.pipelines.get_async, id=pipeline_id)
        return await collect_items_via_sdk(coll_ctx, list_method)
    return await collect_items_via_sdk(coll_ctx, client.pipelines.list_async)


__all__ = ["collect_product_pipelines"]
