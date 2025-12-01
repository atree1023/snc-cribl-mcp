"""Helpers for listing configured routes across products and groups."""

import logging

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context

from .common import CollectionContext, ProductResult, collect_items_via_sdk

logger = logging.getLogger("snc_cribl_mcp.operations.routes")


async def collect_product_routes(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> ProductResult:
    """Fetch all configured routes for all groups of a product.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.

    Returns:
        Standard result dictionary with grouped route items.

    """
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="routes",
    )
    return await collect_items_via_sdk(coll_ctx, client.routes.list_async)


__all__ = ["collect_product_routes"]
