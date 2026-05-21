"""Helpers for listing configured variables across products and groups."""

import logging

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from .common import CollectionContext, HttpCollectionContext, ProductResult, collect_items_via_http

logger = logging.getLogger("snc_cribl_mcp.operations.variables")


async def collect_product_variables(
    client: CriblControlPlane,
    security: Security,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> ProductResult:
    """Fetch all configured variables for all groups of a product."""
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="variables",
    )
    http_ctx = HttpCollectionContext(
        coll_ctx=coll_ctx,
        security=security,
        endpoint_path="lib/vars",
    )
    return await collect_items_via_http(http_ctx)


__all__ = ["collect_product_variables"]
