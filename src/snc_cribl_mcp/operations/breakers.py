"""Helpers for listing configured event breakers across products and groups."""

import logging

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from .common import (
    CollectionContext,
    HttpCollectionContext,
    ProductResult,
    collect_items_via_http,
)

logger = logging.getLogger("snc_cribl_mcp.operations.breakers")


async def collect_product_breakers(
    client: CriblControlPlane,
    security: Security,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> ProductResult:
    """Fetch all configured event breakers for all groups of a product.

    Unlike pipelines, destinations, and routes (which use SDK methods scoped to a
    group/product), breakers do not have a corresponding SDK method. Therefore, this
    function performs direct HTTP requests to the `/m/{group_id}/lib/breakers` endpoint.

    Args:
        client: The Cribl Control Plane client.
        security: Security configuration with bearer token.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.

    Returns:
        Standard result dictionary with grouped event breaker items.

    """
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="breakers",
    )
    http_ctx = HttpCollectionContext(
        coll_ctx=coll_ctx,
        security=security,
        endpoint_path="lib/breakers",
    )
    return await collect_items_via_http(http_ctx)


__all__ = ["collect_product_breakers"]
