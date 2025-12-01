"""Helpers for listing configured pipelines across products and groups.

This module uses direct HTTP requests instead of SDK methods to preserve
complete function configuration data. The SDK's FunctionSpecificConfigs class
is empty, causing function `conf` objects to serialize as `{}`.

By using HTTP collection (like breakers and lookups), we get raw JSON that
preserves all configuration details for each pipeline function.
"""

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

logger = logging.getLogger("snc_cribl_mcp.operations.pipelines")


async def collect_product_pipelines(
    client: CriblControlPlane,
    security: Security,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> ProductResult:
    """Fetch all configured pipelines for all groups of a product.

    This function uses direct HTTP requests to the `/m/{group_id}/pipelines`
    endpoint to preserve complete function configuration data. The SDK's
    PipelineFunctionConf.conf field uses an empty FunctionSpecificConfigs class,
    which would serialize as `{}` and lose all function-specific settings.

    Args:
        client: The Cribl Control Plane client.
        security: Security configuration with bearer token.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.

    Returns:
        Standard result dictionary with grouped pipeline items, including
        complete function configurations.

    """
    coll_ctx = CollectionContext(
        client=client,
        product=product,
        timeout_ms=timeout_ms,
        ctx=ctx,
        resource_type="pipelines",
    )
    http_ctx = HttpCollectionContext(
        coll_ctx=coll_ctx,
        security=security,
        endpoint_path="pipelines",
    )
    return await collect_items_via_http(http_ctx)


__all__ = ["collect_product_pipelines"]
