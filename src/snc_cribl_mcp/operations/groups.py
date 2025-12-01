"""Helpers for working with groups across Cribl products."""

import logging
from typing import Any

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.configgroup import ConfigGroup
from cribl_control_plane.models.listconfiggroupbyproductop import (
    ListConfigGroupByProductResponse,
)
from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context
from pydantic import ValidationError

from .common import HTTP_NOT_FOUND
from .validation_errors import (
    format_validation_error_response,
    parse_validation_error,
)

logger = logging.getLogger("snc_cribl_mcp.operations.groups")


def serialize_config_group(group: ConfigGroup) -> dict[str, Any]:
    """Convert a ConfigGroup object into JSON-serialisable data."""
    return group.model_dump(mode="json", exclude_none=True)


async def collect_product_groups(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> dict[str, Any]:
    """Fetch groups for a specific Cribl product and shape the response.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.
        ctx: FastMCP context for logging.

    Returns:
        Dictionary with status, count, and items.

    """
    try:
        response: ListConfigGroupByProductResponse = await client.groups.list_async(
            product=product,
            timeout_ms=timeout_ms,
        )
    except ResponseValidationError as exc:
        # Handle Pydantic validation errors from SDK
        await ctx.error(f"SDK validation error for groups in {product.value}: {exc}")
        cause = exc.cause
        body = exc.body if hasattr(exc, "body") else None
        validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []
        return format_validation_error_response(
            resource_type="groups",
            product=product.value,
            group_id="(listing groups)",
            body=body,
            validation_errors=validation_errors,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            message = f"Cribl product '{product.value}' is unavailable; returning an empty list."
            await ctx.warning(message)
            logger.info(message)
            return {
                "status": "unavailable",
                "count": 0,
                "items": [],
                "message": "Endpoint returned HTTP 404 (Not Found).",
            }
        msg = f"Cribl API error while listing {product.value} groups: {exc}"
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while listing {product.value} groups: {exc}"
        raise RuntimeError(msg) from exc

    items = [serialize_config_group(item) for item in response.items or []]
    result: dict[str, Any] = {
        "status": "ok",
        "count": len(items),
        "items": items,
    }
    if response.count is not None:
        result["reported_count"] = response.count
    return result


__all__ = ["HTTP_NOT_FOUND", "collect_product_groups", "serialize_config_group"]
