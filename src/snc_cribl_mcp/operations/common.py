"""Common utilities for Cribl operations modules.

This module contains shared functions and constants used across all operations
modules (groups, sources, destinations, pipelines, routes, breakers, lookups).

Collection Strategies:
    - SDK Collection (collect_items_via_sdk): Use for resources with SDK methods
      like sources, destinations, pipelines, and routes. The SDK handles
      request building, authentication, and response parsing.
    - HTTP Collection (collect_items_via_http): Use for resources without SDK
      methods like breakers and lookups. Requires direct HTTP calls with manual
      authentication header management.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol, cast

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context
from pydantic import ValidationError

from .validation_errors import (
    SDKValidationError,
    format_validation_error_response,
    parse_validation_error,
)

logger = logging.getLogger("snc_cribl_mcp.operations.common")

# HTTP status codes
HTTP_NOT_FOUND = 404

# Type aliases using Python 3.12+ syntax
type GroupEntry = dict[str, Any]
type ProductResult = dict[str, Any]
# CollectorFunc is used by tools/common.py for collector function signatures
type CollectorFunc = Callable[..., Awaitable[dict[str, Any]]]


class HasItemsCount(Protocol):
    """Protocol for SDK list responses exposing optional 'items' and 'count'.

    Used to type-hint SDK list method return values. The actual SDK response
    types have `items` as specific model types, but we access them via getattr
    to avoid tight coupling to specific SDK versions.

    This protocol documents the expected response shape rather than enforcing
    strict typing, since SDK methods return various concrete types.
    """

    @property
    def items(self) -> list[object] | None:
        """List of items in the response."""
        ...

    @property
    def count(self) -> int | None:
        """Total count of items."""
        ...


@dataclass(frozen=True, slots=True)
class CollectionContext:
    """Context for collecting items from Cribl API.

    Groups related parameters to reduce function argument counts.
    """

    client: CriblControlPlane
    product: ProductsCore
    timeout_ms: int
    ctx: Context
    resource_type: str


def serialize_model(obj: object) -> dict[str, Any]:
    """Serialize a Pydantic model to JSON-compatible dict, excluding Nones.

    Args:
        obj: A Pydantic model instance with a `model_dump` method.

    Returns:
        JSON-serializable dictionary representation of the model.
        Returns empty dict if serialization fails.

    """
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        try:
            return model_dump(mode="json", exclude_none=True)  # type: ignore[call-arg]
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Failed to serialize model %s: %s",
                type(obj).__name__,
                exc,
            )
            return {}
    return {}


async def list_groups_minimal(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
) -> list[dict[str, Any]]:
    """Return minimal group info for a given product.

    Args:
        client: The Cribl Control Plane client.
        product: The product type (Stream or Edge).
        timeout_ms: Request timeout in milliseconds.

    Returns:
        List of serialized group dictionaries with minimal info.

    """
    resp = await client.groups.list_async(product=product, timeout_ms=timeout_ms)
    return [serialize_model(item) for item in resp.items or []]


def build_unavailable_result(*, is_grouped: bool = True) -> ProductResult:
    """Build a standard unavailable result response.

    Args:
        is_grouped: Whether the result contains per-group items.

    Returns:
        Standard unavailable result dictionary.

    """
    result: ProductResult = {
        "status": "unavailable",
        "message": "Endpoint returned HTTP 404 (Not Found).",
    }
    if is_grouped:
        result["total_count"] = 0
        result["groups"] = []
    else:
        result["count"] = 0
        result["items"] = []
    return result


def build_success_result(
    items: list[dict[str, Any]],
    *,
    reported_count: int | None = None,
    is_grouped: bool = True,
    groups: list[GroupEntry] | None = None,
) -> ProductResult:
    """Build a standard success result response.

    Args:
        items: List of serialized items (only used when is_grouped=False).
        reported_count: The count reported by the API, if any.
        is_grouped: Whether the result contains per-group items.
        groups: List of group entries (only used when is_grouped=True).

    Returns:
        Standard success result dictionary.

    """
    result: ProductResult = {"status": "ok"}
    if is_grouped and groups is not None:
        total = sum(g.get("count", 0) for g in groups)
        result["total_count"] = total
        result["groups"] = groups
    else:
        result["count"] = len(items)
        result["items"] = items
        if reported_count is not None:
            result["reported_count"] = reported_count
    return result


def build_group_entry(
    group_id: str,
    items: list[dict[str, Any]],
    *,
    reported_count: int | None = None,
) -> GroupEntry:
    """Build a standard group entry for grouped results.

    Args:
        group_id: The group identifier.
        items: List of serialized items for this group.
        reported_count: The count reported by the API, if any.

    Returns:
        Standard group entry dictionary.

    """
    entry: GroupEntry = {
        "group_id": group_id,
        "count": len(items),
        "items": items,
    }
    if reported_count is not None:
        entry["reported_count"] = reported_count
    return entry


def extract_group_id(group: dict[str, Any]) -> str | None:
    """Extract group ID from a group dictionary.

    Args:
        group: A serialized group dictionary.

    Returns:
        The group ID or None if not found.

    """
    return group.get("id") or group.get("groupId")


async def handle_product_unavailable(
    ctx: Context,
    product: ProductsCore,
    resource_type: str,
) -> ProductResult:
    """Handle HTTP 404 for unavailable products.

    Args:
        ctx: FastMCP context for logging.
        product: The product type that was unavailable.
        resource_type: Human-readable name of the resource type.

    Returns:
        Standard unavailable result dictionary.

    """
    message = f"Cribl product '{product.value}' is unavailable; returning empty {resource_type}."
    await ctx.warning(message)
    logger.info(message)
    return build_unavailable_result()


def get_group_url(client: CriblControlPlane, group_id: str) -> str:
    """Build the group-scoped URL for API requests.

    Trailing slashes are stripped from the base URL to prevent double slashes
    in the resulting URL (e.g., "https://host/api/v1//m/group").

    Args:
        client: The Cribl Control Plane client.
        group_id: The group identifier.

    Returns:
        The group-scoped URL.

    Raises:
        ValueError: If the client's server_url is not configured.

    """
    server_url = client.sdk_configuration.server_url
    if not server_url:
        msg = "Client server_url is not configured"
        raise ValueError(msg)
    base_url: str = server_url.rstrip("/")
    return f"{base_url}/m/{group_id}"


def get_auth_headers(security: Security) -> dict[str, str]:
    """Build authorization headers from security configuration.

    Args:
        security: The security configuration with bearer token.

    Returns:
        Headers dictionary with Authorization if token present.

    """
    headers: dict[str, str] = {}
    if security.bearer_auth:
        headers["Authorization"] = f"Bearer {security.bearer_auth}"
    return headers


async def collect_items_via_sdk(
    coll_ctx: CollectionContext,
    list_method: Callable[..., Awaitable[Any]],
) -> ProductResult:
    """Generic collector for resources accessible via SDK methods.

    This function handles the common pattern of:
    1. Listing groups for a product
    2. Iterating over groups and calling an SDK method for each (in parallel)
    3. Building the result with proper error handling

    Args:
        coll_ctx: Collection context with client, product, timeout, ctx, and resource_type.
        list_method: SDK method to call for each group (e.g., client.sources.list_async).
            The method should return an object with optional `items` and `count` attributes.

    Returns:
        Standard result dictionary with grouped items.

    """
    try:
        groups = await list_groups_minimal(
            coll_ctx.client,
            product=coll_ctx.product,
            timeout_ms=coll_ctx.timeout_ms,
        )
    except ResponseValidationError as exc:
        # Handle Pydantic validation errors when listing groups
        await coll_ctx.ctx.error(f"SDK validation error listing {coll_ctx.product.value} groups: {exc}")
        cause = exc.cause
        body = exc.body if hasattr(exc, "body") else None
        validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []
        return format_validation_error_response(
            resource_type="groups",
            product=coll_ctx.product.value,
            group_id="(listing groups)",
            body=body,
            validation_errors=validation_errors,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return await handle_product_unavailable(
                coll_ctx.ctx,
                coll_ctx.product,
                coll_ctx.resource_type,
            )
        msg = f"Cribl API error while listing {coll_ctx.product.value} groups for {coll_ctx.resource_type}: {exc}"
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while listing {coll_ctx.product.value} groups: {exc}"
        raise RuntimeError(msg) from exc

    # Filter groups with valid IDs and fetch items in parallel
    valid_groups = [(group, extract_group_id(group)) for group in groups]
    valid_groups = [(group, gid) for group, gid in valid_groups if gid]

    if not valid_groups:
        return build_success_result([], is_grouped=True, groups=[])

    tasks = [
        _collect_group_items_sdk(
            coll_ctx=coll_ctx,
            group_id=group_id,
            list_method=list_method,
        )
        for _, group_id in valid_groups
    ]

    try:
        group_results: list[GroupEntry] = list(await asyncio.gather(*tasks))
    except SDKValidationError as exc:
        # Return validation error response without partial results
        return exc.error_response

    return build_success_result([], is_grouped=True, groups=group_results)


def _handle_response_validation_error(
    *,
    exc: ResponseValidationError,
    resource_type: str,
    product: str,
    group_id: str,
) -> NoReturn:
    """Handle a ResponseValidationError by raising SDKValidationError.

    Extracts validation error details from the SDK exception and formats them
    into a user-friendly error response.

    Args:
        exc: The ResponseValidationError from the SDK.
        resource_type: The type of resource being fetched (e.g., "sources").
        product: The product name (e.g., "stream", "edge").
        group_id: The group ID where the error occurred.

    Raises:
        SDKValidationError: Always raised with formatted error details.

    """
    cause = exc.cause
    body = exc.body if hasattr(exc, "body") else None

    # Parse validation errors from Pydantic, or use empty list for unexpected cause types
    validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []

    error_response = format_validation_error_response(
        resource_type=resource_type,
        product=product,
        group_id=group_id,
        body=body,
        validation_errors=validation_errors,
    )
    raise SDKValidationError(error_response) from exc


async def _collect_group_items_sdk(
    *,
    coll_ctx: CollectionContext,
    group_id: str,
    list_method: Callable[..., Awaitable[Any]],
) -> GroupEntry:
    """Collect items for a single group via SDK method.

    Args:
        coll_ctx: Collection context with client, product, timeout, ctx, and resource_type.
        group_id: The group identifier to collect items for.
        list_method: SDK method to call (e.g., client.sources.list_async).

    Returns:
        Group entry dictionary with group_id, count, and items.

    Raises:
        SDKValidationError: When the SDK cannot validate the API response.
        RuntimeError: On API or network errors (except 404, which returns empty).

    """
    try:
        group_url = get_group_url(coll_ctx.client, group_id)
        resp = await list_method(
            server_url=group_url,
            timeout_ms=coll_ctx.timeout_ms,
        )
    except ResponseValidationError as exc:
        # Handle Pydantic validation errors from SDK
        await coll_ctx.ctx.error(
            f"SDK validation error for {coll_ctx.resource_type} in {coll_ctx.product.value} group '{group_id}': {exc}"
        )
        _handle_response_validation_error(
            exc=exc,
            resource_type=coll_ctx.resource_type,
            product=coll_ctx.product.value,
            group_id=group_id,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            await coll_ctx.ctx.warning(
                f"{coll_ctx.resource_type.capitalize()} endpoint 404 for "
                f"{coll_ctx.product.value} group '{group_id}'; skipping.",
            )
            return build_group_entry(group_id, [])
        msg = f"Cribl API error while listing {coll_ctx.resource_type} for {coll_ctx.product.value} group '{group_id}': {exc}"
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while listing {coll_ctx.resource_type} for {coll_ctx.product.value} group '{group_id}': {exc}"
        raise RuntimeError(msg) from exc

    raw_items: list[object] = getattr(resp, "items", None) or []
    items = [serialize_model(item) for item in raw_items]
    reported = getattr(resp, "count", None)
    return build_group_entry(group_id, items, reported_count=reported)


@dataclass(frozen=True, slots=True)
class HttpCollectionContext:
    """Context for collecting items via direct HTTP requests.

    Extends CollectionContext with HTTP-specific parameters.
    """

    coll_ctx: CollectionContext
    security: Security
    endpoint_path: str


async def collect_items_via_http(http_ctx: HttpCollectionContext) -> ProductResult:
    """Generic collector for resources requiring direct HTTP calls.

    This function handles resources like breakers and lookups that don't have
    SDK methods and require direct HTTP requests. Groups are fetched in parallel.

    Note: Trailing slashes are stripped from the base URL to prevent double
    slashes in endpoint URLs.

    Args:
        http_ctx: HTTP collection context with security and endpoint path.

    Returns:
        Standard result dictionary with grouped items.

    Raises:
        ValueError: If the client's server_url is not configured.

    """
    coll_ctx = http_ctx.coll_ctx
    try:
        groups = await list_groups_minimal(
            coll_ctx.client,
            product=coll_ctx.product,
            timeout_ms=coll_ctx.timeout_ms,
        )
    except ResponseValidationError as exc:
        # Handle Pydantic validation errors when listing groups
        await coll_ctx.ctx.error(f"SDK validation error listing {coll_ctx.product.value} groups: {exc}")
        cause = exc.cause
        body = exc.body if hasattr(exc, "body") else None
        validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []
        return format_validation_error_response(
            resource_type="groups",
            product=coll_ctx.product.value,
            group_id="(listing groups)",
            body=body,
            validation_errors=validation_errors,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return await handle_product_unavailable(
                coll_ctx.ctx,
                coll_ctx.product,
                coll_ctx.resource_type,
            )
        msg = f"Cribl API error while listing {coll_ctx.product.value} groups for {coll_ctx.resource_type}: {exc}"
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while listing {coll_ctx.product.value} groups: {exc}"
        raise RuntimeError(msg) from exc

    # The SDK types async_client as AsyncHttpClient (Protocol) | None, but at runtime
    # it's always an httpx.AsyncClient instance. We need the concrete type to use .get().
    http_client = cast("httpx.AsyncClient", coll_ctx.client.sdk_configuration.async_client)
    server_url = coll_ctx.client.sdk_configuration.server_url
    if not server_url:
        msg = "Client server_url is not configured"
        raise ValueError(msg)
    base_url = server_url.rstrip("/")
    headers = get_auth_headers(http_ctx.security)

    # Filter groups with valid IDs and fetch items in parallel
    valid_groups = [(group, extract_group_id(group)) for group in groups]
    valid_groups = [(group, gid) for group, gid in valid_groups if gid]

    if not valid_groups:
        return build_success_result([], is_grouped=True, groups=[])

    tasks = [
        _collect_group_items_http(
            http_client=http_client,
            base_url=base_url,
            headers=headers,
            group_id=group_id,
            coll_ctx=coll_ctx,
            endpoint_path=http_ctx.endpoint_path,
        )
        for _, group_id in valid_groups
    ]
    group_results: list[GroupEntry] = list(await asyncio.gather(*tasks))

    return build_success_result([], is_grouped=True, groups=group_results)


async def _collect_group_items_http(  # noqa: PLR0913 (unavoidable for HTTP context)
    *,
    http_client: httpx.AsyncClient,
    base_url: str,
    headers: dict[str, str],
    group_id: str,
    coll_ctx: CollectionContext,
    endpoint_path: str,
) -> GroupEntry:
    """Collect items for a single group via direct HTTP request.

    Args:
        http_client: The httpx async client for making requests.
        base_url: Base URL of the Cribl API (trailing slashes should be stripped).
        headers: Authorization headers.
        group_id: The group identifier to collect items for.
        coll_ctx: Collection context with product, timeout, ctx, and resource_type.
        endpoint_path: API endpoint path (e.g., "lib/breakers").

    Returns:
        Group entry dictionary with group_id, count, and items.

    Raises:
        RuntimeError: On network errors or invalid JSON response (except 404, which returns empty).

    """
    url = f"{base_url}/m/{group_id}/{endpoint_path}"

    try:
        resp = await http_client.get(
            url,
            headers=headers,
            timeout=coll_ctx.timeout_ms / 1000,
        )

        if resp.status_code == HTTP_NOT_FOUND:
            await coll_ctx.ctx.warning(
                f"{coll_ctx.resource_type.capitalize()} endpoint 404 for "
                f"{coll_ctx.product.value} group '{group_id}'; skipping.",
            )
            return build_group_entry(group_id, [])

        resp.raise_for_status()

    except httpx.HTTPError as exc:
        msg = f"Network error while listing {coll_ctx.resource_type} for {coll_ctx.product.value} group '{group_id}': {exc}"
        raise RuntimeError(msg) from exc

    try:
        data = resp.json()
    except ValueError as exc:
        msg = f"Invalid JSON response from {coll_ctx.resource_type} endpoint for group '{group_id}': {exc}"
        raise RuntimeError(msg) from exc

    items: list[dict[str, Any]] = data.get("items", [])
    reported = data.get("count")
    return build_group_entry(group_id, items, reported_count=reported)


__all__ = [
    "HTTP_NOT_FOUND",
    "CollectionContext",
    "CollectorFunc",
    "GroupEntry",
    "HasItemsCount",
    "HttpCollectionContext",
    "ProductResult",
    "SDKValidationError",
    "build_group_entry",
    "build_success_result",
    "build_unavailable_result",
    "collect_items_via_http",
    "collect_items_via_sdk",
    "extract_group_id",
    "get_auth_headers",
    "get_group_url",
    "handle_product_unavailable",
    "list_groups_minimal",
    "serialize_model",
]
