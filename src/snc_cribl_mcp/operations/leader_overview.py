"""Build a compact operational overview for a configured Cribl leader."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, HealthServerStatusError, ResponseValidationError
from cribl_control_plane.models.productsbase import ProductsBase
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context
from pydantic import ValidationError

from ..config import CriblConfig
from .common import HTTP_NOT_FOUND, extract_group_id, get_auth_headers, get_group_url, serialize_model
from .groups import collect_product_groups
from .validation_errors import format_validation_error_response, parse_validation_error

logger = logging.getLogger("snc_cribl_mcp.operations.leader_overview")

STATUS_PAGE_LIMIT = 500
SYSTEM_INFO_TOP_FIELDS = ("version", "cribl_version", "criblVersion", "build", "distMode", "hostname", "guid")
SYSTEM_INFO_NODE_FIELDS = ("hostname", "node", "platform", "release", "architecture")
SYSTEM_INFO_CRIBL_FIELDS = ("version", "distMode", "guid", "group", "startTime", "installType")
VERSION_FIELDS = ("cribl_version", "criblVersion", "version")

type StatusListMethod = Callable[..., Awaitable[object | None]]


@dataclass(frozen=True, slots=True)
class ProductOverviewContext:
    """Shared context for product-level overview collection."""

    client: CriblControlPlane
    product: ProductsCore
    timeout_ms: int
    ctx: Context


def _error_result(message: str, *, status_code: int | None = None) -> dict[str, Any]:
    """Return a compact error result for a non-critical overview subsection."""
    result: dict[str, Any] = {"status": "error", "message": message}
    if status_code is not None:
        result["status_code"] = status_code
    return result


def _unavailable_result(message: str) -> dict[str, Any]:
    """Return a compact unavailable result."""
    return {"status": "unavailable", "message": message}


def _as_int(value: object) -> int | None:
    """Return an integer when the value is numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return None


def _as_str(value: object) -> str | None:
    """Return a non-empty string value."""
    if isinstance(value, str) and value:
        return value
    return None


def _serialize_item(item: object) -> dict[str, Any]:
    """Serialize an SDK model or raw dict."""
    raw_dict = _as_dict(item)
    if raw_dict is not None:
        return raw_dict
    return serialize_model(item)


def _as_dict(value: object) -> dict[str, Any] | None:
    """Return a string-keyed dictionary when the value is a JSON object."""
    if isinstance(value, dict):
        return cast("dict[str, Any]", value)
    return None


async def _collect_paginated_items(response: object | None) -> tuple[list[dict[str, Any]], int | None]:
    """Collect items from an SDK response that may expose a paginated wrapper."""
    items: list[dict[str, Any]] = []
    reported_count: int | None = None
    current = response

    while current is not None:
        counted = getattr(current, "result", current)
        if reported_count is None:
            reported = getattr(counted, "count", None)
            reported_count = reported if isinstance(reported, int) else None

        raw_items = getattr(counted, "items", None)
        if isinstance(raw_items, list | tuple):
            typed_items = cast("list[object] | tuple[object, ...]", raw_items)
            items.extend(_serialize_item(item) for item in typed_items)

        next_func = getattr(current, "next", None)
        if not callable(next_func):
            break

        maybe_next = next_func()
        if inspect.isawaitable(maybe_next):
            current = await cast("Awaitable[object | None]", maybe_next)
        else:
            current = cast("object | None", maybe_next)

    return items, reported_count


def _status_validation_error(
    *,
    exc: ResponseValidationError,
    resource_type: str,
    product: ProductsCore,
    group_id: str,
) -> dict[str, Any]:
    """Convert SDK validation errors into the repo's standard response shape."""
    cause = exc.cause
    body = exc.body if hasattr(exc, "body") else None
    validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []
    return format_validation_error_response(
        resource_type=resource_type,
        product=product.value,
        group_id=group_id,
        body=body,
        validation_errors=validation_errors,
    )


def _compact_runtime_status(item: dict[str, Any]) -> dict[str, Any]:
    """Return a compact Source/Destination runtime status item."""
    status_body = _as_dict(item.get("status")) or {}

    compact: dict[str, Any] = {}
    for key in ("id", "type"):
        value = item.get(key)
        if value is not None:
            compact[key] = value

    for source_key, target_key in (
        ("health", "health"),
        ("healthCounts", "health_counts"),
        ("timestamp", "timestamp"),
        ("error", "error"),
        ("pq", "pq"),
    ):
        value = status_body.get(source_key)
        if value is not None:
            compact[target_key] = value

    return compact


def _runtime_status_response(items: list[dict[str, Any]], reported_count: int | None) -> dict[str, Any]:
    """Build a compact status summary for Source/Destination runtime statuses."""
    compact_items = [_compact_runtime_status(item) for item in items]
    health_counts: Counter[str] = Counter()
    for item in compact_items:
        health = item.get("health")
        if isinstance(health, str):
            health_counts[health] += 1

    result: dict[str, Any] = {
        "status": "ok",
        "count": len(compact_items),
        "health_counts": dict(sorted(health_counts.items())),
        "items": compact_items,
    }
    if reported_count is not None:
        result["reported_count"] = reported_count
    return result


async def _collect_group_statuses(
    overview_ctx: ProductOverviewContext,
    *,
    group_id: str,
    resource_type: str,
    list_method: StatusListMethod,
) -> dict[str, Any]:
    """Collect source or destination runtime statuses for one group/fleet."""
    try:
        response = await list_method(
            metrics=False,
            offset=0,
            limit=STATUS_PAGE_LIMIT,
            server_url=get_group_url(overview_ctx.client, group_id),
            timeout_ms=overview_ctx.timeout_ms,
        )
        items, reported_count = await _collect_paginated_items(response)
    except ResponseValidationError as exc:
        await overview_ctx.ctx.error(
            f"SDK validation error for {resource_type} status in {overview_ctx.product.value} group '{group_id}': {exc}",
        )
        return _status_validation_error(
            exc=exc,
            resource_type=resource_type,
            product=overview_ctx.product,
            group_id=group_id,
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            message = f"{resource_type.capitalize()} status endpoint returned HTTP 404 for group '{group_id}'."
            await overview_ctx.ctx.warning(message)
            return _unavailable_result(message)
        return _error_result(f"Cribl API error while listing {resource_type} status for group '{group_id}': {exc}")
    except httpx.HTTPError as exc:
        return _error_result(f"Network error while listing {resource_type} status for group '{group_id}': {exc}")

    return _runtime_status_response(items, reported_count)


async def _collect_health(client: CriblControlPlane, *, timeout_ms: int) -> dict[str, Any]:
    """Collect leader health through the SDK."""
    try:
        health = await client.health.get_async(timeout_ms=timeout_ms)
    except HealthServerStatusError as exc:
        return {
            "status": "not_healthy",
            "status_code": exc.status_code,
            "details": serialize_model(exc.data),
        }
    except CriblControlPlaneError as exc:
        return _error_result(f"Cribl API error while checking leader health: {exc}", status_code=exc.status_code)
    except httpx.HTTPError as exc:
        return _error_result(f"Network error while checking leader health: {exc}")

    return {"status": "ok", "details": serialize_model(health)}


def _http_client(client: CriblControlPlane) -> httpx.AsyncClient:
    """Return the SDK-owned HTTP client for direct calls."""
    http_client = client.sdk_configuration.async_client
    if not isinstance(http_client, httpx.AsyncClient):
        msg = "Cribl SDK client does not expose an httpx.AsyncClient."
        raise TypeError(msg)
    return http_client


def _system_info_url(config: CriblConfig) -> str:
    """Return the direct system-info endpoint URL."""
    return f"{config.base_url_str.rstrip('/')}/system/info"


def _first_counted_item(payload: object) -> dict[str, Any] | None:
    """Extract the first item from a counted Cribl API response."""
    payload_dict = _as_dict(payload)
    if payload_dict is None:
        return None
    items = payload_dict.get("items")
    if not isinstance(items, list) or not items:
        return None
    typed_items = cast("list[object]", items)
    first = typed_items[0]
    return _as_dict(first)


def _version_from_build(build: object) -> str | None:
    """Extract a version from system-info build metadata when present."""
    build_dict = _as_dict(build)
    if build_dict is None:
        return None

    raw_version = build_dict.get("VERSION") or build_dict.get("version")
    if not isinstance(raw_version, str) or not raw_version:
        return None

    try:
        parsed = json.loads(raw_version)
    except json.JSONDecodeError:
        return raw_version
    return parsed if isinstance(parsed, str) else raw_version


def _version_from_fields(data: dict[str, Any], *, source_prefix: str | None = None) -> tuple[str | None, str | None]:
    """Extract a Cribl software version from one object."""
    for key in VERSION_FIELDS:
        version = _as_str(data.get(key))
        if version is not None:
            source = f"{source_prefix}.{key}" if source_prefix is not None else key
            return version, source

    for build_key in ("build", "BUILD"):
        build_version = _version_from_build(data.get(build_key))
        if build_version is not None:
            source = f"{source_prefix}.{build_key}.VERSION" if source_prefix is not None else f"{build_key}.VERSION"
            return build_version, source
    return None, None


def _system_info_version(item: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract a Cribl software version from known leader system-info shapes."""
    candidates: list[tuple[dict[str, Any], str | None]] = [(item, None)]
    info = _as_dict(item.get("info"))
    if info is not None:
        cribl = _as_dict(info.get("cribl"))
        if cribl is not None:
            candidates.append((cribl, "info.cribl"))
        candidates.append((info, "info"))

    for data, prefix in candidates:
        version, source = _version_from_fields(data, source_prefix=prefix)
        if version is not None:
            return version, source
    return None, None


def _compact_fields(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Return a copy with only present fields."""
    return {key: value for key in fields if (value := source.get(key)) is not None}


def _compact_system_info(item: dict[str, Any]) -> dict[str, Any]:
    """Keep only system-info fields useful for leader identity and version."""
    result: dict[str, Any] = {"status": "ok"}
    result.update(_compact_fields(item, SYSTEM_INFO_TOP_FIELDS))
    if "build" not in result:
        build = item.get("BUILD")
        if build is not None:
            result["build"] = build

    info = _as_dict(item.get("info"))
    if info is not None:
        node_info = _compact_fields(info, SYSTEM_INFO_NODE_FIELDS)
        if node_info:
            result["node"] = node_info

        cribl_info = _as_dict(info.get("cribl"))
        if cribl_info is not None:
            compact_cribl = _compact_fields(cribl_info, SYSTEM_INFO_CRIBL_FIELDS)
            if compact_cribl:
                result["cribl"] = compact_cribl

    version, version_source = _system_info_version(item)
    result["cribl_version"] = version
    if version_source is not None:
        result["version_source"] = version_source
    return result


async def _collect_system_info(
    client: CriblControlPlane,
    *,
    config: CriblConfig,
    security: Security,
) -> dict[str, Any]:
    """Collect leader system info through direct HTTP until the Python SDK exposes it."""
    try:
        response = await _http_client(client).get(
            _system_info_url(config),
            headers=get_auth_headers(security),
            timeout=config.timeout_ms / 1000,
        )
    except httpx.HTTPError as exc:
        return _error_result(f"Network error while fetching leader system info: {exc}")

    if response.status_code == HTTP_NOT_FOUND:
        return _unavailable_result("Endpoint /system/info is unavailable on this Cribl leader.")

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return _error_result(
            f"HTTP error while fetching leader system info: {exc}",
            status_code=response.status_code,
        )

    item = _first_counted_item(response.json())
    if item is None:
        return _error_result("Leader system info response did not include a counted item.")
    return _compact_system_info(item)


def _summary_first_item(summary_response: object) -> dict[str, Any]:
    """Return the first item from a summary SDK response."""
    data = serialize_model(summary_response)
    first = _first_counted_item(data)
    return first or {}


async def _collect_product_summary(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> dict[str, Any]:
    """Collect aggregate deployment summary for one product."""
    try:
        summary = await client.nodes.summaries.get_async(
            product=ProductsBase(product.value),
            timeout_ms=timeout_ms,
        )
    except ResponseValidationError as exc:
        await ctx.error(f"SDK validation error for {product.value} summary: {exc}")
        return _status_validation_error(exc=exc, resource_type="summary", product=product, group_id="(product)")
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return _unavailable_result(f"Summary endpoint returned HTTP 404 for {product.value}.")
        return _error_result(f"Cribl API error while fetching {product.value} summary: {exc}", status_code=exc.status_code)
    except httpx.HTTPError as exc:
        return _error_result(f"Network error while fetching {product.value} summary: {exc}")

    return {"status": "ok", "summary": _summary_first_item(summary)}


def _node_counts_from_summary(summary: dict[str, Any]) -> dict[str, int]:
    """Extract compact node counts from a product summary result."""
    summary_item = _as_dict(summary.get("summary"))
    if summary_item is None:
        return {}
    workers = _as_dict(summary_item.get("workers"))
    if workers is None:
        return {}

    total = _as_int(workers.get("count"))
    disconnected = _as_int(workers.get("disconnectedCount")) or 0
    counts: dict[str, int] = {}
    if total is not None:
        counts["total"] = total
        counts["connected"] = max(total - disconnected, 0)
    if disconnected:
        counts["disconnected"] = disconnected

    for source_key, target_key in (
        ("alive", "healthy"),
        ("unhealthy", "unhealthy"),
        ("groups", "groups_with_nodes"),
        ("softwareVersions", "software_versions"),
        ("confVersions", "config_versions"),
    ):
        value = _as_int(workers.get(source_key))
        if value is not None:
            counts[target_key] = value

    return counts


def _version_from_node(item: dict[str, Any]) -> str | None:
    """Extract a Cribl software version from a node inventory item."""
    info = _as_dict(item.get("info"))
    if info is None:
        return None
    cribl = _as_dict(info.get("cribl"))
    if cribl is None:
        return None
    return _as_str(cribl.get("version"))


async def _collect_node_inventory(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> dict[str, Any]:
    """Collect node inventory counts by group/fleet for one product."""
    try:
        response = await client.nodes.list_async(
            product=product,
            limit=STATUS_PAGE_LIMIT,
            offset=0,
            timeout_ms=timeout_ms,
        )
        items, reported_count = await _collect_paginated_items(response)
    except ResponseValidationError as exc:
        await ctx.error(f"SDK validation error for {product.value} nodes: {exc}")
        return _status_validation_error(exc=exc, resource_type="nodes", product=product, group_id="(product)")
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return _unavailable_result(f"Nodes endpoint returned HTTP 404 for {product.value}.")
        return _error_result(f"Cribl API error while fetching {product.value} nodes: {exc}", status_code=exc.status_code)
    except httpx.HTTPError as exc:
        return _error_result(f"Network error while fetching {product.value} nodes: {exc}")

    by_group: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    for item in items:
        group_id = _as_str(item.get("group"))
        if group_id is not None:
            by_group[group_id] += 1
        version = _version_from_node(item)
        if version is not None:
            versions[version] += 1
        status = _as_str(item.get("status"))
        if status is not None:
            statuses[status] += 1

    result: dict[str, Any] = {
        "status": "ok",
        "count": len(items),
        "by_group": dict(sorted(by_group.items())),
        "versions": dict(sorted(versions.items())),
        "statuses": dict(sorted(statuses.items())),
    }
    if reported_count is not None:
        result["reported_count"] = reported_count
    return result


def _active_group_count(group: dict[str, Any], node_inventory: dict[str, Any]) -> int:
    """Return the best available node count for a group/fleet."""
    group_id = extract_group_id(group)
    by_group = _as_dict(node_inventory.get("by_group"))
    if by_group is not None and group_id is not None:
        node_count = _as_int(by_group.get(group_id))
        if node_count is not None:
            return node_count
    return _as_int(group.get("workerCount")) or 0


async def _build_active_group_report(
    overview_ctx: ProductOverviewContext,
    *,
    group: dict[str, Any],
    node_count: int,
) -> dict[str, Any]:
    """Build the overview report for one active group/fleet."""
    group_id = extract_group_id(group)
    if group_id is None:
        return {"status": "error", "message": "Group item did not include an id.", "node_count": node_count}

    source_statuses, destination_statuses = await asyncio.gather(
        _collect_group_statuses(
            overview_ctx,
            group_id=group_id,
            resource_type="sources",
            list_method=overview_ctx.client.sources.statuses.list_async,
        ),
        _collect_group_statuses(
            overview_ctx,
            group_id=group_id,
            resource_type="destinations",
            list_method=overview_ctx.client.destinations.statuses.list_async,
        ),
    )

    report: dict[str, Any] = {
        "id": group_id,
        "node_count": node_count,
        "reported_worker_count": group.get("workerCount"),
        "sources": source_statuses,
        "destinations": destination_statuses,
    }
    for key in ("name", "description", "type", "configVersion"):
        value = group.get(key)
        if value is not None:
            report[key] = value
    return report


async def _collect_product_overview(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    timeout_ms: int,
    ctx: Context,
) -> tuple[str, dict[str, Any]]:
    """Collect the Stream or Edge portion of the leader overview."""
    groups_result = await collect_product_groups(client, product=product, timeout_ms=timeout_ms, ctx=ctx)
    if groups_result.get("status") != "ok":
        return product.value, groups_result

    summary, node_inventory = await asyncio.gather(
        _collect_product_summary(client, product=product, timeout_ms=timeout_ms, ctx=ctx),
        _collect_node_inventory(client, product=product, timeout_ms=timeout_ms, ctx=ctx),
    )
    overview_ctx = ProductOverviewContext(client=client, product=product, timeout_ms=timeout_ms, ctx=ctx)

    group_items = cast("list[dict[str, Any]]", groups_result.get("items", []))
    active_groups: list[tuple[dict[str, Any], int]] = []
    for group in group_items:
        node_count = _active_group_count(group, node_inventory)
        if node_count > 0:
            active_groups.append((group, node_count))

    group_reports = await asyncio.gather(
        *[
            _build_active_group_report(
                overview_ctx,
                group=group,
                node_count=node_count,
            )
            for group, node_count in active_groups
        ]
    )

    product_result: dict[str, Any] = {
        "status": "ok",
        "summary": summary,
        "node_counts": _node_counts_from_summary(summary),
        "node_inventory": node_inventory,
        "group_count": groups_result.get("count", len(group_items)),
        "groups_with_nodes": list(group_reports),
        "omitted_empty_group_count": max(len(group_items) - len(active_groups), 0),
    }
    return product.value, product_result


async def collect_leader_overview(
    client: CriblControlPlane,
    *,
    config: CriblConfig,
    security: Security,
    products: tuple[ProductsCore, ...],
    ctx: Context,
) -> dict[str, Any]:
    """Return a compact overview report for the configured Cribl leader."""
    await ctx.info("Collecting Cribl leader overview.")

    health_task = _collect_health(client, timeout_ms=config.timeout_ms)
    system_info_task = _collect_system_info(client, config=config, security=security)
    product_tasks = [
        _collect_product_overview(
            client,
            product=product,
            timeout_ms=config.timeout_ms,
            ctx=ctx,
        )
        for product in products
    ]

    health, system_info, product_pairs = await asyncio.gather(
        health_task,
        system_info_task,
        asyncio.gather(*product_tasks),
    )

    products_result = dict(product_pairs)
    return {
        "retrieved_at": datetime.now(UTC).isoformat(),
        "server": config.server_name,
        "base_url": config.base_url_str,
        "health": health,
        "cribl_version": system_info.get("cribl_version"),
        "system_info": system_info,
        "products": products_result,
    }


__all__ = ["collect_leader_overview"]
