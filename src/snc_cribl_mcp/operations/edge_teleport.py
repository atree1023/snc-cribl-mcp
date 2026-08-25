"""Helpers for Cribl Edge teleport API requests."""

from __future__ import annotations

import inspect
import logging
import re
import string
from collections.abc import Awaitable
from time import time
from typing import Any, cast
from urllib.parse import quote

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from fastmcp import Context

from ..config import CriblConfig
from .common import get_auth_headers, serialize_model

logger = logging.getLogger("snc_cribl_mcp.operations.edge_teleport")

SERVICE_NOW_DOMAIN = "service-now.com"
DATACENTER_TOKEN_LENGTH = 3
DEFAULT_FILE_LIMIT = 50
DEFAULT_SEARCH_WINDOW_SECONDS = 3600
MAX_FILE_LIMIT = 1000
NODE_PAGE_LIMIT = 500
SUPPORTED_INFO_TYPES = frozenset({"file"})
SEARCH_QUOTE_TRIGGER_CHARS = frozenset(string.punctuation) - {'"'}


def _clean_str(value: object) -> str | None:
    """Return a stripped non-empty string."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _as_dict(value: object) -> dict[str, Any] | None:
    """Return a string-keyed dictionary when the value is a JSON object."""
    if isinstance(value, dict):
        return cast("dict[str, Any]", value)
    return None


def _serialize_item(item: object) -> dict[str, Any]:
    """Serialize an SDK model or raw dictionary."""
    raw_dict = _as_dict(item)
    if raw_dict is not None:
        return raw_dict
    return serialize_model(item)


def _normalize_datacenter(datacenter: str) -> str:
    """Return the first three-letter datacenter token from a selector."""
    cleaned = _clean_str(datacenter)
    if cleaned is None:
        msg = "Datacenter is required."
        raise ValueError(msg)

    for token in re.split(r"[^A-Za-z0-9]+", cleaned.lower()):
        if len(token) >= DATACENTER_TOKEN_LENGTH and token[:DATACENTER_TOKEN_LENGTH].isalpha():
            return token[:DATACENTER_TOKEN_LENGTH]

    msg = f"Could not extract a three-letter datacenter token from '{datacenter}'."
    raise ValueError(msg)


def normalize_edge_hostname(edge_host: str, *, datacenter: str | None = None) -> str:
    """Normalize an Edge host to a service-now.com FQDN when possible."""
    cleaned = _clean_str(edge_host)
    if cleaned is None:
        msg = "edge_host is required."
        raise ValueError(msg)

    host = cleaned.lower().rstrip(".")
    if host.endswith(f".{SERVICE_NOW_DOMAIN}"):
        return host
    if "." in host:
        return f"{host}.{SERVICE_NOW_DOMAIN}"

    dc = _clean_str(datacenter)
    if dc is not None:
        return f"{host}.{dc.lower().rstrip('.')}.{SERVICE_NOW_DOMAIN}"
    return host


def extract_datacenter_from_edge_host(edge_host: str, *, datacenter: str | None = None) -> str:
    """Extract the three-letter datacenter token from an Edge hostname."""
    if datacenter is not None:
        return _normalize_datacenter(datacenter)

    host = normalize_edge_hostname(edge_host)
    labels = host.split(".")
    if len(labels) < 2:  # noqa: PLR2004
        msg = "Edge host must include a datacenter label such as 'cribl01.fra0' or pass datacenter explicitly."
        raise ValueError(msg)

    label = labels[1]
    if len(label) >= DATACENTER_TOKEN_LENGTH and label[:DATACENTER_TOKEN_LENGTH].isalpha():
        return label[:DATACENTER_TOKEN_LENGTH]

    msg = f"Could not extract a three-letter datacenter token from Edge host '{edge_host}'."
    raise ValueError(msg)


def _without_service_now_domain(hostname: str) -> str:
    """Return the host without the standard service-now.com suffix."""
    suffix = f".{SERVICE_NOW_DOMAIN}"
    return hostname.removesuffix(suffix)


def _node_info(node: dict[str, Any]) -> dict[str, Any]:
    """Return a node's nested info object, if present."""
    return _as_dict(node.get("info")) or {}


def _node_cribl_info(node: dict[str, Any]) -> dict[str, Any]:
    """Return a node's nested info.cribl object, if present."""
    return _as_dict(_node_info(node).get("cribl")) or {}


def _node_id(node: dict[str, Any]) -> str | None:
    """Return the best available node GUID."""
    return _clean_str(node.get("id")) or _clean_str(_node_cribl_info(node).get("guid"))


def _node_hostname(node: dict[str, Any]) -> str | None:
    """Return a node hostname."""
    return _clean_str(_node_info(node).get("hostname"))


def _node_matches_host(node: dict[str, Any], target_host: str, raw_host: str) -> bool:
    """Return whether node metadata matches a requested host or GUID."""
    target = target_host.lower()
    target_short = _without_service_now_domain(target)
    raw = raw_host.lower().rstrip(".")
    candidates: set[str] = set()

    node_id = _node_id(node)
    if node_id is not None:
        candidates.add(node_id.lower())

    hostname = _node_hostname(node)
    if hostname is not None:
        host = hostname.lower().rstrip(".")
        candidates.add(host)
        candidates.add(_without_service_now_domain(host))

    return target in candidates or target_short in candidates or raw in candidates


def _edge_node_summary(node: dict[str, Any]) -> dict[str, Any]:
    """Build a compact Edge node summary for tool responses."""
    summary: dict[str, Any] = {}
    node_id = _node_id(node)
    if node_id is not None:
        summary["id"] = node_id
    hostname = _node_hostname(node)
    if hostname is not None:
        summary["hostname"] = hostname
    for key in ("group", "status", "disconnected"):
        if key in node:
            summary[key] = node[key]
    return summary


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


async def resolve_edge_node(
    client: CriblControlPlane,
    *,
    edge_host: str,
    timeout_ms: int,
) -> dict[str, Any]:
    """Resolve an Edge hostname or GUID to a node inventory item."""
    normalized_host = normalize_edge_hostname(edge_host)
    try:
        response = await client.nodes.list_async(
            product=ProductsCore.EDGE,
            limit=NODE_PAGE_LIMIT,
            offset=0,
            timeout_ms=timeout_ms,
        )
        nodes, _reported_count = await _collect_paginated_items(response)
    except ResponseValidationError as exc:
        msg = f"SDK validation error while listing Edge nodes: {exc}"
        raise RuntimeError(msg) from exc
    except CriblControlPlaneError as exc:
        msg = f"Cribl API error while listing Edge nodes: {exc}"
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while listing Edge nodes: {exc}"
        raise RuntimeError(msg) from exc

    matches = [node for node in nodes if _node_matches_host(node, normalized_host, edge_host)]
    if not matches:
        msg = f"No Edge node with hostname or GUID '{edge_host}' was found on the selected leader."
        raise RuntimeError(msg)
    if len(matches) > 1:
        hostnames = ", ".join(_node_hostname(node) or _node_id(node) or "<unknown>" for node in matches)
        msg = f"Edge host '{edge_host}' matched multiple nodes: {hostnames}."
        raise RuntimeError(msg)
    return matches[0]


def _validate_file_request(*, file_path: str, offset: int, limit: int) -> None:
    """Validate file teleport request bounds."""
    if not file_path.startswith("/"):
        msg = "file_path must be an absolute path on the Edge node."
        raise ValueError(msg)
    if offset < 0:
        msg = "offset must be greater than or equal to 0."
        raise ValueError(msg)
    if limit < 1 or limit > MAX_FILE_LIMIT:
        msg = f"limit must be between 1 and {MAX_FILE_LIMIT}."
        raise ValueError(msg)


def _normalize_file_search_query(query: str | None) -> str:
    """Quote file search terms containing punctuation, matching the Edge UI behavior."""
    cleaned = _clean_str(query)
    if cleaned is None:
        return ""
    if len(cleaned) >= 2 and cleaned.startswith('"') and cleaned.endswith('"'):  # noqa: PLR2004
        return cleaned
    if any(char in SEARCH_QUOTE_TRIGGER_CHARS for char in cleaned):
        escaped = cleaned.replace('"', '\\"')
        return f'"{escaped}"'
    return cleaned


def _resolve_file_search_et(
    *,
    query: str,
    earliest_time: int | None,
    search_window_seconds: int,
) -> int:
    """Resolve the Edge teleport ``et`` value."""
    if search_window_seconds < 0:
        msg = "search_window_seconds must be greater than or equal to 0."
        raise ValueError(msg)
    if earliest_time is not None:
        return earliest_time
    if query:
        return int(time()) - search_window_seconds
    return int(time())


def _next_offset(response: dict[str, Any]) -> int | None:
    """Extract the next file offset from a teleport file response."""
    batches = response.get("items")
    if not isinstance(batches, list) or not batches:
        return None
    typed_batches = cast("list[object]", batches)
    first_raw = typed_batches[0]
    first_batch = _as_dict(first_raw)
    if first_batch is None:
        return None
    offset = first_batch.get("offset")
    return offset if isinstance(offset, int) else None


def _build_file_search_payload(
    *,
    file_path: str,
    query: str,
    offset: int,
    limit: int,
    et: int,
    rulesets: list[str] | None,
) -> dict[str, Any]:
    """Build the Edge teleport file search request body."""
    return {
        "file": file_path,
        "offset": offset,
        "limit": limit,
        "et": et,
        "query": query,
        "rulesets": list(rulesets or []),
    }


async def _post_file_search(
    client: CriblControlPlane,
    *,
    security: Security,
    node_id: str,
    payload: dict[str, Any],
    timeout_ms: int,
) -> dict[str, Any]:
    """Call the Edge teleport file search endpoint."""
    http_client = cast("httpx.AsyncClient", client.sdk_configuration.async_client)
    server_url = client.sdk_configuration.server_url
    if not server_url:
        msg = "Client server_url is not configured."
        raise ValueError(msg)

    base_url = server_url.rstrip("/")
    url = f"{base_url}/w/{quote(node_id, safe='')}/edge/search/file"
    headers = get_auth_headers(security)

    try:
        response = await http_client.post(
            url,
            headers=headers,
            json=payload,
            timeout=timeout_ms / 1000,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        msg = f"Cribl Edge teleport file endpoint returned HTTP {exc.response.status_code} for node '{node_id}'."
        raise RuntimeError(msg) from exc
    except httpx.HTTPError as exc:
        msg = f"Network error while calling Cribl Edge teleport file endpoint for node '{node_id}': {exc}"
        raise RuntimeError(msg) from exc

    try:
        data = response.json()
    except ValueError as exc:
        msg = "Invalid JSON response from Cribl Edge teleport file endpoint."
        raise RuntimeError(msg) from exc

    if not isinstance(data, dict):
        msg = "Unexpected non-object JSON response from Cribl Edge teleport file endpoint."
        raise TypeError(msg)
    return cast("dict[str, Any]", data)


async def collect_edge_info(
    client: CriblControlPlane,
    *,
    config: CriblConfig,
    security: Security,
    edge_host: str,
    info_type: str,
    file_path: str,
    query: str | None,
    offset: int = 0,
    limit: int = DEFAULT_FILE_LIMIT,
    earliest_time: int | None = None,
    search_window_seconds: int = DEFAULT_SEARCH_WINDOW_SECONDS,
    rulesets: list[str] | None = None,
    datacenter: str | None = None,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Collect data from an Edge node through the leader's teleport API."""
    if info_type not in SUPPORTED_INFO_TYPES:
        supported = ", ".join(sorted(SUPPORTED_INFO_TYPES))
        msg = f"Unsupported Edge info_type '{info_type}'. Supported values: {supported}."
        raise ValueError(msg)

    _validate_file_request(file_path=file_path, offset=offset, limit=limit)
    normalized_host = normalize_edge_hostname(edge_host, datacenter=datacenter)
    dc = extract_datacenter_from_edge_host(normalized_host, datacenter=datacenter)
    search_query = _normalize_file_search_query(query)
    operation = "search_file" if search_query else "read_file"
    et = _resolve_file_search_et(
        query=search_query,
        earliest_time=earliest_time,
        search_window_seconds=search_window_seconds,
    )

    if ctx is not None:
        await ctx.info(f"Resolving Edge node '{normalized_host}' on leader '{config.server_name or config.base_url_str}'.")

    node = await resolve_edge_node(
        client,
        edge_host=normalized_host,
        timeout_ms=config.timeout_ms,
    )
    node_id = _node_id(node)
    if node_id is None:
        msg = f"Matched Edge node '{normalized_host}' but it did not include an id/guid."
        raise RuntimeError(msg)

    if ctx is not None:
        await ctx.info(f"Calling Edge teleport file endpoint for '{normalized_host}'.")

    payload = _build_file_search_payload(
        file_path=file_path,
        query=search_query,
        offset=offset,
        limit=limit,
        et=et,
        rulesets=rulesets,
    )
    response = await _post_file_search(
        client,
        security=security,
        node_id=node_id,
        payload=payload,
        timeout_ms=config.timeout_ms,
    )

    return {
        "status": "ok",
        "operation": operation,
        "info_type": info_type,
        "server": config.server_name,
        "base_url": config.base_url_str,
        "datacenter": dc,
        "edge_host": normalized_host,
        "node": _edge_node_summary(node),
        "request": payload,
        "next_offset": _next_offset(response),
        "response": response,
    }


__all__ = [
    "DEFAULT_FILE_LIMIT",
    "DEFAULT_SEARCH_WINDOW_SECONDS",
    "MAX_FILE_LIMIT",
    "SUPPORTED_INFO_TYPES",
    "collect_edge_info",
    "extract_datacenter_from_edge_host",
    "normalize_edge_hostname",
    "resolve_edge_node",
]
