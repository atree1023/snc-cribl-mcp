"""Helpers for managing top-level Cribl Packs."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import quote

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security
from pydantic import ValidationError

from .common import (
    HTTP_NOT_FOUND,
    build_unavailable_result,
    extract_group_id,
    get_auth_headers,
    get_group_url,
    list_groups_minimal,
    serialize_model,
)
from .config_objects import ConfigObjectKind, extract_config_object_refs
from .validation_errors import format_validation_error_response, parse_validation_error

type GroupMatchField = Literal["description", "id", "name"]
type PackObjectDetail = Literal["summary", "refs", "full"]
type PackObjectKind = Literal[
    "destinations",
    "knowledge",
    "knowledge.appscope_configs",
    "knowledge.breakers",
    "knowledge.database_connections",
    "knowledge.functions",
    "knowledge.grok",
    "knowledge.hmac_functions",
    "knowledge.lookups",
    "knowledge.parsers",
    "knowledge.regexes",
    "knowledge.samples",
    "knowledge.schemas",
    "knowledge.variables",
    "pipelines",
    "routes",
    "settings",
    "settings.auth",
    "settings.conf",
    "settings.cribl",
    "settings.git",
    "settings.system",
    "sources",
]
type PackApiCall = Callable[[], Awaitable[object]]
type PackSerializer = Callable[[object], dict[str, Any]]

_DEFAULT_OBJECT_LIMIT = 50
_MAX_OBJECT_LIMIT = 250

_INSTALL_REQUEST_FIELDS = frozenset(
    {
        "allowCustomFunctions",
        "allow_custom_functions",
        "author",
        "description",
        "displayName",
        "display_name",
        "force",
        "id",
        "minLogStreamVersion",
        "min_log_stream_version",
        "source",
        "spec",
        "tags",
        "version",
    }
)

_SDK_SECTION_TO_CONFIG_KIND: dict[str, ConfigObjectKind] = {
    "sources": "sources",
    "destinations": "destinations",
    "pipelines": "pipelines",
    "routes": "routes",
}

_KNOWLEDGE_ENDPOINTS: dict[str, str] = {
    "knowledge.appscope_configs": "lib/appscope-configs",
    "knowledge.breakers": "lib/breakers",
    "knowledge.database_connections": "lib/database-connections",
    "knowledge.functions": "functions",
    "knowledge.grok": "lib/grok",
    "knowledge.hmac_functions": "lib/hmac-functions",
    "knowledge.lookups": "system/lookups",
    "knowledge.parsers": "lib/parsers",
    "knowledge.regexes": "lib/regex",
    "knowledge.samples": "system/samples",
    "knowledge.schemas": "lib/schemas",
    "knowledge.variables": "lib/vars",
}

_SETTINGS_ENDPOINTS: dict[str, str] = {
    "settings.auth": "system/settings/auth",
    "settings.conf": "system/settings/conf",
    "settings.cribl": "system/settings/cribl",
    "settings.git": "system/settings/git-settings",
    "settings.system": "system/settings",
}

_KNOWLEDGE_CATEGORY_NAMES: dict[str, str] = {
    "knowledge.appscope_configs": "appscope_configs",
    "knowledge.breakers": "breakers",
    "knowledge.database_connections": "database_connections",
    "knowledge.functions": "functions",
    "knowledge.grok": "grok",
    "knowledge.hmac_functions": "hmac_functions",
    "knowledge.lookups": "lookups",
    "knowledge.parsers": "parsers",
    "knowledge.regexes": "regexes",
    "knowledge.samples": "samples",
    "knowledge.schemas": "schemas",
    "knowledge.variables": "variables",
}

_SETTINGS_CATEGORY_NAMES: dict[str, str] = {
    "settings.auth": "auth",
    "settings.conf": "conf",
    "settings.cribl": "cribl",
    "settings.git": "git",
    "settings.system": "system",
}


@dataclass(frozen=True, slots=True)
class PackUpgradeOptions:
    """Optional fields accepted by the SDK Pack upgrade endpoint."""

    allow_custom_functions: bool | None = None
    minor: str | None = None
    spec: str | None = None


@dataclass(frozen=True, slots=True)
class PackUpdateRequest:
    """Pack upgrade request fields accepted by the SDK."""

    source: str
    options: PackUpgradeOptions = field(default_factory=PackUpgradeOptions)


@dataclass(frozen=True, slots=True)
class ResolvedPackGroupScope:
    """Resolved distributed Pack API scope."""

    product: ProductsCore
    group_selector: str
    group_id: str
    matched_by: GroupMatchField
    server_url: str
    group_name: str | None = None
    group_description: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        """Return a JSON-friendly scope description."""
        return {
            "product": self.product.value,
            "group_selector": self.group_selector,
            "group_id": self.group_id,
            "matched_by": self.matched_by,
            "group_name": self.group_name,
            "group_description": self.group_description,
        }


def _serialize_counted_response(response: object) -> dict[str, Any]:
    """Serialize an SDK counted or single-object response into the MCP response shape."""
    raw_items_value: object = getattr(response, "items", None)
    raw_items: list[object] | None = None
    if isinstance(raw_items_value, list):
        raw_items = cast("list[object]", raw_items_value)
    elif isinstance(raw_items_value, tuple):
        raw_items = list(cast("tuple[object, ...]", raw_items_value))
    if raw_items is None:
        item = serialize_model(response)
        return {
            "status": "ok",
            "count": 1 if item else 0,
            "items": [item] if item else [],
        }

    items = [serialize_model(item) for item in raw_items]
    reported_count = getattr(response, "count", None)

    result: dict[str, Any] = {
        "status": "ok",
        "count": len(items),
        "items": items,
    }
    if reported_count is not None:
        result["reported_count"] = reported_count
    return result


def _serialize_single_response(response: object) -> dict[str, Any]:
    """Serialize an SDK single-object response into the MCP response shape."""
    return {"status": "ok", **serialize_model(response)}


def _serialize_http_counted_payload(payload: object) -> dict[str, Any]:
    """Serialize a direct HTTP Pack response into the counted response shape."""
    if isinstance(payload, dict):
        payload_dict = cast("dict[str, Any]", payload)
        if "items" in payload_dict:
            items_value: object = payload_dict.get("items", [])
            items = cast("list[object]", items_value) if isinstance(items_value, list) else []
        else:
            items = [payload_dict] if payload_dict else []
        result: dict[str, Any] = {
            "status": "ok",
            "count": len(items),
            "items": [cast("dict[str, Any]", item) for item in items if isinstance(item, dict)],
        }
        reported_count: object = payload_dict.get("count")
        if isinstance(reported_count, int):
            result["reported_count"] = reported_count
        return result
    if isinstance(payload, list):
        payload_list = cast("list[object]", payload)
        return {
            "status": "ok",
            "count": len(payload_list),
            "items": [cast("dict[str, Any]", item) for item in payload_list if isinstance(item, dict)],
        }
    return {
        "status": "error",
        "error": "Unexpected non-JSON-object Pack response.",
        "error_type": type(payload).__name__,
    }


def _pack_call_kwargs(*, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
    """Build SDK call kwargs, preserving existing top-level behavior when unscoped."""
    kwargs: dict[str, Any] = {"timeout_ms": timeout_ms}
    if server_url is not None:
        kwargs["server_url"] = server_url
    return kwargs


def _pack_scope_label(server_url: str | None) -> str:
    """Return a short label for top-level versus group-scoped Pack API calls."""
    return "group-scoped" if server_url is not None else "top-level"


def _coerce_limit(limit: int | None) -> int:
    """Return a bounded Pack object limit."""
    if limit is None or limit < 1:
        return _DEFAULT_OBJECT_LIMIT
    return min(limit, _MAX_OBJECT_LIMIT)


def _coerce_cursor(cursor: str | None) -> int:
    """Return a non-negative integer cursor offset."""
    if cursor is None:
        return 0
    try:
        parsed = int(cursor)
    except ValueError:
        # MCP callers may retry stale or typoed cursors; fall back to the first page instead of failing the read.
        return 0
    return max(parsed, 0)


def _optional_str(value: object) -> str | None:
    """Return a non-empty string value when available."""
    if value is None:
        return None
    text = str(value)
    return text or None


def _pack_item_id(item: dict[str, Any]) -> str | None:
    """Return the most useful identifier for a Pack object."""
    for key in ("id", "name", "fileName", "filename", "path"):
        value = item.get(key)
        if value is not None:
            return str(value)
    return None


def _enabled_state(item: dict[str, Any]) -> bool | None:
    """Return enabled/disabled state when the item has a familiar flag."""
    enabled = item.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    disabled = item.get("disabled")
    if isinstance(disabled, bool):
        return not disabled
    return None


def _include_if_present(summary: dict[str, Any], target_key: str, item: dict[str, Any], *source_keys: str) -> None:
    """Copy the first present item value into the summary."""
    for source_key in source_keys:
        value = item.get(source_key)
        if value is not None:
            summary[target_key] = value
            return


def _summarize_pack_item(
    section_kind: str,
    item: dict[str, Any],
    *,
    detail: PackObjectDetail,
) -> dict[str, Any]:
    """Return a compact Pack object summary, optionally including the full payload."""
    summary: dict[str, Any] = {
        "id": _pack_item_id(item),
        "name": _optional_str(item.get("name")),
        "type": _optional_str(item.get("type")),
        "enabled": _enabled_state(item),
        "description": _optional_str(item.get("description")),
    }
    if section_kind in _SDK_SECTION_TO_CONFIG_KIND:
        config_kind = _SDK_SECTION_TO_CONFIG_KIND[section_kind]
        summary["refs"] = extract_config_object_refs(config_kind, item)
    else:
        summary["refs"] = {}

    if section_kind == "routes" and isinstance(item.get("routes"), list):
        summary["route_count"] = len(cast("list[object]", item["routes"]))
    if section_kind == "pipelines":
        conf = item.get("conf")
        if isinstance(conf, dict):
            conf_dict = cast("dict[str, Any]", conf)
            functions_value: object = conf_dict.get("functions")
            if isinstance(functions_value, list):
                summary["function_count"] = len(cast("list[object]", functions_value))
    if section_kind.startswith("settings"):
        summary["keys"] = sorted(str(key) for key in item)
    for key in ("size", "status", "rowCount", "referenced", "tags", "version", "author", "source"):
        _include_if_present(summary, key, item, key)

    if detail == "full":
        summary["payload"] = item
    return {key: value for key, value in summary.items() if value is not None}


def _shape_pack_objects(
    raw_result: dict[str, Any],
    *,
    section_kind: str,
    detail: PackObjectDetail,
    cursor: str | None,
    limit: int | None,
) -> dict[str, Any]:
    """Shape a counted Pack section into a bounded summary/full response."""
    if raw_result.get("status") != "ok":
        return raw_result

    items_value = raw_result.get("items", [])
    items = cast("list[object]", items_value) if isinstance(items_value, list) else []
    dict_items = [cast("dict[str, Any]", item) for item in items if isinstance(item, dict)]
    start = _coerce_cursor(cursor)
    bounded_limit = _coerce_limit(limit)
    end = start + bounded_limit
    selected_items = dict_items[start:end]
    next_cursor = str(end) if end < len(dict_items) else None

    shaped: dict[str, Any] = {
        "status": "ok",
        "detail": detail,
        "total_count": len(dict_items),
        "returned_count": len(selected_items),
        "items": [
            _summarize_pack_item(
                section_kind,
                item,
                detail=detail,
            )
            for item in selected_items
        ],
        "truncated": next_cursor is not None,
        "next_cursor": next_cursor,
    }
    reported_count = raw_result.get("reported_count")
    if isinstance(reported_count, int):
        shaped["reported_count"] = reported_count
    return shaped


def _group_pack_categories(categories: dict[str, dict[str, Any]], *, detail: PackObjectDetail) -> dict[str, Any]:
    """Return a grouped response for Pack knowledge or settings categories."""
    total_count = 0
    has_error = False
    unavailable_count = 0
    for category in categories.values():
        if category.get("status") == "ok":
            total = category.get("total_count")
            if isinstance(total, int):
                total_count += total
        elif category.get("status") == "unavailable":
            unavailable_count += 1
        else:
            has_error = True
    if has_error:
        status = "partial_error"
    elif categories and unavailable_count == len(categories):
        status = "unavailable"
    elif unavailable_count > 0:
        status = "partial_unavailable"
    else:
        status = "ok"
    return {
        "status": status,
        "detail": detail,
        "total_count": total_count,
        "unavailable_count": unavailable_count,
        "categories": categories,
    }


def _pack_api_error_payload(
    exc: CriblControlPlaneError,
    *,
    resource_type: str,
    server_url: str | None,
) -> dict[str, Any]:
    """Convert SDK errors into structured Pack operation payloads."""
    if isinstance(exc, ResponseValidationError):
        cause = exc.cause
        validation_errors = parse_validation_error(cause) if isinstance(cause, ValidationError) else []
        return format_validation_error_response(
            resource_type=resource_type,
            product="packs",
            group_id=_pack_scope_label(server_url),
            body=exc.body,
            validation_errors=validation_errors,
        )

    if exc.status_code == HTTP_NOT_FOUND:
        return build_unavailable_result(is_grouped=False)

    return {
        "status": "error",
        "error": str(exc),
        "error_type": exc.__class__.__name__,
        "status_code": exc.status_code,
    }


async def _run_pack_api_call(
    call: PackApiCall,
    *,
    serializer: PackSerializer,
    resource_type: str,
    server_url: str | None,
) -> dict[str, Any]:
    """Run a Pack SDK call and return either serialized data or a structured error."""
    try:
        response = await call()
    except CriblControlPlaneError as exc:
        return _pack_api_error_payload(exc, resource_type=resource_type, server_url=server_url)
    except httpx.HTTPError as exc:
        return {
            "status": "error",
            "error": f"Network error while managing Cribl Packs: {exc}",
            "error_type": exc.__class__.__name__,
        }

    return serializer(response)


def _pack_base_url(client: CriblControlPlane, server_url: str | None) -> str:
    """Return the base URL for Pack-scoped direct HTTP calls."""
    selected_url = server_url or client.sdk_configuration.server_url
    if not selected_url:
        msg = "Client server_url is not configured"
        raise ValueError(msg)
    return str(selected_url).rstrip("/")


def _pack_direct_url(
    client: CriblControlPlane,
    *,
    pack_id: str,
    endpoint_path: str,
    server_url: str | None,
    object_id: str | None = None,
) -> str:
    """Build a Pack-scoped direct HTTP endpoint URL."""
    base_url = _pack_base_url(client, server_url)
    encoded_pack_id = quote(pack_id, safe="")
    path = f"{base_url}/p/{encoded_pack_id}/{endpoint_path.strip('/')}"
    if object_id is not None:
        path = f"{path}/{quote(object_id, safe='')}"
    return path


async def _collect_pack_http_objects(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    security: Security,
    timeout_ms: int,
    pack_id: str,
    endpoint_path: str,
    server_url: str | None,
    object_id: str | None = None,
) -> dict[str, Any]:
    """Collect Pack objects from a Pack-prefixed direct HTTP endpoint."""
    http_client = cast("httpx.AsyncClient", client.sdk_configuration.async_client)
    url = _pack_direct_url(
        client,
        pack_id=pack_id,
        endpoint_path=endpoint_path,
        server_url=server_url,
        object_id=object_id,
    )
    try:
        response = await http_client.get(
            url,
            headers=get_auth_headers(security),
            timeout=timeout_ms / 1000,
        )
        if response.status_code == HTTP_NOT_FOUND:
            return build_unavailable_result(is_grouped=False)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return {
            "status": "error",
            "error": str(exc),
            "error_type": exc.__class__.__name__,
            "status_code": exc.response.status_code,
        }
    except httpx.HTTPError as exc:
        return {
            "status": "error",
            "error": f"Network error while reading Pack contents: {exc}",
            "error_type": exc.__class__.__name__,
        }

    try:
        payload = response.json()
    except ValueError as exc:
        return {
            "status": "error",
            "error": f"Invalid JSON response while reading Pack contents: {exc}",
            "error_type": exc.__class__.__name__,
        }
    return _serialize_http_counted_payload(payload)


async def _collect_pack_sdk_objects(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    section_kind: Literal["sources", "destinations", "pipelines", "routes"],
    timeout_ms: int,
    pack_id: str,
    server_url: str | None,
    object_id: str | None = None,
) -> dict[str, Any]:
    """Collect Pack objects through an SDK Pack subresource."""
    sdk = getattr(client.packs, section_kind)
    kwargs = {
        "pack": pack_id,
        **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
    }
    if object_id is None:
        return await _run_pack_api_call(
            lambda: sdk.list_async(**kwargs),
            serializer=_serialize_counted_response,
            resource_type=f"packs.{section_kind}",
            server_url=server_url,
        )
    return await _run_pack_api_call(
        lambda: sdk.get_async(id=object_id, **kwargs),
        serializer=_serialize_counted_response,
        resource_type=f"packs.{section_kind}",
        server_url=server_url,
    )


async def _collect_shaped_sdk_section(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    section_kind: Literal["sources", "destinations", "pipelines", "routes"],
    timeout_ms: int,
    pack_id: str,
    server_url: str | None,
    object_id: str | None,
    detail: PackObjectDetail,
    cursor: str | None,
    limit: int | None,
) -> dict[str, Any]:
    """Collect and shape an SDK-backed Pack section."""
    raw = await _collect_pack_sdk_objects(
        client,
        section_kind=section_kind,
        timeout_ms=timeout_ms,
        pack_id=pack_id,
        server_url=server_url,
        object_id=object_id,
    )
    return _shape_pack_objects(
        raw,
        section_kind=section_kind,
        detail=detail,
        cursor=cursor,
        limit=limit,
    )


async def _collect_shaped_http_section(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    security: Security,
    section_kind: str,
    endpoint_path: str,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None,
    object_id: str | None,
    detail: PackObjectDetail,
    cursor: str | None,
    limit: int | None,
) -> dict[str, Any]:
    """Collect and shape a direct-HTTP Pack section."""
    raw = await _collect_pack_http_objects(
        client,
        security=security,
        timeout_ms=timeout_ms,
        pack_id=pack_id,
        endpoint_path=endpoint_path,
        server_url=server_url,
        object_id=object_id,
    )
    return _shape_pack_objects(
        raw,
        section_kind=section_kind,
        detail=detail,
        cursor=cursor,
        limit=limit,
    )


async def _gather_pack_http_categories(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    security: Security,
    endpoints: Mapping[str, str],
    category_names: Mapping[str, str],
    timeout_ms: int,
    pack_id: str,
    server_url: str | None,
    detail: PackObjectDetail,
    cursor: str | None,
    limit: int | None,
) -> dict[str, dict[str, Any]]:
    """Collect direct-HTTP Pack categories and return them keyed by friendly category name."""
    results = await asyncio.gather(
        *[
            _collect_shaped_http_section(
                client,
                security=security,
                section_kind=endpoint_kind,
                endpoint_path=endpoint_path,
                timeout_ms=timeout_ms,
                pack_id=pack_id,
                server_url=server_url,
                object_id=None,
                detail=detail,
                cursor=cursor,
                limit=limit,
            )
            for endpoint_kind, endpoint_path in endpoints.items()
        ]
    )
    return {category_names[endpoint_kind]: category for endpoint_kind, category in zip(endpoints, results, strict=True)}


def _require_security(security: Security | None) -> Security:
    """Return direct-HTTP security or fail with a clear validation error."""
    if security is not None:
        return security
    msg = "security is required for HTTP-backed Pack kinds"
    raise ValueError(msg)


def _aggregate_kind(kind: PackObjectKind | None) -> bool:
    """Return whether a Pack kind targets a multi-section aggregate."""
    return kind in (None, "knowledge", "settings")


def _validate_pack_detail_request(
    *,
    kind: PackObjectKind | None,
    detail: PackObjectDetail,
    cursor: str | None,
    limit: int | None,
) -> None:
    """Validate options that only make sense for one concrete Pack section."""
    if _aggregate_kind(kind) and (cursor is not None or limit is not None):
        msg = "cursor and limit are only supported when kind names one Pack section or category."
        raise ValueError(msg)
    if _aggregate_kind(kind) and detail == "full":
        msg = "detail='full' is only supported when kind names one Pack section or category."
        raise ValueError(msg)


def _metadata_failure_response(
    metadata: dict[str, Any],
    *,
    pack_id: str,
    detail: PackObjectDetail,
    kind: PackObjectKind | None,
) -> dict[str, Any] | None:
    """Return a short-circuit payload when Pack metadata lookup failed."""
    status = metadata.get("status")
    if status == "ok":
        return None
    response: dict[str, Any] = {
        "status": status if isinstance(status, str) else "error",
        "pack_id": pack_id,
        "detail": detail,
        "metadata": metadata,
    }
    if kind is not None:
        response["kind"] = kind
        response["objects"] = _group_pack_categories({}, detail=detail)
    else:
        response["sections"] = {}
    return response


def _validate_install_pack_request(request: Mapping[str, Any]) -> Mapping[str, Any]:
    """Reject unknown Pack install request fields before invoking the SDK."""
    unknown_fields = sorted(field for field in request if field not in _INSTALL_REQUEST_FIELDS)
    if unknown_fields:
        allowed = ", ".join(sorted(_INSTALL_REQUEST_FIELDS))
        unknown = ", ".join(unknown_fields)
        msg = f"Unsupported Pack install request field(s): {unknown}. Allowed fields: {allowed}."
        raise ValueError(msg)
    return request


def _pack_update_kwargs(
    *,
    pack_id: str,
    request: PackUpdateRequest,
    timeout_ms: int,
    server_url: str | None,
) -> dict[str, Any]:
    """Build Pack update SDK kwargs without forwarding unset optional fields."""
    kwargs = {
        "id": pack_id,
        "source": request.source,
        **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
    }
    options = request.options
    if options.allow_custom_functions is not None:
        kwargs["allow_custom_functions"] = options.allow_custom_functions
    if options.minor is not None:
        kwargs["minor"] = options.minor
    if options.spec is not None:
        kwargs["spec"] = options.spec
    return kwargs


def _resolve_pack_file(file_path: str | Path) -> Path:
    """Return an existing Pack file path or raise a clear error."""
    path = Path(file_path).expanduser()
    if not path.is_file():
        msg = f"Pack file not found: {path}"
        raise ValueError(msg)
    if path.suffix.lower() != ".crbl":
        msg = f"Invalid Pack file extension: {path.suffix}. Expected .crbl"
        raise ValueError(msg)
    return path


def _normalize_group_text(value: object) -> str | None:
    """Normalize group metadata values into comparable strings."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _matching_groups(
    groups: list[dict[str, Any]],
    *,
    selector: str,
    field: GroupMatchField,
    case_sensitive: bool,
) -> list[dict[str, Any]]:
    """Return all groups whose selected field matches the selector."""
    expected = selector if case_sensitive else selector.casefold()
    matches: list[dict[str, Any]] = []
    for group in groups:
        actual = _normalize_group_text(group.get(field))
        if actual is None:
            continue
        candidate = actual if case_sensitive else actual.casefold()
        if candidate == expected:
            matches.append(group)
    return matches


def _select_group_match(
    groups: list[dict[str, Any]],
    *,
    selector: str,
    product: ProductsCore,
) -> tuple[dict[str, Any], GroupMatchField] | None:
    """Find the best matching distributed group by id, name, or description."""
    # Prefer exact/case-sensitive matches before broader case-insensitive matches.
    # Within each pass, stable identifiers intentionally win over display metadata.
    for case_sensitive in (True, False):
        for match_field in ("id", "name", "description"):
            matches = _matching_groups(
                groups,
                selector=selector,
                field=match_field,
                case_sensitive=case_sensitive,
            )
            if len(matches) == 1:
                return matches[0], match_field
            if len(matches) > 1:
                msg = f"Group selector '{selector}' matched multiple {product.value} groups by {match_field}."
                raise ValueError(msg)
    return None


async def resolve_pack_group_scope(
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    group: str,
    timeout_ms: int,
) -> ResolvedPackGroupScope:
    """Resolve a distributed Pack group selector into a group-scoped SDK server URL."""
    normalized_group = group.strip()
    if not normalized_group:
        msg = "group must not be blank when scoping Pack tools to a distributed group."
        raise ValueError(msg)

    groups = await list_groups_minimal(client, product=product, timeout_ms=timeout_ms)
    matched = _select_group_match(groups, selector=normalized_group, product=product)
    if matched is None:
        msg = f"Could not resolve group selector '{normalized_group}' for product '{product.value}'."
        raise ValueError(msg)

    matched_group, matched_by = matched
    group_id = extract_group_id(matched_group)
    if group_id is None:
        msg = f"Resolved group selector '{normalized_group}' but the matching group did not include an id."
        raise ValueError(msg)

    return ResolvedPackGroupScope(
        product=product,
        group_selector=normalized_group,
        group_id=group_id,
        matched_by=matched_by,
        group_name=_normalize_group_text(matched_group.get("name")),
        group_description=_normalize_group_text(matched_group.get("description")),
        server_url=get_group_url(client, group_id),
    )


async def collect_packs(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    with_: str | None = None,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Fetch installed Packs, optionally against a group-scoped Pack API URL.

    Args:
        client: The Cribl Control Plane client.
        timeout_ms: Request timeout in milliseconds.
        with_: Optional comma-separated properties to count in the response.
        server_url: Optional group-scoped SDK server URL.

    Returns:
        Serialized counted Pack response.

    """
    return await _run_pack_api_call(
        lambda: client.packs.list_async(
            with_=with_,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )


async def get_pack(  # noqa: PLR0911, PLR0913
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None = None,
    security: Security | None = None,
    kind: PackObjectKind | None = None,
    object_id: str | None = None,
    detail: PackObjectDetail = "summary",
    cursor: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Fetch one installed Pack by ID or drill into objects contained by it."""
    if object_id is not None and kind == "knowledge":
        msg = "Use a concrete knowledge kind such as 'knowledge.lookups' when object_id is provided."
        raise ValueError(msg)
    if object_id is not None and kind == "settings":
        msg = "Use a concrete settings kind such as 'settings.conf' when object_id is provided."
        raise ValueError(msg)
    if (
        kind not in (None, "knowledge", "settings")
        and kind not in _SDK_SECTION_TO_CONFIG_KIND
        and kind not in _KNOWLEDGE_ENDPOINTS
        and kind not in _SETTINGS_ENDPOINTS
    ):
        msg = f"Unsupported Pack object kind: {kind}"
        raise ValueError(msg)
    _validate_pack_detail_request(kind=kind, detail=detail, cursor=cursor, limit=limit)

    if kind in _SDK_SECTION_TO_CONFIG_KIND:
        objects = await _collect_shaped_sdk_section(
            client,
            section_kind=cast("Literal['sources', 'destinations', 'pipelines', 'routes']", kind),
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=object_id,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        return {
            "status": objects.get("status", "ok"),
            "pack_id": pack_id,
            "kind": kind,
            "object_id": object_id,
            "objects": objects,
        }

    http_security = _require_security(security)
    if kind in _KNOWLEDGE_ENDPOINTS:
        objects = await _collect_shaped_http_section(
            client,
            security=http_security,
            section_kind=kind,
            endpoint_path=_KNOWLEDGE_ENDPOINTS[kind],
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=object_id,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        return {
            "status": objects.get("status", "ok"),
            "pack_id": pack_id,
            "kind": kind,
            "object_id": object_id,
            "objects": objects,
        }

    if kind in _SETTINGS_ENDPOINTS:
        objects = await _collect_shaped_http_section(
            client,
            security=http_security,
            section_kind=kind,
            endpoint_path=_SETTINGS_ENDPOINTS[kind],
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=object_id,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        return {
            "status": objects.get("status", "ok"),
            "pack_id": pack_id,
            "kind": kind,
            "object_id": object_id,
            "objects": objects,
        }

    metadata = await _run_pack_api_call(
        lambda: client.packs.get_async(
            id=pack_id,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )
    metadata_failure = _metadata_failure_response(metadata, pack_id=pack_id, detail=detail, kind=kind)
    if metadata_failure is not None:
        return metadata_failure

    if kind == "knowledge":
        knowledge_categories = await _gather_pack_http_categories(
            client,
            security=http_security,
            endpoints=_KNOWLEDGE_ENDPOINTS,
            category_names=_KNOWLEDGE_CATEGORY_NAMES,
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        objects = _group_pack_categories(knowledge_categories, detail=detail)
        return {
            "status": objects["status"],
            "pack_id": pack_id,
            "kind": kind,
            "metadata": metadata,
            "objects": objects,
        }

    if kind == "settings":
        settings_categories = await _gather_pack_http_categories(
            client,
            security=http_security,
            endpoints=_SETTINGS_ENDPOINTS,
            category_names=_SETTINGS_CATEGORY_NAMES,
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        objects = _group_pack_categories(settings_categories, detail=detail)
        return {
            "status": objects["status"],
            "pack_id": pack_id,
            "kind": kind,
            "metadata": metadata,
            "objects": objects,
        }

    sources, destinations, pipelines, routes, knowledge_categories, settings_categories = await asyncio.gather(
        _collect_shaped_sdk_section(
            client,
            section_kind="sources",
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=None,
            detail=detail,
            cursor=None,
            limit=None,
        ),
        _collect_shaped_sdk_section(
            client,
            section_kind="destinations",
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=None,
            detail=detail,
            cursor=None,
            limit=None,
        ),
        _collect_shaped_sdk_section(
            client,
            section_kind="pipelines",
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=None,
            detail=detail,
            cursor=None,
            limit=None,
        ),
        _collect_shaped_sdk_section(
            client,
            section_kind="routes",
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            object_id=None,
            detail=detail,
            cursor=None,
            limit=None,
        ),
        _gather_pack_http_categories(
            client,
            security=http_security,
            endpoints=_KNOWLEDGE_ENDPOINTS,
            category_names=_KNOWLEDGE_CATEGORY_NAMES,
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            detail=detail,
            cursor=None,
            limit=None,
        ),
        _gather_pack_http_categories(
            client,
            security=http_security,
            endpoints=_SETTINGS_ENDPOINTS,
            category_names=_SETTINGS_CATEGORY_NAMES,
            timeout_ms=timeout_ms,
            pack_id=pack_id,
            server_url=server_url,
            detail=detail,
            cursor=None,
            limit=None,
        ),
    )

    sections = {
        "sources": sources,
        "destinations": destinations,
        "pipelines": pipelines,
        "routes": routes,
        "knowledge": _group_pack_categories(knowledge_categories, detail=detail),
        "settings": _group_pack_categories(settings_categories, detail=detail),
    }
    section_statuses = [section.get("status") for section in sections.values()]
    has_error = any(status not in ("ok", "unavailable", "partial_unavailable") for status in section_statuses)
    has_unavailable = any(status in ("unavailable", "partial_unavailable") for status in section_statuses)
    return {
        "status": "partial_error" if has_error else "partial_unavailable" if has_unavailable else "ok",
        "pack_id": pack_id,
        "detail": detail,
        "metadata": metadata,
        "sections": sections,
    }


async def install_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    request: Mapping[str, Any],
    server_url: str | None = None,
) -> dict[str, Any]:
    """Install a Pack from an ID/source request body."""
    validated_request = _validate_install_pack_request(request)
    return await _run_pack_api_call(
        lambda: client.packs.install_async(
            request=cast("Any", validated_request),
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )


async def upload_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    file_path: str | Path,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Upload a local Pack file and return the install source returned by Cribl."""
    path = _resolve_pack_file(file_path)
    request_body = await asyncio.to_thread(path.read_bytes)

    return await _run_pack_api_call(
        lambda: client.packs.upload_async(
            filename=path.name,
            request_body=request_body,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_single_response,
        resource_type="packs",
        server_url=server_url,
    )


async def update_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    request: PackUpdateRequest,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Upgrade an installed Pack from a source URL or uploaded source ID."""
    return await _run_pack_api_call(
        lambda: client.packs.update_async(
            **_pack_update_kwargs(
                pack_id=pack_id,
                request=request,
                timeout_ms=timeout_ms,
                server_url=server_url,
            ),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )


async def delete_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Uninstall an installed Pack by ID."""
    return await _run_pack_api_call(
        lambda: client.packs.delete_async(
            id=pack_id,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )


__all__ = [
    "PackObjectDetail",
    "PackObjectKind",
    "PackUpdateRequest",
    "PackUpgradeOptions",
    "ResolvedPackGroupScope",
    "collect_packs",
    "delete_pack",
    "get_pack",
    "install_pack",
    "resolve_pack_group_scope",
    "update_pack",
    "upload_pack",
]
