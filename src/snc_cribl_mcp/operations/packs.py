"""Helpers for managing top-level Cribl Packs."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.errors import CriblControlPlaneError, ResponseValidationError
from cribl_control_plane.models.productscore import ProductsCore
from pydantic import ValidationError

from .common import (
    HTTP_NOT_FOUND,
    build_unavailable_result,
    extract_group_id,
    get_group_url,
    list_groups_minimal,
    serialize_model,
)
from .validation_errors import format_validation_error_response, parse_validation_error

type GroupMatchField = Literal["description", "id", "name"]
type PackApiCall = Callable[[], Awaitable[object]]
type PackSerializer = Callable[[object], dict[str, Any]]

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
    """Serialize an SDK counted response into the MCP response shape."""
    raw_items: list[object] = getattr(response, "items", None) or []
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


def _pack_call_kwargs(*, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
    """Build SDK call kwargs, preserving existing top-level behavior when unscoped."""
    kwargs: dict[str, Any] = {"timeout_ms": timeout_ms}
    if server_url is not None:
        kwargs["server_url"] = server_url
    return kwargs


def _pack_scope_label(server_url: str | None) -> str:
    """Return a short label for top-level versus group-scoped Pack API calls."""
    return "group-scoped" if server_url is not None else "top-level"


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


async def get_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Fetch one installed Pack by ID."""
    return await _run_pack_api_call(
        lambda: client.packs.get_async(
            id=pack_id,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        ),
        serializer=_serialize_counted_response,
        resource_type="packs",
        server_url=server_url,
    )


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
