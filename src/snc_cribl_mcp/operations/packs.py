"""Helpers for managing top-level Cribl Packs."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore

from .common import extract_group_id, get_group_url, list_groups_minimal, serialize_model

type GroupMatchField = Literal["description", "id", "name"]


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
        msg = f"Could not resolve group selector '{group}' for product '{product.value}'."
        raise ValueError(msg)

    matched_group, matched_by = matched
    group_id = extract_group_id(matched_group)
    if group_id is None:
        msg = f"Resolved group selector '{group}' but the matching group did not include an id."
        raise ValueError(msg)

    return ResolvedPackGroupScope(
        product=product,
        group_selector=group,
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
    """Fetch all installed Packs.

    Args:
        client: The Cribl Control Plane client.
        timeout_ms: Request timeout in milliseconds.
        with_: Optional comma-separated properties to count in the response.
        server_url: Optional group-scoped SDK server URL.

    Returns:
        Serialized counted Pack response.

    """
    response = await client.packs.list_async(with_=with_, **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url))
    return _serialize_counted_response(response)


async def get_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Fetch one installed Pack by ID."""
    response = await client.packs.get_async(id=pack_id, **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url))
    return _serialize_counted_response(response)


async def install_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    request: Mapping[str, Any],
    server_url: str | None = None,
) -> dict[str, Any]:
    """Install a Pack from an ID/source request body."""
    response = await client.packs.install_async(
        request=cast("Any", request),
        **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
    )
    return _serialize_counted_response(response)


async def upload_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    file_path: str | Path,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Upload a local Pack file and return the install source returned by Cribl."""
    path = _resolve_pack_file(file_path)

    with path.open("rb") as request_body:
        response = await client.packs.upload_async(
            filename=path.name,
            request_body=request_body,
            **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
        )
    return _serialize_single_response(response)


async def update_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    request: PackUpdateRequest,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Upgrade an installed Pack from a source URL or uploaded source ID."""
    response = await client.packs.update_async(
        id=pack_id,
        source=request.source,
        allow_custom_functions=request.options.allow_custom_functions,
        minor=request.options.minor,
        spec=request.options.spec,
        **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url),
    )
    return _serialize_counted_response(response)


async def delete_pack(
    client: CriblControlPlane,
    *,
    timeout_ms: int,
    pack_id: str,
    server_url: str | None = None,
) -> dict[str, Any]:
    """Uninstall an installed Pack by ID."""
    response = await client.packs.delete_async(id=pack_id, **_pack_call_kwargs(timeout_ms=timeout_ms, server_url=server_url))
    return _serialize_counted_response(response)


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
