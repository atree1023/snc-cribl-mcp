"""Context-free CRUD helpers backed by the Cribl Control Plane SDK.

These helpers are intentionally independent of FastMCP ``Context`` so they can
be reused by aggregate processes such as cross-leader copy and sync
validation.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from copy import deepcopy
from dataclasses import dataclass
from functools import cache
from typing import Any, Literal, cast
from urllib.parse import quote

import httpx
from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security

from .common import get_auth_headers, get_group_url, serialize_model

type CrudAction = Literal["append", "create", "delete", "deploy", "get", "list", "update"]
type JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None
type ResourceKind = Literal[
    "breakers",
    "destinations",
    "groups",
    "lookups",
    "pipelines",
    "routes",
    "sources",
    "variables",
]
type ResourceScope = Literal["group", "product"]
type ResourceTransport = Literal["http", "sdk"]

_DUMMY_CLIENT = CriblControlPlane(server_url="https://example.invalid")
_METHOD_NAME_BY_ACTION: dict[CrudAction, str] = {
    "append": "append_async",
    "create": "create_async",
    "delete": "delete_async",
    "deploy": "deploy_async",
    "get": "get_async",
    "list": "list_async",
    "update": "update_async",
}
_METHOD_INFRASTRUCTURE_PARAMS = {
    "http_headers",
    "product",
    "retries",
    "self",
    "server_url",
    "timeout_ms",
}
_CAMEL_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """Describe the SDK surface for a managed Cribl resource."""

    kind: ResourceKind
    client_attr: str | None
    scope: ResourceScope
    supported_actions: frozenset[CrudAction]
    transport: ResourceTransport = "sdk"
    endpoint_path: str | None = None

    def supports(self, action: CrudAction) -> bool:
        """Return whether the SDK exposes the given action for this resource."""
        return action in self.supported_actions


RESOURCE_SPECS: dict[ResourceKind, ResourceSpec] = {
    "groups": ResourceSpec(
        kind="groups",
        client_attr="groups",
        scope="product",
        supported_actions=frozenset({"create", "delete", "deploy", "get", "list", "update"}),
    ),
    "sources": ResourceSpec(
        kind="sources",
        client_attr="sources",
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
    ),
    "destinations": ResourceSpec(
        kind="destinations",
        client_attr="destinations",
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
    ),
    "pipelines": ResourceSpec(
        kind="pipelines",
        client_attr="pipelines",
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
    ),
    "routes": ResourceSpec(
        kind="routes",
        client_attr="routes",
        scope="group",
        supported_actions=frozenset({"append", "get", "list", "update"}),
    ),
    "breakers": ResourceSpec(
        kind="breakers",
        client_attr=None,
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
        transport="http",
        endpoint_path="lib/breakers",
    ),
    "lookups": ResourceSpec(
        kind="lookups",
        client_attr=None,
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
        transport="http",
        endpoint_path="system/lookups",
    ),
    "variables": ResourceSpec(
        kind="variables",
        client_attr=None,
        scope="group",
        supported_actions=frozenset({"create", "delete", "get", "list", "update"}),
        transport="http",
        endpoint_path="lib/vars",
    ),
}


def get_resource_spec(kind: ResourceKind) -> ResourceSpec:
    """Return the static SDK spec for the given resource kind."""
    return RESOURCE_SPECS[kind]


@cache
def _allowed_method_params(kind: ResourceKind, action: CrudAction) -> frozenset[str]:
    """Return the accepted SDK parameter names for a resource action."""
    method_name = _METHOD_NAME_BY_ACTION[action]
    client_attr = RESOURCE_SPECS[kind].client_attr
    if client_attr is None:
        msg = f"Resource kind '{kind}' is not backed by an SDK component."
        raise ValueError(msg)
    component = getattr(_DUMMY_CLIENT, client_attr)
    method = getattr(component, method_name)
    params = set(inspect.signature(method).parameters)
    return frozenset(params - _METHOD_INFRASTRUCTURE_PARAMS)


def build_sdk_capability_matrix() -> dict[ResourceKind, dict[str, bool | str]]:
    """Describe the currently installed SDK capability surface."""
    matrix: dict[ResourceKind, dict[str, bool | str]] = {}
    for kind, spec in RESOURCE_SPECS.items():
        component = getattr(_DUMMY_CLIENT, spec.client_attr) if spec.client_attr is not None else None
        matrix[kind] = {
            "scope": spec.scope,
            "transport": spec.transport,
            "list": spec.supports("list") if component is None else hasattr(component, "list_async"),
            "get": spec.supports("get") if component is None else hasattr(component, "get_async"),
            "create": spec.supports("create") if component is None else hasattr(component, "create_async"),
            "update": spec.supports("update") if component is None else hasattr(component, "update_async"),
            "append": spec.supports("append") if component is None else hasattr(component, "append_async"),
            "delete": spec.supports("delete") if component is None else hasattr(component, "delete_async"),
            "deploy": spec.supports("deploy") if component is None else hasattr(component, "deploy_async"),
        }
    return matrix


def _camel_to_snake(name: str) -> str:
    """Convert lower/upper camel case SDK output keys to snake_case kwargs."""
    if name == "type":
        return "type_"
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def _strip_none_and_copy(value: JsonValue) -> JsonValue:
    """Deep-copy a structure while removing keys with ``None`` values."""
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        typed_value = cast("dict[str, JsonValue]", value)
        for key, val in typed_value.items():
            if val is not None:
                result[key] = _strip_none_and_copy(val)
        return result
    if isinstance(value, list):
        typed_value = cast("list[JsonValue]", value)
        return [_strip_none_and_copy(item) for item in typed_value]
    return deepcopy(value)


def _normalize_keyword_payload(kind: ResourceKind, action: CrudAction, item: dict[str, Any]) -> dict[str, Any]:
    """Normalize item data into explicit SDK keyword arguments."""
    normalized = {_camel_to_snake(str(key)): _strip_none_and_copy(value) for key, value in item.items() if value is not None}
    allowed = _allowed_method_params(kind, action)
    return {key: value for key, value in normalized.items() if key in allowed}


def _build_create_kwargs(kind: ResourceKind, item: dict[str, Any]) -> dict[str, Any]:
    """Build SDK create kwargs from a serialized resource item."""
    clean_item = cast("dict[str, Any]", _strip_none_and_copy(item))
    if kind == "groups":
        return _normalize_keyword_payload(kind, "create", clean_item)
    if kind == "sources":
        return {"request": clean_item}
    if kind == "destinations":
        return {"request": clean_item}
    if kind == "pipelines":
        return {
            "id": str(clean_item["id"]),
            "conf": cast("dict[str, Any]", clean_item["conf"]),
        }
    msg = f"Create is not supported for resource kind '{kind}'."
    raise ValueError(msg)


def _build_update_kwargs(kind: ResourceKind, item_id: str, item: dict[str, Any]) -> dict[str, Any]:
    """Build SDK update kwargs from a serialized resource item."""
    clean_item = cast("dict[str, Any]", _strip_none_and_copy(item))
    if kind == "groups":
        kwargs = _normalize_keyword_payload(kind, "update", clean_item)
        kwargs["id_param"] = item_id
        kwargs["id"] = str(clean_item.get("id", item_id))
        return kwargs
    if kind == "sources":
        return {"id": item_id, "input_": clean_item}
    if kind == "destinations":
        return {"id": item_id, "output": clean_item}
    if kind == "pipelines":
        return {
            "id_param": item_id,
            "id": str(clean_item.get("id", item_id)),
            "conf": cast("dict[str, Any]", clean_item["conf"]),
        }
    if kind == "routes":
        return {
            "id_param": item_id,
            "id": str(clean_item.get("id", item_id)),
            "routes": cast("list[dict[str, Any]]", clean_item.get("routes", [])),
            "comments": cast("list[dict[str, Any]]", clean_item.get("comments", [])),
            "groups": cast("dict[str, Any]", clean_item.get("groups", {})),
        }
    msg = f"Update is not supported for resource kind '{kind}'."
    raise ValueError(msg)


def _build_append_kwargs(item_id: str, item: dict[str, Any]) -> dict[str, Any]:
    """Build SDK append kwargs for route collections."""
    clean_item = cast("dict[str, Any]", _strip_none_and_copy(item))
    return {
        "id": item_id,
        "request_body": cast("list[dict[str, Any]]", clean_item.get("routes", [])),
    }


def canonicalize_resource_item(kind: ResourceKind, item: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911
    """Project a resource into a stable, comparable config payload."""
    clean_item = cast("dict[str, Any]", _strip_none_and_copy(item))
    if kind in {"breakers", "variables"}:
        return clean_item
    if kind == "lookups":
        volatile_lookup_keys = {"_content", "_content_type", "pendingTask", "rows"}
        return {key: value for key, value in clean_item.items() if key not in volatile_lookup_keys}
    if kind == "routes":
        compare_payload = _build_update_kwargs(kind, str(clean_item["id"]), clean_item)
        compare_payload.pop("id_param", None)
        return compare_payload
    if kind == "groups":
        return _build_create_kwargs(kind, clean_item)
    if kind == "sources":
        return cast("dict[str, Any]", _build_create_kwargs(kind, clean_item)["request"])
    if kind == "destinations":
        return cast("dict[str, Any]", _build_create_kwargs(kind, clean_item)["request"])
    if kind == "pipelines":
        return _build_create_kwargs(kind, clean_item)
    msg = f"Unsupported resource kind '{kind}'."
    raise ValueError(msg)


def _component(client: CriblControlPlane, kind: ResourceKind) -> object:
    """Return the SDK component object for the given resource kind."""
    client_attr = RESOURCE_SPECS[kind].client_attr
    if client_attr is None:
        msg = f"Resource kind '{kind}' is not backed by an SDK component."
        raise ValueError(msg)
    return getattr(client, client_attr)


def _base_call_kwargs(
    client: CriblControlPlane,
    spec: ResourceSpec,
    *,
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
) -> dict[str, Any]:
    """Build shared SDK kwargs for product- or group-scoped operations."""
    kwargs: dict[str, Any] = {"timeout_ms": timeout_ms}
    if spec.scope == "product":
        if product is None:
            msg = f"Resource kind '{spec.kind}' requires a product."
            raise ValueError(msg)
        kwargs["product"] = product
        return kwargs

    if group_id is None:
        msg = f"Resource kind '{spec.kind}' requires a group_id."
        raise ValueError(msg)
    kwargs["server_url"] = get_group_url(client, group_id)
    return kwargs


def _serialize_items(response: object) -> list[dict[str, Any]]:
    """Serialize a counted SDK response into plain dictionaries."""
    raw_items = cast("list[object] | None", getattr(response, "items", None)) or []
    return [serialize_model(item) for item in raw_items]


def _require_security(kind: ResourceKind, security: Security | None) -> Security:
    """Return bearer security for direct HTTP resources or raise a clear error."""
    if security is None:
        msg = f"Resource kind '{kind}' requires direct HTTP security."
        raise ValueError(msg)
    return security


def _require_http_spec(kind: ResourceKind) -> ResourceSpec:
    """Return a direct-HTTP resource spec."""
    spec = get_resource_spec(kind)
    if spec.transport != "http" or spec.endpoint_path is None:
        msg = f"Resource kind '{kind}' is not a direct HTTP resource."
        raise ValueError(msg)
    return spec


def _http_client(client: CriblControlPlane) -> httpx.AsyncClient:
    """Return the SDK's underlying httpx client for direct HTTP requests."""
    http_client = client.sdk_configuration.async_client
    if not isinstance(http_client, httpx.AsyncClient):
        msg = "Cribl SDK client does not expose an httpx.AsyncClient."
        raise TypeError(msg)
    return http_client


def _direct_collection_url(client: CriblControlPlane, spec: ResourceSpec, group_id: str | None) -> str:
    """Return the collection URL for a group-scoped direct resource."""
    if group_id is None:
        msg = f"Resource kind '{spec.kind}' requires a group_id."
        raise ValueError(msg)
    return f"{get_group_url(client, group_id).rstrip('/')}/{spec.endpoint_path}"


def _direct_item_url(client: CriblControlPlane, spec: ResourceSpec, group_id: str | None, item_id: str) -> str:
    """Return the item URL for a group-scoped direct resource."""
    encoded_id = quote(item_id, safe="")
    return f"{_direct_collection_url(client, spec, group_id)}/{encoded_id}"


def _response_items(payload: object) -> list[dict[str, Any]]:
    """Extract a standard Cribl `items` array from a JSON payload."""
    if isinstance(payload, dict):
        payload_dict = cast("dict[str, object]", payload)
        items = payload_dict.get("items", [])
        if isinstance(items, list):
            typed_items = cast("list[object]", items)
            return [cast("dict[str, Any]", item) for item in typed_items if isinstance(item, dict)]
    return []


async def _direct_request_json(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    method: str,
    url: str,
    security: Security,
    timeout_ms: int,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Perform a direct JSON request through the SDK-owned HTTP client."""
    response = await _http_client(client).request(
        method,
        url,
        headers={**get_auth_headers(security), "Content-Type": "application/json"},
        json=json_body,
        timeout=timeout_ms / 1000,
    )
    response.raise_for_status()
    payload = response.json()
    return cast("dict[str, Any]", payload) if isinstance(payload, dict) else {}


async def _hydrate_lookup_content(
    client: CriblControlPlane,
    *,
    group_id: str | None,
    item: dict[str, Any],
    security: Security,
    timeout_ms: int,
) -> dict[str, Any]:
    """Attach raw lookup content so lookups can be copied and compared."""
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        return item

    spec = _require_http_spec("lookups")
    url = f"{_direct_item_url(client, spec, group_id, item_id)}/content?raw=1"
    response = await _http_client(client).get(
        url,
        headers=get_auth_headers(security),
        timeout=timeout_ms / 1000,
    )
    response.raise_for_status()
    hydrated = dict(item)
    hydrated["_content"] = response.content.decode(response.encoding or "utf-8")
    hydrated["_content_type"] = response.headers.get("content-type", "text/csv").split(";", maxsplit=1)[0]
    return hydrated


async def _direct_list_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    timeout_ms: int,
    security: Security,
    group_id: str | None,
    hydrate_lookup_content: bool,
) -> list[dict[str, Any]]:
    """List a direct-HTTP resource in a group scope."""
    spec = _require_http_spec(kind)
    payload = await _direct_request_json(
        client,
        method="GET",
        url=_direct_collection_url(client, spec, group_id),
        security=security,
        timeout_ms=timeout_ms,
    )
    items = _response_items(payload)
    if kind == "lookups" and hydrate_lookup_content:
        return list(
            await asyncio.gather(
                *(
                    _hydrate_lookup_content(
                        client,
                        group_id=group_id,
                        item=item,
                        security=security,
                        timeout_ms=timeout_ms,
                    )
                    for item in items
                )
            )
        )
    return items


async def _direct_get_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    timeout_ms: int,
    security: Security,
    group_id: str | None,
    hydrate_lookup_content: bool,
) -> dict[str, Any]:
    """Fetch one direct-HTTP resource item."""
    spec = _require_http_spec(kind)
    payload = await _direct_request_json(
        client,
        method="GET",
        url=_direct_item_url(client, spec, group_id, item_id),
        security=security,
        timeout_ms=timeout_ms,
    )
    items = _response_items(payload)
    if not items:
        msg = f"Resource '{kind}' with id '{item_id}' returned no items."
        raise RuntimeError(msg)
    item = items[0]
    if kind == "lookups" and hydrate_lookup_content:
        return await _hydrate_lookup_content(
            client,
            group_id=group_id,
            item=item,
            security=security,
            timeout_ms=timeout_ms,
        )
    return item


async def _upload_lookup_content(
    client: CriblControlPlane,
    *,
    item: dict[str, Any],
    timeout_ms: int,
    security: Security,
    group_id: str | None,
) -> str:
    """Upload lookup content and return the temporary filename from Cribl."""
    item_id = str(item["id"])
    content = item.get("_content")
    if not isinstance(content, str):
        msg = f"Lookup '{item_id}' does not include downloadable content."
        raise TypeError(msg)

    spec = _require_http_spec("lookups")
    response = await _http_client(client).put(
        _direct_collection_url(client, spec, group_id),
        params={"filename": item_id},
        headers={**get_auth_headers(security), "Content-Type": str(item.get("_content_type") or "text/csv")},
        content=content.encode("utf-8"),
        timeout=timeout_ms / 1000,
    )
    response.raise_for_status()
    payload = cast("dict[str, object]", response.json())
    filename = payload.get("filename")
    if not isinstance(filename, str) or not filename:
        msg = f"Lookup upload for '{item_id}' did not return a temporary filename."
        raise RuntimeError(msg)
    return filename


def _lookup_write_payload(item: dict[str, Any], uploaded_filename: str) -> dict[str, Any]:
    """Build a create/update body for a lookup from hydrated metadata."""
    ignored = {"_content", "_content_type", "fileInfo", "pendingTask", "rows", "size", "version"}
    payload = {key: value for key, value in item.items() if key not in ignored and value is not None}
    payload["id"] = str(item["id"])
    # Cribl requires the temporary upload name here, not the source lookup's original fileInfo metadata.
    payload["fileInfo"] = {"filename": uploaded_filename}
    return payload


async def _direct_write_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    action: Literal["create", "update"],
    item: dict[str, Any],
    timeout_ms: int,
    security: Security,
    group_id: str | None,
    item_id: str | None = None,
) -> list[dict[str, Any]]:
    """Create or update one direct-HTTP resource."""
    spec = _require_http_spec(kind)
    if kind == "lookups":
        uploaded_filename = await _upload_lookup_content(
            client,
            item=item,
            timeout_ms=timeout_ms,
            security=security,
            group_id=group_id,
        )
        body = _lookup_write_payload(item, uploaded_filename)
    else:
        body = cast("dict[str, Any]", _strip_none_and_copy(item))

    if action == "create":
        url = _direct_collection_url(client, spec, group_id)
        method = "POST"
    else:
        resolved_item_id = item_id or str(item["id"])
        url = _direct_item_url(client, spec, group_id, resolved_item_id)
        method = "PATCH"

    payload = await _direct_request_json(
        client,
        method=method,
        url=url,
        security=security,
        timeout_ms=timeout_ms,
        json_body=body,
    )
    return _response_items(payload)


async def list_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    security: Security | None = None,
    hydrate_lookup_content: bool = False,
) -> list[dict[str, Any]]:
    """List resource items within the requested scope."""
    spec = get_resource_spec(kind)
    if spec.transport == "http":
        return await _direct_list_resource(
            client,
            kind,
            timeout_ms=timeout_ms,
            security=_require_security(kind, security),
            group_id=group_id,
            hydrate_lookup_content=hydrate_lookup_content,
        )

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["list"])
    response = await method(**_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product, group_id=group_id))
    return _serialize_items(response)


async def get_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    security: Security | None = None,
    hydrate_lookup_content: bool = False,
) -> dict[str, Any]:
    """Fetch one resource item by id."""
    spec = get_resource_spec(kind)
    if spec.transport == "http":
        return await _direct_get_resource(
            client,
            kind,
            item_id=item_id,
            timeout_ms=timeout_ms,
            security=_require_security(kind, security),
            group_id=group_id,
            hydrate_lookup_content=hydrate_lookup_content,
        )

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["get"])
    response = await method(
        id=item_id,
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product, group_id=group_id),
    )
    items = _serialize_items(response)
    if not items:
        msg = f"Resource '{kind}' with id '{item_id}' returned no items."
        raise RuntimeError(msg)
    return items[0]


async def create_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item: dict[str, Any],
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    security: Security | None = None,
) -> list[dict[str, Any]]:
    """Create a resource from serialized item data."""
    spec = get_resource_spec(kind)
    if not spec.supports("create"):
        msg = f"Create is not supported for resource kind '{kind}'."
        raise ValueError(msg)
    if spec.transport == "http":
        return await _direct_write_resource(
            client,
            kind,
            action="create",
            item=item,
            timeout_ms=timeout_ms,
            security=_require_security(kind, security),
            group_id=group_id,
        )

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["create"])
    response = await method(
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product, group_id=group_id),
        **_build_create_kwargs(kind, item),
    )
    return _serialize_items(response)


async def update_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    item: dict[str, Any],
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    security: Security | None = None,
) -> list[dict[str, Any]]:
    """Replace a resource with serialized item data."""
    spec = get_resource_spec(kind)
    if not spec.supports("update"):
        msg = f"Update is not supported for resource kind '{kind}'."
        raise ValueError(msg)
    if spec.transport == "http":
        return await _direct_write_resource(
            client,
            kind,
            action="update",
            item_id=item_id,
            item=item,
            timeout_ms=timeout_ms,
            security=_require_security(kind, security),
            group_id=group_id,
        )

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["update"])
    response = await method(
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product, group_id=group_id),
        **_build_update_kwargs(kind, item_id, item),
    )
    return _serialize_items(response)


async def append_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    item: dict[str, Any],
    timeout_ms: int,
    group_id: str,
) -> list[dict[str, Any]]:
    """Append route definitions to an existing route set."""
    spec = get_resource_spec(kind)
    if not spec.supports("append"):
        msg = f"Append is not supported for resource kind '{kind}'."
        raise ValueError(msg)

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["append"])
    response = await method(
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, group_id=group_id),
        **_build_append_kwargs(item_id, item),
    )
    return _serialize_items(response)


async def delete_resource(  # noqa: PLR0913
    client: CriblControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    timeout_ms: int,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    security: Security | None = None,
) -> list[dict[str, Any]]:
    """Delete a resource by id."""
    spec = get_resource_spec(kind)
    if not spec.supports("delete"):
        msg = f"Delete is not supported for resource kind '{kind}'."
        raise ValueError(msg)
    if spec.transport == "http":
        payload = await _direct_request_json(
            client,
            method="DELETE",
            url=_direct_item_url(client, spec, group_id, item_id),
            security=_require_security(kind, security),
            timeout_ms=timeout_ms,
        )
        return _response_items(payload)

    component = _component(client, kind)
    method = getattr(component, _METHOD_NAME_BY_ACTION["delete"])
    response = await method(
        id=item_id,
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product, group_id=group_id),
    )
    return _serialize_items(response)


async def deploy_group(  # noqa: PLR0913
    client: CriblControlPlane,
    *,
    product: ProductsCore,
    group_id: str,
    version: str,
    timeout_ms: int,
    lookups: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Deploy a group version using the SDK's group deploy operation."""
    spec = get_resource_spec("groups")
    component = _component(client, "groups")
    method = getattr(component, _METHOD_NAME_BY_ACTION["deploy"])
    response = await method(
        id=group_id,
        version=version,
        lookups=lookups,
        **_base_call_kwargs(client, spec, timeout_ms=timeout_ms, product=product),
    )
    return _serialize_items(response)


__all__ = [
    "RESOURCE_SPECS",
    "CrudAction",
    "ResourceKind",
    "ResourceScope",
    "ResourceSpec",
    "append_resource",
    "build_sdk_capability_matrix",
    "canonicalize_resource_item",
    "create_resource",
    "delete_resource",
    "deploy_group",
    "get_resource",
    "get_resource_spec",
    "list_resource",
    "update_resource",
]
