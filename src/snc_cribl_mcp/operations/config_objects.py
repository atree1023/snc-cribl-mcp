"""Consolidated config object retrieval and response shaping."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal, cast

type ConfigObjectKind = Literal[
    "breakers",
    "destinations",
    "groups",
    "lookups",
    "pipelines",
    "routes",
    "sources",
    "variables",
]
type ConfigObjectDetail = Literal["summary", "refs", "full"]

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 250


@dataclass(frozen=True, slots=True)
class ConfigObjectCatalogEntry:
    """Describe a supported Cribl config object kind."""

    kind: ConfigObjectKind
    scope: Literal["group", "product"]
    sdk_preferred: bool
    requires_security: bool
    description: str


CONFIG_OBJECT_CATALOG: dict[ConfigObjectKind, ConfigObjectCatalogEntry] = {
    "groups": ConfigObjectCatalogEntry(
        kind="groups",
        scope="product",
        sdk_preferred=True,
        requires_security=False,
        description="Stream worker groups and Edge fleets.",
    ),
    "sources": ConfigObjectCatalogEntry(
        kind="sources",
        scope="group",
        sdk_preferred=True,
        requires_security=False,
        description="Configured sources, including collector sources.",
    ),
    "destinations": ConfigObjectCatalogEntry(
        kind="destinations",
        scope="group",
        sdk_preferred=True,
        requires_security=False,
        description="Configured destinations.",
    ),
    "pipelines": ConfigObjectCatalogEntry(
        kind="pipelines",
        scope="group",
        sdk_preferred=True,
        requires_security=False,
        description="Configured pipelines and pipeline functions.",
    ),
    "routes": ConfigObjectCatalogEntry(
        kind="routes",
        scope="group",
        sdk_preferred=True,
        requires_security=False,
        description="Configured routing tables.",
    ),
    "breakers": ConfigObjectCatalogEntry(
        kind="breakers",
        scope="group",
        sdk_preferred=False,
        requires_security=True,
        description="Configured event breakers from direct API fallback.",
    ),
    "lookups": ConfigObjectCatalogEntry(
        kind="lookups",
        scope="group",
        sdk_preferred=False,
        requires_security=True,
        description="Configured lookup files from direct API fallback.",
    ),
    "variables": ConfigObjectCatalogEntry(
        kind="variables",
        scope="group",
        sdk_preferred=False,
        requires_security=True,
        description="Configured variables from direct API fallback.",
    ),
}


@dataclass(frozen=True, slots=True)
class _ConfigObjectRecord:
    product: str
    group_id: str | None
    item: dict[str, Any]


def _coerce_limit(limit: int | None) -> int:
    if limit is None:
        return _DEFAULT_LIMIT
    if limit < 1:
        return _DEFAULT_LIMIT
    return min(limit, _MAX_LIMIT)


def _coerce_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        parsed = int(cursor)
    except ValueError:
        return 0
    return max(parsed, 0)


def _item_id(item: dict[str, Any]) -> str | None:
    value = item.get("id") or item.get("groupId")
    return str(value) if value is not None else None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _enabled_state(item: dict[str, Any]) -> bool | None:
    enabled = item.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    disabled = item.get("disabled")
    if isinstance(disabled, bool):
        return not disabled
    return None


def _selector_matches(item: dict[str, Any], selector: str | None) -> bool:
    if selector is None:
        return True
    needle = selector.casefold()
    wildcard = any(character in selector for character in "*?[")
    haystack = [
        _optional_str(item.get("id")),
        _optional_str(item.get("groupId")),
        _optional_str(item.get("name")),
        _optional_str(item.get("type")),
        _optional_str(item.get("description")),
    ]
    if wildcard:
        return any(fnmatchcase(value.casefold(), needle) for value in haystack if value)
    return any(needle in value.casefold() for value in haystack if value)


def _append_ref(refs: dict[str, set[str]], section: str, value: object) -> None:
    if isinstance(value, str) and value:
        refs.setdefault(section, set()).add(value)


def _as_dict(value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return cast("dict[str, Any]", value)
    return None


def _route_refs(item: dict[str, Any], refs: dict[str, set[str]]) -> None:
    routes_value = item.get("routes")
    if not isinstance(routes_value, list):
        return
    routes = cast("list[object]", routes_value)
    for route_value in routes:
        route = _as_dict(route_value)
        if route is None:
            continue
        _append_ref(refs, "pipelines", route.get("pipeline") or route.get("pipelineId"))
        _append_ref(
            refs,
            "destinations",
            route.get("output") or route.get("destination") or route.get("destId"),
        )


def _source_refs(item: dict[str, Any], refs: dict[str, set[str]]) -> None:
    for key in (
        "pipeline",
        "pipelineId",
        "pipeline_id",
        "preprocessPipeline",
        "preprocess_pipeline",
        "preprocessingPipeline",
    ):
        _append_ref(refs, "pipelines", item.get(key))


def _pipeline_refs(item: dict[str, Any], refs: dict[str, set[str]]) -> None:
    conf = _as_dict(item.get("conf"))
    if conf is None:
        return
    functions_value = conf.get("functions")
    if not isinstance(functions_value, list):
        return
    functions = cast("list[object]", functions_value)
    for function_value in functions:
        function = _as_dict(function_value)
        if function is None:
            continue
        function_conf = _as_dict(function.get("conf"))
        if function_conf is None:
            continue
        for key in ("lookup", "lookupName", "file", "fileName"):
            _append_ref(refs, "lookups", function_conf.get(key))


def extract_config_object_refs(kind: ConfigObjectKind, item: dict[str, Any]) -> dict[str, list[str]]:
    """Return known config dependencies referenced by an object."""
    refs: dict[str, set[str]] = {}
    if kind == "routes":
        _route_refs(item, refs)
    elif kind == "sources":
        _source_refs(item, refs)
    elif kind == "pipelines":
        _pipeline_refs(item, refs)
    return {section: sorted(values) for section, values in sorted(refs.items()) if values}


def _summarize_record(
    kind: ConfigObjectKind,
    record: _ConfigObjectRecord,
    *,
    detail: ConfigObjectDetail,
    include_dependencies: bool,
) -> dict[str, Any]:
    item = record.item
    summary: dict[str, Any] = {
        "product": record.product,
        "group_id": record.group_id,
        "id": _item_id(item),
        "name": _optional_str(item.get("name")),
        "type": _optional_str(item.get("type")),
        "enabled": _enabled_state(item),
        "description": _optional_str(item.get("description")),
        "refs": extract_config_object_refs(kind, item) if include_dependencies or detail == "refs" else {},
    }
    if detail == "full":
        summary["payload"] = item
    return summary


def _iter_product_records(
    product: str,
    product_result: dict[str, Any],
) -> list[_ConfigObjectRecord]:
    records: list[_ConfigObjectRecord] = []
    if product_result.get("status") != "ok":
        return records

    groups_value = product_result.get("groups")
    if isinstance(groups_value, list):
        groups = cast("list[object]", groups_value)
        for group_value in groups:
            group = _as_dict(group_value)
            if group is None:
                continue
            group_id = _optional_str(group.get("group_id"))
            items_value = group.get("items", [])
            if not isinstance(items_value, list):
                continue
            items = cast("list[object]", items_value)
            records.extend(
                _ConfigObjectRecord(product=product, group_id=group_id, item=cast("dict[str, Any]", item))
                for item in items
                if _as_dict(item) is not None
            )
        return records

    items_value = product_result.get("items", [])
    if isinstance(items_value, list):
        items = cast("list[object]", items_value)
        records.extend(
            _ConfigObjectRecord(product=product, group_id=None, item=cast("dict[str, Any]", item))
            for item in items
            if _as_dict(item) is not None
        )
    return records


def _record_sort_key(record: _ConfigObjectRecord) -> tuple[str, str, str]:
    return (
        record.product,
        record.group_id or "",
        _item_id(record.item) or "",
    )


def _status_errors(product_results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for product, result in sorted(product_results.items()):
        status = result.get("status")
        if status == "ok":
            continue
        error: dict[str, Any] = {"product": product, "status": status}
        message = result.get("message")
        if message is not None:
            error["message"] = message
        errors.append(error)
    return errors


def shape_config_object_response(
    *,
    kind: ConfigObjectKind,
    product_results: dict[str, dict[str, Any]],
    detail: ConfigObjectDetail = "summary",
    product: str | None = None,
    group_id: str | None = None,
    selector: str | None = None,
    include_dependencies: bool = False,
    cursor: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Shape collected Cribl config objects into a bounded tool response."""
    if kind not in CONFIG_OBJECT_CATALOG:
        supported = ", ".join(sorted(CONFIG_OBJECT_CATALOG))
        msg = f"Unsupported config object kind '{kind}'. Supported kinds: {supported}."
        raise ValueError(msg)

    offset = _coerce_cursor(cursor)
    page_size = _coerce_limit(limit)
    product_filter = product.casefold() if product else None
    group_filter = group_id.casefold() if group_id else None

    records: list[_ConfigObjectRecord] = []
    for product_name, product_result in product_results.items():
        if product_filter and product_name.casefold() != product_filter:
            continue
        for record in _iter_product_records(product_name, product_result):
            if group_filter and (record.group_id or "").casefold() != group_filter:
                continue
            if not _selector_matches(record.item, selector):
                continue
            records.append(record)

    records.sort(key=_record_sort_key)
    page = records[offset : offset + page_size]
    next_offset = offset + len(page)
    truncated = next_offset < len(records)

    error_results = {
        product_name: product_result
        for product_name, product_result in product_results.items()
        if product_filter is None or product_name.casefold() == product_filter
    }

    return {
        "kind": kind,
        "detail": detail,
        "total_count": len(records),
        "returned_count": len(page),
        "truncated": truncated,
        "next_cursor": str(next_offset) if truncated else None,
        "objects": [
            _summarize_record(
                kind,
                record,
                detail=detail,
                include_dependencies=include_dependencies,
            )
            for record in page
        ],
        "errors": _status_errors(error_results),
    }


__all__ = [
    "CONFIG_OBJECT_CATALOG",
    "ConfigObjectCatalogEntry",
    "ConfigObjectDetail",
    "ConfigObjectKind",
    "extract_config_object_refs",
    "shape_config_object_response",
]
