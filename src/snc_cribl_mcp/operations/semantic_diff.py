"""Semantic config comparison helpers.

The comparison here intentionally separates functional drift from differences
that identify a specific leader, datacenter, or runtime revision.
"""

from __future__ import annotations

from typing import Any, cast

from .config_objects import ConfigObjectKind

type JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None

_MAX_DIFFERENCES = 100
_IDENTITY_LEAVES = {
    "_id",
    "guid",
    "groupid",
    "id",
    "instanceid",
    "uid",
    "uuid",
}
_ENDPOINT_LEAVES = {
    "address",
    "addresses",
    "endpoint",
    "endpoints",
    "host",
    "hostname",
    "hosts",
    "server",
    "servers",
    "url",
    "urls",
}
_TLS_IDENTITY_LEAVES = {
    "ca",
    "capath",
    "cert",
    "certpath",
    "key",
    "keypath",
    "passphrase",
    "secret",
    "token",
}
_VOLATILE_LEAVES = {
    "commit",
    "created",
    "createdat",
    "hash",
    "lastupdate",
    "modified",
    "modifiedat",
    "revision",
    "timestamp",
    "updated",
    "updatedat",
    "version",
}


def _join_path(prefix: str, suffix: str) -> str:
    return suffix if not prefix else f"{prefix}.{suffix}"


def _indexed_path(prefix: str, index: int) -> str:
    return f"{prefix}[{index}]" if prefix else f"[{index}]"


def _path_leaf(path: str) -> str:
    leaf = path.rsplit(".", maxsplit=1)[-1]
    return leaf.split("[", maxsplit=1)[0].casefold()


def _path_contains_function_id(path: str) -> bool:
    return ".functions[" in path and _path_leaf(path) == "id"


def _classify_difference(path: str) -> tuple[str, str]:
    leaf = _path_leaf(path)
    category = "functional"
    reason = "functional configuration"
    if _path_contains_function_id(path):
        return category, reason
    if leaf in _VOLATILE_LEAVES:
        category = "volatile"
        reason = "volatile metadata"
    elif leaf in _IDENTITY_LEAVES:
        category = "identity"
        reason = "object identity"
    elif leaf in _ENDPOINT_LEAVES:
        category = "identity"
        reason = "environment hostname" if leaf in {"host", "hostname", "hosts"} else "environment endpoint list"
    elif leaf in _TLS_IDENTITY_LEAVES:
        category = "identity"
        reason = "environment credential reference"
    return category, reason


def _difference(path: str) -> dict[str, str]:
    category, reason = _classify_difference(path)
    return {"category": category, "path": path or "$", "reason": reason}


def _diff_values(source: JsonValue, target: JsonValue, *, prefix: str = "") -> list[dict[str, str]]:
    if source == target:
        return []

    if isinstance(source, dict) and isinstance(target, dict):
        differences: list[dict[str, str]] = []
        for key in sorted(set(source) | set(target)):
            if len(differences) >= _MAX_DIFFERENCES:
                break
            child = _join_path(prefix, str(key))
            if key not in source or key not in target:
                differences.append(_difference(child))
                continue
            differences.extend(_diff_values(source[key], target[key], prefix=child))
        return differences[:_MAX_DIFFERENCES]

    if isinstance(source, list) and isinstance(target, list):
        differences: list[dict[str, str]] = []
        shared_length = min(len(source), len(target))
        for index in range(shared_length):
            if len(differences) >= _MAX_DIFFERENCES:
                break
            differences.extend(
                _diff_values(
                    source[index],
                    target[index],
                    prefix=_indexed_path(prefix, index),
                )
            )
        if len(source) != len(target) and len(differences) < _MAX_DIFFERENCES:
            differences.append(_difference(_join_path(prefix, "length")))
        return differences[:_MAX_DIFFERENCES]

    return [_difference(prefix)]


def _without_category(difference: dict[str, str]) -> dict[str, str]:
    return {
        "path": difference["path"],
        "reason": difference["reason"],
    }


def compare_config_objects(
    kind: ConfigObjectKind,
    source: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    """Compare two config payloads and classify blocking and non-blocking drift."""
    differences = _diff_values(source, target)
    functional = [_without_category(diff) for diff in differences if diff["category"] == "functional"]
    identity = [_without_category(diff) for diff in differences if diff["category"] == "identity"]
    volatile = [_without_category(diff) for diff in differences if diff["category"] == "volatile"]

    return {
        "kind": kind,
        "status": "functional_difference" if functional else "functionally_equivalent",
        "functional_differences": functional,
        "identity_differences": identity,
        "volatile_differences": volatile,
        "difference_count": len(differences),
    }


def _semantic_item_from_sync_item(kind: ConfigObjectKind, item: dict[str, Any]) -> dict[str, Any]:
    item_id = str(item.get("item_id", ""))
    source = item.get("source")
    target = item.get("target")
    if isinstance(source, dict) and isinstance(target, dict):
        comparison = compare_config_objects(kind, cast("dict[str, Any]", source), cast("dict[str, Any]", target))
        return {
            "item_id": item_id,
            "sync_status": item.get("status"),
            "semantic_status": comparison["status"],
            "functional_differences": comparison["functional_differences"],
            "identity_differences": comparison["identity_differences"],
            "volatile_differences": comparison["volatile_differences"],
        }

    sync_status = str(item.get("status", "unknown"))
    semantic_status = "functionally_equivalent" if sync_status == "in_sync" else sync_status
    result: dict[str, Any] = {
        "item_id": item_id,
        "sync_status": sync_status,
        "semantic_status": semantic_status,
        "functional_differences": [],
        "identity_differences": [],
        "volatile_differences": [],
    }
    if sync_status == "different":
        result["semantic_status"] = "not_evaluated"
        result["warnings"] = ["Source and target payloads were not available for semantic comparison."]
    return result


def _omitted_item_count(sync_result: dict[str, Any]) -> int:
    omitted = sync_result.get("omitted_item_count", 0)
    return omitted if isinstance(omitted, int) and omitted > 0 else 0


def _sync_response_was_truncated(sync_result: dict[str, Any]) -> bool:
    return sync_result.get("response_truncated") is True or _omitted_item_count(sync_result) > 0


def _semantic_in_sync(sync_result: dict[str, Any], items: list[dict[str, Any]]) -> bool:
    if sync_result.get("in_sync") is True:
        return True
    if _sync_response_was_truncated(sync_result):
        return False
    return all(item["semantic_status"] == "functionally_equivalent" for item in items)


def _semantic_warnings(sync_result: dict[str, Any]) -> list[str]:
    warnings = [
        warning
        for warning in sync_result.get("warnings", [])
        if isinstance(warning, str)
    ]
    omitted_count = _omitted_item_count(sync_result)
    if _sync_response_was_truncated(sync_result) and sync_result.get("in_sync") is not True:
        warnings.append(
            f"Semantic validation was incomplete because {omitted_count} item result(s) were omitted from the sync response."
        )
    return warnings


def semantic_validation_from_sync_result(kind: ConfigObjectKind, sync_result: dict[str, Any]) -> dict[str, Any]:
    """Convert byte-level sync validation output into semantic validation output."""
    items = [
        _semantic_item_from_sync_item(kind, cast("dict[str, Any]", item))
        for item in sync_result.get("items", [])
        if isinstance(item, dict)
    ]
    warnings = _semantic_warnings(sync_result)
    result: dict[str, Any] = {
        **{key: value for key, value in sync_result.items() if key not in {"in_sync", "items", "counts", "warnings"}},
        "semantic_evaluation_complete": not _sync_response_was_truncated(sync_result),
        "semantic_in_sync": _semantic_in_sync(sync_result, items),
        "semantic_counts": {
            "functionally_equivalent": sum(item["semantic_status"] == "functionally_equivalent" for item in items),
            "functional_difference": sum(item["semantic_status"] == "functional_difference" for item in items),
            "missing_or_unavailable": sum(
                item["semantic_status"] not in {"functionally_equivalent", "functional_difference"} for item in items
            ),
        },
        "items": items,
    }
    if warnings:
        result["warnings"] = warnings
    return result


__all__ = ["compare_config_objects", "semantic_validation_from_sync_result"]
