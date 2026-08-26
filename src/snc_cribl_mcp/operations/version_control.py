"""Cribl configuration version-control and deployment workflows.

The helpers in this module deliberately separate read-only planning from
mutation.  Every mutating workflow can first return a content-addressed plan;
the caller then supplies that plan hash to guard against configuration drift
between review and execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast
from urllib.parse import quote, urlsplit, urlunsplit

from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore

from ..client.cribl_client import ResolvedControlPlane, connect_to_server
from .common import (
    HTTP_NOT_FOUND,
    collect_paginated_sdk_response_items,
    counted_sdk_response_count,
    counted_sdk_response_items,
)

type CompareTo = Literal["deployed", "head"]
type ProductScope = Literal["all", "edge", "stream"]

_PRODUCTS: tuple[ProductsCore, ...] = (ProductsCore.STREAM, ProductsCore.EDGE)
_GROUP_GIT_FIELDS = "git.commit,git.localChanges"
_MAX_SUMMARY_PATHS = 100
_MAX_STATUS_PATHS = 25
_MAX_ERROR_MESSAGE_CHARS = 2000
_LEADER_METADATA_PATH = "local/cribl/groups.yml"


class _ModelLike(Protocol):
    """Protocol for SDK response models used by serialization helpers."""

    def model_dump(self, **kwargs: object) -> object:
        """Return a JSON-compatible representation."""


def _field_value(payload: dict[str, Any], *names: str) -> object:
    """Return the first non-null field value while preserving zero and false."""
    for name in names:
        value = payload.get(name)
        if value is not None:
            return value
    return None


@dataclass(frozen=True, slots=True)
class GroupTarget:
    """Resolved Stream worker group or Edge fleet deployment target."""

    product: ProductsCore
    group_id: str
    name: str | None = None
    description: str | None = None
    inherits: str | None = None
    config_version: str | None = None
    committed_version: str | None = None
    local_changes: int | None = None
    worker_count: int | None = None
    deploying_worker_count: int | None = None
    incompatible_worker_count: int | None = None
    failed_worker_count: int | None = None

    @classmethod
    def from_payload(cls, product: ProductsCore, payload: dict[str, Any]) -> GroupTarget:
        """Build a deployment target from a serialized SDK group response."""
        group_id = _optional_text(payload.get("id"))
        if group_id is None:
            msg = f"A {product.value} group/fleet response did not include an id."
            raise ValueError(msg)

        git = payload.get("git")
        git_payload = cast("dict[str, Any]", git) if isinstance(git, dict) else {}
        return cls(
            product=product,
            group_id=group_id,
            name=_optional_text(payload.get("name")),
            description=_optional_text(payload.get("description")),
            inherits=_optional_text(payload.get("inherits")),
            config_version=_optional_text(_field_value(payload, "configVersion", "config_version")),
            committed_version=_optional_text(git_payload.get("commit")),
            local_changes=_optional_int(_field_value(git_payload, "localChanges", "local_changes")),
            worker_count=_optional_int(_field_value(payload, "workerCount", "worker_count")),
            deploying_worker_count=_optional_int(_field_value(payload, "deployingWorkerCount", "deploying_worker_count")),
            incompatible_worker_count=_optional_int(
                _field_value(payload, "incompatibleWorkerCount", "incompatible_worker_count")
            ),
            failed_worker_count=_optional_int(_field_value(payload, "failedWorkerCount", "failed_worker_count")),
        )

    def as_dict(self) -> dict[str, Any]:
        """Return stable JSON metadata for plans and responses."""
        return {
            "product": self.product.value,
            "id": self.group_id,
            "name": self.name,
            "description": self.description,
            "inherits": self.inherits,
            "committed_version": self.committed_version,
            "deployed_version": self.config_version,
            "local_changes": self.local_changes,
            "worker_count": self.worker_count,
            "deploying_worker_count": self.deploying_worker_count,
            "incompatible_worker_count": self.incompatible_worker_count,
            "failed_worker_count": self.failed_worker_count,
        }


def _target_ref(target: GroupTarget) -> dict[str, str | None]:
    """Return compact target identity for plans and mutation results."""
    return {
        "product": target.product.value,
        "id": target.group_id,
        "name": target.name,
        "inherits": target.inherits,
    }


def _optional_text(value: object) -> str | None:
    """Return a stripped non-empty string."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: object) -> int | None:
    """Return an integer for numeric SDK fields when possible."""
    if value is None or isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _serialize_model(value: object) -> dict[str, Any]:
    """Serialize one SDK model into a JSON-compatible dictionary."""
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        if isinstance(value, dict):
            return cast("dict[str, Any]", value)
        msg = f"Expected an SDK model response, received {type(value).__name__}."
        raise TypeError(msg)

    payload = cast(
        "_ModelLike",
        value,
    ).model_dump(mode="json", by_alias=True, exclude_none=True)
    if not isinstance(payload, dict):
        msg = f"Expected an SDK model dictionary, received {type(payload).__name__}."
        raise TypeError(msg)
    return cast("dict[str, Any]", payload)


def _serialize_counted_response(response: object) -> dict[str, Any]:
    """Serialize a counted SDK response without assuming generated model types."""
    raw_items = counted_sdk_response_items(response, context="version-control SDK response")
    items = [_serialize_model(item) for item in raw_items]
    count = counted_sdk_response_count(response)
    return {
        "count": len(items) if count is None else count,
        "items": items,
    }


async def _serialize_paginated_counted_response(response: object) -> dict[str, Any]:
    """Serialize every page from a counted SDK list response."""
    raw_items, count = await collect_paginated_sdk_response_items(
        response,
        context="version-control SDK response",
    )
    items = [_serialize_model(item) for item in raw_items]
    return {
        "count": len(items) if count is None else max(count, len(items)),
        "items": items,
    }


def _first_counted_item(response: object) -> dict[str, Any] | None:
    """Return the first serialized item in a counted SDK response."""
    payload = _serialize_counted_response(response)
    items = cast("list[dict[str, Any]]", payload["items"])
    return items[0] if items else None


def _canonical_digest(payload: object) -> str:
    """Return a deterministic SHA-256 digest for a JSON-compatible payload."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _selected_products(scope: ProductScope) -> tuple[ProductsCore, ...]:
    """Map a tool-facing product scope to SDK product values."""
    if scope == "all":
        return _PRODUCTS
    if scope == "stream":
        return (ProductsCore.STREAM,)
    if scope == "edge":
        return (ProductsCore.EDGE,)
    msg = "product must be exactly 'all', 'stream', or 'edge'."
    raise ValueError(msg)


def _group_server_url(base_url: str, group_id: str) -> str:
    """Return the Cribl group/fleet-scoped API base URL."""
    return f"{base_url.rstrip('/')}/m/{quote(group_id, safe='')}"


async def _list_targets(
    resolved: ResolvedControlPlane,
    products: tuple[ProductsCore, ...],
) -> list[GroupTarget]:
    """List groups/fleets with Git and deployment metadata."""
    targets: list[GroupTarget] = []
    for product in products:
        try:
            response = await resolved.client.groups.list_async(
                product=product,
                fields=_GROUP_GIT_FIELDS,
                timeout_ms=resolved.config.timeout_ms,
            )
        except CriblControlPlaneError as exc:
            if exc.status_code == HTTP_NOT_FOUND:
                continue
            raise
        serialized = await _serialize_paginated_counted_response(response)
        targets.extend(
            GroupTarget.from_payload(product, payload)
            for payload in cast("list[dict[str, Any]]", serialized["items"])
            if not (
                product == ProductsCore.STREAM
                and (
                    payload.get("isSearch") is True
                    or _optional_text(payload.get("type")) in {"lake_access", "local_search", "search"}
                )
            )
        )
    return targets


def _target_matches(target: GroupTarget, selector: str, *, case_sensitive: bool) -> bool:
    """Return whether a selector matches a target id, name, or description."""
    expected = selector if case_sensitive else selector.casefold()
    for candidate in (target.group_id, target.name, target.description):
        if candidate is None:
            continue
        actual = candidate if case_sensitive else candidate.casefold()
        if actual == expected:
            return True
    return False


def _resolve_target_from_list(targets: list[GroupTarget], selector: str) -> GroupTarget:
    """Resolve a unique target by id, name, or description."""
    normalized = selector.strip()
    if not normalized:
        msg = "Group/fleet selectors must not be blank."
        raise ValueError(msg)

    for case_sensitive in (True, False):
        matched = [target for target in targets if _target_matches(target, normalized, case_sensitive=case_sensitive)]
        if len(matched) == 1:
            return matched[0]
        if len(matched) > 1:
            ids = ", ".join(sorted(target.group_id for target in matched))
            msg = f"Group/fleet selector '{selector}' matched multiple targets: {ids}."
            raise ValueError(msg)

    available = ", ".join(sorted(target.group_id for target in targets)) or "none"
    msg = f"Could not resolve group/fleet selector '{selector}'. Available ids: {available}."
    raise ValueError(msg)


async def _get_target(
    resolved: ResolvedControlPlane,
    *,
    product: ProductsCore,
    selector: str,
) -> GroupTarget:
    """Resolve and refresh one target's Git and deployment metadata."""
    targets = await _list_targets(resolved, (product,))
    selected = _resolve_target_from_list(targets, selector)
    response = await resolved.client.groups.get_async(
        product=product,
        id=selected.group_id,
        fields=_GROUP_GIT_FIELDS,
        timeout_ms=resolved.config.timeout_ms,
    )
    payload = _first_counted_item(response)
    return selected if payload is None else GroupTarget.from_payload(product, payload)


def _status_changed_paths(status: dict[str, Any]) -> list[str]:  # noqa: C901
    """Return every changed path represented by a Cribl Git status response."""
    paths: set[str] = set()
    for field in ("conflicted", "created", "deleted", "modified", "not_added", "notAdded", "staged"):
        values = status.get(field)
        if isinstance(values, list):
            paths.update(str(value) for value in cast("list[object]", values) if value is not None)

    files = status.get("files")
    if isinstance(files, list):
        for item_value in cast("list[object]", files):
            if isinstance(item_value, dict):
                item = cast("dict[str, object]", item_value)
                path = _optional_text(item.get("path"))
                if path is not None:
                    paths.add(path)

    renamed = status.get("renamed")
    if isinstance(renamed, list):
        for item_value in cast("list[object]", renamed):
            if not isinstance(item_value, dict):
                continue
            item = cast("dict[str, object]", item_value)
            for field in ("from", "from_", "to"):
                path = _optional_text(item.get(field))
                if path is not None:
                    paths.add(path)
    return sorted(paths)


def _status_summary(status: dict[str, Any]) -> dict[str, Any]:
    """Build a compact, stable summary from a Git status item."""
    changed_paths = _status_changed_paths(status)
    conflicts = status.get("conflicted")
    conflicted = sorted(str(item) for item in cast("list[object]", conflicts)) if isinstance(conflicts, list) else []
    return {
        "branch": _optional_text(status.get("current")),
        "ahead": _optional_int(status.get("ahead")) or 0,
        "behind": _optional_int(status.get("behind")) or 0,
        "clean": not changed_paths,
        "changed_count": len(changed_paths),
        "changed_paths": changed_paths[:_MAX_STATUS_PATHS],
        "changed_paths_truncated": len(changed_paths) > _MAX_STATUS_PATHS,
        "changed_paths_sha256": _canonical_digest(changed_paths),
        "conflicted": conflicted[:_MAX_STATUS_PATHS],
        "conflict_count": len(conflicted),
        "conflicts_truncated": len(conflicted) > _MAX_STATUS_PATHS,
        "conflicts_sha256": _canonical_digest(conflicted),
    }


def _compact_git_status(
    status: dict[str, Any],
    *,
    include_change_metadata: bool = True,
    include_changed_paths: bool = False,
) -> dict[str, Any]:
    """Return safety-relevant Git state without repeating changed path previews."""
    excluded = {"changed_paths", "changed_paths_truncated"}
    if not include_change_metadata:
        excluded.update({"changed_count", "changed_paths_sha256"})
    compact = {key: value for key, value in status.items() if key not in excluded}
    if include_changed_paths:
        compact["changed_paths"] = status.get("changed_paths", [])
        compact["changed_paths_truncated"] = bool(status.get("changed_paths_truncated"))
    return compact


def _target_status_snapshot(target: GroupTarget, git_status: dict[str, Any]) -> dict[str, Any]:
    """Return target metadata aligned with the same Git-status snapshot."""
    snapshot = target.as_dict()
    snapshot["local_changes"] = git_status["local_changes"]
    return snapshot


def _plan_change_summary(
    git_status: dict[str, Any],
    pending_diff: dict[str, Any],
    *,
    files: list[str] | None = None,
) -> dict[str, Any]:
    """Return one bounded changed-path preview and complete drift digests for a plan."""
    selected_files = set(files) if files is not None else None
    diff_summary = _diff_summary(cast("dict[str, Any]", pending_diff["payload"]), files=selected_files)
    if selected_files is None:
        changed_count = int(git_status["changed_count"])
        changed_paths = cast("list[str]", git_status["changed_paths"])
        changed_paths_truncated = bool(git_status["changed_paths_truncated"])
        changed_paths_sha256 = git_status["changed_paths_sha256"]
    else:
        changed_paths = cast("list[str]", diff_summary["paths"])
        changed_count = int(diff_summary["path_count"])
        changed_paths_truncated = bool(diff_summary["paths_truncated"])
        changed_paths_sha256 = diff_summary["paths_sha256"]
    return {
        "changed_count": changed_count,
        "changed_paths": changed_paths[:_MAX_STATUS_PATHS],
        "changed_paths_truncated": changed_paths_truncated or len(changed_paths) > _MAX_STATUS_PATHS,
        "changed_paths_sha256": changed_paths_sha256,
        "pending_diff_sha256": pending_diff["sha256"],
        "file_count": diff_summary["file_count"],
        "added_lines": diff_summary["added_lines"],
        "deleted_lines": diff_summary["deleted_lines"],
        "binary_file_count": diff_summary["binary_file_count"],
        "too_big_file_count": diff_summary["too_big_file_count"],
    }


def _execution_change_counts(
    git_status: dict[str, Any],
    pending_diff: dict[str, Any],
    *,
    files: list[str] | None = None,
) -> dict[str, Any]:
    """Return change counts for execution results without path previews."""
    plan_summary = _plan_change_summary(git_status, pending_diff, files=files)
    return {
        key: value
        for key, value in plan_summary.items()
        if key not in {"changed_paths", "changed_paths_truncated", "changed_paths_sha256", "pending_diff_sha256"}
    }


async def _group_status(resolved: ResolvedControlPlane, target: GroupTarget) -> dict[str, Any]:
    """Retrieve full scoped Git status and combine it with deployment metadata."""
    response = await resolved.client.versions.statuses.get_async(
        server_url=_group_server_url(resolved.config.base_url_str, target.group_id),
        timeout_ms=resolved.config.timeout_ms,
    )
    status = _first_counted_item(response) or {}
    summary = _status_summary(status)
    committed_version = target.committed_version
    if committed_version is None:
        history = await resolved.client.versions.commits.list_async(
            count=1,
            server_url=_group_server_url(resolved.config.base_url_str, target.group_id),
            timeout_ms=resolved.config.timeout_ms,
        )
        latest = _first_counted_item(history) or {}
        committed_version = _optional_text(latest.get("hash"))

    summary.update(
        {
            "committed_version": committed_version,
            "deployed_version": target.config_version,
            "deployment_pending": bool(committed_version and committed_version != target.config_version),
            # Group inventory and Git status are separate Cribl calls and can race
            # with an in-flight commit. Keep the public status payload internally
            # coherent by deriving this value from the same status response as
            # clean, changed_count, and changed_paths.
            "local_changes": summary["changed_count"],
            "worker_count": target.worker_count,
            "deploying_worker_count": target.deploying_worker_count,
            "incompatible_worker_count": target.incompatible_worker_count,
        }
    )
    return summary


def _diff_files(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten file-level diff objects from a counted diff response."""
    files: list[dict[str, Any]] = []
    items = payload.get("items")
    if not isinstance(items, list):
        return files
    for item_value in cast("list[object]", items):
        if not isinstance(item_value, dict):
            continue
        item = cast("dict[str, object]", item_value)
        diff_json = item.get("diffJson") or item.get("diff_json")
        if isinstance(diff_json, list):
            files.extend(
                cast(
                    "list[dict[str, Any]]",
                    [entry for entry in cast("list[object]", diff_json) if isinstance(entry, dict)],
                )
            )
    return files


def _diff_summary(payload: dict[str, Any], *, files: set[str] | None = None) -> dict[str, Any]:
    """Summarize a potentially large Cribl diff without returning line bodies."""
    diff_files = _diff_files(payload)
    if files is not None:
        diff_files = [
            item
            for item in diff_files
            if _optional_text(item.get("newName") or item.get("new_name")) in files
            or _optional_text(item.get("oldName") or item.get("old_name")) in files
        ]
    paths: list[str] = []
    for item in diff_files:
        path = _optional_text(item.get("newName") or item.get("new_name") or item.get("oldName") or item.get("old_name"))
        if path is not None:
            paths.append(path)
    return {
        "file_count": len(diff_files),
        "added_lines": sum(_optional_int(item.get("addedLines") or item.get("added_lines")) or 0 for item in diff_files),
        "deleted_lines": sum(_optional_int(item.get("deletedLines") or item.get("deleted_lines")) or 0 for item in diff_files),
        "binary_file_count": sum(bool(item.get("isBinary") or item.get("is_binary")) for item in diff_files),
        "too_big_file_count": sum(bool(item.get("isTooBig") or item.get("is_too_big")) for item in diff_files),
        "paths": paths[:_MAX_SUMMARY_PATHS],
        "path_count": len(paths),
        "paths_truncated": len(paths) > _MAX_SUMMARY_PATHS,
        "paths_sha256": _canonical_digest(paths),
    }


async def _fetch_diff(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
    *,
    commit: str | None = None,
    filename: str | None = None,
    diff_line_limit: int = 0,
) -> dict[str, Any]:
    """Retrieve and serialize a scoped Git diff."""
    response = await resolved.client.versions.commits.diff_async(
        commit=commit,
        filename=filename,
        diff_line_limit=diff_line_limit,
        server_url=_group_server_url(resolved.config.base_url_str, target.group_id),
        timeout_ms=resolved.config.timeout_ms,
    )
    payload = _serialize_counted_response(response)
    files = _diff_files(payload)
    return {
        "payload": payload,
        "sha256": _canonical_digest(files),
        "summary": _diff_summary(payload),
    }


async def _global_status(resolved: ResolvedControlPlane) -> dict[str, Any]:
    """Return the Leader repository Git status summary."""
    response = await resolved.client.versions.statuses.get_async(timeout_ms=resolved.config.timeout_ms)
    raw_status = _first_counted_item(response) or {}
    summary = _status_summary(raw_status)
    summary["deployment_metadata_changed"] = _LEADER_METADATA_PATH in _status_changed_paths(raw_status)
    return summary


def _safe_remote(remote: str) -> str:
    """Remove URL credentials from a configured Git remote before returning it."""
    try:
        parsed = urlsplit(remote)
    except ValueError:
        return "configured"
    if not parsed.scheme or not parsed.hostname:
        return "configured"
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError:
        return "configured"
    if port is not None:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


async def _git_info(resolved: ResolvedControlPlane) -> dict[str, Any]:
    """Return non-secret Leader Git integration metadata."""
    response = await resolved.client.versions.configs.get_async(timeout_ms=resolved.config.timeout_ms)
    item = _first_counted_item(response) or {}
    remote = _optional_text(item.get("remote"))
    remote_configured = remote is not None and remote.casefold() not in {"false", "none"}
    return {
        "versioning": bool(item.get("versioning")),
        "remote_configured": remote_configured,
        "remote": _safe_remote(remote) if remote_configured and remote is not None else None,
    }


def _leader_metadata_paths(status: dict[str, Any]) -> list[str]:
    """Return changed Leader files that record deployed group versions."""
    return [_LEADER_METADATA_PATH] if bool(status.get("deployment_metadata_changed")) else []


def _target_sort_key(target: GroupTarget) -> tuple[str, str]:
    """Return a deterministic target ordering key."""
    return target.product.value, target.group_id


def _deployment_order(targets: list[GroupTarget]) -> list[GroupTarget]:
    """Order Stream groups deterministically and Edge fleets parent-before-child."""
    stream_targets = sorted((target for target in targets if target.product == ProductsCore.STREAM), key=_target_sort_key)
    edge_targets = [target for target in targets if target.product == ProductsCore.EDGE]
    by_id = {target.group_id: target for target in edge_targets}
    children: dict[str, list[str]] = {group_id: [] for group_id in by_id}
    indegree: dict[str, int] = dict.fromkeys(by_id, 0)

    for target in edge_targets:
        if target.inherits is None:
            continue
        if target.inherits not in by_id:
            msg = f"Edge fleet '{target.group_id}' inherits from unknown fleet '{target.inherits}'."
            raise ValueError(msg)
        children[target.inherits].append(target.group_id)
        indegree[target.group_id] += 1

    ready = sorted(group_id for group_id, degree in indegree.items() if degree == 0)
    edge_order: list[GroupTarget] = []
    while ready:
        group_id = ready.pop(0)
        edge_order.append(by_id[group_id])
        for child in sorted(children[group_id]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()

    if len(edge_order) != len(edge_targets):
        cycle = ", ".join(sorted(group_id for group_id, degree in indegree.items() if degree > 0))
        msg = f"Edge fleet inheritance contains a cycle involving: {cycle}."
        raise ValueError(msg)
    return [*stream_targets, *edge_order]


def _blocked_edge_ancestor(
    target: GroupTarget,
    *,
    edge_targets: dict[str, GroupTarget],
    blocked_ids: set[str],
) -> str | None:
    """Return the closest failed/skipped Edge ancestor, if one exists."""
    parent_id = target.inherits
    while target.product == ProductsCore.EDGE and parent_id is not None:
        if parent_id in blocked_ids:
            return parent_id
        parent = edge_targets.get(parent_id)
        parent_id = parent.inherits if parent is not None else None
    return None


async def _edge_ancestor_preflight(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Inspect a targeted subfleet's ancestors and require them to be settled first."""
    if target.product != ProductsCore.EDGE or target.inherits is None:
        return [], []

    edge_targets = {item.group_id: item for item in await _list_targets(resolved, (ProductsCore.EDGE,))}
    ancestors: list[dict[str, Any]] = []
    blocked_reasons: list[str] = []
    seen = {target.group_id}
    parent_id: str | None = target.inherits
    while parent_id is not None:
        if parent_id in seen:
            blocked_reasons.append(f"Edge fleet inheritance contains a cycle involving '{parent_id}'.")
            break
        seen.add(parent_id)
        parent = edge_targets.get(parent_id)
        if parent is None:
            blocked_reasons.append(
                f"Cannot inspect Edge ancestor '{parent_id}'; deploy the parent chain before targeting '{target.group_id}'."
            )
            break
        try:
            git_status = await _group_status(resolved, parent)
        except Exception as exc:  # noqa: BLE001 - return a reviewable blocked plan
            ancestors.append({"target": _target_ref(parent), "status": "error", "error": _error_payload(exc)})
            blocked_reasons.append(
                f"Cannot verify Edge ancestor '{parent_id}'; deploy the parent chain before targeting '{target.group_id}'."
            )
            break

        ancestors.append({"target": _target_ref(parent), "status": "ok", "git": _compact_git_status(git_status)})
        if not bool(git_status["clean"]) or bool(git_status["local_changes"]) or bool(git_status["deployment_pending"]):
            blocked_reasons.append(
                f"Edge ancestor '{parent_id}' has pending configuration; commit and deploy the parent chain first."
            )
        parent_id = parent.inherits

    ancestors.reverse()
    return ancestors, blocked_reasons


def _error_payload(exc: Exception) -> dict[str, Any]:
    """Return a compact structured workflow error."""
    message = str(exc)
    payload: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": message[:_MAX_ERROR_MESSAGE_CHARS],
    }
    if len(message) > _MAX_ERROR_MESSAGE_CHARS:
        payload["message_truncated"] = True
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        payload["status_code"] = status_code
    return payload


def _validate_message(message: str) -> str:
    """Return a stripped commit message or reject a blank value."""
    normalized = message.strip()
    if not normalized:
        msg = "Commit messages must not be blank."
        raise ValueError(msg)
    return normalized


def _commit_hash(response_payload: dict[str, Any]) -> str | None:
    """Extract the created commit hash from a counted commit response."""
    items = response_payload.get("items")
    if not isinstance(items, list) or not items:
        return None
    first = cast("list[object]", items)[0]
    if not isinstance(first, dict):
        return None
    return _optional_text(cast("dict[str, object]", first).get("commit"))


def _first_response_item(response_payload: dict[str, Any]) -> dict[str, Any]:
    """Return the first item from an already serialized counted response."""
    items = response_payload.get("items")
    if not isinstance(items, list) or not items:
        return {}
    first = cast("list[object]", items)[0]
    return cast("dict[str, Any]", first) if isinstance(first, dict) else {}


def _commit_result_summary(
    response_payload: dict[str, Any],
    *,
    version: str,
    changes: dict[str, Any],
) -> dict[str, Any]:
    """Summarize a commit response without returning affected path arrays."""
    item = _first_response_item(response_payload)
    files_value = item.get("files")
    files = cast("dict[str, Any]", files_value) if isinstance(files_value, dict) else {}
    file_counts: dict[str, int] = {}
    for change_type in ("created", "modified", "deleted", "renamed"):
        changed = files.get(change_type)
        file_counts[change_type] = len(cast("list[object]", changed)) if isinstance(changed, list) else 0
    return {
        "version": version,
        "branch": _optional_text(item.get("branch")),
        "line_changes": {
            # SDK 0.11 can intermittently lose deletions from the create-commit
            # response. The immediately preceding pending diff is the reviewed,
            # drift-checked source for these audit counts.
            "total": int(changes["added_lines"]) + int(changes["deleted_lines"]),
            "insertions": int(changes["added_lines"]),
            "deletions": int(changes["deleted_lines"]),
        },
        "file_changes": {
            **file_counts,
            "total": sum(file_counts.values()),
        },
    }


def _rollout_summary(target: GroupTarget) -> dict[str, int | None]:
    """Return aggregate rollout counts available from the group/fleet response."""
    updated: int | None = None
    counts = (target.worker_count, target.deploying_worker_count, target.incompatible_worker_count)
    if all(value is not None for value in counts):
        total, deploying, incompatible = cast("tuple[int, int, int]", counts)
        updated = max(total - deploying - incompatible - (target.failed_worker_count or 0), 0)
    return {
        "total": target.worker_count,
        "updated": updated,
        "deploying": target.deploying_worker_count,
        "failed": target.failed_worker_count,
        "incompatible": target.incompatible_worker_count,
    }


def _push_result(*, requested: bool, pushed: bool = False, attempted: bool = False) -> dict[str, Any]:
    """Return a stable push outcome without the raw SDK response."""
    status = "not_requested"
    if requested:
        status = "pushed" if pushed else "failed" if attempted else "not_attempted"
    return {
        "requested": requested,
        "status": status,
    }


async def _create_group_commit(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
    *,
    message: str,
    effective: bool,
    files: list[str] | None,
) -> tuple[str, dict[str, Any]]:
    """Commit pending changes for one scoped group/fleet."""
    response = await resolved.client.versions.commits.create_async(
        message=message,
        effective=effective,
        files=files,
        server_url=_group_server_url(resolved.config.base_url_str, target.group_id),
        timeout_ms=resolved.config.timeout_ms,
    )
    payload = _serialize_counted_response(response)
    version = _commit_hash(payload)
    if version is None:
        msg = f"Cribl did not return a commit hash after committing {target.product.value} target '{target.group_id}'."
        raise RuntimeError(msg)
    return version, payload


async def _deploy_version(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
    version: str,
) -> dict[str, Any]:
    """Deploy one immutable commit version to a group/fleet."""
    response = await resolved.client.groups.deploy_async(
        product=target.product,
        id=target.group_id,
        version=version,
        timeout_ms=resolved.config.timeout_ms,
    )
    return _serialize_counted_response(response)


async def _commit_leader_metadata(resolved: ResolvedControlPlane, *, message: str) -> dict[str, Any]:
    """Commit only Leader group-version metadata produced by deployment."""
    status = await _global_status(resolved)
    files = _leader_metadata_paths(status)
    if not files:
        return {
            "status": "noop",
            "message": "Deployment did not leave uncommitted Leader groups.yml metadata.",
            "files": [],
        }
    response = await resolved.client.versions.commits.create_async(
        message=message,
        files=files,
        timeout_ms=resolved.config.timeout_ms,
    )
    payload = _serialize_counted_response(response)
    return {
        "status": "committed",
        "files": files,
        "commit": _commit_hash(payload),
    }


async def _push(resolved: ResolvedControlPlane) -> dict[str, Any]:
    """Push committed Leader configuration changes to the configured remote."""
    response = await resolved.client.versions.commits.push_async(timeout_ms=resolved.config.timeout_ms)
    return _serialize_counted_response(response)


async def _guard_predeploy_leader_state(resolved: ResolvedControlPlane) -> dict[str, Any]:
    """Recheck Leader state immediately before deployment begins."""
    status = await _global_status(resolved)
    reasons: list[str] = []
    if _leader_metadata_paths(status):
        reasons.append("Leader groups.yml changed after planning.")
    if status["conflicted"]:
        reasons.append("The Leader Git working tree contains conflicts.")
    if reasons:
        msg = "Pre-deployment state check failed: " + " ".join(reasons)
        raise RuntimeError(msg)
    return status


async def collect_group_git_status(
    server: str | None = None,
    *,
    product: ProductScope = "all",
    group: str | None = None,
) -> dict[str, Any]:
    """Collect scoped Git and deployment status for one or all groups/fleets."""
    products = _selected_products(product)
    if group is not None and len(products) != 1:
        msg = "product must be 'stream' or 'edge' when group is provided."
        raise ValueError(msg)

    async with connect_to_server(server) as resolved:
        targets = await _list_targets(resolved, products)
        if group is not None:
            targets = [_resolve_target_from_list(targets, group)]

        results: list[dict[str, Any]] = []
        ordered_targets = sorted(targets, key=_target_sort_key)
        for target in ordered_targets:
            try:
                status = await _group_status(resolved, target)
                results.append({"target": _target_status_snapshot(target, status), "status": "ok", "git": status})
            except Exception as exc:  # noqa: BLE001 - preserve partial inventory results
                results.append({"target": target.as_dict(), "status": "error", "error": _error_payload(exc)})

        return {
            "server": resolved.server_name,
            "base_url": resolved.config.base_url_str,
            "product": product,
            "count": len(results),
            "targets": results,
        }


async def collect_group_git_diff(
    server: str | None,
    *,
    product: ProductsCore,
    group: str,
    compare_to: CompareTo = "deployed",
    filename: str | None = None,
    diff_line_limit: int = 1000,
) -> dict[str, Any]:
    """Return a group/fleet diff plus a full pending-diff drift guard."""
    if diff_line_limit < 0:
        msg = "diff_line_limit must be zero or greater."
        raise ValueError(msg)
    if compare_to not in {"deployed", "head"}:
        msg = "compare_to must be exactly 'deployed' or 'head'."
        raise ValueError(msg)

    async with connect_to_server(server) as resolved:
        target = await _get_target(resolved, product=product, selector=group)
        status = await _group_status(resolved, target)
        warning: str | None = None
        comparison_commit: str | None = None
        if compare_to == "deployed":
            comparison_commit = target.config_version
            if comparison_commit is None:
                warning = "The target has no deployed configVersion; the diff falls back to HEAD."

        comparison = await _fetch_diff(
            resolved,
            target,
            commit=comparison_commit,
            filename=filename,
            diff_line_limit=diff_line_limit,
        )
        pending = comparison
        if comparison_commit is not None or diff_line_limit != 0 or filename is not None:
            pending = await _fetch_diff(resolved, target, diff_line_limit=0)

        return {
            "server": resolved.server_name,
            "target": _target_status_snapshot(target, status),
            "git": status,
            "compare_to": compare_to,
            "comparison_commit": comparison_commit or status.get("committed_version"),
            "warning": warning,
            "diff_sha256": comparison["sha256"],
            "pending_diff_sha256": pending["sha256"],
            "summary": comparison["summary"],
            "diff": comparison["payload"],
        }


async def _build_group_plan(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
    *,
    message: str,
    files: list[str] | None,
    effective: bool,
    push: bool,
    deploy: bool = True,
) -> dict[str, Any]:
    """Build a mutation plan for one group/fleet."""
    git_status = await _group_status(resolved, target)
    pending_diff = await _fetch_diff(resolved, target, diff_line_limit=0)
    has_pending = (
        not bool(git_status["clean"]) or bool(pending_diff["summary"]["file_count"]) or bool(git_status["local_changes"])
    )
    committed_version = _optional_text(git_status.get("committed_version"))
    deployed_version = _optional_text(git_status.get("deployed_version"))
    action = "noop"
    if has_pending:
        action = "commit_and_deploy" if deploy else "commit"
    elif deploy and committed_version is not None and committed_version != deployed_version:
        action = "deploy"

    blocked_reasons: list[str] = []
    if git_status["conflicted"]:
        blocked_reasons.append("The group/fleet Git working tree contains conflicts.")
    leader_status = await _global_status(resolved)
    if deploy and action != "noop" and _leader_metadata_paths(leader_status):
        blocked_reasons.append("Leader groups.yml already has uncommitted changes; resolve them before automated deployment.")
    if action != "noop" and leader_status["conflicted"]:
        blocked_reasons.append("The Leader Git working tree contains conflicts.")
    git_info = await _git_info(resolved) if push and action != "noop" else None
    if push and action != "noop" and git_info is not None and not git_info["versioning"]:
        blocked_reasons.append("Git versioning is disabled for this Cribl Leader.")
    if push and action != "noop" and git_info is not None and not git_info["remote_configured"]:
        blocked_reasons.append("No remote Git repository is configured for this Cribl Leader.")
    if push and action != "noop" and leader_status["behind"]:
        blocked_reasons.append("The Leader branch is behind its remote; reconcile it before pushing.")
    edge_ancestors: list[dict[str, Any]] = []
    if action != "noop" and (deploy or effective):
        edge_ancestors, ancestor_blocks = await _edge_ancestor_preflight(resolved, target)
        blocked_reasons.extend(ancestor_blocks)

    plan_body = {
        "target": _target_ref(target),
        "action": action,
        "message": message,
        "files": files,
        "effective": effective,
        "push": push,
        "git": _compact_git_status(git_status, include_change_metadata=False),
        "changes": _plan_change_summary(git_status, pending_diff, files=files),
        "leader_git": _compact_git_status(leader_status),
        "git_integration": git_info,
        "edge_ancestors": edge_ancestors,
        "blocked_reasons": blocked_reasons,
    }
    return {**plan_body, "plan_sha256": _canonical_digest(plan_body)}


def _validate_execution_plan(plan: dict[str, Any], expected_plan_sha256: str | None) -> None:
    """Require an exact reviewed plan before any mutation."""
    actual = str(plan["plan_sha256"])
    if expected_plan_sha256 is None:
        msg = "expected_plan_sha256 is required when dry_run=false. Run the workflow with dry_run=true first."
        raise ValueError(msg)
    if expected_plan_sha256 != actual:
        msg = f"The reviewed plan is stale (expected {expected_plan_sha256}, current {actual}). Review a new dry-run plan."
        raise ValueError(msg)
    blocked = plan.get("blocked_reasons")
    if isinstance(blocked, list) and blocked:
        msg = "Deployment plan is blocked: " + " ".join(str(reason) for reason in cast("list[object]", blocked))
        raise ValueError(msg)


def _validate_runtime_target_drift(
    target: GroupTarget,
    *,
    pending_sha256: object,
    initial_sha256: object,
    changed_ancestor: str | None,
) -> None:
    """Reject mid-workflow target drift unless it came from an earlier Edge parent commit."""
    if pending_sha256 == initial_sha256 or changed_ancestor is not None:
        return
    msg = (
        f"Configuration for {target.product.value} target '{target.group_id}' changed during execution; "
        "review a new dry-run plan."
    )
    raise RuntimeError(msg)


async def commit_group_config(
    server: str | None,
    *,
    product: ProductsCore,
    group: str,
    message: str,
    files: list[str] | None = None,
    effective: bool = True,
    push: bool = False,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Plan or commit one group/fleet without deploying it."""
    normalized_message = _validate_message(message)
    async with connect_to_server(server) as resolved:
        target = await _get_target(resolved, product=product, selector=group)
        plan = await _build_group_plan(
            resolved,
            target,
            message=normalized_message,
            files=files,
            effective=effective,
            push=push,
            deploy=False,
        )
        if dry_run:
            return {"status": "planned", "dry_run": True, "plan": plan}

        _validate_execution_plan(plan, expected_plan_sha256)
        if plan["action"] == "noop":
            return {
                "status": "noop",
                "dry_run": False,
                "action": "noop",
                "executed_plan_sha256": plan["plan_sha256"],
                "push": _push_result(requested=False),
            }

        version, response = await _create_group_commit(
            resolved,
            target,
            message=normalized_message,
            effective=effective,
            files=files,
        )
        try:
            push_response = await _push(resolved) if push else None
        except Exception as exc:  # noqa: BLE001 - the commit already succeeded
            return {
                "status": "partial_failure",
                "dry_run": False,
                "action": plan["action"],
                "executed_plan_sha256": plan["plan_sha256"],
                "commit": _commit_result_summary(
                    response,
                    version=version,
                    changes=cast("dict[str, Any]", plan["changes"]),
                ),
                "push": _push_result(requested=True, attempted=True),
                "completed_steps": ["group_commit"],
                "error": _error_payload(exc),
            }
        return {
            "status": "committed",
            "dry_run": False,
            "action": plan["action"],
            "executed_plan_sha256": plan["plan_sha256"],
            "commit": _commit_result_summary(
                response,
                version=version,
                changes=cast("dict[str, Any]", plan["changes"]),
            ),
            "push": _push_result(requested=push, pushed=push_response is not None),
            "completed_steps": ["group_commit", *(["push"] if push else [])],
        }


async def _deploy_and_finalize(
    resolved: ResolvedControlPlane,
    target: GroupTarget,
    *,
    version: str,
    leader_message: str,
    push: bool,
) -> dict[str, Any]:
    """Deploy one version, commit Leader metadata, and optionally push."""
    completed_steps: list[str] = []
    leader_commit: dict[str, Any] | None = None
    push_attempted = False
    try:
        await _guard_predeploy_leader_state(resolved)
        await _deploy_version(resolved, target, version)
        completed_steps.append("deploy")
        leader_commit = await _commit_leader_metadata(resolved, message=leader_message)
        completed_steps.append("leader_commit")
        if push:
            push_attempted = True
            await _push(resolved)
            completed_steps.append("push")
    except Exception as exc:  # noqa: BLE001 - return recovery details after irreversible steps
        return {
            "status": "partial_failure" if completed_steps else "failed",
            "version": version,
            "completed_steps": completed_steps,
            "leader_commit": leader_commit,
            "push": _push_result(requested=push, pushed="push" in completed_steps, attempted=push_attempted),
            "error": _error_payload(exc),
        }

    try:
        refreshed = await _get_target(resolved, product=target.product, selector=target.group_id)
    except Exception as exc:  # noqa: BLE001 - deployment and finalization already succeeded
        return {
            "status": "partial_failure",
            "version": version,
            "completed_steps": completed_steps,
            "leader_commit": leader_commit,
            "push": _push_result(requested=push, pushed="push" in completed_steps, attempted=push_attempted),
            "control_plane_version_confirmed": None,
            "rollout": _rollout_summary(target),
            "error": _error_payload(exc),
        }
    return {
        "status": "deployed",
        "version": version,
        "completed_steps": completed_steps,
        "leader_commit": leader_commit,
        "push": _push_result(requested=push, pushed="push" in completed_steps, attempted=push_attempted),
        "committed_version": refreshed.committed_version,
        "deployed_version": refreshed.config_version,
        "rollout": _rollout_summary(refreshed),
        "control_plane_version_confirmed": refreshed.config_version == version,
    }


async def deploy_group_config(
    server: str | None,
    *,
    product: ProductsCore,
    group: str,
    version: str,
    push: bool = False,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Plan or deploy an explicit existing commit to one group/fleet."""
    normalized_version = _optional_text(version)
    if normalized_version is None:
        msg = "version must be a non-empty commit hash."
        raise ValueError(msg)

    async with connect_to_server(server) as resolved:
        target = await _get_target(resolved, product=product, selector=group)
        leader_status = await _global_status(resolved)
        action = "noop" if target.config_version == normalized_version else "deploy"
        git_info = await _git_info(resolved) if push and action == "deploy" else None
        blocked_reasons: list[str] = []
        if action == "deploy" and _leader_metadata_paths(leader_status):
            blocked_reasons.append("Leader groups.yml already has uncommitted changes; resolve them before deployment.")
        if action == "deploy" and leader_status["conflicted"]:
            blocked_reasons.append("The Leader Git working tree contains conflicts.")
        if push and action == "deploy" and git_info is not None and not git_info["versioning"]:
            blocked_reasons.append("Git versioning is disabled for this Cribl Leader.")
        if push and action == "deploy" and git_info is not None and not git_info["remote_configured"]:
            blocked_reasons.append("No remote Git repository is configured for this Cribl Leader.")
        if push and action == "deploy" and leader_status["behind"]:
            blocked_reasons.append("The Leader branch is behind its remote; reconcile it before pushing.")
        edge_ancestors: list[dict[str, Any]] = []
        if action == "deploy":
            edge_ancestors, ancestor_blocks = await _edge_ancestor_preflight(resolved, target)
            blocked_reasons.extend(ancestor_blocks)
        plan_body = {
            "target": _target_ref(target),
            "action": action,
            "version": normalized_version,
            "push": push,
            "leader_git": _compact_git_status(leader_status),
            "git_integration": git_info,
            "edge_ancestors": edge_ancestors,
            "blocked_reasons": blocked_reasons,
        }
        plan = {**plan_body, "plan_sha256": _canonical_digest(plan_body)}
        if dry_run:
            return {"status": "planned", "dry_run": True, "plan": plan}

        _validate_execution_plan(plan, expected_plan_sha256)
        if plan["action"] == "noop":
            return {
                "status": "noop",
                "dry_run": False,
                "action": "noop",
                "executed_plan_sha256": plan["plan_sha256"],
                "version": normalized_version,
                "push": _push_result(requested=False),
            }
        result = await _deploy_and_finalize(
            resolved,
            target,
            version=normalized_version,
            leader_message=f"Sync deployed {product.value} group/fleet {target.group_id} at {normalized_version[:12]}",
            push=push,
        )
        return {
            "dry_run": False,
            "action": plan["action"],
            "executed_plan_sha256": plan["plan_sha256"],
            **result,
        }


async def commit_and_deploy_group(
    server: str | None,
    *,
    product: ProductsCore,
    group: str,
    message: str,
    files: list[str] | None = None,
    effective: bool = True,
    push: bool = False,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Plan or commit and deploy one Stream group or Edge fleet."""
    normalized_message = _validate_message(message)
    async with connect_to_server(server) as resolved:
        target = await _get_target(resolved, product=product, selector=group)
        plan = await _build_group_plan(
            resolved,
            target,
            message=normalized_message,
            files=files,
            effective=effective,
            push=push,
        )
        if dry_run:
            return {"status": "planned", "dry_run": True, "plan": plan}

        _validate_execution_plan(plan, expected_plan_sha256)
        if plan["action"] == "noop":
            return {
                "status": "noop",
                "dry_run": False,
                "action": "noop",
                "executed_plan_sha256": plan["plan_sha256"],
                "push": _push_result(requested=False),
            }

        commit_response: dict[str, Any] | None = None
        version = _optional_text(cast("dict[str, Any]", plan["git"]).get("committed_version"))
        completed_steps: list[str] = []
        if plan["action"] == "commit_and_deploy":
            try:
                version, commit_response = await _create_group_commit(
                    resolved,
                    target,
                    message=normalized_message,
                    effective=effective,
                    files=files,
                )
                completed_steps.append("group_commit")
            except Exception as exc:  # noqa: BLE001 - return a stable workflow failure payload
                return {
                    "status": "failed",
                    "dry_run": False,
                    "action": plan["action"],
                    "executed_plan_sha256": plan["plan_sha256"],
                    "push": _push_result(requested=False),
                    "completed_steps": completed_steps,
                    "error": _error_payload(exc),
                }

        if version is None:
            return {
                "status": "failed",
                "dry_run": False,
                "action": plan["action"],
                "executed_plan_sha256": plan["plan_sha256"],
                "push": _push_result(requested=False),
                "completed_steps": completed_steps,
                "error": {"type": "RuntimeError", "message": "No committed version is available to deploy."},
            }

        finalized = await _deploy_and_finalize(
            resolved,
            target,
            version=version,
            leader_message=f"Sync deployed {product.value} group/fleet {target.group_id}: {normalized_message}",
            push=push,
        )
        finalized_steps = cast("list[str]", finalized.get("completed_steps", []))
        result = {
            "dry_run": False,
            "action": plan["action"],
            "executed_plan_sha256": plan["plan_sha256"],
            **finalized,
            "completed_steps": [*completed_steps, *finalized_steps],
        }
        if commit_response is not None:
            result["commit"] = _commit_result_summary(
                commit_response,
                version=version,
                changes=cast("dict[str, Any]", plan["changes"]),
            )
        return result


def _all_target_plan_action(
    target: GroupTarget,
    *,
    has_pending: bool,
    committed: str | None,
    deployed: str | None,
    edge_targets: dict[str, GroupTarget],
    planned_edge_commits: set[str],
) -> tuple[str, str | None]:
    """Return one target's planned action and inheritance trigger."""
    if has_pending:
        if target.product == ProductsCore.EDGE:
            planned_edge_commits.add(target.group_id)
        return "commit_and_deploy", None
    if committed is not None and committed != deployed:
        return "deploy", None
    if target.product != ProductsCore.EDGE:
        return "noop", None
    ancestor = _blocked_edge_ancestor(
        target,
        edge_targets=edge_targets,
        blocked_ids=planned_edge_commits,
    )
    return ("deploy_inherited", ancestor) if ancestor is not None else ("noop", None)


async def _build_all_plan(
    resolved: ResolvedControlPlane,
    *,
    product: ProductScope,
    message: str,
    effective: bool,
    push: bool,
    stop_on_error: bool,
) -> tuple[dict[str, Any], list[GroupTarget]]:
    """Build a deterministic plan for every selected deployment target."""
    targets = _deployment_order(await _list_targets(resolved, _selected_products(product)))
    leader_status = await _global_status(resolved)
    git_info = await _git_info(resolved) if push else None
    blocked_reasons: list[str] = []

    target_plans: list[dict[str, Any]] = []
    edge_targets = {target.group_id: target for target in targets if target.product == ProductsCore.EDGE}
    planned_edge_commits: set[str] = set()
    for target in targets:
        git_status = await _group_status(resolved, target)
        pending = await _fetch_diff(resolved, target, diff_line_limit=0)
        has_pending = (
            not bool(git_status["clean"]) or bool(pending["summary"]["file_count"]) or bool(git_status["local_changes"])
        )
        committed = _optional_text(git_status.get("committed_version"))
        deployed = _optional_text(git_status.get("deployed_version"))
        action, inherited_deploy_from = _all_target_plan_action(
            target,
            has_pending=has_pending,
            committed=committed,
            deployed=deployed,
            edge_targets=edge_targets,
            planned_edge_commits=planned_edge_commits,
        )
        conflicts = cast("list[str]", git_status["conflicted"])
        if conflicts:
            blocked_reasons.append(f"{target.product.value} target '{target.group_id}' contains Git conflicts.")
        target_plans.append(
            {
                "target": _target_ref(target),
                "action": action,
                "inherited_deploy_from": inherited_deploy_from,
                "git": _compact_git_status(git_status, include_change_metadata=False),
                "changes": _plan_change_summary(git_status, pending),
                "commit_message": f"{message} [{target.product.value}:{target.group_id}]",
            }
        )

    has_actions = any(target_plan["action"] != "noop" for target_plan in target_plans)
    push_action = "push" if push and (has_actions or bool(leader_status["ahead"])) else "noop"
    if has_actions and _leader_metadata_paths(leader_status):
        blocked_reasons.append("Leader groups.yml already has uncommitted changes; resolve them before deployment.")
    if has_actions and leader_status["conflicted"]:
        blocked_reasons.append("The Leader Git working tree contains conflicts.")
    if push_action == "push" and git_info is not None and not git_info["versioning"]:
        blocked_reasons.append("Git versioning is disabled for this Cribl Leader.")
    if push_action == "push" and git_info is not None and not git_info["remote_configured"]:
        blocked_reasons.append("No remote Git repository is configured for this Cribl Leader.")
    if push_action == "push" and leader_status["conflicted"]:
        blocked_reasons.append("The Leader Git working tree contains conflicts.")
    if push_action == "push" and leader_status["behind"]:
        blocked_reasons.append("The Leader branch is behind its remote; reconcile it before pushing.")

    plan_body = {
        "product": product,
        "message": message,
        "effective": effective,
        "push": push,
        "push_action": push_action,
        "stop_on_error": stop_on_error,
        "leader_git": _compact_git_status(leader_status),
        "git_integration": git_info,
        "targets": target_plans,
        "blocked_reasons": list(dict.fromkeys(blocked_reasons)),
    }
    return {**plan_body, "plan_sha256": _canonical_digest(plan_body)}, targets


async def commit_and_deploy_all(  # noqa: C901, PLR0912, PLR0915
    server: str | None,
    *,
    message: str,
    product: ProductScope = "all",
    effective: bool = True,
    push: bool = False,
    stop_on_error: bool = True,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Plan or commit and deploy all selected groups in safe dependency order."""
    normalized_message = _validate_message(message)
    async with connect_to_server(server) as resolved:
        plan, targets = await _build_all_plan(
            resolved,
            product=product,
            message=normalized_message,
            effective=effective,
            push=push,
            stop_on_error=stop_on_error,
        )
        if dry_run:
            return {"status": "planned", "dry_run": True, "plan": plan}

        _validate_execution_plan(plan, expected_plan_sha256)
        commit_results: list[dict[str, Any]] = []
        deploy_candidates: dict[tuple[ProductsCore, str], tuple[GroupTarget, str]] = {}
        errors: list[dict[str, Any]] = []
        edge_targets = {target.group_id: target for target in targets if target.product == ProductsCore.EDGE}
        blocked_edge_commits: set[str] = set()
        committed_edge_ids: set[str] = set()
        initial_target_plans = {
            (target.product, target.group_id): target_plan
            for target, target_plan in zip(
                targets,
                cast("list[dict[str, Any]]", plan["targets"]),
                strict=True,
            )
        }

        for planned_target in targets:
            blocked_by = _blocked_edge_ancestor(
                planned_target,
                edge_targets=edge_targets,
                blocked_ids=blocked_edge_commits,
            )
            if blocked_by is not None:
                blocked_edge_commits.add(planned_target.group_id)
                commit_results.append(
                    {
                        "target": _target_ref(planned_target),
                        "status": "skipped_dependency",
                        "blocked_by": blocked_by,
                    }
                )
                continue
            try:
                target = await _get_target(
                    resolved,
                    product=planned_target.product,
                    selector=planned_target.group_id,
                )
                git_status = await _group_status(resolved, target)
                pending = await _fetch_diff(resolved, target, diff_line_limit=0)
                initial_target_plan = initial_target_plans[(target.product, target.group_id)]
                initial_changes = cast("dict[str, Any]", initial_target_plan["changes"])
                changed_ancestor = _blocked_edge_ancestor(
                    target,
                    edge_targets=edge_targets,
                    blocked_ids=committed_edge_ids,
                )
                _validate_runtime_target_drift(
                    target,
                    pending_sha256=pending["sha256"],
                    initial_sha256=initial_changes["pending_diff_sha256"],
                    changed_ancestor=changed_ancestor,
                )
                has_pending = (
                    not bool(git_status["clean"]) or bool(pending["summary"]["file_count"]) or bool(git_status["local_changes"])
                )
                version = _optional_text(git_status.get("committed_version"))
                response: dict[str, Any] | None = None
                action = "noop"
                if has_pending:
                    action = "committed"
                    version, response = await _create_group_commit(
                        resolved,
                        target,
                        message=f"{normalized_message} [{target.product.value}:{target.group_id}]",
                        effective=effective,
                        files=None,
                    )
                    if target.product == ProductsCore.EDGE:
                        committed_edge_ids.add(target.group_id)
                if version is not None and version != target.config_version:
                    deploy_candidates[(target.product, target.group_id)] = (target, version)
                execution_changes = _execution_change_counts(git_status, pending)
                commit_results.append(
                    {
                        "target": _target_ref(target),
                        "status": action,
                        "version": version,
                        "commit": (
                            _commit_result_summary(response, version=version, changes=execution_changes)
                            if response is not None and version is not None
                            else None
                        ),
                        "changes": {
                            **execution_changes,
                            "changed_after_parent_commit": changed_ancestor is not None,
                        },
                    }
                )
            except Exception as exc:  # noqa: BLE001 - all-target workflow reports per-target failures
                error = {
                    "phase": "commit",
                    "target": _target_ref(planned_target),
                    "error": _error_payload(exc),
                }
                errors.append(error)
                commit_results.append({"target": _target_ref(planned_target), "status": "failed", **error})
                if planned_target.product == ProductsCore.EDGE:
                    blocked_edge_commits.add(planned_target.group_id)
                if stop_on_error:
                    break

        deploy_results: list[dict[str, Any]] = []
        blocked_edge_deployments = set(blocked_edge_commits)
        deploy_allowed = not errors or not stop_on_error
        if deploy_allowed and deploy_candidates:
            try:
                await _guard_predeploy_leader_state(resolved)
            except Exception as exc:  # noqa: BLE001 - no deployment has started
                errors.append({"phase": "predeploy", "error": _error_payload(exc)})
                deploy_allowed = False
        if deploy_allowed:
            for planned_target in targets:
                candidate = deploy_candidates.get((planned_target.product, planned_target.group_id))
                if candidate is None:
                    continue
                target, version = candidate
                blocked_by = _blocked_edge_ancestor(
                    target,
                    edge_targets=edge_targets,
                    blocked_ids=blocked_edge_deployments,
                )
                if blocked_by is not None:
                    blocked_edge_deployments.add(target.group_id)
                    deploy_results.append(
                        {
                            "target": _target_ref(target),
                            "status": "skipped_dependency",
                            "version": version,
                            "blocked_by": blocked_by,
                        }
                    )
                    continue
                try:
                    await _deploy_version(resolved, target, version)
                except Exception as exc:  # noqa: BLE001 - preserve earlier successful deployments
                    error = {"phase": "deploy", "target": _target_ref(target), "error": _error_payload(exc)}
                    errors.append(error)
                    deploy_results.append({"status": "failed", "version": version, **error})
                    if target.product == ProductsCore.EDGE:
                        blocked_edge_deployments.add(target.group_id)
                    if stop_on_error:
                        break
                    continue

                deployment_result: dict[str, Any] = {
                    "target": _target_ref(target),
                    "status": "deployed",
                    "version": version,
                    "control_plane_version_confirmed": None,
                    "rollout": _rollout_summary(target),
                }
                try:
                    refreshed = await _get_target(resolved, product=target.product, selector=target.group_id)
                    deployment_result.update(
                        {
                            "committed_version": refreshed.committed_version,
                            "deployed_version": refreshed.config_version,
                            "rollout": _rollout_summary(refreshed),
                            "control_plane_version_confirmed": refreshed.config_version == version,
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - the deployment already succeeded
                    error = {"phase": "verify", "target": _target_ref(target), "error": _error_payload(exc)}
                    errors.append(error)
                    deployment_result["verification_error"] = error["error"]
                deploy_results.append(deployment_result)
                if deployment_result.get("verification_error") is not None and stop_on_error:
                    break

        leader_commit: dict[str, Any] | None = None
        if deploy_results and any(result.get("status") == "deployed" for result in deploy_results):
            try:
                leader_commit = await _commit_leader_metadata(
                    resolved,
                    message=f"Sync deployed group/fleet versions: {normalized_message}",
                )
            except Exception as exc:  # noqa: BLE001 - deployments already occurred
                errors.append({"phase": "leader_commit", "error": _error_payload(exc)})

        push_attempted = False
        pushed = False
        if plan["push_action"] == "push" and not errors:
            try:
                push_attempted = True
                await _push(resolved)
                pushed = True
            except Exception as exc:  # noqa: BLE001 - commits/deployments already occurred
                errors.append({"phase": "push", "error": _error_payload(exc)})

        status = "completed" if not errors else "partial_failure" if commit_results or deploy_results else "failed"
        return {
            "status": status,
            "dry_run": False,
            "action": "commit_and_deploy_all",
            "executed_plan_sha256": plan["plan_sha256"],
            "summary": {
                "target_count": len(targets),
                "committed": sum(result.get("status") == "committed" for result in commit_results),
                "deployed": sum(result.get("status") == "deployed" for result in deploy_results),
                "skipped_dependency": sum(
                    result.get("status") == "skipped_dependency" for result in [*commit_results, *deploy_results]
                ),
                "failed": len(errors),
            },
            "commit_results": commit_results,
            "deploy_results": deploy_results,
            "leader_commit": leader_commit,
            "push": _push_result(
                requested=plan["push_action"] == "push",
                pushed=pushed,
                attempted=push_attempted,
            ),
            "errors": errors,
        }


async def push_config_git(
    server: str | None,
    *,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Plan or push committed Cribl configuration changes to its remote."""
    async with connect_to_server(server) as resolved:
        info = await _git_info(resolved)
        status = await _global_status(resolved)
        action = "push" if status["ahead"] else "noop"
        blocked_reasons: list[str] = []
        if action == "push" and not info["versioning"]:
            blocked_reasons.append("Git versioning is disabled for this Cribl Leader.")
        if action == "push" and not info["remote_configured"]:
            blocked_reasons.append("No remote Git repository is configured for this Cribl Leader.")
        if action == "push" and status["conflicted"]:
            blocked_reasons.append("The Leader Git working tree contains conflicts.")
        if action == "push" and status["behind"]:
            blocked_reasons.append("The Leader branch is behind its remote; reconcile it before pushing.")
        plan_body = {
            "action": action,
            "git_integration": info,
            "leader_git": _compact_git_status(status),
            "blocked_reasons": blocked_reasons,
        }
        plan = {**plan_body, "plan_sha256": _canonical_digest(plan_body)}
        if dry_run:
            return {"status": "planned", "dry_run": True, "plan": plan}

        _validate_execution_plan(plan, expected_plan_sha256)
        if plan["action"] == "noop":
            return {
                "status": "noop",
                "dry_run": False,
                "action": "noop",
                "executed_plan_sha256": plan["plan_sha256"],
                "push": _push_result(requested=False),
            }
        await _push(resolved)
        return {
            "status": "pushed",
            "dry_run": False,
            "action": "push",
            "executed_plan_sha256": plan["plan_sha256"],
            "push": _push_result(requested=True, pushed=True),
        }


__all__ = [
    "CompareTo",
    "ProductScope",
    "collect_group_git_diff",
    "collect_group_git_status",
    "commit_and_deploy_all",
    "commit_and_deploy_group",
    "commit_group_config",
    "deploy_group_config",
    "push_config_git",
]
