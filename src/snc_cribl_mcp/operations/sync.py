"""Aggregate copy and sync-validation helpers for Cribl leaders."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Literal, cast

import httpx
from cribl_control_plane.errors import CriblControlPlaneError
from cribl_control_plane.models.productscore import ProductsCore
from cribl_control_plane.models.security import Security

from ..client.cribl_client import ResolvedControlPlane, connect_server_pair
from .common import HTTP_NOT_FOUND, exception_detail
from .resource_actions import (
    ResourceKind,
    append_resource,
    canonicalize_resource_item,
    create_resource,
    get_resource,
    get_resource_spec,
    list_resource,
    update_resource,
)

_MAX_DIFF_PATHS = 25
_MAX_VALIDATE_RESPONSE_BYTES = 900_000
_SELECTOR_TOKEN_RE = re.compile(r"\(|\)|\bAND\b|\bOR\b|\bNOT\b|[^\s()]+", re.IGNORECASE)
type GroupMatchField = Literal["description", "id", "name", "passthrough"]
type JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None
type CompareKind = ResourceKind | Literal["raw"]
type ItemPredicate = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class ResolvedGroupSelector:
    """Describe how a group selector mapped to a concrete group identifier."""

    selector: str
    group_id: str
    matched_by: GroupMatchField
    name: str | None = None
    description: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        """Return a JSON-friendly representation of the resolved selector."""
        return {
            "selector": self.selector,
            "id": self.group_id,
            "matched_by": self.matched_by,
            "name": self.name,
            "description": self.description,
        }


def _and_predicate(left: ItemPredicate, right: ItemPredicate) -> ItemPredicate:
    """Return a predicate that requires both child predicates to match."""

    def _matches(item_id: str) -> bool:
        return left(item_id) and right(item_id)

    return _matches


def _or_predicate(left: ItemPredicate, right: ItemPredicate) -> ItemPredicate:
    """Return a predicate that requires either child predicate to match."""

    def _matches(item_id: str) -> bool:
        return left(item_id) or right(item_id)

    return _matches


def _not_predicate(predicate: ItemPredicate) -> ItemPredicate:
    """Return a predicate that negates another predicate."""

    def _matches(item_id: str) -> bool:
        return not predicate(item_id)

    return _matches


def _wildcard_predicate(pattern: str, *, case_sensitive: bool) -> ItemPredicate:
    """Compile one wildcard pattern into an item-id predicate."""
    if not pattern:
        msg = "Wildcard item patterns must not be blank."
        raise ValueError(msg)
    expected = pattern if case_sensitive else pattern.casefold()

    def _matches(item_id: str) -> bool:
        candidate = item_id if case_sensitive else item_id.casefold()
        return fnmatchcase(candidate, expected)

    return _matches


def _exact_predicate(expected: str) -> ItemPredicate:
    """Compile one exact item id into an item-id predicate."""

    def _matches(item_id: str) -> bool:
        return item_id == expected

    return _matches


def _regex_predicate(pattern: str, *, case_sensitive: bool, field_name: str) -> ItemPredicate:
    """Compile one regular expression into an item-id predicate."""
    if not pattern.strip():
        msg = f"{field_name} must not be blank."
        raise ValueError(msg)
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        msg = f"Invalid {field_name} regular expression: {exc}."
        raise ValueError(msg) from exc

    def _matches(item_id: str) -> bool:
        return compiled.search(item_id) is not None

    return _matches


def _selector_tokens(expression: str) -> list[str]:
    """Tokenize a wildcard boolean expression."""
    normalized = re.sub(r"\bbut\s+not\b", "and not", expression.strip(), flags=re.IGNORECASE)
    if not normalized:
        msg = "item_pattern must not be blank."
        raise ValueError(msg)
    return _SELECTOR_TOKEN_RE.findall(normalized)


def _operator(token: str) -> str | None:
    """Return the normalized operator for a selector token."""
    normalized = token.casefold()
    return normalized if normalized in {"and", "or", "not"} else None


class _WildcardExpressionParser:
    """Parse boolean wildcard expressions into predicates."""

    def __init__(self, tokens: list[str], *, case_sensitive: bool) -> None:
        self._tokens = tokens
        self._case_sensitive = case_sensitive
        self._index = 0

    def parse(self) -> ItemPredicate:
        """Parse all tokens into a predicate."""
        predicate = self._parse_or()
        if self._peek() is not None:
            msg = f"Unexpected token '{self._peek()}' in item_pattern."
            raise ValueError(msg)
        return predicate

    def _peek(self) -> str | None:
        if self._index >= len(self._tokens):
            return None
        return self._tokens[self._index]

    def _pop(self) -> str:
        current = self._tokens[self._index]
        self._index += 1
        return current

    def _parse_or(self) -> ItemPredicate:
        predicate = self._parse_and()
        while self._peek() is not None and _operator(cast("str", self._peek())) == "or":
            self._pop()
            predicate = _or_predicate(predicate, self._parse_and())
        return predicate

    def _parse_and(self) -> ItemPredicate:
        predicate = self._parse_factor()
        while self._peek() is not None:
            current = cast("str", self._peek())
            operator = _operator(current)
            if current == ")" or operator == "or":
                break
            if operator == "and":
                self._pop()
            predicate = _and_predicate(predicate, self._parse_factor())
        return predicate

    def _parse_factor(self) -> ItemPredicate:
        current = self._peek()
        if current is None:
            msg = "item_pattern ended before a wildcard pattern was provided."
            raise ValueError(msg)
        operator = _operator(current)
        if operator == "not":
            self._pop()
            return _not_predicate(self._parse_factor())
        if operator in {"and", "or"}:
            msg = f"Unexpected operator '{current}' in item_pattern."
            raise ValueError(msg)
        if current == "(":
            self._pop()
            predicate = self._parse_or()
            if self._peek() != ")":
                msg = "item_pattern has an unmatched '('."
                raise ValueError(msg)
            self._pop()
            return predicate
        if current == ")":
            msg = "item_pattern has an unmatched ')'."
            raise ValueError(msg)
        return _wildcard_predicate(self._pop(), case_sensitive=self._case_sensitive)


def _wildcard_expression_predicate(expression: str, *, case_sensitive: bool) -> ItemPredicate:
    """Compile a boolean wildcard selector expression."""
    tokens = _selector_tokens(expression)
    if not tokens:
        msg = "item_pattern must contain at least one wildcard pattern."
        raise ValueError(msg)
    return _WildcardExpressionParser(tokens, case_sensitive=case_sensitive).parse()


def _build_item_filter(
    *,
    item_id: str | None,
    item_pattern: str | None,
    item_regex: str | None,
    exclude_item_pattern: str | None,
    exclude_item_regex: str | None,
    case_sensitive: bool,
) -> tuple[ItemPredicate, dict[str, Any]]:
    """Build an item-id predicate and JSON-friendly selector metadata."""
    non_exact_filter = any((item_pattern, item_regex, exclude_item_pattern, exclude_item_regex))
    if item_id is not None and non_exact_filter:
        msg = "item_id cannot be combined with item_pattern, item_regex, exclude_item_pattern, or exclude_item_regex."
        raise ValueError(msg)

    if item_id is not None:
        return (
            _exact_predicate(item_id),
            {
                "mode": "exact",
                "item_id": item_id,
                "case_sensitive": True,
            },
        )

    include_predicates: list[ItemPredicate] = []
    exclude_predicates: list[ItemPredicate] = []
    details: dict[str, Any] = {
        "mode": "all",
        "case_sensitive": case_sensitive,
    }

    if item_pattern is not None:
        include_predicates.append(_wildcard_expression_predicate(item_pattern, case_sensitive=case_sensitive))
        details["mode"] = "filtered"
        details["item_pattern"] = item_pattern
    if item_regex is not None:
        include_predicates.append(_regex_predicate(item_regex, case_sensitive=case_sensitive, field_name="item_regex"))
        details["mode"] = "filtered"
        details["item_regex"] = item_regex
    if exclude_item_pattern is not None:
        exclude_predicates.append(_wildcard_expression_predicate(exclude_item_pattern, case_sensitive=case_sensitive))
        details["mode"] = "filtered"
        details["exclude_item_pattern"] = exclude_item_pattern
    if exclude_item_regex is not None:
        exclude_predicates.append(
            _regex_predicate(exclude_item_regex, case_sensitive=case_sensitive, field_name="exclude_item_regex")
        )
        details["mode"] = "filtered"
        details["exclude_item_regex"] = exclude_item_regex

    def _matches(candidate_item_id: str) -> bool:
        included = all(predicate(candidate_item_id) for predicate in include_predicates) if include_predicates else True
        excluded = any(predicate(candidate_item_id) for predicate in exclude_predicates)
        return included and not excluded

    return _matches, details


def _filter_indexed_items(
    indexed: dict[str, dict[str, Any]],
    predicate: ItemPredicate,
) -> dict[str, dict[str, Any]]:
    """Return indexed items whose IDs match the selector predicate."""
    return {item_id: item for item_id, item in indexed.items() if predicate(item_id)}


def _selection_warnings(selection: dict[str, Any], *, matched_count: int) -> list[str]:
    """Return warnings for surprising item-selection outcomes."""
    if selection["mode"] != "all" and matched_count == 0:
        return ["No items matched the requested item filters."]
    return []


def _resource_item_id(item: dict[str, Any]) -> str | None:
    """Return the canonical item id from a serialized resource."""
    item_id = item.get("id") or item.get("groupId")
    return str(item_id) if item_id is not None else None


def _join_path(prefix: str, suffix: str) -> str:
    """Join nested diff segments into a dotted path."""
    return suffix if not prefix else f"{prefix}.{suffix}"


def _diff_paths(source: JsonValue, target: JsonValue, *, prefix: str = "") -> list[str]:  # noqa: C901
    """Return a bounded list of differing paths between two payloads."""
    if source == target:
        return []

    if isinstance(source, dict) and isinstance(target, dict):
        source_dict = cast("dict[str, JsonValue]", source)
        target_dict = cast("dict[str, JsonValue]", target)
        diffs: list[str] = []
        for key in sorted(set(source_dict) | set(target_dict)):
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
            child = _join_path(prefix, str(key))
            if key not in source_dict or key not in target_dict:
                diffs.append(child)
                continue
            diffs.extend(_diff_paths(source_dict[key], target_dict[key], prefix=child))
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
        return diffs[:_MAX_DIFF_PATHS]

    if isinstance(source, list) and isinstance(target, list):
        source_list = cast("list[JsonValue]", source)
        target_list = cast("list[JsonValue]", target)
        if len(source_list) != len(target_list):
            return [_join_path(prefix, "length")]
        diffs: list[str] = []
        for index, (left, right) in enumerate(zip(source_list, target_list, strict=False)):
            if len(diffs) >= _MAX_DIFF_PATHS:
                break
            diffs.extend(_diff_paths(left, right, prefix=f"{prefix}[{index}]"))
        return diffs[:_MAX_DIFF_PATHS]

    return [prefix or "$"]


def _normalize_group_text(value: object) -> str | None:
    """Normalize group metadata values into comparable strings."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _match_groups(
    groups: Iterable[dict[str, Any]],
    *,
    selector: str,
    field: Literal["description", "id", "name"],
    case_sensitive: bool,
) -> list[dict[str, Any]]:
    """Return all groups whose field matches the selector."""
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
    server_name: str,
    product: ProductsCore,
) -> tuple[dict[str, Any], GroupMatchField] | None:
    """Find the best matching group by id, name, or description."""
    for case_sensitive in (True, False):
        for field in ("id", "name", "description"):
            matched = _match_groups(
                groups,
                selector=selector,
                field=field,
                case_sensitive=case_sensitive,
            )
            if len(matched) == 1:
                return matched[0], field
            if len(matched) > 1:
                msg = (
                    f"Group selector '{selector}' matched multiple groups by {field} "
                    f"on server '{server_name}' for product '{product.value}'."
                )
                raise ValueError(msg)
    return None


async def _resolve_group_selector(
    resolved: ResolvedControlPlane,
    *,
    selector: str | None,
    product: ProductsCore | None,
) -> ResolvedGroupSelector:
    """Resolve a source or target group selector into a stable group id."""
    if selector is None:
        msg = "A group selector is required for group-scoped resources."
        raise ValueError(msg)

    normalized_selector = selector.strip()
    if not normalized_selector:
        msg = "Group selectors must not be blank."
        raise ValueError(msg)

    if product is None:
        return ResolvedGroupSelector(
            selector=selector,
            group_id=normalized_selector,
            matched_by="passthrough",
        )

    groups = await list_resource(
        resolved.client,
        "groups",
        timeout_ms=resolved.config.timeout_ms,
        product=product,
    )
    matched = _select_group_match(
        groups,
        selector=normalized_selector,
        server_name=resolved.server_name,
        product=product,
    )
    if matched is None:
        msg = f"Could not resolve group selector '{selector}' on server '{resolved.server_name}' for product '{product.value}'."
        raise ValueError(msg)

    group, matched_by = matched
    group_id = _resource_item_id(group)
    if group_id is None:
        msg = (
            f"Resolved group selector '{selector}' on server '{resolved.server_name}' "
            "but the matching group did not include an id."
        )
        raise ValueError(msg)

    return ResolvedGroupSelector(
        selector=selector,
        group_id=group_id,
        matched_by=matched_by,
        name=_normalize_group_text(group.get("name")),
        description=_normalize_group_text(group.get("description")),
    )


async def _resolved_security(resolved: ResolvedControlPlane) -> Security | None:
    """Return fresh security for direct HTTP calls when the resolved client supports it."""
    get_security = cast("Callable[[], Awaitable[Security]] | None", getattr(resolved, "get_security", None))
    if get_security is not None:
        return await get_security()
    return getattr(resolved, "security", None)


def _canonical_compare_payload(kind: CompareKind, item: dict[str, Any]) -> dict[str, Any]:
    """Return the payload shape used for sync comparisons."""
    if kind == "raw":
        return item
    payload = canonicalize_resource_item(kind, item)
    payload.pop("status", None)
    return payload


def _compare_items(
    kind: CompareKind,
    item_id: str,
    source_item: dict[str, Any] | None,
    target_item: dict[str, Any] | None,
    *,
    include_payloads: bool = False,
) -> dict[str, Any]:
    """Compare source and target items and return a JSON-friendly diff summary."""
    if source_item is None and target_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_both",
            "differing_paths": [],
        }
    if source_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_source",
            "differing_paths": [],
        }
    if target_item is None:
        return {
            "item_id": item_id,
            "status": "missing_on_target",
            "differing_paths": [],
        }

    source_payload = _canonical_compare_payload(kind, source_item)
    target_payload = _canonical_compare_payload(kind, target_item)
    differing_paths = _diff_paths(source_payload, target_payload)
    result: dict[str, Any] = {
        "item_id": item_id,
        "status": "in_sync" if not differing_paths else "different",
        "differing_paths": differing_paths,
    }
    if include_payloads:
        result["source"] = source_payload
        result["target"] = target_payload
    return result


def _estimate_json_size_bytes(payload: dict[str, Any]) -> int:
    """Estimate the UTF-8 encoded JSON payload size for a response."""
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _strip_validation_payloads(item: dict[str, Any]) -> dict[str, Any]:
    """Remove source and target payloads from a validation item result."""
    stripped = dict(item)
    stripped.pop("source", None)
    stripped.pop("target", None)
    return stripped


def _summarize_validation_item(item: dict[str, Any]) -> dict[str, Any]:
    """Project a validation item into its smallest useful summary shape."""
    return {
        "item_id": item["item_id"],
        "status": item["status"],
        "differing_paths": item.get("differing_paths", []),
    }


def _apply_validate_response_limit(response: dict[str, Any]) -> dict[str, Any]:
    """Shrink validation responses when needed to stay within MCP payload limits."""
    items = cast("list[dict[str, Any]]", response.get("items", []))
    if not items:
        return response

    adjusted = dict(response)
    adjusted_items = [dict(item) for item in items]
    adjusted["items"] = adjusted_items
    warnings = [warning for warning in adjusted.get("warnings", []) if isinstance(warning, str)]

    if _estimate_json_size_bytes(adjusted) <= _MAX_VALIDATE_RESPONSE_BYTES:
        return adjusted

    if any("source" in item or "target" in item for item in adjusted_items):
        adjusted_items = [_strip_validation_payloads(item) for item in adjusted_items]
        adjusted["items"] = adjusted_items
        warnings.append("Omitted per-item source and target payloads to stay within MCP response limits.")
        if _estimate_json_size_bytes(adjusted) <= _MAX_VALIDATE_RESPONSE_BYTES:
            adjusted["warnings"] = warnings
            return adjusted

    if any(item != _summarize_validation_item(item) for item in adjusted_items):
        adjusted_items = [_summarize_validation_item(item) for item in adjusted_items]
        adjusted["items"] = adjusted_items
        warnings.append("Reduced validation item details to summary fields to stay within MCP response limits.")
        if _estimate_json_size_bytes(adjusted) <= _MAX_VALIDATE_RESPONSE_BYTES:
            adjusted["warnings"] = warnings
            return adjusted

    base_response = {key: value for key, value in adjusted.items() if key != "items"}
    truncated_items: list[dict[str, Any]] = []
    total_items = len(adjusted_items)
    for item in adjusted_items:
        candidate_items = [*truncated_items, item]
        candidate = {
            **base_response,
            "items": candidate_items,
            "response_truncated": True,
            "returned_item_count": len(candidate_items),
            "omitted_item_count": total_items - len(candidate_items),
        }
        candidate_warnings = [
            *warnings,
            (f"Returned {len(candidate_items)} of {total_items} validation item results to stay within MCP response limits."),
        ]
        candidate["warnings"] = candidate_warnings
        if _estimate_json_size_bytes(candidate) > _MAX_VALIDATE_RESPONSE_BYTES:
            break
        truncated_items = candidate_items

    omitted_item_count = total_items - len(truncated_items)
    adjusted["items"] = truncated_items
    adjusted["response_truncated"] = omitted_item_count > 0
    adjusted["returned_item_count"] = len(truncated_items)
    adjusted["omitted_item_count"] = omitted_item_count
    if omitted_item_count > 0:
        warnings.append(
            f"Returned {len(truncated_items)} of {total_items} validation item results to stay within MCP response limits."
        )
    adjusted["warnings"] = warnings
    return adjusted


def _serialize_copy_error(exc: Exception) -> dict[str, Any]:
    """Project an exception into a stable, JSON-friendly error payload."""
    error: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": exception_detail(exc),
    }
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        error["status_code"] = status_code
    return error


def _build_failed_copy_result(
    item_id: str,
    *,
    attempted_action: str,
    exc: Exception,
) -> dict[str, Any]:
    """Build a per-item copy failure result without aborting the batch."""
    return {
        "item_id": item_id,
        "action": "failed",
        "attempted_action": attempted_action,
        "error": _serialize_copy_error(exc),
    }


def _require_resolved_target_group_id(group_id: str | None) -> str:
    """Return the resolved target group id or raise a clear configuration error."""
    if group_id is None:
        msg = "Unable to append routes because the resolved target group id is missing."
        raise ValueError(msg)
    return group_id


async def _maybe_get_item(
    resolved: ResolvedControlPlane,
    kind: ResourceKind,
    *,
    item_id: str,
    product: ProductsCore | None = None,
    group_id: str | None = None,
) -> dict[str, Any] | None:
    """Fetch one item and return ``None`` on HTTP 404."""
    try:
        return await get_resource(
            resolved.client,
            kind,
            item_id=item_id,
            timeout_ms=resolved.config.timeout_ms,
            product=product,
            group_id=group_id,
            security=await _resolved_security(resolved),
        )
    except CriblControlPlaneError as exc:
        if exc.status_code == HTTP_NOT_FOUND:
            return None
        raise
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == HTTP_NOT_FOUND:
            return None
        raise


def _index_items(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index serialized items by id, skipping entries without a stable identifier."""
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = _resource_item_id(item)
        if item_id:
            indexed[item_id] = item
    return indexed


def _copy_plan_digest(payload: object) -> str:
    """Return a deterministic digest for a copy plan or config snapshot."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _copy_plan_snapshot(kind: ResourceKind, item: dict[str, Any]) -> dict[str, Any]:
    """Return write-relevant config state for copy-plan drift detection."""
    snapshot = canonicalize_resource_item(kind, item)
    snapshot.pop("status", None)
    if kind == "lookups":
        for key in ("_content", "_content_type"):
            if key in item:
                snapshot[key] = item[key]
    return snapshot


async def validate_resource_sync(
    kind: ResourceKind,
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    target_group_id: str | None = None,
    item_id: str | None = None,
    item_pattern: str | None = None,
    item_regex: str | None = None,
    exclude_item_pattern: str | None = None,
    exclude_item_regex: str | None = None,
    case_sensitive: bool = False,
    include_payloads: bool = False,
) -> dict[str, Any]:
    """Validate whether two leaders are in sync for a resource scope."""
    spec = get_resource_spec(kind)
    effective_target_group = target_group_id or group_id
    item_filter, item_selection = _build_item_filter(
        item_id=item_id,
        item_pattern=item_pattern,
        item_regex=item_regex,
        exclude_item_pattern=exclude_item_pattern,
        exclude_item_regex=exclude_item_regex,
        case_sensitive=case_sensitive,
    )

    async with connect_server_pair(source_server, target_server) as (source, target):
        source_group = None
        target_group = None
        resolved_source_group_id = group_id
        resolved_target_group_id = effective_target_group
        if spec.scope == "group":
            source_group = await _resolve_group_selector(
                source,
                selector=group_id,
                product=product,
            )
            target_group = await _resolve_group_selector(
                target,
                selector=effective_target_group,
                product=product,
            )
            resolved_source_group_id = source_group.group_id
            resolved_target_group_id = target_group.group_id

        if item_id is not None:
            source_item = await _maybe_get_item(
                source,
                kind,
                item_id=item_id,
                product=product,
                group_id=resolved_source_group_id,
            )
            target_item = await _maybe_get_item(
                target,
                kind,
                item_id=item_id,
                product=product,
                group_id=resolved_target_group_id,
            )
            item_result = _compare_items(
                kind,
                item_id,
                source_item,
                target_item,
                include_payloads=include_payloads,
            )
            return _apply_validate_response_limit(
                {
                    "resource_kind": kind,
                    "scope": spec.scope,
                    "source_server": source.server_name,
                    "target_server": target.server_name,
                    "product": product.value if product else None,
                    "source_group_selector": group_id,
                    "target_group_selector": effective_target_group,
                    "group_id": resolved_source_group_id,
                    "target_group_id": resolved_target_group_id,
                    "source_group": source_group.as_dict() if source_group else None,
                    "target_group": target_group.as_dict() if target_group else None,
                    "item_selection": item_selection,
                    "matched_count": 1,
                    "in_sync": item_result["status"] == "in_sync",
                    "items": [item_result],
                }
            )

        source_items = await list_resource(
            source.client,
            kind,
            timeout_ms=source.config.timeout_ms,
            product=product,
            group_id=resolved_source_group_id,
            security=await _resolved_security(source),
        )
        target_items = await list_resource(
            target.client,
            kind,
            timeout_ms=target.config.timeout_ms,
            product=product,
            group_id=resolved_target_group_id,
            security=await _resolved_security(target),
        )
        source_index = _index_items(source_items)
        target_index = _index_items(target_items)
        compared_ids = sorted(item_id for item_id in set(source_index) | set(target_index) if item_filter(item_id))

        results = [
            _compare_items(
                kind,
                compared_id,
                source_index.get(compared_id),
                target_index.get(compared_id),
                include_payloads=include_payloads,
            )
            for compared_id in compared_ids
        ]

        response: dict[str, Any] = {
            "resource_kind": kind,
            "scope": spec.scope,
            "source_server": source.server_name,
            "target_server": target.server_name,
            "product": product.value if product else None,
            "source_group_selector": group_id,
            "target_group_selector": effective_target_group,
            "group_id": resolved_source_group_id,
            "target_group_id": resolved_target_group_id,
            "source_group": source_group.as_dict() if source_group else None,
            "target_group": target_group.as_dict() if target_group else None,
            "item_selection": item_selection,
            "matched_count": len(compared_ids),
            "in_sync": all(result["status"] == "in_sync" for result in results),
            "counts": {
                "source": sum(compared_id in source_index for compared_id in compared_ids),
                "target": sum(compared_id in target_index for compared_id in compared_ids),
                "in_sync": sum(result["status"] == "in_sync" for result in results),
                "different": sum(result["status"] == "different" for result in results),
                "missing_on_source": sum(result["status"] == "missing_on_source" for result in results),
                "missing_on_target": sum(result["status"] == "missing_on_target" for result in results),
            },
            "items": results,
        }
        warnings = _selection_warnings(item_selection, matched_count=len(compared_ids))
        if warnings:
            response["warnings"] = warnings
        return _apply_validate_response_limit(response)


async def copy_resource_config(  # noqa: C901, PLR0912, PLR0915
    kind: ResourceKind,
    source_server: str,
    target_server: str,
    *,
    product: ProductsCore | None = None,
    group_id: str | None = None,
    target_group_id: str | None = None,
    item_id: str | None = None,
    item_pattern: str | None = None,
    item_regex: str | None = None,
    exclude_item_pattern: str | None = None,
    exclude_item_regex: str | None = None,
    case_sensitive: bool = False,
    overwrite: bool = True,
    validate_after: bool = True,
    append_routes: bool = False,
    dry_run: bool = False,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Copy one or more configs from a source leader to a target leader.

    Exposed callers should first request a dry-run and then return its
    ``plan_sha256`` for execution. Internal aggregate workflows may omit the
    digest while they retain their existing orchestration semantics.
    """
    spec = get_resource_spec(kind)
    effective_target_group = target_group_id or group_id
    item_filter, item_selection = _build_item_filter(
        item_id=item_id,
        item_pattern=item_pattern,
        item_regex=item_regex,
        exclude_item_pattern=exclude_item_pattern,
        exclude_item_regex=exclude_item_regex,
        case_sensitive=case_sensitive,
    )

    async with connect_server_pair(source_server, target_server) as (source, target):
        source_group = None
        target_group = None
        resolved_source_group_id = group_id
        resolved_target_group_id = effective_target_group
        if spec.scope == "group":
            source_group = await _resolve_group_selector(source, selector=group_id, product=product)
            target_group = await _resolve_group_selector(target, selector=effective_target_group, product=product)
            resolved_source_group_id = source_group.group_id
            resolved_target_group_id = target_group.group_id

        if item_id is not None:
            source_item = await get_resource(
                source.client,
                kind,
                item_id=item_id,
                timeout_ms=source.config.timeout_ms,
                product=product,
                group_id=resolved_source_group_id,
                security=await _resolved_security(source),
                hydrate_lookup_content=kind == "lookups",
            )
            source_items = {item_id: source_item}
        else:
            source_items = _filter_indexed_items(
                _index_items(
                    await list_resource(
                        source.client,
                        kind,
                        timeout_ms=source.config.timeout_ms,
                        product=product,
                        group_id=resolved_source_group_id,
                        security=await _resolved_security(source),
                        hydrate_lookup_content=kind == "lookups",
                    )
                ),
                item_filter,
            )

        inspections: list[tuple[str, dict[str, Any], dict[str, Any] | None, dict[str, Any]]] = []
        plan_items: list[dict[str, Any]] = []
        for current_item_id, source_item in source_items.items():
            target_item: dict[str, Any] | None = None
            try:
                target_item = await _maybe_get_item(
                    target,
                    kind,
                    item_id=current_item_id,
                    product=product,
                    group_id=resolved_target_group_id,
                )
                if target_item is None:
                    if spec.supports("create"):
                        plan_result = {"item_id": current_item_id, "action": "would_create"}
                    elif kind == "routes" and spec.supports("update"):
                        plan_result = {
                            "item_id": current_item_id,
                            "action": "unsupported",
                            "reason": "Routes require an existing target route set before they can be updated or appended.",
                        }
                    else:
                        plan_result = {
                            "item_id": current_item_id,
                            "action": "unsupported",
                            "reason": f"Create is not supported for resource kind '{kind}'.",
                        }
                elif not overwrite:
                    plan_result = {
                        "item_id": current_item_id,
                        "action": "would_skip",
                        "reason": "Target item already exists and overwrite is disabled.",
                    }
                elif kind == "routes" and append_routes:
                    plan_result = {"item_id": current_item_id, "action": "would_append"}
                else:
                    plan_result = {"item_id": current_item_id, "action": "would_update"}
            except Exception as exc:  # noqa: BLE001 - include target read failures in the reviewed plan
                plan_result = _build_failed_copy_result(
                    current_item_id,
                    attempted_action="inspect_target",
                    exc=exc,
                )

            inspections.append((current_item_id, source_item, target_item, plan_result))
            plan_items.append(
                {
                    **plan_result,
                    "source_sha256": _copy_plan_digest(_copy_plan_snapshot(kind, source_item)),
                    "target_sha256": (
                        _copy_plan_digest(_copy_plan_snapshot(kind, target_item)) if target_item is not None else None
                    ),
                }
            )

        response_base: dict[str, Any] = {
            "resource_kind": kind,
            "scope": spec.scope,
            "source_server": source.server_name,
            "target_server": target.server_name,
            "product": product.value if product else None,
            "source_group_selector": group_id,
            "target_group_selector": effective_target_group,
            "group_id": resolved_source_group_id,
            "target_group_id": resolved_target_group_id,
            "source_group": source_group.as_dict() if source_group else None,
            "target_group": target_group.as_dict() if target_group else None,
            "item_selection": item_selection,
            "matched_count": len(source_items),
            "overwrite": overwrite,
            "validate_after": validate_after,
            "append_routes": append_routes,
        }
        stable_plan_items = sorted(plan_items, key=lambda result: str(result["item_id"]))
        plan_sha256 = _copy_plan_digest({**response_base, "items": stable_plan_items})

        if dry_run:
            response: dict[str, Any] = {
                **response_base,
                "dry_run": True,
                "plan_sha256": plan_sha256,
                "copied_count": 0,
                "created_count": 0,
                "updated_count": 0,
                "appended_count": 0,
                "skipped_count": sum(result.get("action") == "would_skip" for result in plan_items),
                "unsupported_count": sum(result.get("action") == "unsupported" for result in plan_items),
                "failed_count": sum(result.get("action") == "failed" for result in plan_items),
                "planned_count": sum(
                    result.get("action") in {"would_append", "would_create", "would_update"} for result in plan_items
                ),
                "planned_created_count": sum(result.get("action") == "would_create" for result in plan_items),
                "planned_updated_count": sum(result.get("action") == "would_update" for result in plan_items),
                "planned_appended_count": sum(result.get("action") == "would_append" for result in plan_items),
                "planned_skipped_count": sum(result.get("action") == "would_skip" for result in plan_items),
                "items": [plan_result for _, _, _, plan_result in inspections],
            }
            warnings = _selection_warnings(item_selection, matched_count=len(source_items))
            if warnings:
                response["warnings"] = warnings
            return response

        if expected_plan_sha256 is not None and expected_plan_sha256 != plan_sha256:
            msg = (
                f"The reviewed copy plan is stale (expected {expected_plan_sha256}, current {plan_sha256}). "
                "Review a new dry-run plan."
            )
            raise ValueError(msg)

        item_results: list[dict[str, Any]] = []
        for current_item_id, source_item, _target_item, plan_result in inspections:
            planned_action = plan_result.get("action")
            if planned_action in {"failed", "unsupported"}:
                item_results.append(plan_result)
                continue
            if planned_action == "would_skip":
                item_results.append({**plan_result, "action": "skipped"})
                continue

            attempted_action = str(planned_action).removeprefix("would_")
            try:
                if planned_action == "would_create":
                    await create_resource(
                        target.client,
                        kind,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        product=product,
                        group_id=resolved_target_group_id,
                        security=await _resolved_security(target),
                    )
                    action = "created"
                elif planned_action == "would_append":
                    await append_resource(
                        target.client,
                        kind,
                        item_id=current_item_id,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        group_id=_require_resolved_target_group_id(resolved_target_group_id),
                    )
                    action = "appended"
                else:
                    await update_resource(
                        target.client,
                        kind,
                        item_id=current_item_id,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        product=product,
                        group_id=resolved_target_group_id,
                        security=await _resolved_security(target),
                    )
                    action = "updated"
            except Exception as exc:  # noqa: BLE001 - accumulate per-item failures in batch copy results
                item_results.append(_build_failed_copy_result(current_item_id, attempted_action=attempted_action, exc=exc))
                continue

            result: dict[str, Any] = {"item_id": current_item_id, "action": action}
            if validate_after:
                try:
                    result["validation"] = _compare_items(
                        kind,
                        current_item_id,
                        source_item,
                        await _maybe_get_item(
                            target,
                            kind,
                            item_id=current_item_id,
                            product=product,
                            group_id=resolved_target_group_id,
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 - preserve successful writes even if validation lookup fails
                    result["validation_error"] = _serialize_copy_error(exc)
            item_results.append(result)

        response = {
            **response_base,
            "dry_run": False,
            "executed_plan_sha256": plan_sha256,
            "copied_count": sum(result.get("action") in {"appended", "created", "updated"} for result in item_results),
            "created_count": sum(result.get("action") == "created" for result in item_results),
            "updated_count": sum(result.get("action") == "updated" for result in item_results),
            "appended_count": sum(result.get("action") == "appended" for result in item_results),
            "skipped_count": sum(result.get("action") == "skipped" for result in item_results),
            "unsupported_count": sum(result.get("action") == "unsupported" for result in item_results),
            "failed_count": sum(result.get("action") == "failed" for result in item_results),
            "items": item_results,
        }
        warnings = _selection_warnings(item_selection, matched_count=len(source_items))
        if warnings:
            response["warnings"] = warnings
        return response


__all__ = [
    "copy_resource_config",
    "validate_resource_sync",
]
