"""Review-gated Edge fleet creation and Leader mapping-ruleset replication."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, cast
from urllib.parse import quote

import httpx
from cribl_control_plane.models.productscore import ProductsCore

from ..client.cribl_client import ResolvedControlPlane, connect_to_server
from ..models.edge_fleet import EdgeFleet, ordered_fleets
from .common import HTTP_NOT_FOUND
from .resource_actions import _direct_request_json, create_resource
from .version_control import (
    _GROUP_GIT_FIELDS,
    GroupTarget,
    _canonical_digest,
    _compact_git_status,
    _deployment_order,
    _global_status,
    _group_status,
    _serialize_paginated_counted_response,
    _validate_execution_plan,
    collect_leader_git_diff,
)

LEADER_KINDS = frozenset({"fleets", "fleet_mappings"})
FLEET_FILE = "local/cribl/groups.yml"
MAPPING_FILE = "local/cribl/fleet-mappings.yml"
_MAPPING_PATH = "/fleet-mappings"
_PREVIEW_LIMIT = 25


def leader_files(*, fleets: bool, mappings: bool) -> list[str]:
    """Return the exact Leader files owned by an Edge provisioning request."""
    return ([FLEET_FILE] if fleets else []) + ([MAPPING_FILE] if mappings else [])


async def leader_file_snapshot(server: str | None, files: list[str]) -> dict[str, Any]:
    """Capture complete diff hashes without persisting config bodies in receipts."""
    result: dict[str, Any] = {}
    for filename in files:
        diff = await collect_leader_git_diff(server, filename=filename, diff_line_limit=1)
        result[filename] = {"diff_sha256": diff["diff_sha256"], "file_count": diff["summary"]["file_count"]}
    return result


async def fleet_inventory(resolved: ResolvedControlPlane) -> list[dict[str, Any]]:
    """Read fleets with the same opt-in Git metadata used by deployment status."""
    response = await resolved.client.groups.list_async(
        product=ProductsCore.EDGE, fields=_GROUP_GIT_FIELDS, timeout_ms=resolved.config.timeout_ms
    )
    # Without fields, Cribl omits git.commit. A history fallback returns a full
    # hash, while configVersion uses a short hash, falsely flagging a deployment.
    payload = await _serialize_paginated_counted_response(response)
    return cast("list[dict[str, Any]]", payload["items"])


async def read_mapping(resolved: ResolvedControlPlane, ruleset_id: str) -> dict[str, Any] | None:
    """Read a ruleset, accepting both legacy empty and current 404 absence."""
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,256}", ruleset_id):
        msg = "ruleset_id must contain only letters, digits, underscores, or hyphens (1-256 characters)."
        raise ValueError(msg)
    try:
        payload = await _direct_request_json(
            resolved.client,
            method="GET",
            url=f"{resolved.config.base_url_str.rstrip('/')}{_MAPPING_PATH}/{quote(ruleset_id, safe='')}",
            security=await resolved.get_security(),
            timeout_ms=resolved.config.timeout_ms,
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == HTTP_NOT_FOUND:
            return None
        raise
    items = payload.get("items")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in cast("list[object]", items)):
        msg = "Mapping API returned an unknown counted response shape."
        raise ValueError(msg)
    typed_items = cast("list[dict[str, Any]]", items)
    if not typed_items:
        return None
    if len(typed_items) != 1 or typed_items[0].get("id") != ruleset_id:
        msg = "Mapping API returned an unexpected ruleset identity."
        raise ValueError(msg)
    return mapping_payload(typed_items[0])


def mapping_payload(item: dict[str, Any]) -> dict[str, Any]:
    """Keep the writable ruleset configuration, preserving function order."""
    if not isinstance(item.get("id"), str) or not isinstance(item.get("conf"), dict):
        msg = "Mapping ruleset requires id and conf."
        raise TypeError(msg)
    if item.get("active") is not None and not isinstance(item["active"], bool):
        msg = "Mapping ruleset active must be a boolean."
        raise TypeError(msg)
    conf = cast("dict[str, Any]", item["conf"])
    if not isinstance(conf.get("functions"), list):
        msg = "Mapping ruleset conf.functions must be an array."
        raise TypeError(msg)
    return {"id": item["id"], "conf": deepcopy(conf), "active": bool(item.get("active", False))}


def desired_mapping(source: dict[str, Any], target: dict[str, Any] | None) -> dict[str, Any]:
    """Preserve target activation; create copied rulesets inactive."""
    return {**mapping_payload(source), "active": bool(target and target.get("active", False))}


def leader_item_matches(kind: str, source: dict[str, Any], target: dict[str, Any] | None) -> bool:
    """Compare fleet intent or ordered mapping rules without identity elision."""
    if target is None:
        return False
    if kind == "fleet_mappings":
        return desired_mapping(source, target) == mapping_payload(target)
    # Omitted optional fleet fields are unconstrained, but an omitted parent means root.
    return all(target.get(key) == value for key, value in source.items()) and target.get("inherits") == source.get("inherits")


def leader_item_digest(kind: str, source: dict[str, Any], target: dict[str, Any] | None) -> str:
    """Hash relevant target config without transient node or deployment counters."""
    if kind == "fleets" and target is not None:
        target = {key: target.get(key) for key in {*source, "inherits"}}
    return _canonical_digest(target)


def mapping_dependencies(item: dict[str, Any]) -> tuple[set[str], int]:
    """Extract literal fleet assignments; report unevaluated dynamic expressions."""
    dependencies: set[str] = set()
    dynamic = 0
    for function in cast("list[dict[str, Any]]", item["conf"]["functions"]):
        if function.get("disabled"):
            continue
        if function.get("groupId"):
            dependencies.add(str(function["groupId"]))
        for assignment in function.get("conf", {}).get("add", []):
            if assignment.get("name") != "groupId":
                continue
            value = str(assignment.get("value", "")).strip()
            if (
                len(value) > 1
                and value[0] in {"'", '"'}
                and value[-1] == value[0]
                and all(char.isalnum() or char in "_-" for char in value[1:-1])
            ):
                dependencies.add(value[1:-1])
            else:
                dynamic += 1
    return dependencies, dynamic


async def _parent_readiness(
    resolved: ResolvedControlPlane, target: GroupTarget, *, receipt_owned: bool = False, receipt_guarded_changes: bool = False
) -> tuple[dict[str, Any], list[str]]:
    """Inspect target-local parent state and explain every blocking signal."""
    label = f"Parent fleet '{target.group_id}'"
    if target.committed_version is None and not receipt_owned:
        return {"status": "unavailable", "committed_version": None, "deployed_version": target.config_version}, [
            f"{label}: committed_version unavailable despite requesting git.commit; cannot verify deployment readiness."
        ]
    status = await _group_status(resolved, target)
    snapshot = {
        key: status[key]
        for key in (
            "clean",
            "local_changes",
            "deployment_pending",
            "ahead",
            "behind",
            "conflict_count",
            "changed_paths_sha256",
            "committed_version",
            "deployed_version",
        )
    }
    blocked: list[str] = []
    if (not status["clean"] or status["local_changes"]) and not (receipt_owned or receipt_guarded_changes):
        blocked.append(f"{label}: local_changes={status['local_changes']}, clean={status['clean']}; commit pending changes.")
    if status["deployment_pending"] and not receipt_owned:
        blocked.append(
            f"{label}: deployment_pending=true (committed_version={status['committed_version']}, "
            f"deployed_version={status['deployed_version']}); deploy the parent configuration."
        )
    if status["conflict_count"]:
        blocked.append(f"{label}: conflict_count={status['conflict_count']}; resolve Git conflicts.")
    if status["behind"]:
        blocked.append(f"{label}: behind={status['behind']}; reconcile the target Leader's remote Git state.")
    # ahead is informational: local commit/deploy and remote push are separate.
    if receipt_owned:
        snapshot["receipt_owned"] = True
    return snapshot, blocked


async def provision_preflight(
    resolved: ResolvedControlPlane,
    *,
    fleets: list[EdgeFleet],
    mappings: list[dict[str, Any]],
    receipt_owned_fleets: set[str] | None = None,
    receipt_guarded_groups: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Validate fleet hierarchy, parent readiness, mapping destinations, and Git."""
    inventory = await fleet_inventory(resolved)
    existing = {str(item["id"]): item for item in inventory}
    desired = {fleet.id: fleet.payload() for fleet in ordered_fleets(fleets)}
    blocked: list[str] = []
    for fleet_id, payload in desired.items():
        if fleet_id in existing and not leader_item_matches("fleets", payload, existing[fleet_id]):
            blocked.append(f"Fleet '{fleet_id}' already exists with different settings; creation cannot update or reparent it.")
    merged = {**existing, **{key: value for key, value in desired.items() if key not in existing}}
    _deployment_order([GroupTarget.from_payload(ProductsCore.EDGE, item) for item in merged.values()])
    parents: dict[str, Any] = {}
    for fleet in fleets:
        parent = fleet.inherits
        while parent and parent in existing and parent not in parents:
            target = GroupTarget.from_payload(ProductsCore.EDGE, existing[parent])
            parents[parent], reasons = await _parent_readiness(
                resolved,
                target,
                receipt_owned=parent in (receipt_owned_fleets or set()),
                receipt_guarded_changes=parent in (receipt_guarded_groups or set()),
            )
            blocked.extend(reasons)
            parent = target.inherits
    dynamic = 0
    for mapping in mappings:
        dependencies, count = mapping_dependencies(mapping)
        dynamic += count
        missing = sorted(dependencies - merged.keys())
        if missing:
            blocked.append(
                f"Ruleset '{mapping['id']}' references {len(missing)} missing fleets: {', '.join(missing[:_PREVIEW_LIMIT])}."
            )
    status = await _global_status(resolved)
    if status["conflict_count"]:
        blocked.append(f"Leader Git repository: conflict_count={status['conflict_count']}; resolve Git conflicts.")
    if status["behind"]:
        blocked.append(f"Leader Git repository: behind={status['behind']}; reconcile remote Git state.")
    guard = {
        "server": resolved.server_name,
        "hierarchy_sha256": _canonical_digest(sorted((key, item.get("inherits")) for key, item in merged.items())),
        "fleet_count": len(merged),
        "existing_fleet_count": len(existing),
        "planned_create_count": len(merged) - len(existing),
        "parents_sha256": _canonical_digest(parents),
        "parent_count": len(parents),
        "parents": [{"id": key, **parents[key]} for key in sorted(parents)[:_PREVIEW_LIMIT]],
        "parents_truncated": len(parents) > _PREVIEW_LIMIT,
        "leader_git_sha256": _canonical_digest(status),
        "leader_git": _compact_git_status(status),
        "dynamic_mapping_expressions": dynamic,
    }
    return inventory, blocked, guard


async def write_leader_item(resolved: ResolvedControlPlane, kind: str, item: dict[str, Any], *, overwrite: bool = True) -> str:
    """Apply and verify a reviewed creation or mapping update."""
    if kind == "fleets":
        target = next((entry for entry in await fleet_inventory(resolved) if entry["id"] == item["id"]), None)
        if target is not None:
            if not leader_item_matches(kind, item, target):
                msg = f"Fleet '{item['id']}' already exists with different settings."
                raise ValueError(msg)
            return "noop"
        await create_resource(
            resolved.client, "groups", item=item, product=ProductsCore.EDGE, timeout_ms=resolved.config.timeout_ms
        )
        persisted = next((entry for entry in await fleet_inventory(resolved) if entry["id"] == item["id"]), None)
        action = "created"
    else:
        target = await read_mapping(resolved, str(item["id"]))
        if target is not None and not overwrite:
            return "skipped_existing"
        if leader_item_matches(kind, item, target):
            return "noop"
        desired = desired_mapping(item, target)
        await _direct_request_json(
            resolved.client,
            method="POST" if target is None else "PATCH",
            url=(
                f"{resolved.config.base_url_str.rstrip('/')}{_MAPPING_PATH}"
                + (f"/{quote(str(item['id']), safe='')}" if target is not None else "")
            ),
            json_body=desired,
            security=await resolved.get_security(),
            timeout_ms=resolved.config.timeout_ms,
        )
        persisted = await read_mapping(resolved, str(item["id"]))
        if persisted is not None and persisted.get("active") != desired["active"]:
            msg = "Ruleset activation changed during replication."
            raise RuntimeError(msg)
        action = "created" if target is None else "updated"
    if not leader_item_matches(kind, item, persisted):
        msg = "Post-write validation did not match the reviewed Edge configuration."
        raise RuntimeError(msg)
    return action


async def _provision(
    server: str | None,
    *,
    kind: str,
    item: dict[str, Any],
    source_server: str | None = None,
    overwrite: bool = True,
    dry_run: bool,
    expected_plan_sha256: str | None,
) -> dict[str, Any]:
    async with connect_to_server(server) as resolved:
        fleet = (
            EdgeFleet.model_validate({key: value for key, value in item.items() if key != "type"}) if kind == "fleets" else None
        )
        inventory, blocked, guard = await provision_preflight(
            resolved, fleets=[fleet] if fleet else [], mappings=[item] if kind == "fleet_mappings" else []
        )
        target = (
            next((entry for entry in inventory if entry["id"] == item["id"]), None)
            if fleet
            else await read_mapping(resolved, str(item["id"]))
        )
        action = "create" if target is None else "noop" if leader_item_matches(kind, item, target) else "update"
        if target is not None and not overwrite and kind == "fleet_mappings":
            action = "skip_existing"
        body = {
            "server": resolved.server_name,
            "source_server": source_server,
            "kind": kind,
            "item_id": item["id"],
            "action": action,
            "overwrite": overwrite,
            "source_sha256": _canonical_digest(item),
            "target_sha256": leader_item_digest(kind, item, target),
            "guard": guard,
            "blocked_reasons": blocked,
            "activation": "preserve_target" if kind == "fleet_mappings" else None,
        }
        body["fleet"] = fleet.payload() if fleet else None
        body["target_active"] = bool(target and target.get("active")) if not fleet else None
        if not fleet:
            functions = cast("list[dict[str, Any]]", item["conf"]["functions"])
            body["rule_count"] = len(functions)
            body["rule_order_sha256"] = _canonical_digest(functions)
        plan = {**body, "plan_sha256": _canonical_digest(body)}
        if dry_run:
            return {
                "status": "planned",
                "dry_run": True,
                "plan": {
                    **plan,
                    "blocked_reasons": blocked[:_PREVIEW_LIMIT],
                    "blocked_reason_count": len(blocked),
                    "blocked_reasons_truncated": len(blocked) > _PREVIEW_LIMIT,
                },
            }
        _validate_execution_plan(plan, expected_plan_sha256)
        result = await write_leader_item(resolved, kind, item, overwrite=overwrite)
        return {
            "status": result,
            "dry_run": False,
            "kind": kind,
            "item_id": item["id"],
            "executed_plan_sha256": plan["plan_sha256"],
            "committed": False,
        }


async def create_edge_fleet(
    server: str | None,
    *,
    fleet: EdgeFleet,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Create a fleet or subfleet after reviewing a drift-guarded plan."""
    return await _provision(
        server, kind="fleets", item=fleet.payload(), dry_run=dry_run, expected_plan_sha256=expected_plan_sha256
    )


async def replicate_fleet_mapping_ruleset(
    server: str | None,
    *,
    source_server: str,
    ruleset_id: str,
    overwrite: bool = True,
    dry_run: bool = True,
    expected_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Copy ordered mapping rules while preserving the target activation state."""
    async with connect_to_server(source_server) as source:
        item = await read_mapping(source, ruleset_id)
    if item is None:
        msg = f"Source fleet mapping ruleset '{ruleset_id}' does not exist."
        raise ValueError(msg)
    return await _provision(
        server,
        kind="fleet_mappings",
        item=item,
        source_server=source_server,
        overwrite=overwrite,
        dry_run=dry_run,
        expected_plan_sha256=expected_plan_sha256,
    )
