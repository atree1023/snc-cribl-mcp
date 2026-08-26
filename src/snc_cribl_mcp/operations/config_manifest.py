"""Parallel, review-gated configuration-manifest workflows."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Literal, cast

from cribl_control_plane.models.productscore import ProductsCore

from ..client.cribl_client import ResolvedControlPlane, connect_to_server
from ..models.config_manifest import ConfigManifest, DriftPolicy, LoadedConfigManifest, load_config_manifest
from .manifest_state import ManifestStateStore
from .resource_actions import (
    ResourceKind,
    append_resource,
    canonicalize_resource_item,
    create_resource,
    get_resource,
    get_resource_spec,
    update_resource,
)
from .semantic_diff import compare_config_objects
from .sync import (
    _compare_items,
    _copy_plan_digest,
    _copy_plan_snapshot,
    _maybe_get_item,
    _semantic_change_summary,
)
from .version_control import (
    _deployment_order,
    _fetch_diff,
    _global_status,
    _group_status,
    _list_targets,
    _resolve_target_from_list,
    collect_group_git_diff,
    commit_and_deploy_all,
)
from .version_control_jobs import JobContext

type ManifestOperation = Literal["commit_and_deploy_manifest", "replicate_config_manifest"]
type SnapshotItem = dict[str, Any]
type ValidationDetailScope = Literal["all", "differences"]
type WorkProgressCallback = Callable[[str, int], Awaitable[None]]
type MapProgressCallback = Callable[[str, str, dict[str, Any] | None], Awaitable[None]]

_CONTENT_ORDER = {
    "variables": 0,
    "breakers": 1,
    "lookups": 2,
    "destinations": 3,
    "pipelines": 4,
    "sources": 5,
    "routes": 6,
}
_MAX_ERROR_MESSAGE_CHARS = 2000
_MAX_RESPONSE_DETAILS = 25
_MAX_VALIDATION_DETAILS = 100
_MAX_ACTION_ITEM_PREVIEW = 25
_MAX_CONCURRENCY = 10


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _product(manifest: ConfigManifest) -> ProductsCore:
    return ProductsCore.EDGE if manifest.source.product == "edge" else ProductsCore.STREAM


def resolve_manifest_concurrency(manifest: ConfigManifest, override: int | None) -> int:
    """Resolve a tool override or the manifest's configured target concurrency."""
    effective = manifest.options.concurrency if override is None else override
    if effective < 1 or effective > _MAX_CONCURRENCY:
        msg = f"concurrency must be between 1 and {_MAX_CONCURRENCY}."
        raise ValueError(msg)
    return effective


def _error(exc: Exception) -> dict[str, Any]:
    message = str(exc)
    result: dict[str, Any] = {"type": type(exc).__name__, "message": message[:_MAX_ERROR_MESSAGE_CHARS]}
    if len(message) > _MAX_ERROR_MESSAGE_CHARS:
        result["message_truncated"] = True
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        result["status_code"] = status_code
    return result


def _ordered_content(
    manifest: ConfigManifest,
    *,
    group_order: dict[str, int] | None = None,
) -> list[tuple[str, ResourceKind, list[str]]]:
    order = group_order or {}
    return [
        (entry.group, cast("ResourceKind", entry.kind), sorted(entry.items))
        for entry in sorted(
            manifest.content,
            key=lambda value: (order.get(value.group, len(order)), value.group, _CONTENT_ORDER[value.kind]),
        )
    ]


async def _source_snapshot(loaded: LoadedConfigManifest) -> dict[str, Any]:
    """Read every source object once and return one content-addressed snapshot."""
    manifest = loaded.manifest
    product = _product(manifest)
    items: list[SnapshotItem] = []
    groups: dict[str, str] = {}
    async with connect_to_server(manifest.source.server) as source:
        inventory = await _list_targets(source, (product,))
        for group in sorted({entry.group for entry in manifest.content}):
            groups[group] = _resolve_target_from_list(inventory, group).group_id
        deployment_order = _deployment_order(inventory)
        id_order = {target.group_id: index for index, target in enumerate(deployment_order)}
        group_order = {selector: id_order[group_id] for selector, group_id in groups.items()}

        for group, kind, item_ids in _ordered_content(manifest, group_order=group_order):
            group_id = groups[group]
            for item_id in item_ids:
                item = await get_resource(
                    source.client,
                    kind,
                    item_id=item_id,
                    timeout_ms=source.config.timeout_ms,
                    group_id=group_id,
                    security=await source.get_security(),
                    hydrate_lookup_content=kind == "lookups",
                )
                items.append(
                    {
                        "group": group,
                        "group_id": group_id,
                        "kind": kind,
                        "item_id": item_id,
                        "source_sha256": _copy_plan_digest(_copy_plan_snapshot(kind, item)),
                        "item": item,
                    }
                )
    stable = [
        {key: value for key, value in item.items() if key != "item"}
        for item in sorted(
            items, key=lambda value: (str(value["group_id"]), _CONTENT_ORDER[str(value["kind"])], str(value["item_id"]))
        )
    ]
    snapshot_sha256 = _digest({"groups": groups, "items": stable})
    return {"groups": groups, "items": items, "snapshot_sha256": snapshot_sha256}


def _intent(loaded: LoadedConfigManifest, source_snapshot: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": 1,
        "manifest_path": loaded.relative_path,
        "manifest_sha256": loaded.manifest_sha256,
        "source_snapshot_sha256": source_snapshot["snapshot_sha256"],
    }
    return {**body, "intent_sha256": _digest(body)}


async def _target_git_snapshot(
    resolved: ResolvedControlPlane,
    *,
    product: ProductsCore,
    groups: dict[str, str],
) -> tuple[dict[str, Any], list[str]]:
    """Return safety-relevant Git state and preflight blockers for manifest groups."""
    inventory = await _list_targets(resolved, (product,))
    git: dict[str, Any] = {}
    blocked: list[str] = []
    for selector, expected_group_id in sorted(groups.items()):
        target = _resolve_target_from_list(inventory, selector)
        if target.group_id != expected_group_id:
            blocked.append(
                f"Group selector '{selector}' resolved to '{target.group_id}', but the source resolved to "
                f"'{expected_group_id}'."
            )
            continue
        status = await _group_status(resolved, target)
        pending = await _fetch_diff(resolved, target, diff_line_limit=0)
        git[selector] = {
            "group_id": target.group_id,
            "clean": status["clean"],
            "behind": status["behind"],
            "conflict_count": status["conflict_count"],
            "changed_paths_sha256": status["changed_paths_sha256"],
            "pending_diff_sha256": pending["sha256"],
            "incompatible_worker_count": target.incompatible_worker_count,
        }
        if not status["clean"]:
            blocked.append(f"Group/fleet '{target.group_id}' has pending configuration changes.")
        if status["behind"]:
            blocked.append(f"Group/fleet '{target.group_id}' is behind its configured Git remote.")
        if status["conflict_count"]:
            blocked.append(f"Group/fleet '{target.group_id}' contains Git conflicts.")
    leader = await _global_status(resolved)
    if leader["conflict_count"]:
        blocked.append("The Leader Git working tree contains conflicts.")
    if leader["behind"]:
        blocked.append("The Leader Git branch is behind its configured remote.")
    return {"groups": git, "leader_behind": leader["behind"], "leader_conflict_count": leader["conflict_count"]}, blocked


async def _target_replication_plan(
    target_server: str,
    *,
    loaded: LoadedConfigManifest,
    source_snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Build one target's complete drift-guarded replication plan."""
    manifest = loaded.manifest
    product = _product(manifest)
    plan_items: list[dict[str, Any]] = []
    blocked: list[str] = []
    async with connect_to_server(target_server) as target:
        git, git_blocked = await _target_git_snapshot(
            target,
            product=product,
            groups=cast("dict[str, str]", source_snapshot["groups"]),
        )
        blocked.extend(git_blocked)
        for snapshot_item in cast("list[SnapshotItem]", source_snapshot["items"]):
            group_id = str(snapshot_item["group_id"])
            kind = cast("ResourceKind", snapshot_item["kind"])
            item_id = str(snapshot_item["item_id"])
            source_item = cast("dict[str, Any]", snapshot_item["item"])
            try:
                target_item = await _maybe_get_item(
                    target,
                    kind,
                    item_id=item_id,
                    group_id=group_id,
                    hydrate_lookup_content=kind == "lookups",
                )
                spec = get_resource_spec(kind)
                if target_item is None:
                    if spec.supports("create"):
                        action = "create"
                    else:
                        action = "unsupported"
                        blocked.append(f"{group_id}/{kind}/{item_id} is missing and cannot be created.")
                elif not manifest.options.overwrite:
                    action = "skip_existing"
                elif kind == "routes" and manifest.options.append_routes:
                    action = "append"
                else:
                    comparison = _compare_items(kind, item_id, source_item, target_item)
                    action = "noop" if comparison["status"] == "in_sync" else "update"
                plan_item: dict[str, Any] = {
                    "group": snapshot_item["group"],
                    "group_id": group_id,
                    "kind": kind,
                    "item_id": item_id,
                    "action": action,
                    "source_sha256": snapshot_item["source_sha256"],
                    "target_sha256": (
                        _copy_plan_digest(_copy_plan_snapshot(kind, target_item)) if target_item is not None else None
                    ),
                }
                if action == "update" and target_item is not None:
                    plan_item["semantic_changes"] = _semantic_change_summary(kind, source_item, target_item)
                plan_items.append(plan_item)
            except Exception as exc:  # noqa: BLE001 - retain per-item planning failures
                blocked.append(f"Could not inspect {group_id}/{kind}/{item_id}: {exc}")
                plan_items.append(
                    {
                        "group": snapshot_item["group"],
                        "group_id": group_id,
                        "kind": kind,
                        "item_id": item_id,
                        "action": "failed",
                        "source_sha256": snapshot_item["source_sha256"],
                        "error": _error(exc),
                    }
                )

    digest_body = {"server": target_server, "git": git, "items": plan_items, "blocked_reasons": blocked}
    return {**digest_body, "target_plan_sha256": _digest(digest_body)}


async def _bounded_map(
    values: list[str],
    *,
    concurrency: int,
    operation: Callable[[str], Awaitable[dict[str, Any]]],
    progress_callback: MapProgressCallback | None = None,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def _one(value: str) -> dict[str, Any]:
        async with semaphore:
            if progress_callback is not None:
                await progress_callback("started", value, None)
            try:
                result = await operation(value)
            except Exception as exc:  # noqa: BLE001 - aggregate operations preserve partial target results
                body = {"server": value, "blocked_reasons": [str(exc)], "error": _error(exc)}
                result = {**body, "target_plan_sha256": _digest(body)}
            if progress_callback is not None:
                await progress_callback("completed", value, result)
            return result

    return list(await asyncio.gather(*(_one(value) for value in values)))


def _public_action_items(items: list[dict[str, Any]], actions: set[str]) -> dict[str, Any]:
    """Return bounded item identities plus a complete digest for one action bucket."""
    identities = [
        {
            "group": item.get("group"),
            "group_id": item.get("group_id"),
            "kind": item.get("kind"),
            "item_id": item.get("item_id"),
        }
        for item in items
        if item.get("action") in actions
    ]
    return {
        "count": len(identities),
        "items": identities[:_MAX_ACTION_ITEM_PREVIEW],
        "items_truncated": len(identities) > _MAX_ACTION_ITEM_PREVIEW,
        "items_sha256": _digest(identities),
    }


def _public_apply_order(source_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe the actual dependency-aware content-block order used by replication."""
    blocks: list[dict[str, Any]] = []
    for item in cast("list[SnapshotItem]", source_snapshot["items"]):
        key = (str(item["group"]), str(item["group_id"]), str(item["kind"]))
        if not blocks or tuple(blocks[-1][field] for field in ("group", "group_id", "kind")) != key:
            blocks.append(
                {
                    "sequence": len(blocks) + 1,
                    "group": key[0],
                    "group_id": key[1],
                    "kind": key[2],
                    "item_ids": [],
                }
            )
        cast("list[str]", blocks[-1]["item_ids"]).append(str(item["item_id"]))
    for block in blocks:
        item_ids = cast("list[str]", block.pop("item_ids"))
        block.update(
            {
                "item_count": len(item_ids),
                "item_ids": item_ids[:_MAX_ACTION_ITEM_PREVIEW],
                "item_ids_truncated": len(item_ids) > _MAX_ACTION_ITEM_PREVIEW,
                "item_ids_sha256": _digest(item_ids),
            }
        )
    return blocks


def _public_replication_plan(
    *,
    loaded: LoadedConfigManifest,
    intent: dict[str, Any],
    target_plans: list[dict[str, Any]],
    source_snapshot: dict[str, Any],
    plan_sha256: str,
    concurrency: int,
) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for plan in target_plans:
        items = cast("list[dict[str, Any]]", plan.get("items", []))
        blocked_reasons = cast("list[str]", plan.get("blocked_reasons", []))
        action_items = {
            "create": _public_action_items(items, {"create"}),
            "update": _public_action_items(items, {"update"}),
            "append": _public_action_items(items, {"append"}),
            "noop": _public_action_items(items, {"noop", "skip_existing"}),
            "failed": _public_action_items(items, {"failed", "unsupported"}),
        }
        targets.append(
            {
                "server": plan["server"],
                "target_plan_sha256": plan["target_plan_sha256"],
                "blocked_reason_count": len(blocked_reasons),
                "blocked_reasons": blocked_reasons[:_MAX_RESPONSE_DETAILS],
                "blocked_reasons_truncated": len(blocked_reasons) > _MAX_RESPONSE_DETAILS,
                "summary": {action: detail["count"] for action, detail in action_items.items()},
                "action_items": action_items,
            }
        )
    return {
        "status": "planned",
        "dry_run": True,
        "operation": "replicate_config_manifest",
        "manifest_path": loaded.relative_path,
        "wave": loaded.manifest.wave,
        "source_server": loaded.manifest.source.server,
        "product": loaded.manifest.source.product,
        "concurrency": concurrency,
        **intent,
        "plan_sha256": plan_sha256,
        "target_count": len(targets),
        "blocked_target_count": sum(bool(target["blocked_reasons"]) for target in targets),
        "apply_order": _public_apply_order(source_snapshot),
        "targets": targets,
    }


async def plan_config_manifest_replication(
    manifest_path: str,
    *,
    state_store: ManifestStateStore,
    concurrency: int | None = None,
) -> dict[str, Any]:
    """Build and durably store a multi-target replication plan."""
    loaded = load_config_manifest(manifest_path)
    source_snapshot = await _source_snapshot(loaded)
    intent = _intent(loaded, source_snapshot)
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)

    async def _plan(target: str) -> dict[str, Any]:
        return await _target_replication_plan(target, loaded=loaded, source_snapshot=source_snapshot)

    target_plans = await _bounded_map(
        loaded.manifest.targets,
        concurrency=effective_concurrency,
        operation=_plan,
    )
    plan_body = {
        "operation": "replicate_config_manifest",
        "manifest_path": loaded.relative_path,
        "intent": intent,
        "targets": target_plans,
    }
    plan_sha256 = _digest(plan_body)
    stored = {
        **plan_body,
        "plan_sha256": plan_sha256,
        "created_at": _now(),
    }
    state_store.save_plan(
        plan_sha256=plan_sha256,
        operation="replicate_config_manifest",
        intent_sha256=str(intent["intent_sha256"]),
        manifest_path=loaded.relative_path,
        created_at=str(stored["created_at"]),
        payload=stored,
    )
    return _public_replication_plan(
        loaded=loaded,
        intent=intent,
        target_plans=target_plans,
        source_snapshot=source_snapshot,
        plan_sha256=plan_sha256,
        concurrency=effective_concurrency,
    )


async def _write_target(  # noqa: C901, PLR0912
    target_server: str,
    *,
    loaded: LoadedConfigManifest,
    source_snapshot: dict[str, Any],
    progress_callback: WorkProgressCallback | None = None,
) -> dict[str, Any]:
    """Apply one already-reviewed source snapshot to a target leader."""
    manifest = loaded.manifest
    results: list[dict[str, Any]] = []
    async with connect_to_server(target_server) as target:
        for snapshot_item in cast("list[SnapshotItem]", source_snapshot["items"]):
            kind = cast("ResourceKind", snapshot_item["kind"])
            item_id = str(snapshot_item["item_id"])
            group_id = str(snapshot_item["group_id"])
            source_item = cast("dict[str, Any]", snapshot_item["item"])
            try:
                target_item = await _maybe_get_item(
                    target,
                    kind,
                    item_id=item_id,
                    group_id=group_id,
                    hydrate_lookup_content=kind == "lookups",
                )
                if target_item is None:
                    if not get_resource_spec(kind).supports("create"):
                        msg = f"Missing target item cannot be created for kind '{kind}'."
                        raise ValueError(msg)  # noqa: TRY301
                    await create_resource(
                        target.client,
                        kind,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        group_id=group_id,
                        security=await target.get_security(),
                    )
                    action = "created"
                elif not manifest.options.overwrite:
                    action = "skipped_existing"
                elif kind == "routes" and manifest.options.append_routes:
                    await append_resource(
                        target.client,
                        kind,
                        item_id=item_id,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        group_id=group_id,
                    )
                    action = "appended"
                elif _compare_items(kind, item_id, source_item, target_item)["status"] == "in_sync":
                    action = "noop"
                else:
                    await update_resource(
                        target.client,
                        kind,
                        item_id=item_id,
                        item=source_item,
                        timeout_ms=target.config.timeout_ms,
                        group_id=group_id,
                        security=await target.get_security(),
                    )
                    action = "updated"
                persisted = await _maybe_get_item(
                    target,
                    kind,
                    item_id=item_id,
                    group_id=group_id,
                    hydrate_lookup_content=kind == "lookups",
                )
                in_sync = (
                    action in {"appended", "skipped_existing"}
                    or _compare_items(kind, item_id, source_item, persisted)["status"] == "in_sync"
                )
                if not in_sync:
                    msg = "Post-write validation did not match the reviewed source snapshot."
                    raise RuntimeError(msg)  # noqa: TRY301
                results.append({"group_id": group_id, "kind": kind, "item_id": item_id, "action": action})
                if progress_callback is not None:
                    await progress_callback(action, 1)
            except Exception as exc:  # noqa: BLE001 - stop this target at the first dependency failure
                results.append(
                    {
                        "group_id": group_id,
                        "kind": kind,
                        "item_id": item_id,
                        "action": "failed",
                        "error": _error(exc),
                    }
                )
                if progress_callback is not None:
                    await progress_callback("failed", 1)
                break

    skipped = max(len(cast("list[SnapshotItem]", source_snapshot["items"])) - len(results), 0)
    if skipped and progress_callback is not None:
        await progress_callback("skipped", skipped)

    receipt_groups: dict[str, Any] = {}
    for group_id in sorted(set(cast("dict[str, str]", source_snapshot["groups"]).values())):
        try:
            diff = await collect_group_git_diff(
                target_server,
                product=_product(manifest),
                group=group_id,
                compare_to="head",
                diff_line_limit=0,
            )
            receipt_groups[group_id] = {
                "pending_diff_sha256": diff["pending_diff_sha256"],
                "changed_paths_sha256": diff["summary"]["paths_sha256"],
                "file_count": diff["summary"]["file_count"],
            }
        except Exception as exc:  # noqa: BLE001 - a missing receipt guard makes this target unusable for deployment
            receipt_groups[group_id] = {"error": _error(exc)}

    failed = sum(result["action"] == "failed" for result in results)
    receipt_failed = sum("error" in value for value in receipt_groups.values())
    return {
        "server": target_server,
        "status": "applied" if not failed and not receipt_failed else "partial_failure",
        "summary": {
            "created": sum(result["action"] == "created" for result in results),
            "updated": sum(result["action"] == "updated" for result in results),
            "appended": sum(result["action"] == "appended" for result in results),
            "noop": sum(result["action"] in {"noop", "skipped_existing"} for result in results),
            "skipped": skipped,
            "failed": failed + receipt_failed,
        },
        "failures": [result for result in results if result["action"] == "failed"],
        "receipt_groups": receipt_groups,
    }


def _expected_target_plans(stored_plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    targets = cast("list[dict[str, Any]]", stored_plan.get("targets", []))
    return {str(target["server"]): target for target in targets}


async def execute_config_manifest_replication(  # noqa: C901, PLR0915
    manifest_path: str,
    *,
    expected_plan_sha256: str,
    state_store: ManifestStateStore,
    job_context: JobContext,
    concurrency: int | None = None,
    on_drift: DriftPolicy | None = None,
    resume_details: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute a reviewed replication plan and emit a durable apply receipt."""
    stored = state_store.get_plan(expected_plan_sha256, operation="replicate_config_manifest")
    loaded = load_config_manifest(manifest_path)
    if stored.get("manifest_path") != loaded.relative_path:
        msg = "The reviewed plan belongs to a different manifest path."
        raise ValueError(msg)
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
    item_count = sum(len(entry.items) for entry in loaded.manifest.content)
    progress: dict[str, Any] = {
        "unit": "items",
        "total": item_count * len(loaded.manifest.targets),
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "running": 0,
        "target_total": len(loaded.manifest.targets),
        "targets_completed": 0,
        "targets_failed": 0,
        "targets_skipped": 0,
        "concurrency": effective_concurrency,
        "phase": "snapshotting_source",
        "source_running": 1,
        "revalidation_total": len(loaded.manifest.targets),
        "revalidated": 0,
        "revalidation_running": 0,
        "revalidation_failed": 0,
    }
    progress_lock = asyncio.Lock()

    async def _update_progress(**changes: int | str) -> None:
        async with progress_lock:
            for key, value in changes.items():
                if isinstance(value, int) and isinstance(progress.get(key), int):
                    progress[key] = int(progress[key]) + value
                else:
                    progress[key] = value
            job_context.update_progress(dict(progress))

    job_context.update_progress(dict(progress))
    source_snapshot = await _source_snapshot(loaded)
    progress["source_running"] = 0
    current_intent = _intent(loaded, source_snapshot)
    stored_intent = cast("dict[str, Any]", stored["intent"])
    if current_intent["intent_sha256"] != stored_intent["intent_sha256"]:
        msg = "The manifest or source configuration changed after review; create a new dry-run plan."
        raise ValueError(msg)

    expected_targets = _expected_target_plans(stored)
    drift_policy = on_drift or loaded.manifest.options.on_drift
    prior = resume_details or {}
    progress["phase"] = "revalidating"
    job_context.update_progress(dict(progress))

    async def _resume_state_is_guarded(target: str, detail: dict[str, Any]) -> tuple[str, bool]:
        if detail.get("status") in {"applied", "noop", "completed"}:
            return target, True
        receipt_groups = detail.get("receipt_groups")
        if not isinstance(receipt_groups, dict) or not receipt_groups:
            return target, False
        reasons = await _receipt_drift(
            target,
            loaded=loaded,
            receipt_target={"status": "applied", "groups": receipt_groups},
        )
        return target, not reasons

    resume_guard_results = await asyncio.gather(*(_resume_state_is_guarded(target, detail) for target, detail in prior.items()))
    resume_safe = {target for target, is_safe in resume_guard_results if is_safe}

    async def _plan(target: str) -> dict[str, Any]:
        return await _target_replication_plan(target, loaded=loaded, source_snapshot=source_snapshot)

    async def _revalidation_progress(event: str, _target: str, result: dict[str, Any] | None) -> None:
        if event == "started":
            await _update_progress(running=1, revalidation_running=1)
        else:
            await _update_progress(
                running=-1,
                revalidation_running=-1,
                revalidated=1,
                revalidation_failed=int(result is not None and "error" in result),
            )

    current_plans = await _bounded_map(
        loaded.manifest.targets,
        concurrency=effective_concurrency,
        operation=_plan,
        progress_callback=_revalidation_progress,
    )
    progress["phase"] = "applying"
    job_context.update_progress(dict(progress))
    drifted = {
        str(plan["server"]): plan
        for plan in current_plans
        if str(plan["server"]) not in resume_safe
        and (
            bool(plan.get("blocked_reasons"))
            or str(plan.get("target_plan_sha256"))
            != str(expected_targets.get(str(plan["server"]), {}).get("target_plan_sha256"))
        )
    }
    if drifted and drift_policy == "abort":
        msg = f"Replication aborted because {len(drifted)} target plan(s) drifted after review."
        raise ValueError(msg)

    completed_prior = {server for server, detail in prior.items() if detail.get("status") in {"applied", "noop", "completed"}}
    results: dict[str, dict[str, Any]] = {}
    semaphore = asyncio.Semaphore(effective_concurrency)

    async def _apply(target: str) -> None:
        if target in completed_prior:
            detail = {**prior[target], "status": "resumed_completed", "resumed_from_prior_job": True}
            await _update_progress(completed=item_count)
        elif target in drifted:
            detail = {
                "server": target,
                "status": "skipped_drift",
                "expected_target_plan_sha256": expected_targets.get(target, {}).get("target_plan_sha256"),
                "current_target_plan_sha256": drifted[target].get("target_plan_sha256"),
            }
            await _update_progress(completed=item_count, skipped=item_count)
        else:
            async with semaphore:
                await _update_progress(running=1, phase="applying")
                job_context.set_target_detail(target, {"server": target, "status": "running"})

                async def _item_progress(action: str, count: int) -> None:
                    changes: dict[str, int | str] = {"completed": count}
                    if action == "failed":
                        changes["failed"] = count
                    elif action == "skipped":
                        changes["skipped"] = count
                    await _update_progress(**changes)

                try:
                    detail = await _write_target(
                        target,
                        loaded=loaded,
                        source_snapshot=source_snapshot,
                        progress_callback=_item_progress,
                    )
                finally:
                    await _update_progress(running=-1)
        results[target] = detail
        job_context.set_target_detail(target, detail)
        target_skipped = detail.get("status") == "skipped_drift"
        target_failed = detail.get("status") not in {"applied", "noop", "resumed_completed", "skipped_drift"}
        await _update_progress(
            targets_completed=1,
            targets_failed=int(target_failed),
            targets_skipped=int(target_skipped),
        )

    await asyncio.gather(*(_apply(target) for target in loaded.manifest.targets))
    receipt_targets = {
        target: {
            "status": detail.get("status"),
            "summary": detail.get("summary"),
            "groups": detail.get("receipt_groups", {}),
        }
        for target, detail in sorted(results.items())
    }
    receipt_body = {
        "operation": "replicate_config_manifest",
        "job_id": job_context.job_id,
        "manifest_path": loaded.relative_path,
        "manifest_sha256": loaded.manifest_sha256,
        "intent_sha256": current_intent["intent_sha256"],
        "source_snapshot_sha256": source_snapshot["snapshot_sha256"],
        "created_at": _now(),
        "targets": receipt_targets,
    }
    receipt_sha256 = _digest(receipt_body)
    receipt = {**receipt_body, "receipt_sha256": receipt_sha256}
    state_store.save_receipt(
        receipt_sha256=receipt_sha256,
        job_id=job_context.job_id,
        intent_sha256=str(current_intent["intent_sha256"]),
        manifest_path=loaded.relative_path,
        created_at=str(receipt_body["created_at"]),
        payload=receipt,
    )
    skipped_targets = [target for target, detail in results.items() if detail.get("status") == "skipped_drift"]
    failed_targets = [
        target
        for target, detail in results.items()
        if detail.get("status") not in {"applied", "noop", "resumed_completed", "skipped_drift"}
    ]
    completed = len(results) - len(skipped_targets) - len(failed_targets)
    return {
        "status": "partial_failure" if failed_targets else "partial_skip" if skipped_targets else "completed",
        "operation": "replicate_config_manifest",
        "manifest_path": loaded.relative_path,
        "executed_plan_sha256": expected_plan_sha256,
        "apply_receipt_sha256": receipt_sha256,
        "summary": {
            "target_count": len(results),
            "completed": completed,
            "skipped": len(skipped_targets),
            "failed": len(failed_targets),
        },
        "skipped_targets": skipped_targets,
        "failed_targets": failed_targets,
        "detail_with": "get_config_deployment_job(job_id, target)",
    }


def _validate_detail_page(*, offset: int, limit: int, detail_scope: ValidationDetailScope) -> None:
    """Validate bounded manifest-validation detail controls."""
    if offset < 0:
        msg = "offset must be at least 0."
        raise ValueError(msg)
    if limit < 1 or limit > _MAX_VALIDATION_DETAILS:
        msg = f"limit must be between 1 and {_MAX_VALIDATION_DETAILS}."
        raise ValueError(msg)
    if detail_scope not in {"all", "differences"}:
        msg = "detail_scope must be 'differences' or 'all'."
        raise ValueError(msg)


async def validate_config_manifest(
    manifest_path: str,
    *,
    concurrency: int | None = None,
    target: str | None = None,
    offset: int = 0,
    limit: int = _MAX_RESPONSE_DETAILS,
    detail_scope: ValidationDetailScope = "differences",
) -> dict[str, Any]:
    """Semantically validate manifest items with bounded, pageable detail."""
    loaded = load_config_manifest(manifest_path)
    snapshot = await _source_snapshot(loaded)
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
    _validate_detail_page(offset=offset, limit=limit, detail_scope=detail_scope)
    targets = loaded.manifest.targets
    if target is not None:
        normalized_target = target.strip()
        if normalized_target not in targets:
            msg = f"Target '{normalized_target}' is not present in manifest '{loaded.relative_path}'."
            raise ValueError(msg)
        targets = [normalized_target]

    async def _validate(target_server: str) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        async with connect_to_server(target_server) as resolved_target:
            for source in cast("list[SnapshotItem]", snapshot["items"]):
                kind = cast("ResourceKind", source["kind"])
                target_item = await _maybe_get_item(
                    resolved_target,
                    kind,
                    item_id=str(source["item_id"]),
                    group_id=str(source["group_id"]),
                    hydrate_lookup_content=kind == "lookups",
                )
                if target_item is None:
                    items.append(
                        {
                            "group_id": source["group_id"],
                            "kind": kind,
                            "item_id": source["item_id"],
                            "status": "missing",
                            "action": "create" if get_resource_spec(kind).supports("create") else "unsupported",
                        }
                    )
                    continue
                source_payload = canonicalize_resource_item(kind, cast("dict[str, Any]", source["item"]))
                target_payload = canonicalize_resource_item(kind, target_item)
                source_payload.pop("status", None)
                target_payload.pop("status", None)
                comparison = compare_config_objects(kind, source_payload, target_payload)
                action = "update" if comparison["status"] == "functional_difference" else "noop"
                items.append(
                    {
                        "group_id": source["group_id"],
                        "kind": kind,
                        "item_id": source["item_id"],
                        "status": comparison["status"],
                        "action": action,
                        "functional_difference_count": len(comparison["functional_differences"]),
                        "identity_difference_count": len(comparison["identity_differences"]),
                        "volatile_difference_count": len(comparison["volatile_differences"]),
                    }
                )
        create = sum(item["action"] == "create" for item in items)
        update = sum(item["action"] == "update" for item in items)
        noop = sum(item["action"] == "noop" for item in items)
        unsupported = sum(item["action"] == "unsupported" for item in items)
        blocking = create + update + unsupported
        differences = [
            item
            for item in items
            if item["action"] != "noop"
            or int(item.get("identity_difference_count", 0)) > 0
            or int(item.get("volatile_difference_count", 0)) > 0
        ]
        detail_items = items if detail_scope == "all" else differences
        page = detail_items[offset : offset + limit]
        next_offset = offset + len(page) if offset + len(page) < len(detail_items) else None
        previous_offset = max(offset - limit, 0) if offset > 0 else None
        details_truncated = offset > 0 or next_offset is not None
        detail_key = "items" if detail_scope == "all" else "differences"
        result = {
            "server": target_server,
            "status": "in_sync" if blocking == 0 else "different",
            "summary": {
                "item_count": len(items),
                "create": create,
                "update": update,
                "noop": noop,
                "unsupported": unsupported,
                "missing": create + unsupported,
                "functional_differences": update,
                "functionally_equivalent": noop,
                "functional_or_missing": blocking,
                "identity_differences": sum(int(item.get("identity_difference_count", 0)) for item in items),
                "volatile_differences": sum(int(item.get("volatile_difference_count", 0)) for item in items),
            },
            "detail_scope": detail_scope,
            "detail_count": len(detail_items),
            "detail_offset": offset,
            "detail_limit": limit,
            "next_offset": next_offset,
            "previous_offset": previous_offset,
            "details_truncated": details_truncated,
            detail_key: page,
        }
        if detail_scope == "differences":
            result.update(
                {
                    "difference_count": len(detail_items),
                    "differences_offset": offset,
                    "differences_limit": limit,
                    "differences_next_offset": next_offset,
                    "differences_previous_offset": previous_offset,
                    "differences_truncated": details_truncated,
                }
            )
        return result

    target_results = await _bounded_map(targets, concurrency=effective_concurrency, operation=_validate)
    failed = [target_result for target_result in target_results if target_result.get("status") != "in_sync"]
    return {
        "status": "in_sync" if not failed else "different",
        "operation": "validate_config_manifest",
        "manifest_path": loaded.relative_path,
        "manifest_sha256": loaded.manifest_sha256,
        "source_snapshot_sha256": snapshot["snapshot_sha256"],
        "concurrency": effective_concurrency,
        "target_filter": target,
        "detail_scope": detail_scope,
        "offset": offset,
        "limit": limit,
        "target_count": len(target_results),
        "in_sync_count": len(target_results) - len(failed),
        "different_or_failed_count": len(failed),
        "targets": target_results,
    }


async def _receipt_drift(
    target_server: str,
    *,
    loaded: LoadedConfigManifest,
    receipt_target: dict[str, Any],
) -> list[str]:
    """Verify current group diffs still exactly match an apply receipt."""
    reasons: list[str] = []
    groups = cast("dict[str, dict[str, Any]]", receipt_target.get("groups", {}))
    if receipt_target.get("status") not in {"applied", "noop", "resumed_completed"}:
        reasons.append("The apply receipt does not record this target as successfully applied.")
    for group_id, expected in groups.items():
        if "error" in expected:
            reasons.append(f"The apply receipt could not guard group/fleet '{group_id}'.")
            continue
        current = await collect_group_git_diff(
            target_server,
            product=_product(loaded.manifest),
            group=group_id,
            compare_to="head",
            diff_line_limit=0,
        )
        if current["pending_diff_sha256"] != expected.get("pending_diff_sha256"):
            reasons.append(f"Group/fleet '{group_id}' changed after manifest replication.")
    return reasons


async def check_manifest_receipt_validity(
    manifest_path: str,
    *,
    apply_job_id: str | None,
    apply_receipt_sha256: str | None,
    state_store: ManifestStateStore,
    concurrency: int | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """Check whether an apply receipt still authorizes commit/deploy without mutating configuration."""
    loaded = load_config_manifest(manifest_path)
    receipt = state_store.get_receipt(receipt_sha256=apply_receipt_sha256, job_id=apply_job_id)
    receipt_targets = cast("dict[str, dict[str, Any]]", receipt.get("targets", {}))
    selected_targets = sorted(receipt_targets)
    if target is not None:
        normalized_target = target.strip()
        if normalized_target not in receipt_targets:
            msg = f"Target '{normalized_target}' is not present in the apply receipt."
            raise ValueError(msg)
        selected_targets = [normalized_target]
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
    manifest_reasons: list[str] = []
    if receipt.get("manifest_path") != loaded.relative_path:
        manifest_reasons.append("The apply receipt belongs to a different manifest path.")
    if receipt.get("manifest_sha256") != loaded.manifest_sha256:
        manifest_reasons.append("The manifest content changed after the apply receipt was created.")

    async def _check(target_server: str) -> dict[str, Any]:
        reasons = list(manifest_reasons)
        if not reasons:
            reasons.extend(
                await _receipt_drift(
                    target_server,
                    loaded=loaded,
                    receipt_target=receipt_targets[target_server],
                )
            )
        return {
            "server": target_server,
            "status": "valid" if not reasons else "stale",
            "reason_count": len(reasons),
            "reasons": reasons[:_MAX_RESPONSE_DETAILS],
            "reasons_truncated": len(reasons) > _MAX_RESPONSE_DETAILS,
        }

    target_results = await _bounded_map(selected_targets, concurrency=effective_concurrency, operation=_check)
    for result in target_results:
        if "error" in result:
            result["status"] = "error"
    valid_count = sum(result.get("status") == "valid" for result in target_results)
    stale_count = sum(result.get("status") == "stale" for result in target_results)
    error_count = len(target_results) - valid_count - stale_count
    return {
        "status": "valid" if valid_count == len(target_results) else "stale" if error_count == 0 else "error",
        "operation": "check_manifest_receipt_validity",
        "manifest_path": loaded.relative_path,
        "manifest_sha256": loaded.manifest_sha256,
        "apply_receipt_sha256": receipt["receipt_sha256"],
        "target_filter": target,
        "summary": {
            "target_count": len(target_results),
            "valid": valid_count,
            "stale": stale_count,
            "error": error_count,
        },
        "targets": target_results,
    }


async def plan_manifest_commit_deploy(
    manifest_path: str,
    *,
    apply_job_id: str | None,
    apply_receipt_sha256: str | None,
    message: str,
    push: bool,
    state_store: ManifestStateStore,
    concurrency: int | None = None,
) -> dict[str, Any]:
    """Build and store a receipt-gated commit/deploy plan for all applied targets."""
    loaded = load_config_manifest(manifest_path)
    receipt = state_store.get_receipt(receipt_sha256=apply_receipt_sha256, job_id=apply_job_id)
    if receipt.get("manifest_path") != loaded.relative_path or receipt.get("manifest_sha256") != loaded.manifest_sha256:
        msg = "The apply receipt does not match the current manifest."
        raise ValueError(msg)
    receipt_targets = cast("dict[str, dict[str, Any]]", receipt.get("targets", {}))
    groups = sorted({entry.group for entry in loaded.manifest.content})
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)

    async def _plan(target: str) -> dict[str, Any]:
        target_receipt = receipt_targets.get(target, {})
        blocked = await _receipt_drift(target, loaded=loaded, receipt_target=target_receipt)
        inner = await commit_and_deploy_all(
            target,
            message=message,
            product=loaded.manifest.source.product,
            effective=True,
            push=push,
            stop_on_error=True,
            dry_run=True,
            groups=groups,
        )
        inner_plan = cast("dict[str, Any]", inner["plan"])
        blocked.extend(cast("list[str]", inner_plan.get("blocked_reasons", [])))
        body = {
            "server": target,
            "receipt_sha256": receipt["receipt_sha256"],
            "inner_plan_sha256": inner_plan["plan_sha256"],
            "push_action": inner_plan["push_action"],
            "leader_blocked_paths": inner_plan.get("leader_blocked_paths", []),
            "blocked_reasons": list(dict.fromkeys(blocked)),
            "summary": {
                "target_count": len(cast("list[dict[str, Any]]", inner_plan["targets"])),
                "actions": [item["action"] for item in cast("list[dict[str, Any]]", inner_plan["targets"])],
            },
            "ordered_actions": [
                {
                    "sequence": index,
                    "product": cast("dict[str, Any]", item["target"])["product"],
                    "group": cast("dict[str, Any]", item["target"])["id"],
                    "action": item["action"],
                    "inherited_deploy_from": item.get("inherited_deploy_from"),
                }
                for index, item in enumerate(cast("list[dict[str, Any]]", inner_plan["targets"]), start=1)
            ],
        }
        return {**body, "target_plan_sha256": _digest(body)}

    target_plans = await _bounded_map(list(receipt_targets), concurrency=effective_concurrency, operation=_plan)
    body = {
        "operation": "commit_and_deploy_manifest",
        "manifest_path": loaded.relative_path,
        "manifest_sha256": loaded.manifest_sha256,
        "receipt_sha256": receipt["receipt_sha256"],
        "message": message,
        "push": push,
        "concurrency": effective_concurrency,
        "groups": groups,
        "targets": [
            {
                **plan,
                "blocked_reason_count": len(cast("list[str]", plan.get("blocked_reasons", []))),
                "blocked_reasons": cast("list[str]", plan.get("blocked_reasons", []))[:_MAX_RESPONSE_DETAILS],
                "blocked_reasons_truncated": len(cast("list[str]", plan.get("blocked_reasons", []))) > _MAX_RESPONSE_DETAILS,
            }
            for plan in target_plans
        ],
    }
    plan_sha256 = _digest(body)
    stored = {**body, "plan_sha256": plan_sha256, "created_at": _now()}
    state_store.save_plan(
        plan_sha256=plan_sha256,
        operation="commit_and_deploy_manifest",
        intent_sha256=str(receipt["intent_sha256"]),
        manifest_path=loaded.relative_path,
        created_at=str(stored["created_at"]),
        payload=stored,
    )
    return {
        "status": "planned",
        "dry_run": True,
        "operation": "commit_and_deploy_manifest",
        "manifest_path": loaded.relative_path,
        "apply_receipt_sha256": receipt["receipt_sha256"],
        "plan_sha256": plan_sha256,
        "concurrency": effective_concurrency,
        "target_count": len(target_plans),
        "blocked_target_count": sum(bool(plan.get("blocked_reasons")) for plan in target_plans),
        "targets": target_plans,
    }


async def execute_manifest_commit_deploy(  # noqa: C901, PLR0915
    manifest_path: str,
    *,
    expected_plan_sha256: str,
    message: str,
    push: bool,
    state_store: ManifestStateStore,
    job_context: JobContext,
    concurrency: int | None = None,
    on_drift: DriftPolicy = "skip",
    resume_details: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Commit and deploy receipt-guarded changes to target leaders in parallel."""
    stored = state_store.get_plan(expected_plan_sha256, operation="commit_and_deploy_manifest")
    loaded = load_config_manifest(manifest_path)
    if stored.get("manifest_path") != loaded.relative_path or stored.get("manifest_sha256") != loaded.manifest_sha256:
        msg = "The reviewed commit/deploy plan does not match the current manifest."
        raise ValueError(msg)
    if stored.get("message") != message or bool(stored.get("push")) != push:
        msg = "The commit message or push option changed after review."
        raise ValueError(msg)
    receipt = state_store.get_receipt(receipt_sha256=str(stored["receipt_sha256"]))
    expected = _expected_target_plans(stored)
    groups = cast("list[str]", stored["groups"])
    targets = sorted(expected)
    fleet_counts = {
        target: int(cast("dict[str, Any]", expected[target].get("summary", {})).get("target_count", 0)) for target in targets
    }
    effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
    prior = resume_details or {}
    results: dict[str, dict[str, Any]] = {}
    semaphore = asyncio.Semaphore(effective_concurrency)
    progress: dict[str, Any] = {
        "unit": "fleets",
        "total": sum(fleet_counts.values()),
        "completed": 0,
        "failed": 0,
        "skipped": 0,
        "running": 0,
        "leader_total": len(targets),
        "leaders_completed": 0,
        "leaders_failed": 0,
        "leaders_skipped": 0,
        "concurrency": effective_concurrency,
        "phase": "executing",
    }
    progress_lock = asyncio.Lock()
    job_context.update_progress(dict(progress))

    async def _update_progress(**changes: object) -> None:
        async with progress_lock:
            for key, value in changes.items():
                if isinstance(value, int) and isinstance(progress.get(key), int):
                    progress[key] = int(progress[key]) + value
                else:
                    progress[key] = value
            job_context.update_progress(dict(progress))

    async def _execute(target: str) -> None:
        if prior.get(target, {}).get("status") == "completed":
            detail = {**prior[target], "status": "resumed_completed", "resumed_from_prior_job": True}
            await _update_progress(completed=fleet_counts[target])
        else:
            async with semaphore:
                await _update_progress(running=1, current_server=target)
                job_context.set_target_detail(target, {"server": target, "status": "running"})
                fleet_completed = 0
                try:
                    receipt_target = cast("dict[str, Any]", receipt["targets"].get(target, {}))
                    blocked = await _receipt_drift(target, loaded=loaded, receipt_target=receipt_target)
                    current = await commit_and_deploy_all(
                        target,
                        message=message,
                        product=loaded.manifest.source.product,
                        effective=True,
                        push=push,
                        stop_on_error=True,
                        dry_run=True,
                        groups=groups,
                    )
                    inner_plan = cast("dict[str, Any]", current["plan"])
                    blocked.extend(cast("list[str]", inner_plan.get("blocked_reasons", [])))
                    if inner_plan["plan_sha256"] != expected[target].get("inner_plan_sha256"):
                        blocked.append("The target commit/deploy plan changed after review.")
                    blocked = list(dict.fromkeys(blocked))
                    if blocked:
                        if on_drift == "abort":
                            detail = {"server": target, "status": "blocked", "blocked_reasons": blocked}
                        else:
                            detail = {"server": target, "status": "skipped_drift", "blocked_reasons": blocked}
                        await _update_progress(completed=fleet_counts[target], skipped=fleet_counts[target])
                    else:

                        async def _fleet_progress(fleet: dict[str, Any]) -> None:
                            nonlocal fleet_completed
                            fleet_status = str(fleet.get("status"))
                            skipped = fleet_status.startswith("skipped") or fleet_status == "not_started"
                            failed = fleet_status == "failed"
                            fleet_completed += 1
                            await _update_progress(
                                completed=1,
                                skipped=int(skipped),
                                failed=int(failed),
                                current_server=target,
                                current_product=fleet.get("product"),
                                current_group=fleet.get("group"),
                                current_phase=fleet.get("phase"),
                            )

                        result = await commit_and_deploy_all(
                            target,
                            message=message,
                            product=loaded.manifest.source.product,
                            effective=True,
                            push=push,
                            stop_on_error=True,
                            dry_run=False,
                            expected_plan_sha256=str(inner_plan["plan_sha256"]),
                            groups=groups,
                            progress_callback=_fleet_progress,
                        )
                        if not push and cast("dict[str, Any]", result.get("push", {})).get("requested") is True:
                            msg = "The inner workflow attempted a Git push even though push=false."
                            raise RuntimeError(msg)  # noqa: TRY301
                        detail = {
                            "server": target,
                            "status": "completed" if result["status"] == "completed" else result["status"],
                            "summary": result["summary"],
                            "push": result["push"],
                            "errors": result["errors"],
                        }
                except Exception as exc:  # noqa: BLE001 - preserve one leader failure without aborting peer leaders
                    detail = {"server": target, "status": "failed", "error": _error(exc)}
                    remaining = max(fleet_counts[target] - fleet_completed, 0)
                    await _update_progress(completed=remaining, failed=remaining)
                finally:
                    await _update_progress(running=-1)
        results[target] = detail
        job_context.set_target_detail(target, detail)
        skipped = detail.get("status") in {"blocked", "skipped_drift"}
        failed = detail.get("status") not in {"completed", "resumed_completed", "blocked", "skipped_drift"}
        await _update_progress(
            leaders_completed=1,
            leaders_skipped=int(skipped),
            leaders_failed=int(failed),
        )

    if on_drift == "abort":
        # Validate all receipt, Leader, and group/fleet guards before the first mutation.
        async def _abort_preflight(target: str) -> dict[str, Any]:
            reasons = await _receipt_drift(
                target,
                loaded=loaded,
                receipt_target=cast("dict[str, Any]", receipt["targets"].get(target, {})),
            )
            current = await commit_and_deploy_all(
                target,
                message=message,
                product=loaded.manifest.source.product,
                effective=True,
                push=push,
                stop_on_error=True,
                dry_run=True,
                groups=groups,
            )
            inner_plan = cast("dict[str, Any]", current["plan"])
            reasons.extend(cast("list[str]", inner_plan.get("blocked_reasons", [])))
            if inner_plan["plan_sha256"] != expected[target].get("inner_plan_sha256"):
                reasons.append("The target commit/deploy plan changed after review.")
            return {"server": target, "blocked_reasons": list(dict.fromkeys(reasons))}

        preflight = await _bounded_map(targets, concurrency=effective_concurrency, operation=_abort_preflight)
        if any(result.get("blocked_reasons") or result.get("error") for result in preflight):
            by_target = {str(result["server"]): result for result in preflight}
            for target in targets:
                reasons = cast("list[str]", by_target[target].get("blocked_reasons", []))
                detail = {
                    "server": target,
                    "status": "blocked" if reasons else "not_started_abort",
                    "blocked_reasons": reasons,
                }
                if "error" in by_target[target]:
                    detail["error"] = by_target[target]["error"]
                results[target] = detail
                job_context.set_target_detail(target, detail)
            await _update_progress(
                completed=sum(fleet_counts.values()),
                skipped=sum(fleet_counts.values()),
                leaders_completed=len(targets),
                leaders_skipped=len(targets),
                phase="aborted_preflight",
            )
            return {
                "status": "blocked",
                "operation": "commit_and_deploy_manifest",
                "manifest_path": loaded.relative_path,
                "executed_plan_sha256": expected_plan_sha256,
                "apply_receipt_sha256": stored["receipt_sha256"],
                "push_requested": push,
                "summary": {"target_count": len(targets), "completed": 0, "skipped": len(targets), "failed": 0},
                "skipped_targets": targets,
                "failed_targets": [],
                "detail_with": "get_config_deployment_job(job_id, target)",
            }
    await asyncio.gather(*(_execute(target) for target in targets))
    skipped_targets = [
        target
        for target, detail in results.items()
        if detail.get("status") in {"blocked", "skipped_drift", "not_started_abort"}
    ]
    failed_targets = [
        target
        for target, detail in results.items()
        if detail.get("status") not in {"completed", "resumed_completed", "blocked", "skipped_drift", "not_started_abort"}
    ]
    completed = len(results) - len(skipped_targets) - len(failed_targets)
    return {
        "status": "partial_failure" if failed_targets else "partial_skip" if skipped_targets else "completed",
        "operation": "commit_and_deploy_manifest",
        "manifest_path": loaded.relative_path,
        "executed_plan_sha256": expected_plan_sha256,
        "apply_receipt_sha256": stored["receipt_sha256"],
        "push_requested": push,
        "summary": {
            "target_count": len(results),
            "completed": completed,
            "skipped": len(skipped_targets),
            "failed": len(failed_targets),
        },
        "skipped_targets": skipped_targets,
        "failed_targets": failed_targets,
        "detail_with": "get_config_deployment_job(job_id, target)",
    }


__all__ = [
    "ValidationDetailScope",
    "check_manifest_receipt_validity",
    "execute_config_manifest_replication",
    "execute_manifest_commit_deploy",
    "plan_config_manifest_replication",
    "plan_manifest_commit_deploy",
    "resolve_manifest_concurrency",
    "validate_config_manifest",
]
