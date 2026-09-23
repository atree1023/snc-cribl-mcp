"""MCP tools for parallel configuration-manifest workflows."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from typing import Any, cast

from fastmcp import Context, FastMCP

from ..models.config_manifest import delete_config_manifest, load_config_manifest, write_config_manifest
from ..operations.config_manifest import (
    check_manifest_receipt_validity,
    execute_config_manifest_replication,
    execute_manifest_commit_deploy,
    plan_config_manifest_replication,
    plan_manifest_commit_deploy,
    resolve_manifest_concurrency,
)
from ..operations.config_manifest import (
    validate_config_manifest as validate_manifest_impl,
)
from ..operations.manifest_state import ManifestStateStore
from ..operations.version_control_jobs import JobContext, VersionControlJobManager
from .params import (
    ApplyJobId,
    ApplyReceiptSha256,
    DeployApplyJobId,
    DeployApplyReceiptSha256,
    DeployOnDrift,
    DetailScope,
    DryRun,
    ExpectedFileSha256,
    ExpectedPlanSha256,
    ManifestCommitMessage,
    ManifestConcurrency,
    ManifestContent,
    ManifestName,
    ManifestOverwrite,
    ManifestPath,
    ManifestTarget,
    Push,
    ReceiptTarget,
    ReplicateOnDrift,
    ResumeJobId,
    ValidationLimit,
    ValidationOffset,
)

_PLAN_GUIDANCE = (
    "This mutation defaults to dry_run=true. Review plan_sha256, then pass it as expected_plan_sha256 with "
    "dry_run=false. Execution returns a durable job_id; poll get_config_deployment_job for aggregate progress or "
    "pass job_id plus target for detailed failures. Pass a failed or interrupted job as resume_job_id to retry only "
    "unfinished targets, including after an MCP process restart."
)


def _require_plan_hash(expected_plan_sha256: str | None) -> str:
    if expected_plan_sha256 is None or not expected_plan_sha256.strip():
        msg = "expected_plan_sha256 is required when dry_run=false."
        raise ValueError(msg)
    return expected_plan_sha256.strip()


def register(  # noqa: C901, PLR0915
    app: FastMCP,
    *,
    job_manager: VersionControlJobManager,
    state_store: ManifestStateStore,
) -> None:
    """Register strict multi-leader manifest tools."""

    @app.tool(
        name="write_manifest",
        description=(
            "Validate schema-1 YAML manifest content and write it beneath the configured manifest root so sandboxed "
            "MCP clients can author manifests without direct filesystem access. A missing extension becomes .yaml. "
            "Identical writes are idempotent; replacing different content requires overwrite=true. Returns the "
            "relative manifest_path used by the replication, validation, and commit/deploy tools."
        ),
        annotations={
            "title": "Write configuration manifest",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
    )
    async def write_manifest(
        ctx: Context,
        name: ManifestName,
        content: ManifestContent,
        *,
        overwrite: ManifestOverwrite = False,
    ) -> dict[str, Any]:
        """Validate and persist a configuration manifest in the safe root."""
        await ctx.info("Validating and writing a multi-leader Cribl configuration manifest.")
        loaded, status = write_config_manifest(name, content, overwrite=overwrite)
        item_count = loaded.manifest.item_count
        return {
            "status": status,
            "manifest_path": loaded.relative_path,
            "resolved_path": str(loaded.path),
            "file_sha256": loaded.file_sha256,
            "manifest_sha256": loaded.manifest_sha256,
            "wave": loaded.manifest.wave,
            "source_server": loaded.manifest.source.server,
            "product": loaded.manifest.source.product,
            "target_count": len(loaded.manifest.targets),
            "item_count": item_count,
            "concurrency": loaded.manifest.options.concurrency,
        }

    @app.tool(
        name="delete_manifest",
        description=(
            "Delete one validated YAML manifest beneath the configured manifest root after rollout cleanup. "
            "Pass the file_sha256 returned by write_manifest as expected_file_sha256 to prevent deleting a file "
            "that changed since it was inspected. This does not delete durable plans, receipts, or job history."
        ),
        annotations={
            "title": "Delete configuration manifest",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def delete_manifest(
        ctx: Context,
        manifest_path: ManifestPath,
        *,
        expected_file_sha256: ExpectedFileSha256 = None,
    ) -> dict[str, Any]:
        """Safely remove a manifest from the configured root."""
        await ctx.info("Deleting a validated Cribl configuration manifest.")
        loaded = delete_config_manifest(manifest_path, expected_file_sha256=expected_file_sha256)
        return {
            "status": "deleted",
            "manifest_path": loaded.relative_path,
            "resolved_path": str(loaded.path),
            "deleted_file_sha256": loaded.file_sha256,
            "manifest_sha256": loaded.manifest_sha256,
        }

    @app.tool(
        name="replicate_config_manifest",
        description=(
            "Plan or apply a strict schema-1 YAML manifest to many configured Leaders. Edge manifests support fleets "
            "(typed creation declarations including inherits, isSearch, and streamtags) "
            "and fleet_mappings (source ruleset IDs), "
            "alongside group-scoped content. Fleets are created parent-first, content copied next, mappings last. "
            "Ruleset copies preserve target activation; updating an active ruleset changes live assignment rules. "
            "The source is snapshotted once, each target has an independent drift guard, "
            "and execution emits a durable apply receipt required by commit_and_deploy_manifest. "
            "Retries reuse matching prior receipts for the same manifest and source, "
            "including their own new undeployed parents. "
            f"{_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Replicate configuration manifest",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
    )
    async def replicate_config_manifest(
        ctx: Context,
        manifest_path: ManifestPath,
        *,
        dry_run: DryRun = True,
        expected_plan_sha256: ExpectedPlanSha256 = None,
        concurrency: ManifestConcurrency = None,
        on_drift: ReplicateOnDrift = None,
        resume_job_id: ResumeJobId = None,
    ) -> dict[str, Any]:
        """Plan or asynchronously apply a configuration manifest."""
        await ctx.info("Planning or applying a multi-leader Cribl configuration manifest.")
        if dry_run:
            if resume_job_id is not None:
                msg = "resume_job_id can only be used with dry_run=false."
                raise ValueError(msg)
            return await plan_config_manifest_replication(
                manifest_path,
                state_store=state_store,
                concurrency=concurrency,
            )

        plan_hash = _require_plan_hash(expected_plan_sha256)
        loaded = load_config_manifest(manifest_path)
        effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
        resume_details = job_manager.target_details(resume_job_id) if resume_job_id is not None else None
        request = {
            "manifest_path": loaded.relative_path,
            "expected_plan_sha256": plan_hash,
            "concurrency": concurrency,
            "on_drift": on_drift,
        }
        if resume_job_id is not None:
            prior = job_manager.resume_request(resume_job_id, operation="replicate_config_manifest")
            if prior != request:
                msg = "Resume parameters must exactly match the original replication job request."
                raise ValueError(msg)

        async def _runner(job_context: JobContext) -> dict[str, Any]:
            return await execute_config_manifest_replication(
                manifest_path,
                expected_plan_sha256=plan_hash,
                state_store=state_store,
                job_context=job_context,
                concurrency=concurrency,
                on_drift=on_drift,
                resume_details=resume_details,
            )

        return await job_manager.submit_aggregate(
            operation="replicate_config_manifest",
            servers=loaded.manifest.targets,
            expected_plan_sha256=plan_hash,
            runner=_runner,
            request=request,
            resume_of=resume_job_id,
            initial_progress={
                "unit": "items",
                "total": loaded.manifest.item_count * len(loaded.manifest.targets),
                "completed": 0,
                "failed": 0,
                "skipped": 0,
                "running": 0,
                "target_total": len(loaded.manifest.targets),
                "targets_completed": 0,
                "targets_failed": 0,
                "targets_skipped": 0,
                "revalidation_total": len(loaded.manifest.targets),
                "revalidated": 0,
                "revalidation_running": 0,
                "revalidation_failed": 0,
                "concurrency": effective_concurrency,
                "phase": "queued",
            },
        )

    @app.tool(
        name="validate_config_manifest",
        description=(
            "Validate every explicit item in a YAML configuration manifest against all targets in parallel. "
            "Functional differences and missing objects are blocking; expected leader identity, endpoint, credential "
            "reference, and volatile metadata differences are reported separately and do not fail validation. "
            "Use offset/limit to page bounded detail, target to inspect one leader, and detail_scope='all' to include "
            "noop items. Summary counts split create, update, noop, and unsupported actions."
        ),
        annotations={
            "title": "Validate configuration manifest",
            "readOnlyHint": True,
            "idempotentHint": True,
        },
    )
    async def validate_config_manifest(
        ctx: Context,
        manifest_path: ManifestPath,
        *,
        concurrency: ManifestConcurrency = None,
        target: ManifestTarget = None,
        offset: ValidationOffset = 0,
        limit: ValidationLimit = 25,
        detail_scope: DetailScope = "differences",
    ) -> dict[str, Any]:
        """Validate a configuration manifest across all targets."""
        await ctx.info("Validating a multi-leader Cribl configuration manifest.")
        return await validate_manifest_impl(
            manifest_path,
            concurrency=concurrency,
            target=target,
            offset=offset,
            limit=limit,
            detail_scope=detail_scope,
        )

    @app.tool(
        name="check_manifest_receipt_validity",
        description=(
            "Read-only preflight that checks whether a replicate_config_manifest apply receipt still matches the "
            "current manifest and every guarded group/fleet diff. Use it immediately before commit/deploy to detect "
            "UI edits or other post-apply changes. Provide exactly one of apply_job_id or apply_receipt_sha256."
        ),
        annotations={
            "title": "Check manifest receipt validity",
            "readOnlyHint": True,
            "idempotentHint": True,
        },
    )
    async def check_manifest_receipt_validity_tool(
        ctx: Context,
        manifest_path: ManifestPath,
        *,
        apply_job_id: ApplyJobId = None,
        apply_receipt_sha256: ApplyReceiptSha256 = None,
        concurrency: ManifestConcurrency = None,
        target: ReceiptTarget = None,
    ) -> dict[str, Any]:
        """Check a durable manifest apply receipt without committing or deploying."""
        await ctx.info("Checking whether a manifest apply receipt is still valid.")
        return await check_manifest_receipt_validity(
            manifest_path,
            apply_job_id=apply_job_id,
            apply_receipt_sha256=apply_receipt_sha256,
            state_store=state_store,
            concurrency=concurrency,
            target=target,
        )

    @app.tool(
        name="commit_and_deploy_manifest",
        description=(
            "Plan or commit and deploy the groups and receipt-selected Leader provisioning files changed by an apply "
            "receipt. Edge descendants are included in parent-before-child order so inherited changes are captured. "
            "Leader provisioning files are committed before fleets; mappings-only manifests deploy no fleets. "
            "push=true pushes once per successful Leader and returns per-Leader outcomes and API readback. "
            "Readback may be cached and does not independently verify remote synchronization. "
            "The operation refuses group or Leader-file diffs that no longer match the apply receipt. "
            f"{_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Commit and deploy configuration manifest",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def commit_and_deploy_manifest(
        ctx: Context,
        manifest_path: ManifestPath,
        message: ManifestCommitMessage,
        *,
        apply_job_id: DeployApplyJobId = None,
        apply_receipt_sha256: DeployApplyReceiptSha256 = None,
        push: Push = False,
        dry_run: DryRun = True,
        expected_plan_sha256: ExpectedPlanSha256 = None,
        concurrency: ManifestConcurrency = None,
        on_drift: DeployOnDrift = "skip",
        resume_job_id: ResumeJobId = None,
    ) -> dict[str, Any]:
        """Plan or asynchronously commit and deploy a prior manifest application."""
        await ctx.info("Planning or committing and deploying a multi-leader Cribl configuration manifest.")
        if dry_run:
            if resume_job_id is not None:
                msg = "resume_job_id can only be used with dry_run=false."
                raise ValueError(msg)
            return await plan_manifest_commit_deploy(
                manifest_path,
                apply_job_id=apply_job_id,
                apply_receipt_sha256=apply_receipt_sha256,
                message=message,
                push=push,
                state_store=state_store,
                concurrency=concurrency,
            )

        plan_hash = _require_plan_hash(expected_plan_sha256)
        loaded = load_config_manifest(manifest_path)
        stored_plan = state_store.get_plan(plan_hash, operation="commit_and_deploy_manifest")
        stored_targets = cast("list[dict[str, Any]]", stored_plan.get("targets", []))
        fleet_total = 0
        for target_plan in stored_targets:
            summary = target_plan.get("summary")
            if isinstance(summary, dict):
                fleet_total += int(cast("dict[str, Any]", summary).get("target_count", 0))
        effective_concurrency = resolve_manifest_concurrency(loaded.manifest, concurrency)
        resume_details = job_manager.target_details(resume_job_id) if resume_job_id is not None else None
        request = {
            "manifest_path": loaded.relative_path,
            "expected_plan_sha256": plan_hash,
            "message": message,
            "push": push,
            "concurrency": concurrency,
            "on_drift": on_drift,
        }
        if resume_job_id is not None:
            prior = job_manager.resume_request(resume_job_id, operation="commit_and_deploy_manifest")
            if prior != request:
                msg = "Resume parameters must exactly match the original commit/deploy job request."
                raise ValueError(msg)

        async def _runner(job_context: JobContext) -> dict[str, Any]:
            return await execute_manifest_commit_deploy(
                manifest_path,
                expected_plan_sha256=plan_hash,
                message=message,
                push=push,
                state_store=state_store,
                job_context=job_context,
                concurrency=concurrency,
                on_drift=on_drift,
                resume_details=resume_details,
            )

        return await job_manager.submit_aggregate(
            operation="commit_and_deploy_manifest",
            servers=loaded.manifest.targets,
            expected_plan_sha256=plan_hash,
            runner=_runner,
            request=request,
            resume_of=resume_job_id,
            initial_progress={
                "unit": "fleets",
                "total": fleet_total,
                "completed": 0,
                "failed": 0,
                "skipped": 0,
                "running": 0,
                "leader_total": len(loaded.manifest.targets),
                "leaders_completed": 0,
                "leaders_failed": 0,
                "leaders_skipped": 0,
                "concurrency": effective_concurrency,
                "phase": "queued",
            },
        )


__all__ = ["register"]
