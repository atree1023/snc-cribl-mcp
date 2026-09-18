"""Standalone tools for Edge fleet creation and ruleset replication."""

# pyright: reportUnusedFunction=false
from __future__ import annotations

from typing import Any

from fastmcp import Context, FastMCP

from ..models.edge_fleet import EdgeFleet
from ..operations.edge_provisioning import create_edge_fleet, replicate_fleet_mapping_ruleset
from ..operations.version_control_jobs import VersionControlJobManager


def register(app: FastMCP, *, job_manager: VersionControlJobManager) -> None:
    """Register reviewed, asynchronous Edge provisioning operations."""

    @app.tool(
        name="create_edge_fleet",
        description=(
            "Create a Cribl Edge fleet, or a subfleet by setting fleet.inherits to its parent's exact ID. "
            "fleet accepts id, name, description, inherits, and workerRemoteAccess. Existing matching fleets are "
            "noops; different settings are blocked. Defaults to dry_run=true. Review plan.plan_sha256, then pass "
            "it as expected_plan_sha256 with dry_run=false. Execution returns a job_id; poll "
            "get_config_deployment_job. Changes remain uncommitted. Also supported by manifest fleets declarations."
        ),
        annotations={"title": "Create Edge fleet or subfleet", "readOnlyHint": False, "destructiveHint": False},
    )
    async def create_fleet(
        ctx: Context,
        *,
        fleet: EdgeFleet,
        server: str | None = None,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or submit one fleet creation."""
        await ctx.info("Planning Edge fleet creation." if dry_run else "Submitting Edge fleet creation.")
        if dry_run:
            return await create_edge_fleet(server, fleet=fleet)

        async def _run() -> dict[str, Any]:
            return await create_edge_fleet(server, fleet=fleet, dry_run=False, expected_plan_sha256=expected_plan_sha256)

        return await job_manager.submit(
            operation="create_edge_fleet", server=server, expected_plan_sha256=expected_plan_sha256, runner=_run
        )

    @app.tool(
        name="replicate_fleet_mapping_ruleset",
        description=(
            "Copy one Edge mapping ruleset by ID from source_server to target server, preserving rule order and "
            "the target's active state. New copies are inactive; updating an already-active ruleset changes live "
            "node assignment rules. Literal fleet references must exist on the target; dynamic expressions are "
            "reported but never evaluated. overwrite=false skips existing rulesets. Defaults to dry_run=true. "
            "Review plan.plan_sha256 and pass it as expected_plan_sha256 with dry_run=false. Execution returns a "
            "job_id; poll get_config_deployment_job. Changes remain uncommitted. Manifest fleet_mappings accepts IDs."
        ),
        annotations={"title": "Replicate Edge fleet mapping ruleset", "readOnlyHint": False, "destructiveHint": True},
    )
    async def copy_ruleset(
        ctx: Context,
        *,
        source_server: str,
        ruleset_id: str,
        server: str | None = None,
        overwrite: bool = True,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or submit one Leader-scoped mapping replication."""
        await ctx.info("Planning fleet mapping replication." if dry_run else "Submitting fleet mapping replication.")
        if dry_run:
            return await replicate_fleet_mapping_ruleset(
                server, source_server=source_server, ruleset_id=ruleset_id, overwrite=overwrite
            )

        async def _run() -> dict[str, Any]:
            return await replicate_fleet_mapping_ruleset(
                server,
                source_server=source_server,
                ruleset_id=ruleset_id,
                overwrite=overwrite,
                dry_run=False,
                expected_plan_sha256=expected_plan_sha256,
            )

        return await job_manager.submit(
            operation="replicate_fleet_mapping_ruleset", server=server, expected_plan_sha256=expected_plan_sha256, runner=_run
        )
