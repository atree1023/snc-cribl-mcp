"""MCP tools for Cribl configuration commits, deployments, and Git push."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.version_control import CompareTo, ProductScope
from ..operations.version_control_jobs import VersionControlJobManager
from .sync_common import ProductName, parse_product

type VersionControlFunc = Callable[..., Awaitable[dict[str, Any]]]

_PLAN_GUIDANCE = (
    "This mutation defaults to dry_run=true. Review the returned plan and pass its plan_sha256 as "
    "expected_plan_sha256 with dry_run=false; execution stops if Git or deployment state drifted. "
    "Execution returns a job_id immediately; poll get_config_deployment_job for the bounded final result."
)


def register(  # noqa: C901
    app: FastMCP,
    *,
    status_impl: VersionControlFunc,
    diff_impl: VersionControlFunc,
    commit_impl: VersionControlFunc,
    deploy_impl: VersionControlFunc,
    commit_deploy_impl: VersionControlFunc,
    commit_deploy_all_impl: VersionControlFunc,
    push_impl: VersionControlFunc,
    job_manager: VersionControlJobManager,
) -> None:
    """Register Cribl Git and deployment workflow tools."""

    async def _plan_or_submit(
        *,
        operation: str,
        server: str | None,
        dry_run: bool,
        expected_plan_sha256: str | None,
        impl: VersionControlFunc,
        **kwargs: object,
    ) -> dict[str, Any]:
        """Run review plans inline and mutations in the isolated job worker."""
        if dry_run:
            return await impl(
                server,
                **kwargs,
                dry_run=True,
                expected_plan_sha256=expected_plan_sha256,
            )

        async def _runner() -> dict[str, Any]:
            return await impl(
                server,
                **kwargs,
                dry_run=False,
                expected_plan_sha256=expected_plan_sha256,
            )

        return await job_manager.submit(
            operation=operation,
            server=server,
            expected_plan_sha256=expected_plan_sha256,
            runner=_runner,
        )

    @app.tool(
        name="get_group_git_status",
        description=(
            "Get Git working-tree and deployment status for Stream worker groups and Edge fleets. Returns branch, "
            "ahead/behind counts, conflicts, changed paths, committed and deployed versions, and rollout node counts. "
            "Use product='all' with no group to inspect every target; specify product and group for one target."
        ),
        annotations={
            "title": "Get group and fleet Git status",
            "readOnlyHint": True,
            "idempotentHint": True,
        },
    )
    async def get_group_git_status(
        ctx: Context,
        server: str | None = None,
        product: ProductScope = "all",
        group: str | None = None,
    ) -> dict[str, Any]:
        """Get group/fleet Git status and deployed configuration versions."""
        await ctx.info("Getting Cribl group and fleet Git and deployment status.")
        return await status_impl(server, product=product, group=group)

    @app.tool(
        name="get_group_git_diff",
        description=(
            "Get a Stream worker group or Edge fleet configuration diff. compare_to='deployed' compares the current "
            "working configuration with the active configVersion for deployment sanity review; compare_to='head' "
            "shows only pending uncommitted changes. The response includes a full pending_diff_sha256 drift guard. "
            "Set diff_line_limit=0 for the complete diff or filename to inspect one changed file."
        ),
        annotations={
            "title": "Get group or fleet Git diff",
            "readOnlyHint": True,
            "idempotentHint": True,
        },
    )
    async def get_group_git_diff(
        ctx: Context,
        group: str,
        product: ProductName = "stream",
        server: str | None = None,
        compare_to: CompareTo = "deployed",
        filename: str | None = None,
        diff_line_limit: int = 1000,
    ) -> dict[str, Any]:
        """Get one group/fleet diff with deployed and pending baselines."""
        await ctx.info(f"Getting the Cribl {product} configuration diff for '{group}'.")
        return await diff_impl(
            server,
            product=parse_product(product),
            group=group,
            compare_to=compare_to,
            filename=filename,
            diff_line_limit=diff_line_limit,
        )

    @app.tool(
        name="get_config_deployment_job",
        description=(
            "Get the current state and bounded result of an asynchronous Cribl commit, deploy, or Git push job. "
            "Pass the job_id returned by a mutation execution for its final result, or omit job_id to list recent "
            "jobs. Job state is retained in this MCP server process and is cleared when the server restarts."
        ),
        annotations={
            "title": "Get configuration deployment job",
            "readOnlyHint": True,
            "idempotentHint": True,
        },
    )
    async def get_config_deployment_job(
        ctx: Context,
        job_id: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Get one deployment job or list recent jobs."""
        await ctx.info("Getting Cribl configuration deployment job status.")
        return await job_manager.get(job_id=job_id, limit=limit)

    @app.tool(
        name="commit_group_config",
        description=(
            "Commit pending configuration changes for one Stream worker group or Edge fleet without deploying them. "
            "Optionally restrict the commit to selected relative file paths and push committed changes to the "
            f"configured remote. {_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Commit group or fleet configuration",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def commit_group_config(
        ctx: Context,
        group: str,
        message: str,
        product: ProductName = "stream",
        server: str | None = None,
        files: list[str] | None = None,
        *,
        effective: bool = True,
        push: bool = False,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or commit one group/fleet configuration."""
        await ctx.info(f"Planning or committing Cribl {product} configuration for '{group}'.")
        return await _plan_or_submit(
            operation="commit_group_config",
            server=server,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
            impl=commit_impl,
            product=parse_product(product),
            group=group,
            message=message,
            files=files,
            effective=effective,
            push=push,
        )

    @app.tool(
        name="deploy_group_config",
        description=(
            "Deploy an explicit existing commit hash to one Stream worker group or Edge fleet. This can deploy a "
            "previous version for a controlled rollback. The workflow commits only deployment metadata in the "
            f"Leader groups.yml afterward and can optionally push. {_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Deploy group or fleet commit",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def deploy_group_config(
        ctx: Context,
        group: str,
        version: str,
        product: ProductName = "stream",
        server: str | None = None,
        *,
        push: bool = False,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or deploy an explicit group/fleet configuration version."""
        await ctx.info(f"Planning or deploying Cribl {product} version '{version}' to '{group}'.")
        return await _plan_or_submit(
            operation="deploy_group_config",
            server=server,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
            impl=deploy_impl,
            product=parse_product(product),
            group=group,
            version=version,
            push=push,
        )

    @app.tool(
        name="commit_and_deploy_group",
        description=(
            "Commit pending changes and deploy the resulting immutable commit to one Stream worker group or Edge "
            "fleet. If the working tree is clean but committed changes are not active, deploys the current committed "
            "version. Commits Leader deployment metadata afterward and can optionally push. "
            f"{_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Commit and deploy group or fleet",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def commit_and_deploy_group(
        ctx: Context,
        group: str,
        message: str,
        product: ProductName = "stream",
        server: str | None = None,
        files: list[str] | None = None,
        *,
        effective: bool = True,
        push: bool = False,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or commit and deploy one group/fleet."""
        await ctx.info(f"Planning or committing and deploying Cribl {product} target '{group}'.")
        return await _plan_or_submit(
            operation="commit_and_deploy_group",
            server=server,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
            impl=commit_deploy_impl,
            product=parse_product(product),
            group=group,
            message=message,
            files=files,
            effective=effective,
            push=push,
        )

    @app.tool(
        name="commit_and_deploy_all",
        description=(
            "Commit and deploy all selected Stream worker groups and/or Edge fleets. Stream groups are deterministic; "
            "Edge fleets are committed and deployed in parent-before-descendant order, with each descendant "
            "re-evaluated after its parent commit so inherited changes are captured. Clean descendants affected by a "
            "planned ancestor commit are reported as deploy_inherited. Leader deployment metadata is "
            "committed once after successful deployments. push occurs only when no workflow errors remain. "
            f"{_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Commit and deploy all groups and fleets",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def commit_and_deploy_all(
        ctx: Context,
        message: str,
        server: str | None = None,
        product: ProductScope = "all",
        *,
        effective: bool = True,
        push: bool = False,
        stop_on_error: bool = True,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or commit and deploy all selected targets."""
        await ctx.info(f"Planning or committing and deploying all Cribl {product} targets.")
        return await _plan_or_submit(
            operation="commit_and_deploy_all",
            server=server,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
            impl=commit_deploy_all_impl,
            message=message,
            product=product,
            effective=effective,
            push=push,
            stop_on_error=stop_on_error,
        )

    @app.tool(
        name="push_config_git",
        description=(
            "Push already committed Cribl configuration changes from the Leader repository to its configured remote. "
            "The preflight blocks missing remotes, conflicts, and branches behind their remote. "
            f"{_PLAN_GUIDANCE}"
        ),
        annotations={
            "title": "Push Cribl configuration Git repository",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
    )
    async def push_config_git(
        ctx: Context,
        server: str | None = None,
        *,
        dry_run: bool = True,
        expected_plan_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Plan or push the configured Cribl Git remote."""
        await ctx.info("Planning or pushing the Cribl configuration Git repository.")
        return await _plan_or_submit(
            operation="push_config_git",
            server=server,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
            impl=push_impl,
        )


__all__ = ["register"]
