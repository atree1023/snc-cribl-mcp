"""MCP tools for whole group/fleet replication and validation."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from .params import (
    AppendRoutes,
    ComparePayloads,
    ContentKinds,
    CopyOverwrite,
    CopyValidateAfter,
    GroupProduct,
    GroupSyncSource,
    GroupSyncTarget,
    IncludeGroupSettings,
    SourceServer,
    TargetServer,
)
from .sync_common import parse_product

type GroupWorkflowFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(
    app: FastMCP,
    *,
    replicate_impl: GroupWorkflowFunc,
    validate_impl: GroupWorkflowFunc,
) -> None:
    """Register group/fleet workflow MCP tools."""

    @app.tool(
        name="replicate_group_config",
        description=(
            "Replicate a complete Stream worker group or Edge fleet between configured leaders, including "
            "group/fleet settings plus variables, breakers, lookups, destinations, pipelines, sources, and routes. "
            "content_kinds may include variables, breakers, lookups, destinations, pipelines, sources, and routes. "
            "Changes apply immediately: there is no dry run or plan hash, existing target items that differ are "
            "overwritten unless overwrite=false, and target route tables are replaced unless append_routes=true. "
            "Use validate_group_config to preview the differences first."
        ),
        annotations={
            "title": "Replicate group or fleet",
            "readOnlyHint": False,
        },
    )
    async def replicate_group_config(
        ctx: Context,
        source_server: SourceServer,
        target_server: TargetServer,
        source_group: GroupSyncSource,
        target_group: GroupSyncTarget = None,
        product: GroupProduct = "stream",
        content_kinds: ContentKinds = None,
        *,
        include_group_settings: IncludeGroupSettings = True,
        overwrite: CopyOverwrite = True,
        validate_after: CopyValidateAfter = True,
        append_routes: AppendRoutes = False,
    ) -> dict[str, Any]:
        """Replicate a worker group or Edge fleet and its contents."""
        await ctx.info(f"Replicating Cribl {product} group/fleet '{source_group}' to '{target_server}'.")
        return await replicate_impl(
            source_server,
            target_server,
            product=parse_product(product),
            source_group=source_group,
            target_group=target_group,
            content_kinds=content_kinds,
            include_group_settings=include_group_settings,
            overwrite=overwrite,
            validate_after=validate_after,
            append_routes=append_routes,
        )

    @app.tool(
        name="validate_group_config",
        description=(
            "Validate a complete Stream worker group or Edge fleet across configured leaders, including "
            "group/fleet settings plus variables, breakers, lookups, destinations, pipelines, sources, and routes. "
            "content_kinds may include variables, breakers, lookups, destinations, pipelines, sources, and routes."
        ),
        annotations={
            "title": "Validate group or fleet sync",
            "readOnlyHint": True,
        },
    )
    async def validate_group_config(
        ctx: Context,
        source_server: SourceServer,
        target_server: TargetServer,
        source_group: GroupSyncSource,
        target_group: GroupSyncTarget = None,
        product: GroupProduct = "stream",
        content_kinds: ContentKinds = None,
        *,
        include_group_settings: IncludeGroupSettings = True,
        include_payloads: ComparePayloads = False,
    ) -> dict[str, Any]:
        """Validate a worker group or Edge fleet and its contents."""
        await ctx.info(f"Validating Cribl {product} group/fleet '{source_group}' against '{target_server}'.")
        return await validate_impl(
            source_server,
            target_server,
            product=parse_product(product),
            source_group=source_group,
            target_group=target_group,
            content_kinds=content_kinds,
            include_group_settings=include_group_settings,
            include_payloads=include_payloads,
        )


__all__ = ["register"]
