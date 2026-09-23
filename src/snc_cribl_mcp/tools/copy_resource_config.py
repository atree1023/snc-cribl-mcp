"""MCP tool: copy_resource_config."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from .params import (
    AppendRoutes,
    CaseSensitive,
    CopyOverwrite,
    CopyResourceKind,
    CopyValidateAfter,
    DryRun,
    ExcludeItemPattern,
    ExcludeItemRegex,
    ExpectedPlanSha256,
    ItemId,
    ItemPattern,
    ItemRegex,
    SourceGroup,
    SourceServer,
    SyncProduct,
    TargetGroup,
    TargetServer,
)
from .sync_common import parse_product

type CopyResourceConfigFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(app: FastMCP, *, impl: CopyResourceConfigFunc) -> None:
    """Register the copy_resource_config MCP tool."""

    @app.tool(
        name="copy_resource_config",
        description=(
            "Copy groups, sources, destinations, pipelines, routes, breakers, lookups, or variables from one "
            "configured Cribl leader to another. Group-scoped resources support different source and target group selectors. "
            "Use item_pattern for wildcard boolean expressions such as 'oodp-* and not oodp-source-*' or 'oodp-* but not "
            "oodp-source-*', item_regex for regular expressions. This mutation defaults to dry_run=true; pass the returned "
            "plan_sha256 as expected_plan_sha256 with dry_run=false to execute the exact reviewed plan. Semantically "
            "identical targets are skipped; real updates report bounded added, changed, and removed config paths."
        ),
        annotations={
            "title": "Copy config between leaders",
            "readOnlyHint": False,
        },
    )
    async def copy_resource_config(
        ctx: Context,
        resource_kind: CopyResourceKind,
        source_server: SourceServer,
        target_server: TargetServer,
        source_group: SourceGroup = None,
        target_group: TargetGroup = None,
        item_id: ItemId = None,
        item_pattern: ItemPattern = None,
        item_regex: ItemRegex = None,
        exclude_item_pattern: ExcludeItemPattern = None,
        exclude_item_regex: ExcludeItemRegex = None,
        product: SyncProduct = "stream",
        *,
        case_sensitive: CaseSensitive = False,
        overwrite: CopyOverwrite = True,
        validate_after: CopyValidateAfter = True,
        append_routes: AppendRoutes = False,
        dry_run: DryRun = True,
        expected_plan_sha256: ExpectedPlanSha256 = None,
    ) -> dict[str, Any]:
        """Copy one config or a whole resource scope between leaders."""
        await ctx.info(f"Copying Cribl {resource_kind} from '{source_server}' to '{target_server}'.")

        if not dry_run and expected_plan_sha256 is None:
            msg = "expected_plan_sha256 is required when dry_run=false. Run copy_resource_config with dry_run=true first."
            raise ValueError(msg)

        if resource_kind == "groups":
            if source_group is not None or target_group is not None:
                msg = (
                    "source_group and target_group only apply to sources, destinations, pipelines, and routes, "
                    "plus breakers, lookups, and variables."
                )
                raise ValueError(msg)
        elif source_group is None:
            msg = "source_group is required for sources, destinations, pipelines, routes, breakers, lookups, and variables."
            raise ValueError(msg)

        return await impl(
            resource_kind,
            source_server,
            target_server,
            product=parse_product(product),
            group_id=source_group,
            target_group_id=target_group,
            item_id=item_id,
            item_pattern=item_pattern,
            item_regex=item_regex,
            exclude_item_pattern=exclude_item_pattern,
            exclude_item_regex=exclude_item_regex,
            case_sensitive=case_sensitive,
            overwrite=overwrite,
            validate_after=validate_after,
            append_routes=append_routes,
            dry_run=dry_run,
            expected_plan_sha256=expected_plan_sha256,
        )


__all__ = ["register"]
