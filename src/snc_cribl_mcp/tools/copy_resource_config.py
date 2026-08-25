"""MCP tool: copy_resource_config."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.resource_actions import ResourceKind
from .sync_common import ProductName, parse_product

type CopyResourceConfigFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(app: FastMCP, *, impl: CopyResourceConfigFunc) -> None:
    """Register the copy_resource_config MCP tool."""

    @app.tool(
        name="copy_resource_config",
        description=(
            "Copy groups, sources, destinations, pipelines, routes, breakers, lookups, or variables from one "
            "configured Cribl leader to another. Group-scoped resources support different source and target group selectors. "
            "Use item_pattern for wildcard boolean expressions such as 'oodp-* and not oodp-source-*' or 'oodp-* but not "
            "oodp-source-*', item_regex for regular expressions, and dry_run=true to inspect planned actions without writing."
        ),
        annotations={
            "title": "Copy config between leaders",
            "readOnlyHint": False,
        },
    )
    async def copy_resource_config(
        ctx: Context,
        resource_kind: ResourceKind,
        source_server: str,
        target_server: str,
        source_group: str | None = None,
        target_group: str | None = None,
        item_id: str | None = None,
        item_pattern: str | None = None,
        item_regex: str | None = None,
        exclude_item_pattern: str | None = None,
        exclude_item_regex: str | None = None,
        product: ProductName = "stream",
        *,
        case_sensitive: bool = False,
        overwrite: bool = True,
        validate_after: bool = True,
        append_routes: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Copy one config or a whole resource scope between leaders."""
        await ctx.info(f"Copying Cribl {resource_kind} from '{source_server}' to '{target_server}'.")

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
        )


__all__ = ["register"]
