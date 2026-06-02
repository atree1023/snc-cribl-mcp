"""MCP tool: validate_resource_sync."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.resource_actions import ResourceKind
from .sync_common import ProductName, parse_product

type ValidateResourceSyncFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(app: FastMCP, *, impl: ValidateResourceSyncFunc) -> None:
    """Register the validate_resource_sync MCP tool."""

    @app.tool(
        name="validate_resource_sync",
        description=(
            "Compare groups, sources, destinations, pipelines, routes, breakers, lookups, or variables between two configured "
            "Cribl leaders. "
            "Group-scoped resources support different source and target group selectors. Use item_pattern for wildcard boolean "
            "expressions such as 'sdpe-rest-* and not sdpe-rest-test-*' or 'sdpe-rest-* but not sdpe-rest-test-*', "
            "item_regex for regular expressions, and exclude filters to compare a matched subset in one call."
        ),
        annotations={
            "title": "Validate config sync",
            "readOnlyHint": True,
        },
    )
    async def validate_resource_sync(  # noqa: PLR0913
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
        include_payloads: bool = False,
    ) -> dict[str, Any]:
        """Validate whether one config or scope is in sync between leaders."""
        await ctx.info(f"Validating Cribl {resource_kind} sync between '{source_server}' and '{target_server}'.")

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
            include_payloads=include_payloads,
        )


__all__ = ["register"]
