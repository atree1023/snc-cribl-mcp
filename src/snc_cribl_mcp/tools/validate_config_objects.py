"""MCP tool: validate_config_objects."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.resource_actions import ResourceKind
from ..operations.semantic_diff import semantic_validation_from_sync_result
from .sync_common import ProductName, parse_product

type ValidateResourceSyncFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(app: FastMCP, *, impl: ValidateResourceSyncFunc) -> None:
    """Register semantic config validation over the existing sync validation path."""

    @app.tool(
        name="validate_config_objects",
        description=(
            "Semantically compare groups, sources, destinations, pipelines, routes, breakers, lookups, or variables between "
            "two configured Cribl leaders. "
            "Expected environment identity differences such as hostnames, endpoint lists, generated IDs, and volatile metadata "
            "are reported but do not count as functional drift. Supports item_pattern wildcard boolean expressions, item_regex "
            "regular expressions, and exclude filters for validating a subset in one call."
        ),
        annotations={
            "title": "Validate config objects semantically",
            "readOnlyHint": True,
        },
    )
    async def validate_config_objects(  # noqa: PLR0913
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
    ) -> dict[str, Any]:
        """Validate whether two config scopes are functionally equivalent."""
        await ctx.info(f"Semantically validating Cribl {resource_kind} between '{source_server}' and '{target_server}'.")

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

        sync_result = await impl(
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
            include_payloads=True,
        )
        return semantic_validation_from_sync_result(resource_kind, sync_result)


__all__ = ["register"]
