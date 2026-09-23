"""MCP tool: validate_config_objects."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.semantic_diff import semantic_validation_from_sync_result
from .params import (
    CaseSensitive,
    CopyResourceKind,
    ExcludeItemPattern,
    ExcludeItemRegex,
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
            "regular expressions, and exclude filters for validating a subset in one call. Group-scoped reads use Cribl's "
            "effective configuration view (including inherited parent-fleet objects), reported as config_scope='effective'. "
            "Semantic counts keep truly missing objects separate from response-limited not_evaluated objects."
        ),
        annotations={
            "title": "Validate config objects semantically",
            "readOnlyHint": True,
        },
    )
    async def validate_config_objects(
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
