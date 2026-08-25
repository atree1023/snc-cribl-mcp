"""MCP tool: get_config_objects."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context, FastMCP

from ..operations.config_objects import (
    CONFIG_OBJECT_CATALOG,
    ConfigObjectDetail,
    ConfigObjectKind,
    shape_config_object_response,
)
from .sync_common import ProductName, parse_product

type ProductCollector = Callable[..., Awaitable[dict[str, Any]]]

_COLLECTOR_ATTRS: dict[ConfigObjectKind, str] = {
    "breakers": "collect_product_breakers",
    "destinations": "collect_product_destinations",
    "groups": "collect_product_groups",
    "lookups": "collect_product_lookups",
    "pipelines": "collect_product_pipelines",
    "routes": "collect_product_routes",
    "sources": "collect_product_sources",
    "variables": "collect_product_variables",
}


def _selected_products(products: tuple[ProductsCore, ...], product: ProductName | None) -> tuple[ProductsCore, ...]:
    if product is None:
        return products
    selected = parse_product(product)
    return (selected,)


def _collector_for_kind(deps: SimpleNamespace, kind: ConfigObjectKind) -> ProductCollector:
    if kind not in CONFIG_OBJECT_CATALOG:
        supported = ", ".join(sorted(CONFIG_OBJECT_CATALOG))
        msg = f"Unsupported config object kind '{kind}'. Supported kinds: {supported}."
        raise ValueError(msg)
    collector = getattr(deps, _COLLECTOR_ATTRS[kind], None)
    if not callable(collector):
        msg = f"Config object kind '{kind}' is not registered on this server."
        raise TypeError(msg)
    return cast("ProductCollector", collector)


async def _collect_product_results(
    *,
    deps: SimpleNamespace,
    ctx: Context,
    kind: ConfigObjectKind,
    server: str | None,
    product: ProductName | None,
) -> tuple[str, dict[str, dict[str, Any]]]:
    config = deps.resolve_config(server)
    token_manager = deps.get_token_manager(config)
    security = await token_manager.get_security()
    collector = _collector_for_kind(deps, kind)
    results: dict[str, dict[str, Any]] = {}

    async with deps.create_cp(config, security=security) as client:
        for selected_product in _selected_products(deps.products, product):
            if CONFIG_OBJECT_CATALOG[kind].requires_security:
                result = await collector(
                    client,
                    security,
                    product=selected_product,
                    timeout_ms=config.timeout_ms,
                    ctx=ctx,
                )
            else:
                result = await collector(
                    client,
                    product=selected_product,
                    timeout_ms=config.timeout_ms,
                    ctx=ctx,
                )
            results[selected_product.value] = result

    return config.base_url_str, results


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the consolidated config object retrieval tool."""

    @app.tool(
        name="get_config_objects",
        description=(
            "Query Cribl config objects with bounded results. Supports groups, sources, destinations, "
            "pipelines, routes, breakers, lookups, and variables. Returns compact summaries by default; use filters "
            "and detail='full' for selected payloads."
        ),
        annotations={
            "title": "Get config objects",
            "readOnlyHint": True,
        },
    )
    async def get_config_objects(
        ctx: Context,
        kind: ConfigObjectKind,
        server: str | None = None,
        product: ProductName | None = None,
        group_id: str | None = None,
        selector: str | None = None,
        detail: ConfigObjectDetail = "summary",
        *,
        include_dependencies: bool = False,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, normalized config object listing."""
        await ctx.info(f"Querying Cribl config objects of kind '{kind}'.")
        base_url, product_results = await _collect_product_results(
            deps=deps,
            ctx=ctx,
            kind=kind,
            server=server,
            product=product,
        )
        response = shape_config_object_response(
            kind=kind,
            product_results=product_results,
            detail=detail,
            product=product,
            group_id=group_id,
            selector=selector,
            include_dependencies=include_dependencies,
            cursor=cursor,
            limit=limit,
        )
        return {
            "retrieved_at": datetime.now(UTC).isoformat(),
            "base_url": base_url,
            **response,
        }


__all__ = ["register"]
