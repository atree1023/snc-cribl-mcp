"""Entry point for the SNC Cribl MCP server.

This module wires together the FastMCP app and registers tools. Implementation
logic has been split into focused modules under ``snc_cribl_mcp/`` to avoid
duplication and improve maintainability.

Registered tools:
- ``list_groups``: list worker groups (Stream) and fleets (Edge)
- ``list_sources``: list configured sources per group across products
- ``list_destinations``: list configured destinations per group across products
- ``list_pipelines``: list configured pipelines per group across products
- ``list_routes``: list configured routes per group across products
- ``list_breakers``: list configured event breakers per group across products
- ``list_lookups``: list configured lookups per group across products
"""

import logging
import os
import signal
import sys
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from cribl_control_plane.models.productscore import ProductsCore
from fastmcp import Context, FastMCP

from . import prompts, resources
from .client.cribl_client import create_control_plane
from .client.token_manager import TokenManager, get_token_manager
from .config import CriblConfig
from .operations.breakers import collect_product_breakers
from .operations.destinations import collect_product_destinations
from .operations.groups import collect_product_groups, serialize_config_group
from .operations.lookups import collect_product_lookups
from .operations.pipelines import collect_product_pipelines
from .operations.routes import collect_product_routes
from .operations.sources import collect_product_sources
from .tools.list_breakers import register as register_list_breakers
from .tools.list_destinations import register as register_list_destinations
from .tools.list_groups import register as register_list_groups
from .tools.list_lookups import register as register_list_lookups
from .tools.list_pipelines import register as register_list_pipelines
from .tools.list_routes import register as register_list_routes
from .tools.list_sources import register as register_list_sources

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("snc_cribl_mcp.server")

PRODUCTS: tuple[ProductsCore, ...] = (
    ProductsCore.STREAM,
    ProductsCore.EDGE,
)

app = FastMCP(
    name="snc-cribl-mcp",
    instructions=("Expose tools that query a customer-managed Cribl deployment for metadata."),
)


async def list_groups_impl(ctx: Context, server: str | None = None) -> dict[str, Any]:
    """Return worker groups and Edge fleets from the Cribl deployment as JSON."""
    await ctx.info("Listing Cribl worker groups and Edge fleets.")

    config = CriblConfig.resolve(server)
    token_manager = get_token_manager(config)
    results: dict[str, Any] = {}
    security = await token_manager.get_security()
    async with create_control_plane(config, security=security) as client:
        for product in PRODUCTS:
            result = await collect_product_groups(
                client,
                product=product,
                timeout_ms=config.timeout_ms,
                ctx=ctx,
            )
            results[product.value] = result

    return {
        "retrieved_at": datetime.now(UTC).isoformat(),
        "base_url": config.base_url_str,
        "groups": results,
    }


# Explicit re-exports for public API stability (and to satisfy linters)
__all__ = [
    "PRODUCTS",
    "CriblConfig",
    "TokenManager",
    "app",
    "collect_product_groups",
    "create_control_plane",
    "get_token_manager",
    "handle_interrupt",
    "list_groups_impl",
    "main",
    "serialize_config_group",
]


def _register_capabilities() -> None:
    """Import tool, resource, and prompt modules and register them with the app instance."""
    register_list_groups(app, impl=list_groups_impl)
    deps = SimpleNamespace(
        resolve_config=CriblConfig.resolve,
        get_token_manager=get_token_manager,
        products=PRODUCTS,
        create_cp=create_control_plane,
        collect_product_groups=collect_product_groups,
        collect_product_sources=collect_product_sources,
        collect_product_destinations=collect_product_destinations,
        collect_product_pipelines=collect_product_pipelines,
        collect_product_routes=collect_product_routes,
        collect_product_breakers=collect_product_breakers,
        collect_product_lookups=collect_product_lookups,
    )
    register_list_sources(app, deps=deps)
    register_list_destinations(app, deps=deps)
    register_list_pipelines(app, deps=deps)
    register_list_routes(app, deps=deps)
    register_list_breakers(app, deps=deps)
    register_list_lookups(app, deps=deps)
    resources.register(app, deps=deps)
    prompts.register(app)


# Register all capabilities with the app instance (after function is defined)
_register_capabilities()


def handle_interrupt(signum: int, frame: object) -> None:  # noqa: ARG001
    """Handle keyboard interrupt gracefully."""
    logger.info("Received interrupt signal, shutting down...")
    sys.exit(0)


def main() -> None:
    """Entry point for the snc-cribl-mcp console script."""
    signal.signal(signal.SIGINT, handle_interrupt)
    signal.signal(signal.SIGTERM, handle_interrupt)
    app.run()


if __name__ == "__main__":
    main()
