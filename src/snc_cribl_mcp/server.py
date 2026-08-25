"""Entry point for the SNC Cribl MCP server.

This module wires together the FastMCP app and registers tools. Implementation
logic has been split into focused modules under ``snc_cribl_mcp/`` to avoid
duplication and improve maintainability.

Registered tools:
- ``list_groups``: list worker groups (Stream) and fleets (Edge)
- ``get_leader_overview``: summarize leader health, version, nodes, groups, and runtime status
- ``list_sources``: list configured sources per group across products
- ``list_destinations``: list configured destinations per group across products
- ``list_pipelines``: list configured pipelines per group across products
- ``list_routes``: list configured routes per group across products
- ``list_breakers``: list configured event breakers per group across products
- ``list_lookups``: list configured lookups per group across products
- ``list_variables``: list configured variables per group across products
- ``list_packs``: list installed Packs
- ``get_pack``: get an installed Pack
- ``install_pack``: install a Pack
- ``upload_pack``: upload a Pack file
- ``update_pack``: upgrade a Pack
- ``delete_pack``: uninstall a Pack
- ``get_edge_info``: query an Edge node through the leader-proxied teleport API
- ``get_config_objects``: query supported config objects with bounded responses
- ``validate_config_objects``: semantically compare supported configs between leaders
- ``copy_resource_config``: copy supported configs between configured leaders
- ``validate_resource_sync``: compare supported configs between configured leaders
- ``sync_user``: create or replicate local users between configured leaders
- ``replicate_group_config``: replicate a whole worker group or Edge fleet
- ``validate_group_config``: validate a whole worker group or Edge fleet
- ``replicate_system_settings``: replicate global system settings
- ``validate_system_settings``: validate global system settings
- ``get_group_git_status``: inspect group/fleet Git and deployment status
- ``get_group_git_diff``: inspect pending or deployed-baseline group/fleet diffs
- ``get_config_deployment_job``: poll asynchronous commit, deploy, and push jobs
- ``commit_group_config``: commit one group/fleet configuration
- ``deploy_group_config``: deploy an explicit group/fleet commit
- ``commit_and_deploy_group``: commit and deploy one group/fleet
- ``commit_and_deploy_all``: commit and deploy groups/fleets in dependency order
- ``push_config_git``: push committed Cribl configuration to its Git remote
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
from .operations.edge_teleport import collect_edge_info
from .operations.group_sync import replicate_group_config, validate_group_config_sync
from .operations.groups import collect_product_groups, serialize_config_group
from .operations.leader_overview import collect_leader_overview
from .operations.lookups import collect_product_lookups
from .operations.packs import collect_packs
from .operations.pipelines import collect_product_pipelines
from .operations.routes import collect_product_routes
from .operations.sources import collect_product_sources
from .operations.sync import copy_resource_config, validate_resource_sync
from .operations.system_settings import replicate_system_settings, validate_system_settings_sync
from .operations.users import sync_user
from .operations.variables import collect_product_variables
from .operations.version_control import (
    collect_group_git_diff,
    collect_group_git_status,
    commit_and_deploy_all,
    commit_and_deploy_group,
    commit_group_config,
    deploy_group_config,
    push_config_git,
)
from .operations.version_control_jobs import VersionControlJobManager
from .tools.copy_resource_config import register as register_copy_resource_config
from .tools.edge_info import register as register_edge_info
from .tools.get_config_objects import register as register_get_config_objects
from .tools.group_sync import register as register_group_sync_tools
from .tools.leader_overview import register as register_leader_overview
from .tools.list_breakers import register as register_list_breakers
from .tools.list_destinations import register as register_list_destinations
from .tools.list_groups import register as register_list_groups
from .tools.list_lookups import register as register_list_lookups
from .tools.list_pipelines import register as register_list_pipelines
from .tools.list_routes import register as register_list_routes
from .tools.list_sources import register as register_list_sources
from .tools.list_variables import register as register_list_variables
from .tools.packs import register as register_pack_tools
from .tools.system_settings import register as register_system_settings_tools
from .tools.users import register as register_user_tools
from .tools.validate_config_objects import register as register_validate_config_objects
from .tools.validate_resource_sync import register as register_validate_resource_sync
from .tools.version_control import register as register_version_control_tools

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
version_control_jobs = VersionControlJobManager()


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
    "collect_edge_info",
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
        resolve_config_for_datacenter=CriblConfig.resolve_for_datacenter,
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
        collect_product_variables=collect_product_variables,
        collect_packs=collect_packs,
        collect_leader_overview=collect_leader_overview,
        collect_edge_info=collect_edge_info,
    )
    register_leader_overview(app, deps=deps)
    register_edge_info(app, deps=deps)
    register_list_sources(app, deps=deps)
    register_list_destinations(app, deps=deps)
    register_list_pipelines(app, deps=deps)
    register_list_routes(app, deps=deps)
    register_list_breakers(app, deps=deps)
    register_list_lookups(app, deps=deps)
    register_list_variables(app, deps=deps)
    register_pack_tools(app, deps=deps)
    register_get_config_objects(app, deps=deps)
    register_copy_resource_config(app, impl=copy_resource_config)
    register_validate_resource_sync(app, impl=validate_resource_sync)
    register_validate_config_objects(app, impl=validate_resource_sync)
    register_user_tools(app, impl=sync_user)
    register_group_sync_tools(
        app,
        replicate_impl=replicate_group_config,
        validate_impl=validate_group_config_sync,
    )
    register_system_settings_tools(
        app,
        replicate_impl=replicate_system_settings,
        validate_impl=validate_system_settings_sync,
    )
    register_version_control_tools(
        app,
        status_impl=collect_group_git_status,
        diff_impl=collect_group_git_diff,
        commit_impl=commit_group_config,
        deploy_impl=deploy_group_config,
        commit_deploy_impl=commit_and_deploy_group,
        commit_deploy_all_impl=commit_and_deploy_all,
        push_impl=push_config_git,
        job_manager=version_control_jobs,
    )
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
