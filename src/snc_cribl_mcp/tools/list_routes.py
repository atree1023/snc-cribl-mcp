"""MCP tool: list_routes.

Lists all configured Stream and Edge routes across all groups in the
configured Cribl deployment.
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_routes tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config, products, token_manager, create_cp,
              and collect_product_routes.

    """
    tool_config = ToolConfig(
        collector=deps.collect_product_routes,
        section_name="routes",
        log_message="Listing Cribl Stream and Edge routes across all groups.",
    )

    @app.tool(
        name="list_routes",
        description="Return JSON describing all configured Stream and Edge routes in all groups in the Cribl deployment.",
        annotations={
            "title": "List configured routes",
            "readOnlyHint": True,
        },
    )
    async def list_routes(ctx: Context, server: str | None = None) -> dict[str, Any]:
        return await generic_list_tool(ctx, deps, tool_config, server=server)


__all__ = ["register"]
