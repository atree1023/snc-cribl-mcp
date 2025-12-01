"""MCP tool: list_destinations.

Lists all configured Stream and Edge destinations across all groups in the
configured Cribl deployment.
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_destinations tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config, products, token_manager, create_cp,
              and collect_product_destinations.

    """
    tool_config = ToolConfig(
        collector=deps.collect_product_destinations,
        section_name="destinations",
        log_message="Listing Cribl Stream and Edge destinations across all groups.",
    )

    @app.tool(
        name="list_destinations",
        description="Return JSON describing all configured Stream and Edge destinations in all groups in the Cribl deployment.",
        annotations={
            "title": "List configured destinations",
            "readOnlyHint": True,
        },
    )
    async def list_destinations(ctx: Context) -> dict[str, Any]:
        return await generic_list_tool(ctx, deps, tool_config)


__all__ = ["register"]
