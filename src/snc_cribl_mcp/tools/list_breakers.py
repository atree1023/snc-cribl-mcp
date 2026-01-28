"""MCP tool: list_breakers.

Lists all configured Stream and Edge event breakers across all groups in the
configured Cribl deployment.
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_breakers tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config, products, token_manager, create_cp,
              and collect_product_breakers.

    """
    tool_config = ToolConfig(
        collector=deps.collect_product_breakers,
        section_name="breakers",
        log_message="Listing Cribl Stream and Edge event breakers across all groups.",
        requires_security=True,
    )

    @app.tool(
        name="list_breakers",
        description=(
            "Return JSON describing all configured Stream and Edge event breakers in all groups in the Cribl deployment."
        ),
        annotations={
            "title": "List configured event breakers",
            "readOnlyHint": True,
        },
    )
    async def list_breakers(ctx: Context, server: str | None = None) -> dict[str, Any]:
        return await generic_list_tool(ctx, deps, tool_config, server=server)


__all__ = ["register"]
