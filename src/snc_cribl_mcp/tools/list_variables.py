"""MCP tool: list_variables."""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_variables tool on the provided app instance."""
    tool_config = ToolConfig(
        collector=deps.collect_product_variables,
        section_name="variables",
        log_message="Listing Cribl Stream and Edge variables across all groups.",
        requires_security=True,
    )

    @app.tool(
        name="list_variables",
        description="Return JSON describing all configured Stream and Edge variables in all groups in the Cribl deployment.",
        annotations={
            "title": "List configured variables",
            "readOnlyHint": True,
        },
    )
    async def list_variables(ctx: Context, server: str | None = None) -> dict[str, Any]:
        return await generic_list_tool(ctx, deps, tool_config, server=server)


__all__ = ["register"]
