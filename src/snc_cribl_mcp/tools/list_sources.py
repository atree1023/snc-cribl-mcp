"""MCP tool: list_sources.

Lists all configured Stream and Edge sources across all groups in the
configured Cribl deployment.

This tool returns both:
- Regular sources (from /system/inputs endpoint)
- Collector sources (from /lib/jobs endpoint, filtered to type='collection')
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_sources tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config, products, token_manager, create_cp,
              and collect_product_sources.

    """
    tool_config = ToolConfig(
        collector=deps.collect_product_sources,
        section_name="sources",
        log_message="Listing Cribl Stream and Edge sources across all groups.",
        requires_security=True,  # Required for collector sources via HTTP
    )

    @app.tool(
        name="list_sources",
        description=(
            "Return JSON describing all configured Stream and Edge sources in all groups in the Cribl deployment. "
            "Includes both regular input sources and collector sources (S3, REST, database, etc.)."
        ),
        annotations={
            "title": "List configured sources",
            "readOnlyHint": True,
        },
    )
    async def list_sources(ctx: Context, server: str | None = None) -> dict[str, Any]:
        return await generic_list_tool(ctx, deps, tool_config, server=server)


__all__ = ["register"]
