"""MCP tool: list_pipelines.

Lists configured Stream and Edge pipelines across all groups in the
configured Cribl deployment, optionally filtered by pipeline ID.
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .common import ToolConfig, generic_list_tool


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the list_pipelines tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config, products, token_manager, create_cp,
              and collect_product_pipelines.

    """
    tool_config = ToolConfig(
        collector=deps.collect_product_pipelines,
        section_name="pipelines",
        log_message="Listing Cribl Stream and Edge pipelines across all groups.",
        requires_security=True,
    )

    @app.tool(
        name="list_pipelines",
        description=(
            "Return JSON describing configured Stream and Edge pipelines in all groups in the Cribl deployment. "
            "Optionally filter by pipeline_id to fetch a specific pipeline."
        ),
        annotations={
            "title": "List configured pipelines",
            "readOnlyHint": True,
        },
    )
    async def list_pipelines(ctx: Context, pipeline_id: str | None = None) -> dict[str, Any]:
        return await generic_list_tool(
            ctx,
            deps,
            tool_config,
            collector_kwargs={"pipeline_id": pipeline_id},
        )


__all__ = ["register"]
