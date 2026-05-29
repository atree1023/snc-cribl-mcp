"""MCP tool: get_leader_overview."""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the get_leader_overview tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config resolution, token management,
              SDK client creation, products, and collect_leader_overview.

    """

    @app.tool(
        name="get_leader_overview",
        description=(
            "Return a compact operational overview for a configured Cribl leader, including leader health, "
            "Cribl version, Stream worker and Edge node counts, active groups/fleets, and source/destination "
            "runtime health by group."
        ),
        annotations={
            "title": "Get leader overview",
            "readOnlyHint": True,
        },
    )
    async def get_leader_overview(ctx: Context, server: str | None = None) -> dict[str, Any]:
        config = deps.resolve_config(server)
        token_manager = deps.get_token_manager(config)
        security = await token_manager.get_security()
        async with deps.create_cp(config, security=security) as client:
            return await deps.collect_leader_overview(
                client,
                config=config,
                security=security,
                products=deps.products,
                ctx=ctx,
            )


__all__ = ["register"]
