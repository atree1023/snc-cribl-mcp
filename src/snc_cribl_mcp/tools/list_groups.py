"""MCP tool: list_groups.

Registers the tool with the FastMCP app. The implementation is delegated to
``server.list_groups_impl`` to avoid duplication and preserve testability.
"""

# pyright: reportUnusedFunction=false
from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP


def register(app: FastMCP, *, impl: Callable[[Context], Awaitable[dict[str, Any]]]) -> None:
    """Register the list_groups tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        impl: The implementation callable that returns the JSON dict.

    """

    @app.tool(
        name="list_groups",
        description=("Return JSON describing all Stream worker groups and Edge fleets in the configured Cribl deployment."),
        annotations={
            "title": "List worker groups and fleets",
            "readOnlyHint": True,
        },
    )
    async def list_groups(ctx: Context) -> dict[str, Any]:
        return await impl(ctx)


__all__ = ["register"]
