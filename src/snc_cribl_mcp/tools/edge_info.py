"""MCP tool: get_edge_info.

Fetches data from Cribl Edge nodes through the leader-proxied teleport API.
"""

# pyright: reportUnusedFunction=false

from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from ..operations.edge_teleport import extract_datacenter_from_edge_host, normalize_edge_hostname
from .params import (
    EdgeDatacenter,
    EdgeEarliestTime,
    EdgeFile,
    EdgeHost,
    EdgeInfoType,
    EdgeLimit,
    EdgeOffset,
    EdgeQuery,
    EdgeRulesets,
    EdgeSearchWindow,
    EdgeServer,
)


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register the get_edge_info tool on the provided app instance.

    Args:
        app: The FastMCP application instance to add the tool to.
        deps: Dependencies namespace with config resolution, token manager,
              client factory, and collect_edge_info.

    """

    @app.tool(
        name="get_edge_info",
        description=(
            "Return JSON from a Cribl Edge node using the leader-proxied teleport API. "
            "info_type='file' reads the file at the absolute Edge node path given in file when query is empty, "
            "and searches that file when query is set. If server is omitted, the tool takes the three-letter "
            "datacenter from edge_host (or datacenter) and selects the matching configured leader."
        ),
        annotations={
            "title": "Get Edge node information",
            "readOnlyHint": True,
            "openWorldHint": False,
        },
    )
    async def get_edge_info(
        ctx: Context,
        edge_host: EdgeHost,
        file: EdgeFile,
        query: EdgeQuery = None,
        offset: EdgeOffset = 0,
        limit: EdgeLimit = 50,
        earliest_time: EdgeEarliestTime = None,
        search_window_seconds: EdgeSearchWindow = 3600,
        rulesets: EdgeRulesets = None,
        info_type: EdgeInfoType = "file",
        datacenter: EdgeDatacenter = None,
        server: EdgeServer = None,
    ) -> dict[str, Any]:
        normalized_host = normalize_edge_hostname(edge_host, datacenter=datacenter)
        dc = extract_datacenter_from_edge_host(normalized_host, datacenter=datacenter)
        await ctx.info(f"Preparing Edge teleport {info_type} request for '{normalized_host}'.")

        config = deps.resolve_config(server) if server else deps.resolve_config_for_datacenter(dc)
        token_manager = deps.get_token_manager(config)
        security = await token_manager.get_security()
        async with deps.create_cp(config, security=security) as client:
            return await deps.collect_edge_info(
                client,
                config=config,
                security=security,
                edge_host=normalized_host,
                info_type=info_type,
                file_path=file,
                query=query,
                offset=offset,
                limit=limit,
                earliest_time=earliest_time,
                search_window_seconds=search_window_seconds,
                rulesets=rulesets,
                datacenter=dc,
                ctx=ctx,
            )


__all__ = ["register"]
