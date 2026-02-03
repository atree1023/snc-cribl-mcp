"""MCP Apps registrations for snc-cribl-mcp.

This module wires:
- a UI resource at a ui:// URI
- a tool that references that UI via _meta.ui.resourceUri
"""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from importlib.resources import files
from types import SimpleNamespace
from typing import Any

from fastmcp import Context, FastMCP

from .tools.common import resolve_tool_deps

UI_RESOURCE_URI = "ui://snc-cribl-mcp/cribl-explorer.html"
UI_MIME_TYPE = "text/html;profile=mcp-app"


def _load_ui_html() -> str:
    """Load the bundled UI HTML from package resources."""
    return files("snc_cribl_mcp.ui").joinpath("cribl-explorer.html").read_text(encoding="utf-8")


async def _collect_groups_payload(ctx: Context, *, deps: SimpleNamespace, server: str | None) -> dict[str, Any]:
    """Return the same shape as list_groups, but for UI seeding."""
    resolved = resolve_tool_deps(deps, server)
    results: dict[str, Any] = {}

    security = await resolved.token_manager.get_security()
    async with resolved.create_cp(resolved.config, security=security) as client:
        for product in resolved.products:
            results[product.value] = await resolved.collect_product_groups(
                client,
                product=product,
                timeout_ms=resolved.config.timeout_ms,
                ctx=ctx,
            )

    return {
        "base_url": resolved.config.base_url_str,
        "groups": results,
    }


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:
    """Register MCP Apps tool + resource on the provided FastMCP app."""

    @app.resource(
        uri=UI_RESOURCE_URI,
        name="Cribl Explorer UI",
        description="Interactive explorer UI for Cribl config (groups/sources/destinations/pipelines/etc).",
        mime_type=UI_MIME_TYPE,
        tags={"ui", "mcp-app"},
        annotations={"readOnlyHint": True},
    )
    async def cribl_explorer_ui() -> str:
        return _load_ui_html()

    @app.tool(
        name="cribl_explorer",
        description=(
            "Open an interactive Cribl Explorer UI (MCP App) to browse groups, sources, destinations, "
            "pipelines, routes, breakers, and lookups."
        ),
        annotations={"title": "Cribl Explorer", "readOnlyHint": True},
        meta={"ui": {"resourceUri": UI_RESOURCE_URI}},
    )
    async def cribl_explorer(ctx: Context, server: str | None = None) -> dict[str, Any]:
        resolved = resolve_tool_deps(deps, server)
        security = await resolved.token_manager.get_security()
        results: dict[str, Any] = {}
        async with resolved.create_cp(resolved.config, security=security) as client:
            for product in resolved.products:
                results[product.value] = await resolved.collect_product_groups(
                    client,
                    product=product,
                    timeout_ms=resolved.config.timeout_ms,
                    ctx=ctx,
                )
        return {
            "base_url": resolved.config.base_url_str,
            "groups": results,
        }


__all__ = ["UI_RESOURCE_URI", "register"]
