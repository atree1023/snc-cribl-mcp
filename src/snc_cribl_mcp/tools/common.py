"""Common utilities for MCP tool registration.

Provides factories and helpers for registering tools with consistent patterns.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from cribl_control_plane.models.security import Security
from fastmcp import Context

from ..operations.common import CollectorFunc, ProductResult


@dataclass(frozen=True, slots=True)
class ToolConfig:
    """Configuration for a generic list tool."""

    collector: CollectorFunc
    section_name: str
    log_message: str
    requires_security: bool = False


async def collect_for_products(
    deps: SimpleNamespace,
    collector: CollectorFunc,
    *,
    requires_security: bool = False,
) -> dict[str, ProductResult]:
    """Collect data across all products using the given collector function.

    Args:
        deps: Dependencies namespace with config, products, token_manager, create_cp.
        collector: Async function to call for each product.
        requires_security: Whether the collector requires a security parameter.

    Returns:
        Dictionary mapping product names to their collected results.

    """
    results: dict[str, ProductResult] = {}
    security: Security = await deps.token_manager.get_security()
    async with deps.create_cp(deps.config, security=security) as client:
        for product in deps.products:
            if requires_security:
                result = await collector(
                    client,
                    security=security,
                    product=product,
                    timeout_ms=deps.config.timeout_ms,
                    ctx=deps.ctx,
                )
            else:
                result = await collector(
                    client,
                    product=product,
                    timeout_ms=deps.config.timeout_ms,
                    ctx=deps.ctx,
                )
            results[product.value] = result
    return results


def build_tool_response(
    deps: SimpleNamespace,
    section_name: str,
    data: dict[str, ProductResult],
) -> dict[str, Any]:
    """Build a standard tool response with metadata.

    Args:
        deps: Dependencies namespace with config.
        section_name: Name of the data section (e.g., "sources", "destinations").
        data: Collected data to include in the response.

    Returns:
        Standard response dictionary with metadata.

    """
    return {
        "retrieved_at": datetime.now(UTC).isoformat(),
        "base_url": deps.config.base_url_str,
        section_name: data,
    }


async def generic_list_tool(
    ctx: Context,
    deps: SimpleNamespace,
    tool_config: ToolConfig,
) -> dict[str, Any]:
    """Generic implementation for list tools.

    Args:
        ctx: FastMCP context.
        deps: Dependencies namespace.
        tool_config: Configuration for the tool including collector and settings.

    Returns:
        Tool response dictionary.

    """
    await ctx.info(tool_config.log_message)

    # Inject context into deps for the collector
    deps_with_ctx = SimpleNamespace(**vars(deps), ctx=ctx)

    results = await collect_for_products(
        deps_with_ctx,
        tool_config.collector,
        requires_security=tool_config.requires_security,
    )
    return build_tool_response(deps, tool_config.section_name, results)


__all__ = [
    "CollectorFunc",
    "ProductResult",
    "ToolConfig",
    "build_tool_response",
    "collect_for_products",
    "generic_list_tool",
]
