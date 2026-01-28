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
    collector_kwargs: dict[str, Any] | None = None,
) -> dict[str, ProductResult]:
    """Collect data across all products using the given collector function.

    Args:
        deps: Dependencies namespace with config, products, token_manager, create_cp.
        collector: Async function to call for each product.
        requires_security: Whether the collector requires a security parameter.
        collector_kwargs: Extra keyword arguments forwarded to the collector.

    Returns:
        Dictionary mapping product names to their collected results.

    """
    results: dict[str, ProductResult] = {}
    extra_kwargs = collector_kwargs or {}
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
                    **extra_kwargs,
                )
            else:
                result = await collector(
                    client,
                    product=product,
                    timeout_ms=deps.config.timeout_ms,
                    ctx=deps.ctx,
                    **extra_kwargs,
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


def resolve_tool_deps(
    deps: SimpleNamespace,
    server: str | None,
) -> SimpleNamespace:
    """Resolve per-request dependencies for a tool invocation.

    Args:
        deps: Base dependency namespace with resolve_config and get_token_manager.
        server: Optional server name passed to the tool.

    Returns:
        Resolved dependency namespace containing config and token_manager.

    """
    config = deps.resolve_config(server)
    token_manager = deps.get_token_manager(config)
    base = dict(vars(deps))
    base.pop("config", None)
    base.pop("token_manager", None)
    return SimpleNamespace(**base, config=config, token_manager=token_manager)


async def generic_list_tool(
    ctx: Context,
    deps: SimpleNamespace,
    tool_config: ToolConfig,
    *,
    server: str | None = None,
    collector_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generic implementation for list tools.

    Args:
        ctx: FastMCP context.
        deps: Dependencies namespace.
        tool_config: Configuration for the tool including collector and settings.
        server: Optional server name passed to the tool.
        collector_kwargs: Extra keyword arguments forwarded to the collector.

    Returns:
        Tool response dictionary.

    """
    await ctx.info(tool_config.log_message)

    resolved_deps = resolve_tool_deps(deps, server)
    # Inject context into deps for the collector
    deps_with_ctx = SimpleNamespace(**vars(resolved_deps), ctx=ctx)

    results = await collect_for_products(
        deps_with_ctx,
        tool_config.collector,
        requires_security=tool_config.requires_security,
        collector_kwargs=collector_kwargs,
    )
    return build_tool_response(resolved_deps, tool_config.section_name, results)


__all__ = [
    "CollectorFunc",
    "ProductResult",
    "ToolConfig",
    "build_tool_response",
    "collect_for_products",
    "generic_list_tool",
    "resolve_tool_deps",
]
