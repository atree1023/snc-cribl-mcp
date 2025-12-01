"""MCP resources for Cribl configuration.

Exposes Cribl configuration as read-only resources.
"""

# pyright: reportUnusedFunction=false

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from cribl_control_plane import CriblControlPlane
from cribl_control_plane.models.security import Security
from fastmcp import Context, FastMCP


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:  # noqa: C901 (many nested resource definitions)
    """Register resources on the provided app instance.

    Args:
        app: The FastMCP application instance to add resources to.
        deps: Dependencies namespace containing config, products, token_manager,
              create_cp, and all collector functions.

    """

    async def _collect_resource_payload(
        ctx: Context,
        *,
        collect_fn: Callable[..., Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Collect per-product data while guarding against collector errors.

        Args:
            ctx: FastMCP context for logging.
            collect_fn: Async collector function to invoke for each product.

        Returns:
            Dictionary mapping product names to their collected results.

        """
        results: dict[str, Any] = {}
        security = await deps.token_manager.get_security()
        async with deps.create_cp(deps.config, security=security) as client:
            for product in deps.products:
                results[product.value] = await _run_collect_fn(
                    collect_fn,
                    client=client,
                    product=product,
                    ctx=ctx,
                    security=security,
                )

        return results

    async def _run_collect_fn(
        collect_fn: Callable[..., Awaitable[dict[str, Any]]],
        *,
        client: CriblControlPlane,
        product: object,
        ctx: Context,
        security: Security,
    ) -> dict[str, Any]:
        """Execute a collector and downgrade failures to structured errors.

        Args:
            collect_fn: Async collector function to invoke.
            client: The Cribl Control Plane client.
            product: The product type (Stream or Edge).
            ctx: FastMCP context for logging.
            security: Security configuration with bearer token.

        Returns:
            Collected result dictionary, or an error payload on failure.

        """
        try:
            if collect_fn in (
                deps.collect_product_breakers,
                deps.collect_product_lookups,
                deps.collect_product_pipelines,
                deps.collect_product_sources,
            ):
                return await collect_fn(
                    client,
                    security=security,
                    product=product,
                    timeout_ms=deps.config.timeout_ms,
                    ctx=ctx,
                )
            return await collect_fn(
                client,
                product=product,
                timeout_ms=deps.config.timeout_ms,
                ctx=ctx,
            )
        except Exception as exc:  # noqa: BLE001 - propagated as JSON error payload
            return {
                "status": "error",
                "error": str(exc),
                "error_type": exc.__class__.__name__,
            }

    def _build_response(section: str, data: dict[str, Any]) -> dict[str, Any]:
        """Build a standard resource response with metadata.

        Args:
            section: Name of the data section (e.g., "groups", "sources").
            data: Collected data to include in the response.

        Returns:
            Response dictionary with timestamp, base_url, and data section.

        """
        timestamp = datetime.now(UTC).isoformat()
        return {
            "retrieved_at": timestamp,
            "base_url": deps.config.base_url_str,
            section: data,
        }

    @app.resource(
        uri="cribl://groups",
        name="Cribl Groups",
        description="Return a JSON list of all worker groups and Edge fleets.",
        mime_type="application/json",
        tags={"groups", "config"},
    )
    async def get_groups(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_groups)
        return _build_response("groups", data)

    @app.resource(
        uri="cribl://sources",
        name="Cribl Sources",
        description="Return a JSON list of all configured sources.",
        mime_type="application/json",
        tags={"sources", "config"},
    )
    async def get_sources(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_sources)
        return _build_response("sources", data)

    @app.resource(
        uri="cribl://destinations",
        name="Cribl Destinations",
        description="Return a JSON list of all configured destinations.",
        mime_type="application/json",
        tags={"destinations", "config"},
    )
    async def get_destinations(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(
            ctx,
            collect_fn=deps.collect_product_destinations,
        )
        return _build_response("destinations", data)

    @app.resource(
        uri="cribl://pipelines",
        name="Cribl Pipelines",
        description="Return a JSON list of all configured pipelines.",
        mime_type="application/json",
        tags={"pipelines", "config"},
    )
    async def get_pipelines(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_pipelines)
        return _build_response("pipelines", data)

    @app.resource(
        uri="cribl://routes",
        name="Cribl Routes",
        description="Return a JSON list of all configured routes.",
        mime_type="application/json",
        tags={"routes", "config"},
    )
    async def get_routes(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_routes)
        return _build_response("routes", data)

    @app.resource(
        uri="cribl://breakers",
        name="Cribl Event Breakers",
        description="Return a JSON list of all configured event breakers.",
        mime_type="application/json",
        tags={"breakers", "config"},
    )
    async def get_breakers(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_breakers)
        return _build_response("breakers", data)

    @app.resource(
        uri="cribl://lookups",
        name="Cribl Lookups",
        description="Return a JSON list of all configured lookups.",
        mime_type="application/json",
        tags={"lookups", "config"},
    )
    async def get_lookups(ctx: Context) -> dict[str, Any]:
        data = await _collect_resource_payload(ctx, collect_fn=deps.collect_product_lookups)
        return _build_response("lookups", data)


__all__ = ["register"]
