"""MCP tools for Cribl global system settings sync."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

type SystemSettingsFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(
    app: FastMCP,
    *,
    replicate_impl: SystemSettingsFunc,
    validate_impl: SystemSettingsFunc,
) -> None:
    """Register system settings workflow MCP tools."""

    @app.tool(
        name="replicate_system_settings",
        description="Replicate global Cribl system settings from one configured leader to another.",
        annotations={
            "title": "Replicate system settings",
            "readOnlyHint": False,
        },
    )
    async def replicate_system_settings(
        ctx: Context,
        source_server: str,
        target_server: str,
        *,
        overwrite: bool = True,
        validate_after: bool = True,
    ) -> dict[str, Any]:
        """Replicate global system settings."""
        await ctx.info(f"Replicating global system settings from '{source_server}' to '{target_server}'.")
        return await replicate_impl(
            source_server,
            target_server,
            overwrite=overwrite,
            validate_after=validate_after,
        )

    @app.tool(
        name="validate_system_settings",
        description="Validate global Cribl system settings between two configured leaders.",
        annotations={
            "title": "Validate system settings",
            "readOnlyHint": True,
        },
    )
    async def validate_system_settings(
        ctx: Context,
        source_server: str,
        target_server: str,
        *,
        include_payloads: bool = False,
    ) -> dict[str, Any]:
        """Validate global system settings."""
        await ctx.info(f"Validating global system settings from '{source_server}' against '{target_server}'.")
        return await validate_impl(
            source_server,
            target_server,
            include_payloads=include_payloads,
        )


__all__ = ["register"]
