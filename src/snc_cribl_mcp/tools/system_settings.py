"""MCP tools for Cribl global system settings sync."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

from .params import SettingsOverwrite, SettingsPayloads, SettingsValidateAfter, SourceServer, TargetServer

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
        description=(
            "Replicate global Cribl system settings (the Global Settings page, /system/settings/conf) from one "
            "configured leader to another. Changes apply immediately with no dry run: when the raw settings differ, "
            "the complete source settings are PATCHed onto the target, so every differing value, including "
            "environment-specific ones, takes the source value. Settings already in sync are skipped. "
            "Use validate_system_settings to preview the differences first."
        ),
        annotations={
            "title": "Replicate system settings",
            "readOnlyHint": False,
        },
    )
    async def replicate_system_settings(
        ctx: Context,
        source_server: SourceServer,
        target_server: TargetServer,
        *,
        overwrite: SettingsOverwrite = True,
        validate_after: SettingsValidateAfter = True,
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
        description=(
            "Compare global Cribl system settings (/system/settings/conf) between two configured leaders. "
            "The raw payloads are compared without semantic normalization, so environment-specific values "
            "count as differences. Read-only."
        ),
        annotations={
            "title": "Validate system settings",
            "readOnlyHint": True,
        },
    )
    async def validate_system_settings(
        ctx: Context,
        source_server: SourceServer,
        target_server: TargetServer,
        *,
        include_payloads: SettingsPayloads = False,
    ) -> dict[str, Any]:
        """Validate global system settings."""
        await ctx.info(f"Validating global system settings from '{source_server}' against '{target_server}'.")
        return await validate_impl(
            source_server,
            target_server,
            include_payloads=include_payloads,
        )


__all__ = ["register"]
