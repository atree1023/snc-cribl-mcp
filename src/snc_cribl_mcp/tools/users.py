"""MCP tool: sync_user."""

# pyright: reportUnusedFunction=false

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp import Context, FastMCP

type SyncUserFunc = Callable[..., Awaitable[dict[str, Any]]]


def register(app: FastMCP, *, impl: SyncUserFunc) -> None:
    """Register the sync_user MCP tool."""

    @app.tool(
        name="sync_user",
        description=(
            "Create or replicate a local Cribl user on a target leader. When source_server is provided, "
            "user profile fields and roles are copied from that leader. Passwords are not readable from "
            "Cribl, so provide password or password_env when creating a missing target user."
        ),
        annotations={
            "title": "Create or replicate local user",
            "readOnlyHint": False,
        },
    )
    async def sync_user(
        ctx: Context,
        target_server: str,
        username: str,
        source_server: str | None = None,
        password: str | None = None,
        password_env: str | None = None,
        first: str | None = None,
        last: str | None = None,
        email: str | None = None,
        roles: list[str] | None = None,
        *,
        disabled: bool | None = None,
        overwrite: bool = True,
        validate_after: bool = True,
    ) -> dict[str, Any]:
        """Create or replicate a local user."""
        await ctx.info(f"Syncing local Cribl user '{username}' to '{target_server}'.")
        return await impl(
            target_server=target_server,
            username=username,
            source_server=source_server,
            password=password,
            password_env=password_env,
            first=first,
            last=last,
            email=email,
            roles=roles,
            disabled=disabled,
            overwrite=overwrite,
            validate_after=validate_after,
        )


__all__ = ["register"]
