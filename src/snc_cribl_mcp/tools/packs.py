"""MCP tools for managing Cribl Packs."""

# pyright: reportUnusedFunction=false

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from cribl_control_plane import CriblControlPlane
from fastmcp import Context, FastMCP

from ..operations.packs import (
    PackUpdateRequest,
    PackUpgradeOptions,
    collect_packs,
    delete_pack,
    get_pack,
    install_pack,
    resolve_pack_group_scope,
    update_pack,
    upload_pack,
)
from .common import resolve_tool_deps
from .sync_common import ProductName, parse_product

type PackOperation = Callable[[CriblControlPlane, int, str | None], Awaitable[dict[str, Any]]]

_PACK_SCOPE_DESCRIPTION = (
    'For distributed environments, pass product="stream" or product="edge" and a group selector. '
    "The group selector can match the group's id, name, or description."
)


@dataclass(frozen=True, slots=True)
class PackToolCall:
    """Resolved Pack operation details for one MCP tool invocation."""

    server: str | None
    log_message: str
    operation: PackOperation
    section_name: str
    product: ProductName
    group: str | None


async def _run_pack_operation(
    ctx: Context,
    deps: SimpleNamespace,
    call: PackToolCall,
) -> dict[str, Any]:
    """Resolve dependencies, run one Pack operation, and wrap the response."""
    await ctx.info(call.log_message)

    resolved_deps = resolve_tool_deps(deps, call.server)
    security = await resolved_deps.token_manager.get_security()
    scope: dict[str, str | None] | None = None
    async with resolved_deps.create_cp(resolved_deps.config, security=security) as client:
        server_url = None
        if call.group is not None:
            resolved_scope = await resolve_pack_group_scope(
                client,
                product=parse_product(call.product),
                group=call.group,
                timeout_ms=resolved_deps.config.timeout_ms,
            )
            server_url = resolved_scope.server_url
            scope = resolved_scope.as_dict()
        payload = await call.operation(client, resolved_deps.config.timeout_ms, server_url)

    response = {
        "retrieved_at": datetime.now(UTC).isoformat(),
        "base_url": resolved_deps.config.base_url_str,
        call.section_name: payload,
    }
    if scope is not None:
        response["scope"] = scope
    return response


def register(app: FastMCP, *, deps: SimpleNamespace) -> None:  # noqa: C901
    """Register Pack management MCP tools."""

    @app.tool(
        name="list_packs",
        description=(
            "Return JSON describing installed Cribl Packs. Optionally include counts for Pack inputs and outputs "
            'by passing with_="inputs", "outputs", or "inputs,outputs". '
            f"{_PACK_SCOPE_DESCRIPTION}"
        ),
        annotations={
            "title": "List Packs",
            "readOnlyHint": True,
        },
    )
    async def list_packs(
        ctx: Context,
        server: str | None = None,
        with_: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await collect_packs(client, timeout_ms=timeout_ms, with_=with_, server_url=server_url)

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message="Listing installed Cribl Packs.",
                operation=_operation,
                section_name="packs",
                product=product,
                group=group,
            ),
        )

    @app.tool(
        name="get_pack",
        description=f"Return JSON describing one installed Cribl Pack by Pack ID. {_PACK_SCOPE_DESCRIPTION}",
        annotations={
            "title": "Get Pack",
            "readOnlyHint": True,
        },
    )
    async def get_pack_tool(
        ctx: Context,
        pack_id: str,
        server: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await get_pack(client, timeout_ms=timeout_ms, pack_id=pack_id, server_url=server_url)

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message=f"Getting Cribl Pack '{pack_id}'.",
                operation=_operation,
                section_name="pack",
                product=product,
                group=group,
            ),
        )

    @app.tool(
        name="install_pack",
        description=(
            "Install a Cribl Pack. Pass the SDK Pack request body as JSON, such as an id for an empty Pack, "
            "a source URL, git+ repository URL, or an uploaded source returned by upload_pack. "
            f"{_PACK_SCOPE_DESCRIPTION}"
        ),
        annotations={
            "title": "Install Pack",
            "readOnlyHint": False,
        },
    )
    async def install_pack_tool(
        ctx: Context,
        request: dict[str, Any],
        server: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await install_pack(client, timeout_ms=timeout_ms, request=request, server_url=server_url)

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message="Installing Cribl Pack.",
                operation=_operation,
                section_name="install",
                product=product,
                group=group,
            ),
        )

    @app.tool(
        name="upload_pack",
        description=(
            "Upload a local .crbl Pack file and return the source value to pass to install_pack. "
            f"{_PACK_SCOPE_DESCRIPTION}"
        ),
        annotations={
            "title": "Upload Pack",
            "readOnlyHint": False,
        },
    )
    async def upload_pack_tool(
        ctx: Context,
        file_path: str,
        server: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await upload_pack(client, timeout_ms=timeout_ms, file_path=file_path, server_url=server_url)

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message=f"Uploading Cribl Pack file '{file_path}'.",
                operation=_operation,
                section_name="upload",
                product=product,
                group=group,
            ),
        )

    @app.tool(
        name="update_pack",
        description=f"Upgrade an installed Cribl Pack from a source URL or uploaded source ID. {_PACK_SCOPE_DESCRIPTION}",
        annotations={
            "title": "Upgrade Pack",
            "readOnlyHint": False,
        },
    )
    async def update_pack_tool(  # noqa: PLR0913
        ctx: Context,
        pack_id: str,
        source: str,
        server: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
        allow_custom_functions: bool | None = None,  # noqa: FBT001
        minor: str | None = None,
        spec: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await update_pack(
                client,
                timeout_ms=timeout_ms,
                pack_id=pack_id,
                server_url=server_url,
                request=PackUpdateRequest(
                    source=source,
                    options=PackUpgradeOptions(
                        allow_custom_functions=allow_custom_functions,
                        minor=minor,
                        spec=spec,
                    ),
                ),
            )

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message=f"Upgrading Cribl Pack '{pack_id}'.",
                operation=_operation,
                section_name="update",
                product=product,
                group=group,
            ),
        )

    @app.tool(
        name="delete_pack",
        description=f"Uninstall an installed Cribl Pack by Pack ID. {_PACK_SCOPE_DESCRIPTION}",
        annotations={
            "title": "Uninstall Pack",
            "readOnlyHint": False,
        },
    )
    async def delete_pack_tool(
        ctx: Context,
        pack_id: str,
        server: str | None = None,
        product: ProductName = "stream",
        group: str | None = None,
    ) -> dict[str, Any]:
        async def _operation(client: CriblControlPlane, timeout_ms: int, server_url: str | None) -> dict[str, Any]:
            return await delete_pack(client, timeout_ms=timeout_ms, pack_id=pack_id, server_url=server_url)

        return await _run_pack_operation(
            ctx,
            deps,
            PackToolCall(
                server=server,
                log_message=f"Uninstalling Cribl Pack '{pack_id}'.",
                operation=_operation,
                section_name="delete",
                product=product,
                group=group,
            ),
        )


__all__ = ["register"]
